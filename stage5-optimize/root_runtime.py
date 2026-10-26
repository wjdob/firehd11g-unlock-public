"""Bounded, journaled root runtime trials; no boot hooks or verified-partition writes."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shlex
import time
import uuid

import fireopt as f
import root_net

ZDEV = "/dev/block/zram0"
ZSYS = "/sys/block/zram0"
MIB = 1024 * 1024
MARGIN_KIB = 256 * 1024


def integers(text: str) -> dict:
    return {k: int(v) for k, v in re.findall(r"(?m)^(\w+)[:=]?\s+(\d+)(?: kB)?$", text)}


def swaps(adb) -> list[dict]:
    rows = []
    for line in adb.shell("cat /proc/swaps", root=True).splitlines()[1:]:
        fields = line.split()
        if len(fields) != 5:
            raise f.Error("Unrecognized swap table")
        rows.append({"device": fields[0], "size_kib": int(fields[2]),
                     "used_kib": int(fields[3]), "priority": int(fields[4])})
    return rows


def zram_state(adb) -> dict:
    output = adb.shell(
        "set -e\n" + "\n".join(f"printf '{key}='; cat {ZSYS}/{key}" for key in
                                   ("disksize", "initstate", "mem_limit", "max_comp_streams", "comp_algorithm")), root=True)
    values = f.settings_map(output)
    algorithm = re.search(r"\[([a-z0-9_]+)\]", values.get("comp_algorithm", ""))
    if not algorithm:
        raise f.Error("Cannot identify zRAM compressor")
    return {"disksize": int(values["disksize"]), "initstate": int(values["initstate"]),
            "mem_limit": int(values["mem_limit"]), "max_comp_streams": int(values["max_comp_streams"]),
            "algorithm": algorithm[1], "active": any(row["device"].endswith("/zram0") for row in swaps(adb))}


def vm_state(adb) -> int:
    return int(adb.shell("cat /proc/sys/vm/swappiness", root=True))


def assert_zram_device(adb):
    output = adb.shell(f"set -e\ntest -b {ZDEV}\nprintf 'sys='; cat {ZSYS}/dev\n"
        f"printf 'block='; stat -c '%t:%T' {ZDEV}\nprintf 'path='; readlink -f {ZSYS}\n"
        f"printf 'holders='; ls {ZSYS}/holders; echo\n"
        f"printf 'backing='; if [ -e {ZSYS}/backing_dev ]; then cat {ZSYS}/backing_dev; else echo none; fi\n"
        "if grep -q '/zram0 ' /proc/mounts; then exit 1; fi", root=True)
    fields = f.settings_map(output)
    try:
        sys_device = tuple(int(n) for n in fields["sys"].split(":"))
        block_device = tuple(int(n, 16) for n in fields["block"].split(":"))
    except (KeyError, ValueError) as exc:
        raise f.Error("Cannot establish zRAM block-device identity") from exc
    if sys_device != block_device or fields.get("path") != "/sys/devices/virtual/block/zram0" or fields.get("holders") or fields.get("backing") != "none":
        raise f.Error("zram0 node is not an unused, RAM-only virtual block device")


def metrics(adb) -> dict:
    result = {"memory_kib": integers(adb.shell("cat /proc/meminfo", root=True)),
            "vmstat": integers(adb.shell("cat /proc/vmstat", root=True)),
            "cpu_ticks": [int(n) for n in adb.shell("head -1 /proc/stat", root=True).split()[1:]],
            "diskstats": adb.shell("cat /proc/diskstats", root=True),
            "uptime": adb.shell("cat /proc/uptime", root=True), "swaps": swaps(adb)}
    for key, command in {
        "zram_statistics": f"cat {ZSYS}/mm_stat {ZSYS}/io_stat",
        "thermal": "for p in /sys/class/thermal/thermal_zone*; do printf '%s ' $p; cat $p/temp; done",
        "wakeup_sources": "cat /sys/kernel/debug/wakeup_sources",
    }.items():
        try:
            result[key] = adb.shell(command, root=True)
        except f.Error as exc:
            result[key] = {"unavailable": str(exc)}
    return result


def inspect(adb) -> dict:
    snapshot = f.inspect(adb)
    f.ready(snapshot)
    zram = {"available": False}
    try:
        assert_zram_device(adb)
        zram = {"available": True, "state": zram_state(adb),
                "statistics": adb.shell(f"cat {ZSYS}/mm_stat", root=True)}
        adb.shell("test -x /system/bin/mkswap && test -x /system/bin/swapon && test -x /system/bin/swapoff", root=True)
    except f.Error as exc:
        zram.update(available=False, error=str(exc))
    snapshot["runtime"] = {"zram": zram, "swappiness": vm_state(adb),
        "network": root_net.inspect(adb), "metrics": metrics(adb),
        "cpu_io": adb.shell("for p in /sys/devices/system/cpu/cpufreq/policy*; do echo $p; "
            "cat $p/scaling_governor $p/scaling_min_freq $p/scaling_max_freq; done; "
            "cat /sys/block/mmcblk0/queue/scheduler /sys/block/mmcblk0/queue/read_ahead_kb", root=True)}
    if f.identity(adb) != snapshot["identity"]:
        raise f.Error("Device changed during root assessment")
    return snapshot


def build_plan(snapshot: dict, zram_mib: int | None, swappiness: int | None, network_packages: list[str]) -> dict:
    f.ready(snapshot)
    operations = []
    if zram_mib is not None:
        if zram_mib not in (256, 512):
            raise f.Error("zRAM trials are limited to 256 or 512 MiB")
        capability = snapshot["runtime"]["zram"]
        if not capability["available"]:
            raise f.Error("Required zRAM capabilities are unavailable")
        before = capability["state"]
        if before["active"] or before["initstate"] != 0 or before["disksize"] != 0:
            raise f.Error("zram0 is already configured; the suite never replaces it")
        if snapshot["runtime"]["metrics"]["memory_kib"].get("MemAvailable", 0) < 512 * 1024:
            raise f.Error("Insufficient memory headroom for a zRAM trial")
        operations.append({"kind": "zram", "key": "zram0", "before": dict(before),
            "after": dict(before, disksize=zram_mib * MIB, mem_limit=zram_mib * MIB // 2,
                          initstate=1, active=True),
            "reason": f"{zram_mib} MiB compressed RAM swap, allocator cap {zram_mib // 2} MiB; no flash backing"})
    if swappiness is not None:
        if type(swappiness) is not int or not 0 <= swappiness <= 100:
            raise f.Error("Kernel 4.4 swappiness range is 0..100")
        before = snapshot["runtime"]["swappiness"]
        if before != swappiness:
            operations.append({"kind": "vm", "key": "swappiness", "before": before, "after": swappiness,
                               "reason": "Explicit VM policy experiment, not a universal performance setting"})
    network_snapshot = dict(snapshot, network=snapshot["runtime"]["network"])
    operations.extend(root_net.build_operations(network_snapshot, network_packages))
    if not operations:
        raise f.Error("Choose --zram-mib, --swappiness or --network-packages; no changes selected")
    validate(operations)
    return {"schema": f.SCHEMA, "kind": "root-plan", "identity": snapshot["identity"],
            "root": snapshot["root"], "operations": operations,
            "runtime_only": True, "created_utc": datetime.now(timezone.utc).isoformat()}


def validate(operations: list) -> None:
    if not isinstance(operations, list) or not 1 <= len(operations) <= 5:
        raise f.Error("Invalid runtime operation count")
    seen = set()
    for op in operations:
        if not isinstance(op, dict) or not isinstance(op.get("key"), str):
            raise f.Error("Invalid runtime operation")
        key = (op.get("kind"), op["key"])
        if key in seen:
            raise f.Error("Duplicate runtime operation")
        seen.add(key)
        if key == ("zram", "zram0"):
            for state in (op.get("before"), op.get("after")):
                if not isinstance(state, dict) or set(state) != {"disksize", "initstate", "mem_limit", "max_comp_streams", "algorithm", "active"}:
                    raise f.Error("Invalid zRAM state")
                if any(type(state[k]) is not int or state[k] < 0 for k in ("disksize", "initstate", "mem_limit", "max_comp_streams")) or type(state["active"]) is not bool:
                    raise f.Error("Invalid zRAM numeric state")
                if not re.fullmatch(r"[a-z0-9_]{1,24}", state["algorithm"]) or not 1 <= state["max_comp_streams"] <= 64:
                    raise f.Error("Invalid zRAM compressor/streams")
            before, after = op["before"], op["after"]
            if before["active"] or before["disksize"] or before["initstate"] or before["mem_limit"] > 512 * MIB:
                raise f.Error("Only an unconfigured zram0 may be managed")
            expected = dict(before, disksize=after["disksize"], mem_limit=after["disksize"] // 2, initstate=1, active=True)
            if after["disksize"] not in (256 * MIB, 512 * MIB) or after != expected:
                raise f.Error("Disallowed zRAM target")
        elif key == ("vm", "swappiness"):
            if any(type(op.get(k)) is not int or not 0 <= op[k] <= 100 for k in ("before", "after")):
                raise f.Error("Invalid swappiness operation")
        elif op.get("kind") == "uid-network":
            root_net.validate_operation(op)
        else:
            raise f.Error("Runtime operation is not allowlisted")


def state_now(adb, op):
    if op["kind"] == "zram":
        return zram_state(adb)
    if op["kind"] == "vm":
        return vm_state(adb)
    return root_net.read_state(adb, op)


def owned_partial(state: dict, op: dict) -> bool:
    if op["kind"] == "uid-network":
        return root_net.state_is_owned_partial(state, op)
    if op["kind"] != "zram":
        return False
    before, after = op["before"], op["after"]
    if state["disksize"] == 0 and state["initstate"] == 0 and state["active"] is False and state["mem_limit"] == 0:
        return state["max_comp_streams"] in (before["max_comp_streams"], 1) and state["algorithm"] in (before["algorithm"], "lzo", "lz4")
    return (state["algorithm"] == before["algorithm"] and state["max_comp_streams"] == before["max_comp_streams"]
            and state["disksize"] in (before["disksize"], after["disksize"])
            and state["mem_limit"] in (before["mem_limit"], after["mem_limit"], 0)
            and state["initstate"] in (0, 1))


def write_state(adb, op, target):
    if op["kind"] == "uid-network":
        root_net.write_state(adb, op, target)
    elif op["kind"] == "vm":
        adb.shell(f"printf '%s' {target} > /proc/sys/vm/swappiness", root=True)
    elif target == op["after"]:
        assert_zram_device(adb)
        if zram_state(adb) != op["before"]:
            raise f.Error("zRAM changed immediately before initialization")
        if integers(adb.shell("cat /proc/meminfo", root=True)).get("MemAvailable", 0) < 512 * 1024:
            raise f.Error("Insufficient memory headroom at zRAM execution")
        # Each command must finish before its dependent step; no disk-backed swap.
        adb.shell(f"printf '%s' {target['disksize']} > {ZSYS}/disksize", root=True)
        adb.shell(f"printf '%s' {target['mem_limit']} > {ZSYS}/mem_limit", root=True)
        adb.shell(f"toybox mkswap {ZDEV}", root=True)
        if zram_state(adb) != dict(target, active=False):
            raise f.Error("zRAM initialization/cap readback failed; refusing swap activation")
        adb.shell(f"toybox swapon -p 100 {ZDEV}", root=True)
    else:
        assert_zram_device(adb)
        current = zram_state(adb)
        if current["active"]:
            rows = [r for r in swaps(adb) if r["device"].endswith("/zram0")]
            available = integers(adb.shell("cat /proc/meminfo", root=True)).get("MemAvailable", 0)
            # Headroom is a guard, not proof swapoff cannot fail/OOM; reboot resets runtime.
            if available < rows[0]["used_kib"] + MARGIN_KIB:
                raise f.Error("Insufficient memory for swapoff; leave zRAM active and restore after workload closes or reboot")
            adb.shell(f"toybox swapoff {ZDEV}", root=True)
            if any(row["device"].endswith("/zram0") for row in swaps(adb)):
                raise f.Error("Swap still active; refusing zRAM reset")
        adb.shell(f"printf '%s' 1 > {ZSYS}/reset", root=True)
        # Linux 4.4 reset also clears streams/mem_limit; restore original inactive configuration.
        adb.shell(f"printf '%s' {shlex.quote(target['algorithm'])} > {ZSYS}/comp_algorithm", root=True)
        adb.shell(f"printf '%s' {target['max_comp_streams']} > {ZSYS}/max_comp_streams", root=True)
        adb.shell(f"printf '%s' {target['mem_limit']} > {ZSYS}/mem_limit", root=True)
    if state_now(adb, op) != target:
        raise f.Error("Root state readback mismatch: " + op["key"])


def journal_valid(journal):
    if journal.get("kind") != "root-journal":
        raise f.Error("Expected a root runtime journal")
    validate(journal["operations"])
    if any(op.get("status") not in ("pending", "started", "applied", "restored", "restore_failed") for op in journal["operations"]):
        raise f.Error("Invalid runtime journal status")


def restore(adb, journal: dict, path: Path, *, automatic=False) -> list[str]:
    journal_valid(journal)
    current_identity = f.identity(adb)
    f.same_device(journal["identity"], current_identity, same_boot=False)
    changed_boot = current_identity["boot_id"] != journal["identity"]["boot_id"]
    conflicts = []
    for op in reversed(journal["operations"]):
        if op["status"] not in ("started", "applied", "restore_failed"):
            continue
        try:
            if automatic and op.get("outcome_unknown"):
                raise f.Error("Remote command may still run; wait, then explicitly restore/verify")
            state = state_now(adb, op)
            if state != op["before"]:
                if changed_boot:
                    raise f.Error("New boot has different runtime state; old journal does not own it")
                if state != op["after"] and not owned_partial(state, op):
                    raise f.Error("Foreign runtime state; refusing overwrite")
                f.same_device(current_identity, f.identity(adb), same_boot=True)
                write_state(adb, op, op["before"])
            op.update(status="restored", outcome_unknown=False)
            op.pop("restore_error", None)
        except (f.Error, KeyboardInterrupt) as exc:
            if isinstance(exc, (f.Uncertain, KeyboardInterrupt)):
                op["outcome_unknown"] = True
            op.update(status="restore_failed", restore_error=str(exc))
            conflicts.append(op["key"])
        f.save(path, journal)
    journal["status"] = "restore_incomplete" if conflicts else "restored"
    f.save(path, journal)
    return conflicts


def apply(adb, plan: dict, path: Path) -> dict:
    if plan.get("kind") != "root-plan" or plan.get("runtime_only") is not True:
        raise f.Error("Expected a runtime-only root plan")
    validate(plan["operations"])
    baseline = inspect(adb)
    f.same_device(plan["identity"], baseline["identity"], same_boot=True)
    if plan["root"].get("hashes") != baseline["root"].get("hashes"):
        raise f.Error("Root assets changed since planning")
    network_ops = [op for op in plan["operations"] if op["kind"] == "uid-network"]
    if network_ops:
        recreated = root_net.build_operations(dict(baseline, network=baseline["runtime"]["network"]), [op["key"] for op in network_ops])
        if [(op["key"], op["uid"], op["version"] ) for op in recreated] != [(op["key"], op["uid"], op["version"]) for op in network_ops]:
            raise f.Error("Network package identity/protection changed")
    for op in plan["operations"]:
        if state_now(adb, op) != op["before"]:
            raise f.Error("Runtime state changed since planning: " + op["key"])
    journal = {"schema": f.SCHEMA, "kind": "root-journal", "identity": baseline["identity"],
        "status": "applying", "baseline": baseline, "plan_sha256": f.digest(plan),
        "operations": [dict(op, status="pending") for op in plan["operations"]]}
    f.save(path, journal)
    try:
        for op in journal["operations"]:
            f.same_device(journal["identity"], f.identity(adb), same_boot=True)
            if op["kind"] == "uid-network":
                latest = f.inspect(adb)
                f.ready(latest)
                package = latest["packages"].get(op["key"], {})
                if (op["key"] in latest["protected"] or not package.get("effective_enabled") or package.get("hidden") or package.get("suspended")
                    or (package.get("uid"), package.get("version")) != (op["uid"], op["version"])):
                    raise f.Error("Network target policy changed")
            if state_now(adb, op) != op["before"]:
                raise f.Error("Runtime state changed immediately before write")
            op["status"] = "started"
            f.save(path, journal)
            try:
                write_state(adb, op, op["after"])
            except (f.Uncertain, KeyboardInterrupt):
                op["outcome_unknown"] = True
                f.save(path, journal)
                raise
            op["status"] = "applied"
            f.save(path, journal)
        after = inspect(adb)
        f.same_device(journal["identity"], after["identity"], same_boot=True)
        if baseline["root"]["hashes"] != after["root"]["hashes"] or baseline["home"] != after["home"] or baseline["persistence"] != after["persistence"]:
            raise f.Error("Root/launcher/persistence changed")
        for op in journal["operations"]:
            if state_now(adb, op) != op["after"]:
                raise f.Error("Runtime state drift after apply")
        journal.update(status="applied", after=after)
        f.save(path, journal)
        return journal
    except BaseException as exc:
        journal.update(status="failed", error=str(exc))
        f.save(path, journal)
        try:
            conflicts = restore(adb, journal, path, automatic=True)
            suffix = "restore incomplete: " + ", ".join(conflicts) if conflicts else "original runtime configuration restored"
        except BaseException as rollback:
            journal.update(status="restore_incomplete", restore_error=str(rollback))
            f.save(path, journal)
            suffix = "restore incomplete; reconnect and restore this journal"
        raise f.Error(f"Root apply failed: {exc}; {suffix}. Journal: {path}") from exc


@contextmanager
def device_lock(adb, source: Path):
    f.RUNS.mkdir(parents=True, exist_ok=True)
    import hashlib
    lock = f.RUNS / (hashlib.sha256(adb.serial.encode()).hexdigest()[:16] + ".lock")
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise f.Error(f"Device transaction lock exists: {lock}") from exc
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(f"pid={os.getpid()}\nsource={source.resolve()}\n")
        yield
    finally:
        lock.unlink(missing_ok=True)


def new_folder() -> Path:
    return f.RUNS / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8])


def summary(plan):
    return "\n".join([f"Root runtime plan: {len(plan['operations'])} changes (reset on reboot)"] +
                     [f"  {op['kind']} {op['key']}: {op['reason']}" for op in plan["operations"]])


def sample(adb, seconds: int, out: Path):
    identity = f.identity(adb)
    health = f.inspect(adb)
    f.ready(health)
    start = metrics(adb)
    t0 = time.monotonic()
    print(f"Sampling {seconds}s; use the workload you want to compare.", flush=True)
    time.sleep(seconds)
    end = metrics(adb)
    elapsed = time.monotonic() - t0
    f.same_device(identity, f.identity(adb), same_boot=True)
    delta = {k: end["vmstat"][k] - v for k, v in start["vmstat"].items() if k in end["vmstat"]}
    cpu = [b - a for a, b in zip(start["cpu_ticks"][:8], end["cpu_ticks"][:8])]
    data = {"schema": f.SCHEMA, "kind": "root-sample", "identity": identity, "seconds": elapsed,
            "start": start, "end": end, "vmstat_delta": delta,
            "cpu_busy_percent": 100 * (sum(cpu) - cpu[3] - cpu[4]) / max(sum(cpu), 1)}
    f.save(out, data)
    print(f"CPU busy {data['cpu_busy_percent']:.1f}%; major faults {delta.get('pgmajfault', 0)}; "
          f"swap-in/out pages {delta.get('pswpin', 0)}/{delta.get('pswpout', 0)}")
    print(f"Available RAM {start['memory_kib'].get('MemAvailable', 0)//1024} -> {end['memory_kib'].get('MemAvailable', 0)//1024} MiB")


def add_parsers(sub):
    p = sub.add_parser("root-assess", help="Read-only kernel, zRAM and UID firewall capabilities")
    p.add_argument("--out", type=Path)
    p = sub.add_parser("root-plan", help="Plan root runtime trials")
    p.add_argument("--zram-mib", type=int, choices=(256, 512))
    p.add_argument("--swappiness", type=int, choices=range(101), metavar="0..100")
    p.add_argument("--network-packages", help="Exact comma-separated metrics packages; blocks all non-loopback egress")
    p.add_argument("--out", type=Path)
    for action in ("root-apply", "root-restore", "root-verify"):
        p = sub.add_parser(action)
        p.add_argument("file", type=Path)
        if action != "root-verify":
            p.add_argument("--execute", action="store_true")
    p = sub.add_parser("sample", help="Read-only short workload counter measurement")
    p.add_argument("--seconds", type=int, choices=range(1, 61), default=15, metavar="1..60")
    p.add_argument("--out", type=Path)


def dispatch(args, adb) -> int:
    if args.command == "sample":
        out = args.out or new_folder() / "sample.json"
        sample(adb, args.seconds, out)
        print(f"Saved: {out.resolve()}")
        return 0
    if args.command in ("root-assess", "root-plan"):
        snapshot = inspect(adb)
        out = args.out or new_folder() / ("root-assessment.json" if args.command == "root-assess" else "root-plan.json")
        if args.command == "root-assess":
            f.save(out, snapshot)
            print(f.report(snapshot))
            print(f"zRAM: {snapshot['runtime']['zram']}; swappiness: {snapshot['runtime']['swappiness']}")
        else:
            packages = [p.strip() for p in (args.network_packages or "").split(",") if p.strip()]
            plan = build_plan(snapshot, args.zram_mib, args.swappiness, packages)
            f.save(out.parent / (out.stem + ".assessment.json"), snapshot)
            f.save(out, plan)
            print(summary(plan))
        print(f"Saved: {out.resolve()}")
        return 0
    data = f.read(args.file)
    if args.command == "root-apply":
        if data.get("kind") != "root-plan":
            raise f.Error("Expected a root plan")
        validate(data["operations"])
        if not args.execute:
            print(summary(data))
            print("Preview only. Add --execute for this runtime trial.")
            return 0
    else:
        journal_valid(data)
        f.same_device(data["identity"], f.identity(adb), same_boot=False)
        if args.command == "root-verify":
            if data.get("status") not in ("applied", "restored") or any(op.get("outcome_unknown") or op["status"] in ("started", "restore_failed") for op in data["operations"]):
                raise f.Error("Runtime transaction is unresolved; allow remote commands to finish, then restore")
            current = inspect(adb)
            if current["root"]["hashes"] != data["baseline"]["root"]["hashes"]:
                raise f.Error("Root assets changed")
            for op in data["operations"]:
                expected = op["after"] if op["status"] == "applied" else op["before"]
                if state_now(adb, op) != expected:
                    raise f.Error("Runtime verification mismatch: " + op["key"])
            print("Root runtime configuration and persistence health verified.")
            return 0
        if not args.execute:
            for op in data["operations"]:
                print(f"{op['key']}: {state_now(adb, op)} -> {op['before']} ({op['status']})")
            print("Preview only. Add --execute to restore runtime state.")
            return 0
    with device_lock(adb, args.file):
        if args.command == "root-apply":
            for old_path in f.RUNS.glob("*/journal.json"):
                old = f.read(old_path)
                if old.get("identity", {}).get("serial") == adb.serial and old.get("status") in ("applying", "failed", "restore_incomplete"):
                    raise f.Error(f"Unresolved transaction: {old_path}")
            path = new_folder() / "journal.json"
            print(f"Journal: {path.resolve()}", flush=True)
            apply(adb, data, path)
            print("Root trial applied and read back. Keep the journal for restoration.")
        else:
            conflicts = restore(adb, data, args.file)
            if conflicts:
                raise f.Error("Runtime restore incomplete: " + ", ".join(conflicts))
            print("Original runtime configuration restored; counters and workload history are not reset.")
    return 0
