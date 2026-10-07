#!/usr/bin/env python3
"""Reversible Fire HD 10 configuration changes; Python stdlib + adb only."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import uuid

HERE = Path(__file__).resolve().parent
RUNS = HERE / "runs"
SCHEMA = 1
PERSIST = "io.github.voidnullvalue.snusnuroot.persistence"
GROUPS = {
    "apps": {
        "com.amazon.photos": "Amazon Photos; removes its sync/UI",
        "com.amazon.photos.importer": "Amazon photo import",
        "com.amazon.avod": "Prime Video",
        "com.amazon.imdb.tv.mobile.app": "Amazon streaming app",
        "com.amazon.mp3": "Amazon Music",
        "com.amazon.kindle": "Kindle reader",
        "com.amazon.kindle.personal_video": "Amazon personal video UI",
        "com.audible.application.kindle": "Audible",
        "com.goodreads.kindle": "Goodreads",
        "com.amazon.weather": "Amazon weather",
        "com.kingsoft.office.amz": "Bundled office app",
        "com.amazon.kor.demo": "Retail demonstration app",
    },
    "shopping": {"com.amazon.windowshop": "Amazon shopping UI"},
    "alexa": {
        "com.amazon.dee.app": "Alexa app",
        "com.amazon.alexa.multimodal.gemini": "Alexa multimodal UI",
        "com.amazon.alexa.youtube.app": "Alexa YouTube UI",
        "com.amazon.smartgenie": "Amazon assistant UI",
        "amazon.speech.sim": "Alexa speech; shared UID may prevent disabling",
        "amazon.speech.davs.davcservice": "Alexa voice assets",
        "amazon.speech.audiostreamproviderservice": "Alexa audio stream service",
        "com.amazon.comms.kids": "Amazon kids communication",
    },
    "ads": {"com.amazon.kindle.kso": "Amazon special-offer UI; may affect lockscreen"},
    "store": {"com.amazon.venezia": "Amazon Appstore; Amazon app licensing/updates may need it"},
    "metrics": {
        "com.amazon.client.metrics": "Amazon client telemetry; some callers may log failures",
        "com.amazon.device.metrics": "Amazon device telemetry; dependency effects unverified",
        "com.amazon.wirelessmetrics.service": "Amazon wireless telemetry; dependency effects unverified",
    },
}
PROFILES = {"conservative": ("apps", "shopping"),
            "google": ("apps", "shopping", "alexa")}
CATALOG = {p: (g, reason) for g, packages in GROUPS.items() for p, reason in packages.items()}
ANIMATIONS = ("window_animation_scale", "transition_animation_scale", "animator_duration_scale")
STATE_COMMAND = {0: "default-state", 1: "enable", 2: "disable", 3: "disable-user", 4: "disable-until-used"}
PROTECTED = {
    PERSIST, "com.amazon.webview.chromium", "com.amazon.firelauncher", "com.android.launcher3",
    "com.amazon.parentalcontrols", "com.amazon.fireos.service.timeservice",
    "com.amazon.device.software.ota", "com.amazon.device.software.ota.override",
    "com.amazon.settings.systemupdates", "com.amazon.kindle.otter.oobe",
    "com.amazon.kindle.otter.oobe.forced.ota", "com.amazon.media.session.monitor",
    "com.amazon.device.messaging", "com.amazon.identity.auth.device.authorization",
}
ROOT_FILES = ("/data/snusnu_hwbinder_root", "/data/securedStorageLocation/w/b",
              "/data/securedStorageLocation/snusnu/waiter.sh", "/data/snusnu_root/bin/watchdog.sh")
PROPS = ("ro.product.device", "ro.product.model", "ro.build.fingerprint", "ro.build.id",
         "ro.build.version.incremental", "ro.build.version.sdk", "ro.build.version.name",
         "ro.build.version.security_patch", "ro.boot.verifiedbootstate", "ro.boot.flash.locked")


class Error(RuntimeError):
    pass


class Uncertain(Error):
    """Transport ended without proof that the remote command has completed."""


def save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with tmp.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(data, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def read(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise Error("Unsupported document schema")
    return data


def digest(data: object) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Adb:
    def __init__(self, executable: str, serial: str | None = None):
        self.executable = executable
        devices = self.run("devices").splitlines()[1:]
        online = [x.split()[0] for x in devices if len(x.split()) >= 2 and x.split()[1] == "device"]
        if serial is None and len(online) != 1:
            raise Error("Specify --serial: exactly one authorized device is required")
        self.serial = serial or online[0]
        if self.serial not in online:
            raise Error("Selected device is offline or unauthorized")

    def run(self, *args: str, payload: str | None = None, timeout: int = 45) -> str:
        try:
            result = subprocess.run([self.executable, *args], input=payload, text=True,
                                    encoding="utf-8", errors="replace", capture_output=True,
                                    timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Uncertain(f"ADB transport failed: {exc}") from exc
        if result.returncode:
            raise Uncertain(f"ADB rc={result.returncode}: {(result.stderr or result.stdout).strip()[:500]}")
        return result.stdout.replace("\r\n", "\n")

    def shell(self, command: str, *, root: bool = False) -> str:
        marker = "__FIREOPT_" + uuid.uuid4().hex + "__"
        script = f"( {command}\n) 2>&1; rc=$?; printf '\\n{marker}:%s\\n' \"$rc\"\n"
        if root:
            # The listener's transport exit code is not the command exit code.
            script = '[ "$(id -u)" = 0 ] || exit 90\n' + script + "exit\n"
            out = self.run("-s", self.serial, "shell", "toybox nc -w 30 127.0.0.1 4325", payload=script)
        else:
            out = self.run("-s", self.serial, "shell", script)
        match = re.search(r"\n" + re.escape(marker) + r":(\d+)\s*$", out)
        if match is None:
            raise Uncertain("Incomplete device response; operation outcome is unknown")
        if int(match[1]):
            raise Error(f"Device command rc={match[1]}: {out[:match.start()].strip()[:500]}")
        return out[:match.start()].strip()


def package_dump(text: str) -> dict:
    # Updated system apps also appear as factory versions in a second section.
    # Those are not the running package or its current user state.
    text = re.split(r"(?m)^Hidden system packages:", text, maxsplit=1)[0]
    result = {}
    for section in re.split(r"(?m)^  Package \[", text)[1:]:
        name = section.split("]", 1)[0]
        uid = re.search(r"\buserId=(\d+)", section)
        version = re.search(r"\bversionCode=(\d+)", section)
        user = re.search(r"(?m)^\s+User 0: ([^\n]+)", section)
        if not uid or not version or not user:
            raise Error(f"Cannot parse package state: {name}")
        state = dict(re.findall(r"(\w+)=([^\s]+)", user[1]))
        enabled = int(state.get("enabled", "-1"))
        if enabled not in STATE_COMMAND or "installed" not in state:
            raise Error(f"Unknown enabled/installed state for {name}")
        result[name] = {"uid": int(uid[1]), "version": version[1], "enabled": enabled,
                        "installed": state["installed"] == "true",
                        "hidden": state.get("hidden") == "true",
                        "suspended": state.get("suspended") == "true",
                        "stopped": state.get("stopped") == "true",
                        "write_secure_settings": bool(re.search(r"android\.permission\.WRITE_SECURE_SETTINGS: granted=true", section))}
    if not result:
        raise Error("Package inventory is empty or unrecognized")
    return result


def settings_map(text: str) -> dict:
    result = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def setting_state(values: dict, key: str) -> dict:
    return {"present": key in values, "value": values.get(key)}


def identity(adb: Adb) -> dict:
    command = "\n".join(f"printf '%s=' {shlex.quote(key)}; getprop {shlex.quote(key)}" for key in PROPS)
    props = settings_map(adb.shell(command))
    if not all(props.get(k) for k in PROPS[:6]):
        raise Error("Incomplete firmware identity")
    if (props["ro.product.device"], props["ro.product.model"], props["ro.build.version.sdk"]) != ("trona", "KFTRWI", "28"):
        raise Error("Only trona/KFTRWI Android 9 (API 28) is supported")
    if adb.shell("am get-current-user") != "0":
        raise Error("Switch to the Owner (user 0) before using the suite")
    return {"serial": adb.serial, "props": props,
            "boot_id": adb.shell("cat /proc/sys/kernel/random/boot_id")}


def root_health(adb: Adb) -> dict:
    result = {"available": False, "selinux": adb.shell("getenforce")}
    try:
        result["id"] = adb.shell("id", root=True)
        result["available"] = bool(re.match(r"uid=0\(root\)", result["id"]))
        command = "\n".join(f"if [ -f {shlex.quote(p)} ]; then sha256sum {shlex.quote(p)}; fi" for p in ROOT_FILES)
        hashes = adb.shell(command, root=True)
        result["hashes"] = {m[2]: m[1] for m in re.finditer(r"(?m)^([0-9a-f]{64})\s+(\S+)\s*$", hashes)}
        procs = adb.shell("ps -A -o PID,PPID,ARGS", root=True)
        result["carrier_resident"] = any("snusnu_hwbinder_root stateful-root-hold" in x for x in procs.splitlines())
        result["watchdog_resident"] = any("sh /data/snusnu_root/bin/watchdog.sh" in x for x in procs.splitlines())
        trigger = adb.shell("getprop persist.sys.saved_time", root=True)
        result["trigger_armed"] = trigger == "x[$(sleep 30;/system/bin/sh /data/securedStorageLocation/w/b)]000"
    except Error as exc:
        result["error"] = str(exc)
    return result


def inspect(adb: Adb) -> dict:
    ident = identity(adb)
    raw_packages = adb.shell("dumpsys package packages")
    packages = package_dump(raw_packages)
    enabled = set(re.findall(r"(?m)^package:(\S+)$", adb.shell("pm list packages -e --user 0")))
    for name, state in packages.items():
        state["effective_enabled"] = name in enabled
    global_values = settings_map(adb.shell("settings list global"))
    # This Fire OS settings tool rejects --user for list/delete; Owner is gated above.
    secure = settings_map(adb.shell("settings list secure"))
    home = adb.shell("cmd package resolve-activity --brief --user 0 -a android.intent.action.MAIN -c android.intent.category.HOME")
    webview = adb.shell("dumpsys webviewupdate")
    policy = adb.shell("dumpsys device_policy")
    protected = set(PROTECTED)
    protected.update(re.findall(r"([\w.]+)/[\w.$]+", home + "\n" + policy))
    for key in ("default_input_method", "enabled_input_methods", "enabled_accessibility_services",
                "assistant", "voice_interaction_service", "voice_recognition_service"):
        protected.update(re.findall(r"([\w.]+)/", secure.get(key, "")))
    protected.update(re.findall(r"(?:Current|Preferred) WebView package.*?: \(([^,\s]+)", webview))
    counts = Counter(p["uid"] for p in packages.values() if p["installed"])
    for name, state in packages.items():
        if name.startswith(("com.android.", "android", "com.google.", "com.mgoogle.", "app.revanced.android.gms")) or state["uid"] < 10000 or counts[state["uid"]] > 1:
            protected.add(name)
    memory = adb.shell("cat /proc/meminfo")
    data = {"schema": SCHEMA, "kind": "assessment", "created_utc": datetime.now(timezone.utc).isoformat(),
            "identity": ident, "packages": packages, "protected": sorted(protected),
            "home": home, "webview": webview, "root": root_health(adb),
            "settings": {k: setting_state(global_values, k) for k in ANIMATIONS},
            "persistence": {k: global_values.get(k) for k in ("snusnu_persist_enabled", "snusnu_persist_status", "snusnu_rearm_status", "snusnu_retry_count")},
            "metrics": {"memory_kib": {k: int(v) for k, v in re.findall(r"(?m)^(\w+):\s+(\d+) kB", memory)},
                        "disk": adb.shell("df -k /data /system /vendor"),
                        "swap": adb.shell("cat /proc/swaps"), "uptime": adb.shell("cat /proc/uptime"),
                        "battery": adb.shell("dumpsys battery"),
                        "memory_by_process": adb.shell("dumpsys meminfo --oom"),
                        "processes": adb.shell("ps -A -o PID,PPID,ARGS")}}
    if identity(adb) != ident:
        raise Error("Device rebooted or firmware changed during assessment")
    return data


def ready(snapshot: dict) -> None:
    root = snapshot["root"]
    if root.get("error") or not root.get("available") or root.get("selinux") != "Permissive":
        raise Error("Healthy existing uid-0 listener and Permissive mode are required; the suite never re-roots")
    if snapshot["persistence"].get("snusnu_persist_enabled") == "1":
        if not root.get("carrier_resident") or not root.get("watchdog_resident") or set(root.get("hashes", {})) != set(ROOT_FILES):
            raise Error("Persistence is enabled but its files/processes are incomplete")
        actor = snapshot["packages"].get(PERSIST, {})
        if not actor.get("installed") or not actor.get("effective_enabled") or actor.get("hidden") or actor.get("suspended") or actor.get("stopped") or not actor.get("write_secure_settings"):
            raise Error("Persistence actor is missing, disabled, stopped or lacks its required grant")
        if not root.get("trigger_armed") or snapshot["persistence"].get("snusnu_persist_status") != "kernel_write_ok" or snapshot["persistence"].get("snusnu_rearm_status") != "ok":
            raise Error("Persistence is not currently ready for the next boot; wait for re-arm and assess again")


def make_plan(snapshot: dict, profile: str, groups: list[str] | None, animations: str | None, only: list[str] | None = None) -> dict:
    ready(snapshot)
    selected = groups if groups is not None else list(PROFILES[profile])
    if any(g not in GROUPS for g in selected):
        raise Error("Unknown group")
    if only and any(p not in CATALOG or CATALOG[p][0] not in selected for p in only):
        raise Error("--only packages must belong to selected allowlisted groups")
    operations, skipped = [], []
    for name, (group, reason) in CATALOG.items():
        if group not in selected or (only and name not in only):
            continue
        old = snapshot["packages"].get(name)
        why = "not installed" if not old or not old["installed"] else None
        if old and old["installed"]:
            if name in snapshot["protected"]:
                why = "protected dependency, active role, admin or shared UID"
            elif old["hidden"] or old["suspended"]:
                why = "hidden or suspended; preserve existing policy"
            elif not old["effective_enabled"]:
                why = "already disabled; preserve original state"
        if why:
            skipped.append({"package": name, "reason": why})
        else:
            operations.append({"kind": "package", "key": name, "before": old["enabled"], "after": 3,
                               "uid": old["uid"], "version": old["version"], "reason": reason})
    if animations is not None:
        if animations not in ("0", "0.5", "1"):
            raise Error("Animation scale must be 0, 0.5 or 1")
        for key, old in snapshot["settings"].items():
            try:
                matches = old["present"] and old["value"] is not None and float(old["value"]) == float(animations)
            except ValueError:
                matches = False
            if matches:
                skipped.append({"setting": key, "reason": "already at requested scale"})
            else:
                operations.append({"kind": "setting", "key": key, "before": old,
                                   "after": {"present": True, "value": animations}, "reason": "Animation duration; no compute-speed claim"})
    return {"schema": SCHEMA, "kind": "plan", "identity": snapshot["identity"], "root": snapshot["root"],
            "profile": profile, "groups": selected, "operations": operations, "skipped": skipped}


def validate_operations(operations: list) -> None:
    if not isinstance(operations, list) or len(operations) > len(CATALOG) + len(ANIMATIONS):
        raise Error("Invalid operation list")
    seen = set()
    for op in operations:
        if not isinstance(op, dict):
            raise Error("Invalid operation")
        kind, key = op.get("kind"), op.get("key")
        if not isinstance(key, str) or (kind, key) in seen:
            raise Error("Invalid or duplicate operation key")
        seen.add((kind, key))
        if kind == "package":
            if key not in CATALOG or key in PROTECTED or type(op.get("before")) is not int or op["before"] not in (0, 1) or type(op.get("after")) is not int or op["after"] != 3 or type(op.get("uid")) is not int or op["uid"] < 10000 or not re.fullmatch(r"\d+", str(op.get("version", ""))):
                raise Error(f"Disallowed package operation: {key}")
        elif kind == "setting" and key in ANIMATIONS:
            for state in (op.get("before"), op.get("after")):
                if not isinstance(state, dict) or type(state.get("present")) is not bool:
                    raise Error("Invalid setting state")
                value = state.get("value")
                if state["present"] and (not isinstance(value, str) or len(value) > 128 or any(c in value for c in "\r\n\x00")):
                    raise Error("Invalid animation value")
                if not state["present"] and value is not None:
                    raise Error("Absent setting must have no value")
            if op["after"] not in ({"present": True, "value": "0"}, {"present": True, "value": "0.5"}, {"present": True, "value": "1"}):
                raise Error("Disallowed animation target")
        else:
            raise Error(f"Disallowed operation: {kind}/{key}")


def same_device(expected: dict, current: dict, *, same_boot: bool) -> None:
    if not isinstance(expected, dict) or expected.get("serial") != current["serial"] or expected.get("props") != current["props"] or (same_boot and expected.get("boot_id") != current["boot_id"]):
        raise Error("Device/firmware/boot differs from saved state; assess and plan again")


def validate_journal(journal: dict) -> None:
    validate_operations(journal["operations"])
    if journal.get("kind") != "journal" or any(op.get("status") not in ("pending", "started", "applied", "restored", "restore_failed") for op in journal["operations"]):
        raise Error("Invalid journal operation status")


def state_now(adb: Adb, op: dict) -> object:
    if op["kind"] == "package":
        packages = package_dump(adb.shell("dumpsys package " + shlex.quote(op["key"])))
        state = packages.get(op["key"])
        if not state or not state["installed"] or (state["uid"], state["version"]) != (op["uid"], op["version"]):
            raise Error("Package removed, reinstalled or updated: " + op["key"])
        return state["enabled"]
    return setting_state(settings_map(adb.shell("settings list global")), op["key"])


def set_state(adb: Adb, op: dict, state: object) -> None:
    key = shlex.quote(op["key"])
    if op["kind"] == "package":
        command = f"pm {STATE_COMMAND[state]} --user 0 {key}"
    elif state["present"]:
        command = f"settings put global {key} {shlex.quote(state['value'])}"
    else:
        command = f"settings delete global {key}"
    adb.shell(command)
    if state_now(adb, op) != state:
        raise Error("Readback did not match: " + op["key"])


def restore(adb: Adb, journal: dict, path: Path, *, automatic: bool = False) -> list[str]:
    validate_journal(journal)
    same_device(journal["identity"], identity(adb), same_boot=False)
    conflicts = []
    for op in reversed(journal["operations"]):
        if op.get("status") not in ("started", "applied", "restore_failed"):
            continue
        try:
            if automatic and op.get("outcome_unknown"):
                raise Error("Remote command may still be running; allow it to finish, then explicitly restore and verify")
            current = state_now(adb, op)
            if current != op["before"]:
                if current != op["after"]:
                    raise Error("State changed outside this transaction; refusing to overwrite it")
                set_state(adb, op, op["before"])
            op["status"] = "restored"
            op["outcome_unknown"] = False
            op.pop("restore_error", None)
        except (Error, KeyboardInterrupt) as exc:
            if isinstance(exc, (Uncertain, KeyboardInterrupt)):
                op["outcome_unknown"] = True
            conflicts.append(op["key"])
            op["status"] = "restore_failed"
            op["restore_error"] = str(exc) or "Interrupted"
        save(path, journal)
    journal["status"] = "restore_incomplete" if conflicts else "restored"
    save(path, journal)
    return conflicts


def apply(adb: Adb, plan: dict, path: Path) -> dict:
    if plan.get("kind") != "plan":
        raise Error("Expected a saved plan")
    validate_operations(plan["operations"])
    current = inspect(adb)
    ready(current)
    same_device(plan["identity"], current["identity"], same_boot=True)
    if plan.get("root", {}).get("hashes") != current["root"].get("hashes"):
        raise Error("Root assets changed since planning")
    for op in plan["operations"]:
        if op["kind"] == "package" and op["key"] in current["protected"]:
            raise Error("Package is now protected: " + op["key"])
        if op["kind"] == "package":
            state = current["packages"].get(op["key"], {})
            if state.get("hidden") or state.get("suspended") or not state.get("effective_enabled"):
                raise Error("Package policy changed since planning: " + op["key"])
        if state_now(adb, op) != op["before"]:
            raise Error("State changed since planning: " + op["key"])
    journal = {"schema": SCHEMA, "kind": "journal", "identity": current["identity"],
               "plan_sha256": digest(plan), "status": "applying", "baseline": current,
               "operations": [dict(op, status="pending") for op in plan["operations"]]}
    save(path, journal)
    try:
        for op in journal["operations"]:
            same_device(journal["identity"], identity(adb), same_boot=True)
            # Re-read roles and shared UIDs at each package boundary, not only at planning.
            if op["kind"] == "package":
                latest = inspect(adb)
                ready(latest)
                if op["key"] in latest["protected"]:
                    raise Error("Package acquired a protected role: " + op["key"])
                state = latest["packages"].get(op["key"], {})
                if state.get("hidden") or state.get("suspended") or not state.get("effective_enabled"):
                    raise Error("Package policy changed before mutation: " + op["key"])
            if state_now(adb, op) != op["before"]:
                raise Error("State changed immediately before mutation: " + op["key"])
            op["status"] = "started"
            save(path, journal)  # Include this attempt even if transport fails after the write.
            try:
                set_state(adb, op, op["after"])
            except (Uncertain, KeyboardInterrupt):
                op["outcome_unknown"] = True
                save(path, journal)
                raise
            op["status"] = "applied"
            save(path, journal)
        after = inspect(adb)
        ready(after)
        same_device(journal["identity"], after["identity"], same_boot=True)
        if after["root"].get("hashes") != current["root"].get("hashes") or after["home"] != current["home"] or after["persistence"] != current["persistence"]:
            raise Error("Root assets, launcher or persistence status changed")
        for op in journal["operations"]:
            if state_now(adb, op) != op["after"]:
                raise Error("Final state drift: " + op["key"])
        journal.update(status="applied", after=after)
        save(path, journal)
    except BaseException as exc:
        journal.update(status="failed", error=str(exc) or type(exc).__name__)
        save(path, journal)
        try:
            conflicts = restore(adb, journal, path, automatic=True)
            result = "restore incomplete: " + ", ".join(conflicts) if conflicts else "original configuration restored"
        except BaseException as rollback_exc:
            journal.update(status="restore_incomplete", restore_error=str(rollback_exc))
            save(path, journal)
            result = "restore incomplete; reconnect and run restore with this journal"
        raise Error(f"Apply failed: {exc}; {result}. Journal: {path}") from exc
    return journal


def report(snapshot: dict) -> str:
    mem = snapshot["metrics"]["memory_kib"]
    packages = snapshot["packages"]
    return (f"Device: {snapshot['identity']['props']['ro.build.version.name']}\n"
            f"Packages: {sum(p['installed'] for p in packages.values())} installed; "
            f"{sum(p['installed'] and not p['effective_enabled'] for p in packages.values())} disabled\n"
            f"RAM available: {mem.get('MemAvailable', 0) / 1024:.0f} MiB; swap: {mem.get('SwapTotal', 0) / 1024:.0f} MiB\n"
            f"Root: {snapshot['root'].get('available')}; SELinux: {snapshot['root']['selinux']}; "
            f"persistence: {snapshot['persistence']}\n{snapshot['metrics']['disk']}")


def summary(plan: dict) -> str:
    lines = [f"Plan: {len(plan['operations'])} changes; {len(plan['skipped'])} skipped"]
    for op in plan["operations"]:
        lines.append(f"  {op['kind']} {op['key']}: {op['before']} -> {op['after']} ({op['reason']})")
    for op in plan["skipped"]:
        lines.append(f"  skip {op.get('package', op.get('setting'))}: {op['reason']}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default=os.environ.get("ADB") or shutil.which("adb") or "adb")
    parser.add_argument("--serial", help="Required when multiple devices are connected")
    sub = parser.add_subparsers(dest="command", required=True)
    import root_runtime
    root_runtime.add_parsers(sub)
    assess = sub.add_parser("assess", help="Read-only device inventory and measurements")
    assess.add_argument("--out", type=Path)
    plan_parser = sub.add_parser("plan", help="Read-only assessment plus reviewable change plan")
    plan_parser.add_argument("--profile", choices=PROFILES, default="conservative")
    plan_parser.add_argument("--groups", help="Comma-separated groups; overrides profile groups")
    plan_parser.add_argument("--only", help="Comma-separated exact package names within selected groups")
    plan_parser.add_argument("--animations", choices=("0", "0.5", "1"))
    plan_parser.add_argument("--out", type=Path)
    for action in ("apply", "restore", "verify"):
        p = sub.add_parser(action)
        p.add_argument("file", type=Path)
        if action in ("apply", "restore"):
            p.add_argument("--execute", action="store_true", help="Perform changes; otherwise only display/inspect")
    args = parser.parse_args()
    try:
        adb = Adb(args.adb, args.serial)
        if args.command.startswith("root-") or args.command == "sample":
            return root_runtime.dispatch(args, adb)
        if args.command in ("assess", "plan"):
            snapshot = inspect(adb)
            folder = RUNS / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8])
            if args.command == "assess":
                out = args.out or folder / "assessment.json"
                save(out, snapshot)
                print(report(snapshot))
            else:
                groups = [g.strip() for g in args.groups.split(",") if g.strip()] if args.groups is not None else None
                only = [g.strip() for g in args.only.split(",") if g.strip()] if args.only else None
                plan = make_plan(snapshot, args.profile, groups, args.animations, only)
                out = args.out or folder / "plan.json"
                save(out.parent / (out.stem + ".assessment.json"), snapshot)
                save(out, plan)
                print(summary(plan))
            print(f"Saved: {out.resolve()}")
            return 0
        document = read(args.file)
        if args.command == "apply" and not args.execute:
            if document.get("kind") != "plan":
                raise Error("Expected a plan")
            validate_operations(document["operations"])
            print(summary(document))
            print("Preview only. Add --execute to apply this exact plan.")
            return 0
        if args.command in ("restore", "verify"):
            validate_journal(document)
            same_device(document["identity"], identity(adb), same_boot=False)
        if args.command == "verify":
            if document.get("status") not in ("applied", "restored") or any(op.get("outcome_unknown") or op.get("status") in ("started", "restore_failed") for op in document["operations"]):
                raise Error("Transaction is unresolved; allow remote commands to finish, then restore")
            mismatches = []
            for op in document["operations"]:
                expected = op["after"] if op.get("status") == "applied" else op["before"]
                current = state_now(adb, op)
                print(f"{op['key']}: {current} (expected {expected})")
                if current != expected:
                    mismatches.append(op["key"])
            verified = inspect(adb)
            ready(verified)
            health = verified["root"]
            print(f"Current root: {health.get('available')}; SELinux: {health['selinux']}")
            if health.get("hashes") != document["baseline"]["root"].get("hashes") or not health.get("available"):
                mismatches.append("root health/assets")
            if mismatches:
                raise Error("Verification mismatch: " + ", ".join(mismatches))
            print("Configuration and root readback passed; check app behavior on the tablet.")
            return 0
        if args.command == "restore" and not args.execute:
            for op in document["operations"]:
                print(f"{op['key']}: {state_now(adb, op)} -> original {op['before']} ({op.get('status')})")
            print("Preview only. Add --execute to restore attempted changes.")
            return 0
        RUNS.mkdir(parents=True, exist_ok=True)
        lock = RUNS / (hashlib.sha256(adb.serial.encode()).hexdigest()[:16] + ".lock")
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise Error(f"Device transaction lock exists: {lock}. If its process is gone, review the journal before removing the stale lock.")
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(f"pid={os.getpid()}\nsource={args.file.resolve()}\n")
            if args.command == "apply":
                # ponytail: one host lock per device; external ADB tools are guarded by readback, not locked.
                for old_path in RUNS.glob("*/journal.json"):
                    old = read(old_path)
                    if old.get("identity", {}).get("serial") == adb.serial and old.get("status") in ("applying", "failed", "restore_incomplete"):
                        raise Error(f"Unresolved transaction: restore {old_path} first")
                if not document["operations"]:
                    print("No changes needed.")
                    return 0
                path = RUNS / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8]) / "journal.json"
                print(f"Journal: {path.resolve()}", flush=True)
                apply(adb, document, path)
                print("Applied and verified. Keep this journal for exact rollback.")
            else:
                conflicts = restore(adb, document, args.file)
                if conflicts:
                    raise Error("Restore incomplete: " + ", ".join(conflicts))
                print("Original package enabled states and settings restored.")
        finally:
            lock.unlink(missing_ok=True)
        return 0
    except (Error, KeyError, ValueError, TypeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    # Runtime helpers share these exception classes when this file is the CLI entry.
    sys.modules["fireopt"] = sys.modules[__name__]
    raise SystemExit(main())
