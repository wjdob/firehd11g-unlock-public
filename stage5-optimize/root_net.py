"""Opt-in, reversible owner-UID egress rejection; never replace Android/VPN rules."""
from __future__ import annotations

from collections import Counter
import re
import shlex

from fireopt import Adb, CATALOG, Error, PROTECTED, package_dump


FAMILIES = {"v4": ("iptables", "icmp-port-unreachable"),
            "v6": ("ip6tables", "icmp6-port-unreachable")}


def _command(adb: Adb, family: str, *args: str) -> str:
    return adb.shell(shlex.join((FAMILIES[family][0], "-w", "5", "-t", "filter", *args)), root=True)


def inspect(adb: Adb) -> dict:
    """Read both filter tables and extension help; do not install probe rules."""
    families = {}
    for family, (tool, reject) in FAMILIES.items():
        capability = {"tool": tool, "available": False, "filter_rules": [],
                      "owner_supported": False, "reject_supported": False}
        try:
            capability["filter_rules"] = _command(adb, family, "-S").splitlines()
            owner = _command(adb, family, "-m", "owner", "-h")
            reject_help = _command(adb, family, "-j", "REJECT", "-h")
            capability["owner_supported"] = "--uid-owner" in owner
            capability["reject_supported"] = "--reject-with" in reject_help and reject in reject_help
            capability["available"] = (capability["owner_supported"] and capability["reject_supported"])
        except Error as exc:
            capability["error"] = str(exc)
        families[family] = capability
    return {"available": all(c["available"] for c in families.values()), "families": families}


def _empty() -> dict:
    return {"chain": False, "rules": [], "hooks": [], "hook_positions": [], "foreign": []}


def _desired(uid: int, family: str) -> dict:
    chain = "FOPT_UID" + str(uid)
    return {"chain": True,
            "rules": [f"-A {chain} -o lo -j RETURN",
                      f"-A {chain} -j REJECT --reject-with {FAMILIES[family][1]}"],
            "hooks": [f"-A OUTPUT -m owner --uid-owner {uid} -j {chain}"],
            "hook_positions": [0], "foreign": []}


def _state(lines: list[str], uid: int, family: str) -> dict:
    """Record every rule in/referencing the chain, including unknown alterations."""
    chain = "FOPT_UID" + str(uid)
    state, output_position = _empty(), 0
    hook = _desired(uid, family)["hooks"][0]
    try:
        rows = [shlex.split(line) for line in lines]
    except ValueError as exc:
        raise Error("Cannot parse filter rule") from exc
    # Several planned UIDs each insert at OUTPUT's head. Ignore earlier hooks only
    # when the entire referenced chain has the same exact, complete owned shape.
    trusted_hooks = set()
    for words in rows:
        match = re.fullmatch(r"-A OUTPUT -m owner --uid-owner (\d+) -j FOPT_UID\1", shlex.join(words))
        if not match or not 10000 <= int(match[1]) < 100000:
            continue
        other_uid = int(match[1])
        other_chain = "FOPT_UID" + str(other_uid)
        touching = [shlex.join(row) for row in rows if
                    (len(row) > 1 and row[1] == other_chain) or
                    any(row[n] in ("-j", "--jump", "-g", "--goto") and
                        n + 1 < len(row) and row[n + 1] == other_chain for n in range(len(row)))]
        desired = _desired(other_uid, family)
        expected = ["-N " + other_chain, *desired["rules"], *desired["hooks"]]
        if Counter(touching) == Counter(expected):
            trusted_hooks.add(desired["hooks"][0])
    for words in rows:
        if not words:
            continue
        normalized = shlex.join(words)
        own_source = len(words) > 1 and words[1] == chain
        references = any(words[n] in ("-j", "--jump", "-g", "--goto") and
                         n + 1 < len(words) and words[n + 1] == chain
                         for n in range(len(words)))
        if own_source and words[0] == "-N" and len(words) == 2:
            if state["chain"]:
                state["foreign"].append(normalized)
            state["chain"] = True
        elif own_source and words[0] == "-A":
            state["rules"].append(normalized)
            if references:
                state["foreign"].append(normalized)
        elif own_source:
            state["foreign"].append(normalized)
        elif references:
            if normalized == hook:
                state["hooks"].append(normalized)
                state["hook_positions"].append(output_position)
            else:
                state["foreign"].append(normalized)
        if len(words) > 1 and words[:2] == ["-A", "OUTPUT"] and normalized not in trusted_hooks:
            output_position += 1
    return state


def build_operations(snapshot: dict, packages: list[str]) -> list[dict]:
    """Only the three metric clients are eligible; no blanket Amazon UID filtering."""
    if (not isinstance(packages, list) or any(not isinstance(p, str) for p in packages) or
            len(set(packages)) != len(packages)):
        raise Error("Telemetry isolation requires unique exact package names")
    if not packages:
        return []
    if not snapshot.get("root", {}).get("available") or not snapshot.get("network", {}).get("available"):
        raise Error("UID isolation requires healthy root and owner/REJECT support in both IP families")
    installed = snapshot["packages"]
    counts = Counter(s["uid"] for s in installed.values() if s.get("installed"))
    protected = set(snapshot["protected"]) | PROTECTED
    operations = []
    for name in packages:
        if name not in CATALOG or CATALOG[name][0] != "metrics":
            raise Error("Only allowlisted metric clients support UID isolation: " + str(name))
        state = installed.get(name, {})
        uid = state.get("uid")
        if (not state.get("installed") or not state.get("effective_enabled") or
                state.get("hidden") or state.get("suspended")):
            raise Error("Telemetry client is missing, disabled, hidden or suspended: " + name)
        if type(uid) is not int or not 10000 <= uid < 100000 or counts[uid] != 1 or name in protected:
            raise Error("Telemetry client has a protected role, system/shared UID or non-Owner UID: " + name)
        before = {f: _state(snapshot["network"]["families"][f]["filter_rules"], uid, f) for f in FAMILIES}
        after = {f: _desired(uid, f) for f in FAMILIES}
        if before == after:
            continue
        if before != {f: _empty() for f in FAMILIES}:
            raise Error("Telemetry chain already exists or is altered; restore its original journal: " + name)
        operation = {"kind": "uid-network", "key": name, "uid": uid,
                     "version": state["version"], "before": before, "after": after,
                     "reason": "Root owner-UID isolation of all foreground/background egress except loopback; volatile until reboot"}
        validate_operation(operation)
        operations.append(operation)
    return operations


def validate_operation(op: dict) -> None:
    if not isinstance(op, dict):
        raise Error("Invalid UID network operation")
    name, uid, version = op.get("key"), op.get("uid"), op.get("version")
    if (op.get("kind") != "uid-network" or not isinstance(name, str) or
            name not in CATALOG or CATALOG[name][0] != "metrics" or
            name in PROTECTED or type(uid) is not int or not 10000 <= uid < 100000 or
            not isinstance(version, str) or not re.fullmatch(r"\d+", version) or
            op.get("before") != {f: _empty() for f in FAMILIES} or
            op.get("after") != {f: _desired(uid, f) for f in FAMILIES}):
        raise Error("Disallowed UID network operation: " + str(name))


def read_state(adb: Adb, op: dict) -> dict:
    validate_operation(op)
    state = package_dump(adb.shell("dumpsys package " + shlex.quote(op["key"]))).get(op["key"], {})
    if not state.get("installed") or (state.get("uid"), state.get("version")) != (op["uid"], op["version"]):
        raise Error("Telemetry package removed, reinstalled or updated: " + op["key"])
    return {f: _state(_command(adb, f, "-S").splitlines(), op["uid"], f) for f in FAMILIES}


def state_is_owned_partial(state: dict, op: dict) -> bool:
    """A failed create/delete can leave only a prefix of our exact owned rules."""
    validate_operation(op)
    if not isinstance(state, dict) or set(state) != set(FAMILIES):
        return False
    for family in FAMILIES:
        current, wanted = state[family], op["after"][family]
        if not isinstance(current, dict) or set(current) != set(wanted):
            return False
        if current == op["before"][family]:
            continue
        rules, hooks = current["rules"], current["hooks"]
        if (current["chain"] is not True or current["foreign"] != [] or
                not isinstance(rules, list) or rules != wanted["rules"][:len(rules)] or
                hooks not in ([], wanted["hooks"]) or
                current["hook_positions"] != ([0] if hooks else []) or
                (hooks and rules != wanted["rules"])):
            return False
    return True


def write_state(adb: Adb, op: dict, target: dict) -> None:
    """Stage both families before activating; restore only our exact owned rules."""
    validate_operation(op)
    if target not in (op["before"], op["after"]):
        raise Error("Disallowed UID network target")
    current = read_state(adb, op)
    if current == target:
        return
    if target == op["after"]:
        if current != op["before"]:
            raise Error("Firewall changed since planning; restore the journal first")
        for family in FAMILIES:
            chain = "FOPT_UID" + str(op["uid"])
            _command(adb, family, "-N", chain)
            for rule in target[family]["rules"]:
                _command(adb, family, *shlex.split(rule))
        staged = {f: dict(op["after"][f], hooks=[], hook_positions=[]) for f in FAMILIES}
        if read_state(adb, op) != staged:
            raise Error("Staged UID chains changed; refusing to activate")
        for family in FAMILIES:
            rule = shlex.split(target[family]["hooks"][0])
            _command(adb, family, "-I", rule[1], "1", *rule[2:])
    else:
        if not state_is_owned_partial(current, op):
            raise Error("UID firewall chain/rules changed outside this transaction; refusing rollback")
        for family in FAMILIES:
            state = current[family]
            for rule in reversed(state["hooks"]):
                _command(adb, family, "-D", *shlex.split(rule)[1:])
            for rule in reversed(state["rules"]):
                _command(adb, family, "-D", *shlex.split(rule)[1:])
            if state["chain"]:
                _command(adb, family, "-X", "FOPT_UID" + str(op["uid"]))
    if read_state(adb, op) != target:
        raise Error("UID firewall readback did not match: " + op["key"])
