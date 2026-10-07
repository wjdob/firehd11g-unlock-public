"""Host-only tests of exact rule ownership and partial firewall rollback."""
from copy import deepcopy
import shlex
import unittest

import fireopt
import root_net
from test_fireopt import FakeAdb as BaseAdb, dump, package


METRICS = "com.amazon.client.metrics"
UID = 10101


class FakeAdb(BaseAdb):
    def __init__(self):
        super().__init__({METRICS: package(UID), "com.nordvpn.android": package(10202)})
        stock = ["-P INPUT ACCEPT", "-P FORWARD ACCEPT", "-P OUTPUT ACCEPT",
                 "-N fw_OUTPUT", "-N bw_OUTPUT", "-N nordvpn_OUTPUT",
                 "-A OUTPUT -j fw_OUTPUT", "-A OUTPUT -j bw_OUTPUT",
                 "-A OUTPUT -j nordvpn_OUTPUT",
                 "-A fw_OUTPUT -m owner --uid-owner 1000 -j RETURN",
                 "-A nordvpn_OUTPUT -m owner --uid-owner 10202 -j ACCEPT"]
        self.tables = {f: list(stock) for f in root_net.FAMILIES}
        self.commands = []
        self.fail_once = None
        self.owner_supported = True

    def shell(self, command, *, root=False):
        self.commands.append((command, root))
        if not root:
            return super().shell(command, root=root)
        words = shlex.split(command)
        tool = words[0]
        if tool not in ("iptables", "ip6tables") or words[1:5] != ["-w", "5", "-t", "filter"]:
            raise AssertionError("Unexpected root command: " + command)
        family = "v4" if tool == "iptables" else "v6"
        args, table = words[5:], self.tables[family]
        if args == ["-S"]:
            return "\n".join(table)
        if args == ["-m", "owner", "-h"]:
            return "--uid-owner userid" if self.owner_supported else "unsupported"
        if args == ["-j", "REJECT", "-h"]:
            return "--reject-with " + root_net.FAMILIES[family][1]
        if self.fail_once == (family, args):
            self.fail_once = None
            raise fireopt.Error("Injected family mutation failure")
        self.mutations.append((family, args))
        if args[0] == "-N":
            if shlex.join(args) in table:
                raise fireopt.Error("Chain exists")
            table.append(shlex.join(args))
        elif args[0] == "-A":
            table.append(shlex.join(args))
        elif args[0] == "-I":
            chain = args[1]
            first = next((n for n, line in enumerate(table) if line.startswith("-A " + chain + " ")), len(table))
            table.insert(first, shlex.join(["-A", chain, *args[3:]]))
        elif args[0] == "-D":
            line = shlex.join(["-A", *args[1:]])
            if line not in table:
                raise fireopt.Error("Exact rule missing")
            table.remove(line)
        elif args[0] == "-X":
            chain = args[1]
            if any(line.startswith("-A " + chain + " ") or "-j " + chain in line for line in table):
                raise fireopt.Error("Chain is not empty or referenced")
            table.remove("-N " + chain)
        else:
            raise AssertionError("Forbidden mutation: " + command)
        return ""

    def snapshot(self):
        state = super().snapshot()
        state["network"] = root_net.inspect(self)
        return state


class RootNetworkTests(unittest.TestCase):
    def operation(self, adb):
        return root_net.build_operations(adb.snapshot(), [METRICS])[0]

    def test_capability_probes_are_read_only_and_require_both_families(self):
        adb = FakeAdb()
        self.assertTrue(root_net.inspect(adb)["available"])
        self.assertEqual(adb.mutations, [])
        adb.owner_supported = False
        self.assertFalse(root_net.inspect(adb)["available"])
        with self.assertRaises(fireopt.Error):
            root_net.build_operations(adb.snapshot(), [METRICS])
        self.assertEqual(adb.mutations, [])

    def test_opt_in_guard_rejects_other_apps_shared_uids_and_active_roles(self):
        adb = FakeAdb()
        base = adb.snapshot()
        variants = [("not-metrics", base, ["com.nordvpn.android"])]
        for field, value in (("uid", 0), ("uid", 100000), ("installed", False),
                             ("effective_enabled", False), ("hidden", True), ("suspended", True)):
            snapshot = deepcopy(base)
            snapshot["packages"][METRICS][field] = value
            variants.append((field + str(value), snapshot, [METRICS]))
        shared = deepcopy(base)
        shared["packages"]["com.test.shared"] = package(UID)
        variants.append(("shared", shared, [METRICS]))
        protected = deepcopy(base)
        protected["protected"].append(METRICS)
        variants.append(("protected", protected, [METRICS]))
        variants.append(("duplicate", base, [METRICS, METRICS]))
        for reason, snapshot, names in variants:
            with self.subTest(reason=reason), self.assertRaises(fireopt.Error):
                root_net.build_operations(snapshot, names)
        self.assertEqual(adb.mutations, [])

    def test_exact_dual_stack_isolation_and_rollback_preserve_framework_and_vpn(self):
        adb = FakeAdb()
        baseline = deepcopy(adb.tables)
        op = self.operation(adb)
        root_net.write_state(adb, op, op["after"])
        self.assertEqual(root_net.read_state(adb, op), op["after"])
        # Both complete chains are staged before the first OUTPUT hook is installed.
        commands = adb.mutations
        first_hook = next(n for n, (_, args) in enumerate(commands) if args[0] == "-I")
        self.assertEqual(first_hook, 6)
        self.assertEqual(root_net.build_operations(adb.snapshot(), [METRICS]), [])
        root_net.write_state(adb, op, op["before"])
        self.assertEqual(adb.tables, baseline)
        self.assertEqual(root_net.read_state(adb, op), op["before"])
        self.assertFalse(any(args[0] in ("-F", "-P") for _, args in adb.mutations))

    def test_partial_ipv6_stage_failure_can_remove_only_our_rules(self):
        adb = FakeAdb()
        baseline = deepcopy(adb.tables)
        op = self.operation(adb)
        chain = "FOPT_UID" + str(UID)
        adb.fail_once = ("v6", ["-A", chain, "-j", "REJECT", "--reject-with", "icmp6-port-unreachable"])
        with self.assertRaises(fireopt.Error):
            root_net.write_state(adb, op, op["after"])
        partial = root_net.read_state(adb, op)
        self.assertTrue(root_net.state_is_owned_partial(partial, op))
        self.assertEqual(partial["v4"]["hooks"], [])
        self.assertEqual(partial["v6"]["hooks"], [])
        self.assertEqual(len(partial["v6"]["rules"]), 1)
        root_net.write_state(adb, op, op["before"])
        self.assertEqual(adb.tables, baseline)

    def test_multiple_metric_uid_hooks_stay_ahead_of_framework_rules(self):
        adb = FakeAdb()
        other = "com.amazon.device.metrics"
        adb.packages[other] = package(10102)
        baseline = deepcopy(adb.tables)
        operations = root_net.build_operations(adb.snapshot(), [METRICS, other])
        for op in operations:
            root_net.write_state(adb, op, op["after"])
        for op in operations:
            self.assertEqual(root_net.read_state(adb, op), op["after"])
        for op in reversed(operations):
            root_net.write_state(adb, op, op["before"])
        self.assertEqual(adb.tables, baseline)

    def test_partial_second_hook_failure_and_partial_rollback_are_recoverable(self):
        adb = FakeAdb()
        baseline = deepcopy(adb.tables)
        op = self.operation(adb)
        hook = shlex.split(op["after"]["v6"]["hooks"][0])
        adb.fail_once = ("v6", ["-I", hook[1], "1", *hook[2:]])
        with self.assertRaises(fireopt.Error):
            root_net.write_state(adb, op, op["after"])
        self.assertTrue(root_net.state_is_owned_partial(root_net.read_state(adb, op), op))
        rule = shlex.split(op["after"]["v4"]["rules"][0])
        adb.fail_once = ("v4", ["-D", *rule[1:]])
        with self.assertRaises(fireopt.Error):
            root_net.write_state(adb, op, op["before"])
        self.assertTrue(root_net.state_is_owned_partial(root_net.read_state(adb, op), op))
        root_net.write_state(adb, op, op["before"])
        self.assertEqual(adb.tables, baseline)

    def test_unknown_chain_rule_reference_or_moved_hook_refuses_rollback(self):
        for alteration in ("chain-rule", "foreign-reference", "moved-hook"):
            with self.subTest(alteration=alteration):
                adb = FakeAdb()
                op = self.operation(adb)
                root_net.write_state(adb, op, op["after"])
                chain = "FOPT_UID" + str(UID)
                if alteration == "chain-rule":
                    adb.tables["v4"].append(f"-A {chain} -j ACCEPT")
                elif alteration == "foreign-reference":
                    adb.tables["v4"].append(f"-A nordvpn_OUTPUT -j {chain}")
                else:
                    hook = op["after"]["v4"]["hooks"][0]
                    adb.tables["v4"].remove(hook)
                    adb.tables["v4"].append(hook)
                changed = deepcopy(adb.tables)
                self.assertFalse(root_net.state_is_owned_partial(root_net.read_state(adb, op), op))
                with self.assertRaises(fireopt.Error):
                    root_net.write_state(adb, op, op["before"])
                self.assertEqual(adb.tables, changed)

    def test_existing_chain_cannot_be_claimed_and_saved_uid_is_revalidated(self):
        adb = FakeAdb()
        op = self.operation(adb)
        adb.tables["v4"].append("-N FOPT_UID" + str(UID))
        with self.assertRaises(fireopt.Error):
            root_net.build_operations(adb.snapshot(), [METRICS])
        adb.tables["v4"].pop()
        adb.packages[METRICS]["uid"] += 1
        with self.assertRaises(fireopt.Error):
            root_net.write_state(adb, op, op["after"])
        self.assertEqual(adb.mutations, [])

    def test_tampered_saved_rule_or_privileged_uid_cannot_execute(self):
        adb = FakeAdb()
        original = self.operation(adb)
        for field, value in (("uid", 2000), ("key", "com.nordvpn.android"),
                             ("version", "1234;id")):
            op = deepcopy(original)
            op[field] = value
            with self.subTest(field=field), self.assertRaises(fireopt.Error):
                root_net.write_state(adb, op, op["after"])
        op = deepcopy(original)
        op["after"]["v4"]["rules"][1] = "-A OUTPUT -j DROP"
        with self.assertRaises(fireopt.Error):
            root_net.validate_operation(op)
        self.assertEqual(adb.mutations, [])


if __name__ == "__main__":
    unittest.main()
