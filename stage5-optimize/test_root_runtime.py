"""Host-only runtime transaction checks; fake shell commands never touch a device."""
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch

import fireopt
import root_net
import root_runtime as runtime
from test_fireopt import FakeAdb, package


METRICS = "com.amazon.client.metrics"
FILTER = ["-P INPUT ACCEPT", "-P FORWARD DROP", "-P OUTPUT ACCEPT",
          "-N bw_OUTPUT", "-A OUTPUT -j bw_OUTPUT"]


class FakeRootAdb(FakeAdb):
    def __init__(self):
        super().__init__()
        self.packages[METRICS] = package(10300)
        self.zram = {"disksize": 0, "initstate": 0, "mem_limit": 17 * runtime.MIB,
                     "max_comp_streams": 4, "algorithm": "lz4", "active": False}
        self.swappiness = 60
        self.available_kib = 900000
        self.used_kib = 0
        self.root_writes = []
        self.fail_command = None
        self.fail_error = fireopt.Error
        self.fail_after_write = False
        self.inspect_count = 0
        self.protect_on_inspect = None

    def snapshot(self):
        result = super().snapshot()
        self.inspect_count += 1
        if self.protect_on_inspect == self.inspect_count:
            result["protected"].append(METRICS)
        return result

    def network(self):
        return {"available": True, "families": {
            family: {"available": True, "filter_rules": list(FILTER),
                     "owner_supported": True, "reject_supported": True}
            for family in root_net.FAMILIES}}

    def shell(self, command, *, root=False):
        if not root:
            return super().shell(command)
        if command.startswith("set -e\ntest -b "):
            return "sys=253:0\nblock=fd:0\npath=/sys/devices/virtual/block/zram0\nholders=\nbacking=none\n"
        if command.startswith("set -e\n"):
            return "\n".join(f"{key}={self.zram[key]}" for key in
                             ("disksize", "initstate", "mem_limit", "max_comp_streams")) + \
                   "\ncomp_algorithm=lzo [" + self.zram["algorithm"] + "]"
        if command == "cat /proc/swaps":
            header = "Filename Type Size Used Priority\n"
            return header + (f"{runtime.ZDEV} partition {self.zram['disksize']//1024} "
                             f"{self.used_kib} 100\n" if self.zram["active"] else "")
        if command == "cat /proc/sys/vm/swappiness":
            return str(self.swappiness)
        if command == "cat /proc/meminfo":
            return f"MemTotal: 2863632 kB\nMemAvailable: {self.available_kib} kB\n"
        if command == "cat /proc/vmstat":
            return "pgmajfault 4\npswpin 0\npswpout 0\n"
        if command == "head -1 /proc/stat":
            return "cpu 10 0 5 70 4 0 0 0 0 0"
        if command == "cat /proc/diskstats":
            return "179 0 mmcblk0 1 0 4 2 1 0 8 3 0 5 6"
        if command == "cat /proc/uptime":
            return "60.0 40.0"
        if command == f"cat {runtime.ZSYS}/mm_stat":
            return "0 0 0 0 0 0 0"
        if command == f"cat {runtime.ZSYS}/mm_stat {runtime.ZSYS}/io_stat":
            return "0 0 0 0 0 0 0\n0 0 0 0"
        if command == "cat /sys/kernel/debug/wakeup_sources":
            return "name active_count event_count\nfake 0 0"
        if command.startswith("test -x ") or command.startswith("for p in "):
            return ""
        words = shlex.split(command)
        if words[0] in ("iptables", "ip6tables"):
            if words[-1] == "-S":
                return "\n".join(FILTER)
            self.root_writes.append(command)
            raise AssertionError("Stale/protected target must never mutate networking")
        writing = words[:2] == ["printf", "%s"] or words[:2] == ["toybox", "mkswap"] or \
                  words[:2] in (["toybox", "swapon"], ["toybox", "swapoff"])
        if not writing:
            raise AssertionError("Unexpected fake root command: " + command)
        self.root_writes.append(command)
        failing = self.fail_command is not None and self.fail_command in command
        if failing and not self.fail_after_write:
            self.fail_command = None
            raise self.fail_error("Injected root command failure")
        if words[0] == "printf":
            value, node = words[2], words[-1]
            if node == "/proc/sys/vm/swappiness":
                self.swappiness = int(value)
            else:
                key = node.rsplit("/", 1)[-1]
                if key == "reset":
                    if self.zram["active"]:
                        raise AssertionError("Reset of active swap is forbidden")
                    self.zram.update(disksize=0, initstate=0, mem_limit=0, max_comp_streams=1)
                elif key == "comp_algorithm":
                    self.zram["algorithm"] = value
                else:
                    self.zram[key] = int(value)
                    if key == "disksize":
                        self.zram["initstate"] = 1
        elif words[1] == "swapon":
            self.zram["active"] = True
        elif words[1] == "swapoff":
            self.zram["active"] = False
            self.used_kib = 0
        if failing:
            self.fail_command = None
            raise self.fail_error("Injected failure after root mutation")
        return ""


class RootRuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="root-runtime-test-")
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "journal.json"

    def environment(self, adb):
        stack = ExitStack()
        stack.enter_context(patch.object(fireopt, "inspect", side_effect=lambda device: device.snapshot()))
        stack.enter_context(patch.object(fireopt, "identity", side_effect=lambda device: deepcopy(device.ident)))
        stack.enter_context(patch.object(root_net, "inspect", side_effect=lambda device: device.network()))
        return stack

    def plan(self, adb, size=256, swappiness=None, packages=None):
        with self.environment(adb):
            return runtime.build_plan(runtime.inspect(adb), size, swappiness, packages or [])

    def apply(self, adb, plan):
        with self.environment(adb):
            return runtime.apply(adb, plan, self.path)

    def restore(self, adb, journal):
        with self.environment(adb):
            return runtime.restore(adb, journal, self.path)

    def test_plan_requires_inactive_uninitialized_device_and_memory_headroom(self):
        for key, value in (("active", True), ("initstate", 1), ("disksize", runtime.MIB)):
            with self.subTest(key=key):
                adb = FakeRootAdb()
                adb.zram[key] = value
                with self.assertRaises(fireopt.Error):
                    self.plan(adb)
                self.assertEqual(adb.root_writes, [])
        adb = FakeRootAdb()
        adb.available_kib = 512 * 1024 - 1
        with self.assertRaisesRegex(fireopt.Error, "headroom"):
            self.plan(adb)

    def test_plan_rejects_missing_capability_wrong_sizes_and_swappiness(self):
        adb = FakeRootAdb()
        with self.environment(adb):
            snapshot = runtime.inspect(adb)
        snapshot["runtime"]["zram"]["available"] = False
        with self.assertRaises(fireopt.Error):
            runtime.build_plan(snapshot, 256, None, [])
        for size in (0, 128, 768, -256):
            with self.subTest(size=size), self.assertRaises(fireopt.Error):
                self.plan(adb, size)
        for value in (-1, 101, 200, True, "60"):
            with self.subTest(swappiness=value), self.assertRaises(fireopt.Error):
                self.plan(adb, swappiness=value)
        self.assertEqual(adb.root_writes, [])

    def test_validation_rejects_unbounded_and_injected_targets(self):
        operation = self.plan(FakeRootAdb())["operations"][0]
        changes = (("disksize", 1024 * runtime.MIB), ("mem_limit", 9 * runtime.MIB),
                   ("algorithm", "lz4; reboot"), ("algorithm", "lzo"),
                   ("max_comp_streams", 65), ("active", 1))
        for key, value in changes:
            altered = deepcopy(operation)
            altered["after"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(fireopt.Error):
                runtime.validate([altered])
        with self.assertRaises(fireopt.Error):
            runtime.validate([operation, operation])
        with self.assertRaises(fireopt.Error):
            runtime.validate([{"kind": "vm", "key": "drop_caches", "before": 0, "after": 3}])

    def test_bounded_trial_preserves_compressor_vm_and_restores_reset_configuration(self):
        for size in (256, 512):
            with self.subTest(size=size):
                adb = FakeRootAdb()
                original = deepcopy(adb.zram)
                journal = self.apply(adb, self.plan(adb, size))
                self.assertEqual(journal["status"], "applied")
                self.assertEqual(adb.zram["disksize"], size * runtime.MIB)
                self.assertEqual(adb.zram["mem_limit"], size * runtime.MIB // 2)
                self.assertEqual(adb.zram["algorithm"], "lz4")
                self.assertEqual(adb.zram["max_comp_streams"], 4)
                self.assertEqual(adb.swappiness, 60)
                self.assertFalse(any("comp_algorithm" in command or "swappiness" in command
                                     for command in adb.root_writes))
                self.assertEqual(self.restore(adb, journal), [])
                self.assertEqual(adb.zram, original)
                self.assertLess(next(i for i, c in enumerate(adb.root_writes) if "swapoff" in c),
                                next(i for i, c in enumerate(adb.root_writes) if "/reset" in c))

    def test_known_failure_after_initialization_restores_original_configuration(self):
        adb = FakeRootAdb()
        before = deepcopy(adb.zram)
        plan = self.plan(adb)
        adb.fail_command = "/mem_limit"
        with self.assertRaisesRegex(fireopt.Error, "configuration restored"):
            self.apply(adb, plan)
        journal = fireopt.read(self.path)
        self.assertEqual(journal["status"], "restored")
        self.assertEqual(adb.zram, before)
        self.assertTrue(any("/reset" in command for command in adb.root_writes))
        self.assertFalse(any("swapoff" in command for command in adb.root_writes))

    def test_unknown_applied_command_is_retained_until_explicit_restore(self):
        adb = FakeRootAdb()
        before = deepcopy(adb.zram)
        plan = self.plan(adb)
        adb.fail_command = "swapon"
        adb.fail_error = fireopt.Uncertain
        adb.fail_after_write = True
        with self.assertRaisesRegex(fireopt.Error, "restore incomplete"):
            self.apply(adb, plan)
        journal = fireopt.read(self.path)
        self.assertEqual(journal["status"], "restore_incomplete")
        self.assertTrue(journal["operations"][0]["outcome_unknown"])
        self.assertTrue(adb.zram["active"])
        self.assertFalse(any("swapoff" in command or "/reset" in command for command in adb.root_writes))
        self.assertEqual(self.restore(adb, journal), [])
        self.assertEqual(adb.zram, before)
        self.assertFalse(journal["operations"][0]["outcome_unknown"])

    def test_restore_refuses_swapoff_without_headroom_and_can_resume(self):
        adb = FakeRootAdb()
        journal = self.apply(adb, self.plan(adb))
        adb.used_kib = 100 * 1024
        adb.available_kib = adb.used_kib + runtime.MARGIN_KIB - 1
        prior = len(adb.root_writes)
        self.assertEqual(self.restore(adb, journal), ["zram0"])
        self.assertEqual(adb.root_writes[prior:], [])
        self.assertTrue(adb.zram["active"])
        adb.available_kib = 900000
        self.assertEqual(self.restore(adb, journal), [])

    def test_failed_swapoff_never_resets_active_swap(self):
        adb = FakeRootAdb()
        journal = self.apply(adb, self.plan(adb))
        adb.fail_command = "swapoff"
        prior = len(adb.root_writes)
        self.assertEqual(self.restore(adb, journal), ["zram0"])
        self.assertTrue(adb.zram["active"])
        self.assertFalse(any("/reset" in command for command in adb.root_writes[prior:]))
        self.assertEqual(journal["status"], "restore_incomplete")

    def test_restore_resumes_after_reset_changes_streams_and_limit(self):
        adb = FakeRootAdb()
        original = deepcopy(adb.zram)
        journal = self.apply(adb, self.plan(adb))
        adb.fail_command = "/comp_algorithm"
        self.assertEqual(self.restore(adb, journal), ["zram0"])
        self.assertEqual(adb.zram["max_comp_streams"], 1)
        self.assertEqual(adb.zram["mem_limit"], 0)
        self.assertFalse(adb.zram["active"])
        self.assertEqual(self.restore(adb, journal), [])
        self.assertEqual(adb.zram, original)

    def test_unknown_restore_stays_unresolved_until_later_explicit_restore(self):
        adb = FakeRootAdb()
        original = deepcopy(adb.zram)
        journal = self.apply(adb, self.plan(adb))
        adb.fail_command = "swapoff"
        adb.fail_error = fireopt.Uncertain
        adb.fail_after_write = True
        self.assertEqual(self.restore(adb, journal), ["zram0"])
        self.assertTrue(journal["operations"][0]["outcome_unknown"])
        prior = len(adb.root_writes)
        with self.environment(adb):
            self.assertEqual(runtime.restore(adb, journal, self.path, automatic=True), ["zram0"])
        self.assertEqual(adb.root_writes[prior:], [])
        self.assertEqual(self.restore(adb, journal), [])
        self.assertEqual(adb.zram, original)

    def test_later_vm_failure_restores_prior_zram_and_original_swappiness(self):
        adb = FakeRootAdb()
        original = deepcopy(adb.zram)
        plan = self.plan(adb, swappiness=25)
        adb.fail_command = "/proc/sys/vm/swappiness"
        adb.fail_after_write = True
        with self.assertRaisesRegex(fireopt.Error, "configuration restored"):
            self.apply(adb, plan)
        self.assertEqual(adb.swappiness, 60)
        self.assertEqual(adb.zram, original)
        self.assertEqual(fireopt.read(self.path)["status"], "restored")

    def test_reboot_accepts_absent_old_state_but_never_changes_new_runtime(self):
        for foreign in (False, True):
            with self.subTest(foreign=foreign):
                adb = FakeRootAdb()
                original = deepcopy(adb.zram)
                journal = self.apply(adb, self.plan(adb))
                adb.ident["boot_id"] = "boot-two"
                adb.zram = original if not foreign else deepcopy(adb.zram)
                prior = len(adb.root_writes)
                self.assertEqual(self.restore(adb, journal), ["zram0"] if foreign else [])
                self.assertEqual(adb.root_writes[prior:], [])

    def test_root_asset_drift_and_changed_boot_reject_before_mutation(self):
        for change in ("boot", "hash"):
            with self.subTest(change=change):
                adb = FakeRootAdb()
                plan = self.plan(adb)
                if change == "boot":
                    adb.ident["boot_id"] = "other-boot"
                else:
                    plan["root"]["hashes"][fireopt.ROOT_FILES[0]] = "b" * 64
                with self.assertRaises(fireopt.Error):
                    self.apply(adb, plan)
                self.assertEqual(adb.root_writes, [])

    def test_network_protected_or_stale_uid_rejects_before_network_mutation(self):
        for change in ("protected", "uid", "version", "shared"):
            with self.subTest(change=change):
                adb = FakeRootAdb()
                plan = self.plan(adb, size=None, packages=[METRICS])
                if change == "protected":
                    adb.protect_on_inspect = adb.inspect_count + 1
                elif change == "shared":
                    adb.packages["com.example.shared"] = package(adb.packages[METRICS]["uid"])
                else:
                    adb.packages[METRICS][change] = 10301 if change == "uid" else "9999"
                with self.assertRaises(fireopt.Error):
                    self.apply(adb, plan)
                self.assertEqual(adb.root_writes, [])

    def test_network_new_protected_role_at_write_boundary_remains_unmodified(self):
        adb = FakeRootAdb()
        plan = self.plan(adb, size=None, packages=[METRICS])
        adb.protect_on_inspect = adb.inspect_count + 2
        with self.assertRaisesRegex(fireopt.Error, "policy changed"):
            self.apply(adb, plan)
        self.assertEqual(adb.root_writes, [])
        self.assertEqual(fireopt.read(self.path)["status"], "restored")


if __name__ == "__main__":
    unittest.main()
