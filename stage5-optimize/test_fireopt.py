"""Host-only regression checks. FakeAdb never starts a process or touches a device."""
from copy import deepcopy
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch

import fireopt


PHOTOS = "com.amazon.photos"
WEATHER = "com.amazon.weather"
IDENTITY = {"serial": "TEST-DEVICE", "props": {"ro.product.device": "trona",
            "ro.product.model": "KFTRWI", "ro.build.version.sdk": "28",
            "ro.build.id": "PS7319", "ro.build.version.incremental": "0020367984516"},
            "boot_id": "boot-one"}
HEALTH = {"available": True, "selinux": "Permissive", "carrier_resident": True,
          "watchdog_resident": True, "trigger_armed": True,
          "hashes": {p: "a" * 64 for p in fireopt.ROOT_FILES}}


def package(uid=10101, enabled=0, *, installed=True, hidden=False, suspended=False):
    return {"uid": uid, "version": "1234", "enabled": enabled,
            "installed": installed, "hidden": hidden, "suspended": suspended,
            "effective_enabled": installed and enabled in (0, 1),
            "stopped": False, "write_secure_settings": False}


def dump(packages):
    # Android 9 dumpsys uses two spaces before Package and a single User 0 line.
    text = ["Packages:"]
    for name, state in packages.items():
        text.extend((f"  Package [{name}] (12ab34):",
                     f"    userId={state['uid']}",
                     "    codePath=/system/priv-app/Example",
                     f"    versionCode={state['version']} minSdk=21 targetSdk=28",
                     "    User 0: ceDataInode=123 installed=%s hidden=%s suspended=%s "
                     "stopped=false notLaunched=false enabled=%s instant=false virtual=false"
                     % (str(state["installed"]).lower(), str(state["hidden"]).lower(),
                        str(state["suspended"]).lower(), state["enabled"])))
        if state.get("write_secure_settings"):
            text.append("      android.permission.WRITE_SECURE_SETTINGS: granted=true")
    return "\n".join(text) + "\n"


class FakeAdb:
    def __init__(self, packages=None, settings=None):
        self.serial = "TEST-DEVICE"
        self.ident = deepcopy(IDENTITY)
        self.packages = deepcopy(packages if packages is not None else {
            PHOTOS: package(), WEATHER: package(10102, 1)})
        actor = package(10200)
        actor["write_secure_settings"] = True
        self.packages.setdefault(fireopt.PERSIST, actor)
        self.settings = dict(settings or {})
        self.mutations = []
        self.fail_once_after_write = None
        self.after_write_error = fireopt.Uncertain
        self.home = "com.amazon.firelauncher/.Home"

    def shell(self, command, *, root=False):
        if root:
            raise AssertionError("Tests require ordinary ADB; root is mocked separately")
        words = shlex.split(command)
        if words[:2] == ["dumpsys", "package"]:
            return dump(self.packages if words[2] == "packages" else {
                words[2]: self.packages[words[2]]})
        if words[:3] == ["settings", "list", "global"]:
            return "\n".join(f"{key}={value}" for key, value in self.settings.items())
        if words[:3] == ["settings", "list", "secure"]:
            return ""
        if words[:3] == ["pm", "list", "packages"]:
            return "\n".join(f"package:{p}" for p, s in self.packages.items()
                             if s["installed"] and s["enabled"] in (0, 1))
        if words[:3] == ["cmd", "package", "resolve-activity"]:
            return self.home
        if len(words) > 1 and words[0] == "pm" and words[1] in fireopt.STATE_COMMAND.values():
            key = words[-1]
            enabled = next(k for k, v in fireopt.STATE_COMMAND.items() if v == words[1])
            self.packages[key]["enabled"] = enabled
            self.packages[key]["effective_enabled"] = enabled in (0, 1)
            self.mutations.append(("package", key, enabled))
            self._after_write(key)
            return f"Package {key} new state: {words[1]}"
        if words[:3] in (["settings", "put", "global"], ["settings", "delete", "global"]):
            key = words[3]
            if words[1] == "put":
                self.settings[key] = words[4]
            else:
                self.settings.pop(key, None)
            self.mutations.append(("setting", key, self.settings.get(key)))
            self._after_write(key)
            return ""
        if command in ("dumpsys webviewupdate", "dumpsys device_policy", "df -k /data /system /vendor",
                       "cat /proc/swaps", "cat /proc/uptime", "dumpsys battery",
                       "dumpsys meminfo --oom", "ps -A -o PID,PPID,ARGS"):
            return ""
        if command == "cat /proc/meminfo":
            return "MemTotal: 3000000 kB\nMemAvailable: 900000 kB\nSwapTotal: 1000000 kB\n"
        raise AssertionError("Unexpected fake command: " + command)

    def _after_write(self, key):
        if self.fail_once_after_write == key:
            self.fail_once_after_write = None
            raise self.after_write_error("Failure after device mutation")

    def snapshot(self):
        return {"schema": fireopt.SCHEMA, "kind": "assessment", "identity": deepcopy(self.ident),
                "packages": deepcopy(self.packages), "protected": list(fireopt.PROTECTED),
                "root": deepcopy(HEALTH), "home": self.home,
                "persistence": {"snusnu_persist_enabled": "1", "snusnu_persist_status": "kernel_write_ok",
                                "snusnu_rearm_status": "ok"},
                "settings": {k: fireopt.setting_state(self.settings, k) for k in fireopt.ANIMATIONS}}


class FireoptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fireopt-test-")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "journal.json"

    def plan(self, adb, *, animations=None, only=None):
        return fireopt.make_plan(adb.snapshot(), "conservative", None, animations, only)

    def apply(self, adb, plan):
        with patch.object(fireopt, "inspect", side_effect=lambda device: device.snapshot()), \
             patch.object(fireopt, "identity", side_effect=lambda device: deepcopy(device.ident)):
            return fireopt.apply(adb, plan, self.path)

    def restore(self, adb, journal):
        with patch.object(fireopt, "identity", side_effect=lambda device: deepcopy(device.ident)), \
             patch.object(fireopt, "root_health", side_effect=AssertionError("Rollback must not need root")), \
             patch.object(fireopt, "inspect", side_effect=AssertionError("Rollback must not need a root assessment")):
            return fireopt.restore(adb, journal, self.path)

    def test_android9_package_dump_parses_exact_per_user_states(self):
        states = {"com.test.p" + str(n): package(10100 + n, n) for n in range(5)}
        states["com.test.uninstalled"] = package(10120, installed=False, hidden=True, suspended=True)
        parsed = fireopt.package_dump(dump(states))
        self.assertEqual([parsed["com.test.p" + str(n)]["enabled"] for n in range(5)], list(range(5)))
        self.assertFalse(parsed["com.test.uninstalled"]["installed"])
        self.assertTrue(parsed["com.test.uninstalled"]["hidden"])
        self.assertTrue(parsed["com.test.uninstalled"]["suspended"])
        with self.assertRaises(fireopt.Error):
            fireopt.package_dump(dump(states).replace("enabled=0", "enabled=99", 1))

    def test_settings_absence_differs_from_literal_null_and_preserves_equals(self):
        values = fireopt.settings_map("literal=null\npayload=a=b\nwindow_animation_scale=1.0\n")
        self.assertEqual(fireopt.setting_state(values, "missing"), {"present": False, "value": None})
        self.assertEqual(fireopt.setting_state(values, "literal"), {"present": True, "value": "null"})
        self.assertEqual(values["payload"], "a=b")

    def test_hidden_factory_duplicate_does_not_replace_running_package(self):
        running = package(10101, 1)
        running["version"] = "2000"
        factory = package(10101, 0, installed=False)
        factory["version"] = "1000"
        text = dump({PHOTOS: running}) + "Hidden system packages:\n" + dump({PHOTOS: factory})
        parsed = fireopt.package_dump(text)
        self.assertEqual(parsed[PHOTOS]["version"], "2000")
        self.assertEqual(parsed[PHOTOS]["enabled"], 1)
        self.assertTrue(parsed[PHOTOS]["installed"])

    def test_ready_rejects_partial_root_failure_unarmed_trigger_and_bad_actor(self):
        for area, field, value in (("root", "error", "hash response incomplete"),
                                   ("root", "trigger_armed", False),
                                   ("root", "available", False),
                                   ("actor", "write_secure_settings", False),
                                   ("actor", "stopped", True),
                                   ("actor", "effective_enabled", False),
                                   ("persistence", "snusnu_rearm_status", "pending")):
            with self.subTest(area=area, field=field):
                adb = FakeAdb()
                plan = self.plan(adb)
                bad = adb.snapshot()
                target = bad["packages"][fireopt.PERSIST] if area == "actor" else bad[area]
                target[field] = value
                with patch.object(fireopt, "inspect", return_value=bad), self.assertRaises(fireopt.Error):
                    fireopt.apply(adb, plan, self.path)
                self.assertEqual(adb.mutations, [])
                self.assertFalse(self.path.exists())

    def test_shared_uid_and_active_home_are_protected_and_skipped(self):
        adb = FakeAdb({PHOTOS: package(10101), "com.vendor.shared": package(10101), WEATHER: package(10102)})
        adb.home = WEATHER + "/.Home"
        with patch.object(fireopt, "identity", side_effect=lambda device: deepcopy(device.ident)), \
             patch.object(fireopt, "root_health", return_value=deepcopy(HEALTH)):
            snapshot = fireopt.inspect(adb)
        plan = fireopt.make_plan(snapshot, "conservative", None, None, [PHOTOS, WEATHER])
        self.assertEqual(plan["operations"], [])
        self.assertEqual({p["package"] for p in plan["skipped"]}, {PHOTOS, WEATHER})
        self.assertTrue(all("protected" in p["reason"] for p in plan["skipped"]))
        self.assertEqual(adb.mutations, [])

    def test_disabled_hidden_and_suspended_packages_keep_original_policy(self):
        for state in (package(enabled=2), package(enabled=3), package(enabled=4),
                      package(hidden=True), package(suspended=True), package(installed=False)):
            with self.subTest(state=state):
                adb = FakeAdb({PHOTOS: state})
                self.assertEqual(self.plan(adb, only=[PHOTOS])["operations"], [])
                self.assertEqual(adb.packages[PHOTOS], state)

    def test_allowlist_rejects_tampered_operations_before_any_inspection(self):
        baseline = self.plan(FakeAdb(), only=[PHOTOS])["operations"][0]
        invalid = [dict(baseline, key="com.android.systemui"),
                   dict(baseline, key=PHOTOS + "; reboot"), dict(baseline, after=1),
                   dict(baseline, before=True), dict(baseline, uid=1000),
                   {"kind": "setting", "key": "adb_enabled", "before": {"present": False, "value": None},
                    "after": {"present": True, "value": "0"}},
                   {"kind": "setting", "key": fireopt.ANIMATIONS[0], "before": {"present": False, "value": "1"},
                    "after": {"present": True, "value": "0"}}]
        for operations in ([op] for op in invalid):
            with self.subTest(operations=operations):
                adb = FakeAdb()
                plan = self.plan(adb)
                plan["operations"] = operations
                with patch.object(fireopt, "inspect") as inspect, self.assertRaises(fireopt.Error):
                    fireopt.apply(adb, plan, self.path)
                inspect.assert_not_called()
                self.assertEqual(adb.mutations, [])
        with self.assertRaises(fireopt.Error):
            fireopt.validate_operations([baseline, deepcopy(baseline)])
        with self.assertRaises(fireopt.Error):
            fireopt.make_plan(FakeAdb().snapshot(), "conservative", None, None, [fireopt.PERSIST])

    def test_apply_and_restore_preserve_default_explicit_enable_and_absent_setting(self):
        adb = FakeAdb(settings={fireopt.ANIMATIONS[1]: "1.0", fireopt.ANIMATIONS[2]: "0.5"})
        original_packages, original_settings = deepcopy(adb.packages), deepcopy(adb.settings)
        journal = self.apply(adb, self.plan(adb, animations="0.5"))
        self.assertEqual(journal["status"], "applied")
        self.assertEqual(adb.packages[PHOTOS]["enabled"], 3)
        self.assertEqual(adb.packages[WEATHER]["enabled"], 3)
        self.assertEqual(adb.settings[fireopt.ANIMATIONS[0]], "0.5")
        self.assertEqual(self.restore(adb, journal), [])
        self.assertEqual(adb.packages, original_packages)
        self.assertEqual(adb.settings, original_settings)
        self.assertIn(("package", PHOTOS, 0), adb.mutations)
        self.assertIn(("package", WEATHER, 1), adb.mutations)
        self.assertIn(("setting", fireopt.ANIMATIONS[0], None), adb.mutations)
        self.assertEqual(fireopt.read(self.path)["status"], "restored")

    def test_uncertain_write_defers_attempted_item_but_restores_prior_success(self):
        adb = FakeAdb()
        before = deepcopy(adb.packages)
        adb.fail_once_after_write = WEATHER
        with self.assertRaisesRegex(fireopt.Error, "restore incomplete"):
            self.apply(adb, self.plan(adb))
        self.assertEqual(adb.packages[PHOTOS], before[PHOTOS])
        self.assertEqual(adb.packages[WEATHER]["enabled"], 3)
        self.assertEqual(adb.mutations, [("package", PHOTOS, 3), ("package", WEATHER, 3),
                                         ("package", PHOTOS, 0)])
        journal = fireopt.read(self.path)
        self.assertEqual(journal["status"], "restore_incomplete")
        attempted = next(op for op in journal["operations"] if op["key"] == WEATHER)
        self.assertEqual(attempted["status"], "restore_failed")
        self.assertTrue(attempted["outcome_unknown"])
        self.assertEqual(self.restore(adb, journal), [])  # Command has settled; explicit recovery.
        self.assertEqual(adb.packages, before)
        self.assertFalse(attempted["outcome_unknown"])
        self.assertNotIn("restore_error", attempted)
        self.assertEqual(fireopt.read(self.path)["status"], "restored")

    def test_known_completed_failure_automatically_restores_all_attempted_items(self):
        adb = FakeAdb()
        before = deepcopy(adb.packages)
        adb.fail_once_after_write = WEATHER
        adb.after_write_error = fireopt.Error  # Completion is known despite command failure.
        with self.assertRaisesRegex(fireopt.Error, "original configuration restored"):
            self.apply(adb, self.plan(adb))
        self.assertEqual(adb.packages, before)
        self.assertEqual(adb.mutations, [("package", PHOTOS, 3), ("package", WEATHER, 3),
                                         ("package", WEATHER, 1), ("package", PHOTOS, 0)])
        journal = fireopt.read(self.path)
        self.assertEqual(journal["status"], "restored")
        self.assertTrue(all(op["status"] == "restored" for op in journal["operations"]))

    def test_literal_null_animation_is_restored_as_present_value(self):
        key = fireopt.ANIMATIONS[0]
        adb = FakeAdb(settings={key: "null"})
        plan = self.plan(adb, animations="0.5", only=[PHOTOS])
        op = next(op for op in plan["operations"] if op["key"] == key)
        self.assertEqual(op["before"], {"present": True, "value": "null"})
        journal = self.apply(adb, plan)
        self.assertEqual(adb.settings[key], "0.5")
        self.assertEqual(self.restore(adb, journal), [])
        self.assertEqual(adb.settings, {key: "null"})
        self.assertIn(("setting", key, "null"), adb.mutations)

    def test_hidden_and_suspended_policy_drift_abort_before_mutation(self):
        for field in ("hidden", "suspended"):
            for at_boundary in (False, True):
                with self.subTest(field=field, at_boundary=at_boundary):
                    self.path.unlink(missing_ok=True)
                    adb = FakeAdb()
                    plan = self.plan(adb, only=[PHOTOS])
                    calls = 0

                    def inspect(device):
                        nonlocal calls
                        calls += 1
                        if calls == (2 if at_boundary else 1):
                            device.packages[PHOTOS][field] = True
                        return device.snapshot()

                    with patch.object(fireopt, "inspect", side_effect=inspect), \
                         patch.object(fireopt, "identity", side_effect=lambda device: deepcopy(device.ident)), \
                         self.assertRaisesRegex(fireopt.Error, "policy changed"):
                        fireopt.apply(adb, plan, self.path)
                    self.assertEqual(adb.mutations, [])
                    self.assertTrue(adb.packages[PHOTOS][field])
                    self.assertEqual(adb.packages[PHOTOS]["enabled"], 0)

    def test_third_state_drift_is_conflict_and_does_not_overwrite_external_change(self):
        adb = FakeAdb()
        journal = self.apply(adb, self.plan(adb))
        adb.packages[WEATHER]["enabled"] = 2  # External pm disable, distinct from disable-user.
        adb.mutations.clear()
        self.assertEqual(self.restore(adb, journal), [WEATHER])
        self.assertEqual(adb.packages[WEATHER]["enabled"], 2)
        self.assertEqual(adb.packages[PHOTOS]["enabled"], 0)
        self.assertEqual(adb.mutations, [("package", PHOTOS, 0)])
        self.assertEqual(fireopt.read(self.path)["status"], "restore_incomplete")

    def test_restore_works_on_later_boot_without_root_and_is_idempotent(self):
        adb = FakeAdb()
        journal = self.apply(adb, self.plan(adb))
        adb.ident["boot_id"] = "boot-two"
        self.assertEqual(self.restore(adb, journal), [])
        adb.mutations.clear()
        self.assertEqual(self.restore(adb, journal), [])
        self.assertEqual(adb.mutations, [])

    def test_stale_plan_identity_aborts_without_journal_or_mutations(self):
        for changed, value in (("boot_id", "another-boot"), ("serial", "another-device"),
                               ("props", {"ro.build.id": "PS7331"})):
            with self.subTest(changed=changed):
                adb = FakeAdb()
                plan = self.plan(adb)
                adb.ident[changed] = value
                with self.assertRaisesRegex(fireopt.Error, "differs from saved state"):
                    self.apply(adb, plan)
                self.assertEqual(adb.mutations, [])
                self.assertFalse(self.path.exists())

    def test_stale_restore_identity_aborts_before_mutation(self):
        adb = FakeAdb()
        journal = self.apply(adb, self.plan(adb))
        adb.ident["props"]["ro.build.version.incremental"] = "another-build"
        adb.mutations.clear()
        with self.assertRaises(fireopt.Error):
            self.restore(adb, journal)
        self.assertEqual(adb.mutations, [])

    def test_adb_shell_requires_completion_marker_and_inner_success(self):
        adb = object.__new__(fireopt.Adb)
        adb.serial = "TEST-DEVICE"
        for response, expected in (("done", fireopt.Uncertain), ("done\n__FIREOPT_test__:7\n", fireopt.Error)):
            with self.subTest(response=response), \
                 patch.object(fireopt.uuid, "uuid4") as nonce, patch.object(adb, "run", return_value=response):
                nonce.return_value.hex = "test"
                with self.assertRaises(expected) as raised:
                    adb.shell("echo done")
                self.assertIs(type(raised.exception), expected)
        with patch.object(fireopt.uuid, "uuid4") as nonce, \
             patch.object(adb, "run", return_value="done\n__FIREOPT_test__:0\n"):
            nonce.return_value.hex = "test"
            self.assertEqual(adb.shell("echo done"), "done")


if __name__ == "__main__":
    unittest.main()
