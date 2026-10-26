# Gap backlog: causes, tests and fix paths

Companion to the plan in [README.md](README.md). Each gap lists what the artifact shows,
what can be diagnosed on the device today, and what needs a build. The split matters: three
of the five can be advanced without a device tree, and two cannot.

## G1: SELinux is Permissive

**What the artifact shows.** `boot.img` cmdline is
`bootopt=64S3,32N2,64N2 androidboot.selinux=permissive buildvariant=userdebug`. Permissive
is a boot argument, so the policy compiled into the system image is never enforced. The
build also ships `userdebug`, so `adb root` should work without Magisk.

**Why it matters.** With no MAC enforcement, every process can read every other process's
data. That is why the release says not to store sensitive data.

**Diagnosis that needs no build.**

```
adb root
adb shell setenforce 1          # runtime only, lost on reboot
adb shell 'dmesg | grep avc:'   # the denial list to work from
adb shell getenforce
adb shell setenforce 0          # back to the shipped state
```

Expect a burst of denials and possibly a UI restart. Capture the list, group by domain.

**Why the fix is build-gated.** Removing the denials means adding `allow` rules, and those
live in the policy inside the system image. There is no supported way to append policy at
runtime on Android 11. So G1 belongs to the optional build track (§7 of the plan), with the
denial list above as its input.

**Exit criteria.** `getenforce` returns `Enforcing` after a reboot, with a boot that
completes and no repeated denials for the core domains.

## G2: Deep sleep disabled

**What the artifact shows.** Nothing in the boot image; the release notes say it is
intentional. The vendor kernel has the standard suspend core (`kernel/power/suspend.c`) and
MTK's `scp` and `sspm` drivers, which are the usual sources of suspend wake storms.

**Diagnosis that needs no build.**

```
adb shell cat /sys/power/state          # does it list "mem"? or only "freeze"?
adb shell cat /sys/power/mem_sleep
adb root; adb shell cat /sys/kernel/debug/suspend_stats
adb root; adb shell cat /sys/kernel/debug/wakeup_sources | head -20
```

If `/sys/power/state` lacks `mem`, suspend was compiled out or the platform ops were not
registered, which is a kernel fix. If it lists `mem` but the device never enters it, the
blocker is a wakelock or an active wakeup source, which can be fixed in userspace or by
masking the source.

**Why the fix is build-gated.** Registering suspend ops, fixing a wake storm at the driver
level, or disabling a firmware loop all mean touching the kernel. Kernel sources are in
`refs/kernel-7.3.1.9`, and the release's kernel is 4.4.302-lineage, so a fix would be a
patch against a tree close to LineageOS's `android_kernel_amazon_mt8183`.

**Exit criteria.** `suspend_stats` shows successful `suspend_enter` cycles, and standby
drain is measured over one hour with the screen off.

## G3: Battery always reports 100 percent

**What the artifact shows.** The vendor image carries the whole Amazon gauge stack:
`/bin/fuelgauged`, `/bin/fuelgauged_nvram`, `/bin/nvram_daemon`, their init rc files, and
`init.trona.rc` which hands `/mnt/vendor/nvcfg/fg` (`car_tune_value`, `old_fg_data`) to
the system user. Calibration lives on the `nvcfg` partition, 8 MiB on this device, mounted
by `fstab.nvcfg`. The health HAL is AOSP's `android.hardware.health@2.1-service`, which
reads `/sys/class/power_supply`. The kernel side has the gauge too:
`drivers/misc/mediatek/pmic/mt6358/v1/mt6358_gauge.c`, `mtk_battery_intf.c` and the
`mtk_charger` headers.

So the 100 percent reading is a *calibration or reporting* failure, not a missing driver or
a missing HAL. The most likely cause is that `fuelgauged` never gets valid NVCFG data
(mount failure, empty partition, or a property the ROM does not set), after which the
health service falls back to a stubbed value.

**Diagnosis that needs no build.**

```
adb shell ls /sys/class/power_supply/
adb shell cat /sys/class/power_supply/battery/uevent
adb shell cat /sys/class/power_supply/battery/capacity
adb shell ls -l /mnt/vendor/nvcfg /mnt/vendor/nvcfg/fg
adb shell ps -A | grep -i -E 'fuel|nvram'
adb shell dumpsys battery | head -20
adb logcat -d | grep -i -E 'fuel|gauge|nvcfg'
```

Three outcomes decide the fix. If `battery/capacity` exists and moves, the driver and the
kernel are fine and the gap is in the calibration or reporting path. If it exists but
never moves, `fuelgauged` is running without usable NVCFG data. If the directory is
absent, the gauge driver did not probe, which is a kernel or device-tree problem.

**Fix candidates, cheapest first.**

1. Health HAL replacement through a Magisk module, reading `/sys/class/power_supply`. This
   needs a compiled aarch64 binary, so it needs a toolchain but not a full ROM build.
2. Vendor-side HAL fix in a rebuilt vendor image.
3. Kernel/device-tree fix if the gauge never probes.

**Exit criteria.** `dumpsys battery` reports a level that tracks discharge under load.

## G4: The mute button acts as the power button

**What the artifact shows.** The vendor device trees in `refs/kernel-7.3.1.9` declare a
custom keymap property, for example
`keys_down = "KEY_VOLUMEDOWN", "KEY_VOLUMEUP", "KEY_POWER";` in `maverick_evt.dts`. That is
MTK's keypad mapping, so the button-to-keycode assignment happens in the kernel device tree,
not only in a `.kl` file.

**Diagnosis that needs no build.**

```
adb shell getevent -pl          # list input devices and their key codes
adb shell getevent -l           # then press mute and watch the event
adb shell ls -l /vendor/usr/keylayout/
```

If mute emits its own scancode, remap it in the `.kl` file for that device. If it emits
`KEY_POWER`, the kernel keymap is the only place to change it, and the fix is build-gated
unless a Magisk module can override the input mapping.

**Exit criteria.** Pressing mute does not sleep the device.

## G5: Security patch level 2024-02-05

**What the artifact shows.** `post-security-patch-level=2024-02-05`. The build is from
2026-10-24, so the patch level records the last merged Android 11 security branch rather
than the build date.

**Fix path.** Build-gated: it needs a newer LineageOS 18.1 tree with the 2025 and 2026
Android 11 ASB patches merged. LineageOS 18.1 is end-of-life upstream, so realistically
this means either accepting the level on a test device or moving the port to a newer
LineageOS branch, which is a bigger project than this stage.

**Exit criteria.** `getprop ro.build.version.security_patch` reflects the branch actually
merged, and the release notes say so.

## Summary

| gap | diagnose now | fix without a build | fix needs a build |
|---|---|---|---|
| G1 SELinux | yes, `setenforce 1` plus denials | no | yes, policy |
| G2 deep sleep | yes, `suspend_stats` and wakelocks | no | yes, kernel |
| G3 battery | yes, `/sys/class/power_supply` | possibly, Magisk HAL module | yes if the gauge never probes |
| G4 mute button | yes, `getevent` | possibly, keylayout edit | yes if the kernel keymap owns it |
| G5 patch level | yes, `getprop` | no | yes, newer branch |

The order to work them: G3 and G4 diagnosis first (cheap, no build), then G1 with a denial
list in hand, then G2 once the device can be left asleep for an hour.
