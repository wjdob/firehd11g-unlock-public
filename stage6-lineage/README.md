# Stage 6: LineageOS on trona

**Status:** 2026-10-25. A working unofficial LineageOS 18.1 exists, so this stage is about
**adopting, validating and hardening that build**. Writing a port from scratch is the
fallback, not the plan. The from-scratch track is kept in §7 for the day we need to change
something the release does not expose.

**Position of this repository.** Stage 2 gave the boot chain analysis, and its unlock
conclusion is superseded by [../exploits/AMONET-TRONA-DELTA.md](../exploits/AMONET-TRONA-DELTA.md).
With the bootloader unlocked, installing a custom ROM is a flash operation rather than a
research project. What remains worth engineering is proof that the release behaves as
advertised, a repeatable install and rollback procedure, and a fix path for its four
documented gaps.

---

## 1. What already exists

| item | value |
|---|---|
| Release | `lineage-18.1-20261024-UNOFFICIAL-trona.zip` (v0.2, published 2026-10-24) |
| Size / SHA-256 | 766,361,573 bytes / `ECE55B8F66EBA7F37F3F3527804F6C403091D4A67D2B00F39A309C04BE765818` |
| Android | 11 (SDK 30), security patch 2024-02-05 |
| Target fingerprint | `Amazon/trona/trona:9/PS7331.4463N/0031575863040:user/amz-p,release-keys` |
| Writes | `system`, `vendor`, `boot` only (verified from the updater script) |
| Kernel | `4.4.302-lineage-g942c9dc29f17`, clang 11, with an appended DTB |
| Kernel cmdline | `bootopt=64S3,32N2,64N2 androidboot.selinux=permissive buildvariant=userdebug` |
| Ramdisk | contains `fstab.mt8183`, `init`, `debug_ramdisk` |

The build ships its own **vendor** image, so it is a full Android stack replacement rather
than a system-only overlay. Recovery is untouched, which is why TWRP survives an update.

Details and the full compatibility read are in [rom-assessment.md](rom-assessment.md).
The gap backlog with causes, tests and fix paths is in [gaps.md](gaps.md). The
rollback analysis, including why a stock OTA is the wrong vehicle, is in
[rollback.md](rollback.md). The read-only evidence collector is
[validate-device.ps1](validate-device.ps1), which writes a markdown report and a raw log
under `reports/` (gitignored).

## 2. What this stage must produce

| deliverable | done when |
|---|---|
| **Install runbook** | a step-by-step TWRP procedure with a preflight gate and a tested rollback path |
| **Validation report** | every subsystem in §5 has a pass/fail result recorded for the reference unit |
| **Gap backlog** | each of the four documented gaps has an owner, a cause hypothesis and a fix path |
| **Repeatable environment** | a build or patch path that does not depend on one laptop |
| **Rollback proof** | a demonstrated return to stock via TWRP and a stock OTA zip |

## 3. Decisions to settle before the first flash

1. **Base firmware mismatch, narrower than it looks.** The release targets PS7331.4463N and
   the reference unit runs PS7319/1735. The unlock already writes the PS7331 TEE and a LK
   patched from the PS7331 LK (verified by hash), and the ROM replaces system, vendor and
   boot, so the only component that keeps its original version is the preloader. Expect it
   to work and require verification.
2. **Data wipe is mandatory.** Format Data, then wipe system and cache. Back up first.
3. **Root.** The build is `userdebug`, so `adb root` is the first thing to test. Magisk
   flashed from TWRP covers the case where a clean root interface matters for modules.
   KernelSU needs a kernel patch, so it is out of scope for this build.
4. **GApps.** MindTheGapps 11.0.0 arm64, flashed before the first reboot, is optional.
5. **Recovery retention.** The updater writes only system, vendor and boot, so TWRP stays
   installed and remains the rollback vehicle.

## 4. Install runbook

**P0, preflight.**
Verify the zip SHA-256. Confirm TWRP reachability (`adb reboot recovery`, or Volume Up at
power-on). Confirm the unlock is in place (hacked fastboot, `lk` is the kaeru build).
**Take the Tier A backup**: `boot`, `system` and `vendor` to the SD card, plus a read-only
dump of `lk`, `tee1`, `tee2`, `preloader` and `misc` for reference, with hashes recorded.
This is a gate, not a suggestion: without it there is no rollback that avoids the
preloader. Copy the ROM zip and MindTheGapps onto internal storage. Record the current
firmware (`ro.build.version.name`). Charge above 50 percent.

**P1, wipe.**
TWRP: Wipe, Format Data, type yes. Then Wipe, Advanced Wipe, select Data, System, Cache,
swipe.

**P2, flash.**
Install the ROM zip. Optional: install MindTheGapps. Then Format Data again. Reboot to
System.

**P3, first boot.**
Expect several minutes and at least one reboot. Capture `adb logcat -d` and
`adb shell dmesg` as soon as ADB answers.

**Rollback.** Restore `boot`, `system` and `vendor` from the Tier A backup taken in P0.
Do **not** run a stock OTA package as the rollback vehicle: its script also writes the
preloader, both TEE slots and the LK, and a preloader write has no recovery path.
[rollback.md](rollback.md) records the evidence and the three tiers, including
`make-rollback-zip.py` for rebuilding a package that touches only the three partitions.
This corrects the rollback paragraph written on 2026-10-25, which named the stock OTA.

## 5. Validation matrix

| area | test | pass criteria |
|---|---|---|
| Boot | boot to launcher, check `ro.lineage.version` | reaches UI, correct build string |
| Kernel | `uname -a` | 4.4.302-lineage, no oops in dmesg |
| Display | brightness slider, rotation | full range, no tearing |
| Touch | multi-touch test | all points tracked |
| Wi-Fi | scan, join WPA2, throughput | internet reachable, stable |
| Bluetooth | pair a headset | connects, audio routes |
| Audio | speaker, headphones, mic | playback and capture work |
| Camera | rear and front stills | images saved, no HAL crash |
| Sensors | accelerometer, light | values change sensibly |
| Storage | `/data` write test, USB MTP | files persist, host sees device |
| Charging | plug USB, read `/sys/class/power_supply` | reports charging state (currently stubbed, see §6) |
| Sleep | screen off, check `/sys/power/state` and `dumpsys` | identify that deep sleep is disabled, measure drain |
| SELinux | `getenforce` | currently Permissive, record AVC denials |
| Performance | cold app start, `dumpsys gfxinfo` | baseline numbers for later comparison |

## 6. Gap backlog

These are the release's own documented caveats, plus one we found in the boot image.

| # | gap | impact | cause hypothesis | fix path |
|---|---|---|---|---|
| G1 | **SELinux Permissive** (baked into the kernel cmdline) | no MAC enforcement, so the build is not suitable for sensitive data | bring-up shortcut | write `device/amazon/trona/sepolicy`, boot enforcing, triage AVCs, then flip the cmdline flag |
| G2 | **Deep sleep intentionally disabled** | standby drain | MTK suspend path not integrated (SCP/SSPM wake sources) | start from the kernel's suspend support, use `/sys/kernel/debug/suspend_stats`, add wake irq config |
| G3 | **Battery reports a fixed 100 percent** | gauge unusable | power supply HAL stubbed for bring-up | implement the MTK charger/gauge in the health HAL, read the fuel-gauge driver |
| G4 | **Mute button acts as power** | hardware quirk | key layout mapping | adjust the keylayout or fix the GPIO mapping |
| G5 | **Security patch level 2024-02-05** | known Android 11 CVEs after that date | build date | newer build, or accept the risk on a test device |

G1 and G2 are the two that change the build from "demo" to "daily usable". They are also
the two that need a device tree, which is why §7 exists. [gaps.md](gaps.md) separates what
can be diagnosed on the device today from what is build-gated: G3 and G4 are diagnosable
and possibly fixable without a build, G1 and G2 need one.

## 7. Optional track: our own build

Only needed to fix G1 or G2. The published device tree is not public, so a rebuild means
reconstructing it.

**What is available:** the device's partition map, fstab and property surface (this
repository), Amazon's kernel source for 4.4.146 (`refs/kernel-7.3.1.9`), the release's
boot image (kernel 4.4.302 plus appended DTB), and the release's system and vendor images,
which encode the vendor blob list and the vendor init scripts.

**Milestones.**

1. Unpack the release's `system.new.dat.br` and `vendor.new.dat.br` into raw ext4 images,
   list their contents, and derive `proprietary-files.txt` from the vendor image.
2. Draft `device/amazon/trona` (BoardConfig, device.mk, fstab.mt8183, init, sepolicy,
   blob list) against the MTK `mt8183` common trees.
3. Build with `lineage-18.1` on a CI runner: 16 GB RAM, 4 cores, 250 GB disk, ccache
   enabled. This host cannot do it: no usable Linux distribution, 27 GB free on C: and
   86 GB on D:, Docker daemon stopped.
4. Iterate on G1 (SELinux) first, because it needs no hardware validation to make progress,
   then G2 (suspend) with `dmesg` from the reference unit.

**Estimate.** Tree reconstruction plus a first successful build is a multi-day effort with
a real build host. Until G1 or G2 has an owner, stay on the released build.

## 8. Guardrails

- Never write `preloader`, `lk`, `tee1/tee2` or `boot0/boot1` outside the documented unlock
  flow. The unlock release exists to avoid touching them again.
- Keep TWRP installed. It is the only recovery vehicle that survives a bad ROM flash.
- Keep a stock OTA zip on the device before the first flash.
- Do not run `oem relock`. It randomises the IDME unlock binding.
- The device holds no sensitive data while SELinux is permissive (G1).

## 9. Open questions

1. Does the PS7331-targeted build behave identically on a PS7319 unit? Verify with the
   validation matrix rather than assuming.
2. Does the release support OTA updates through the LineageOS updater? The zip is a manual
   TWRP package, so assume manual.
3. Which vendor blobs does the build carry, and do they match a PS7319 vendor? Answer by
   unpacking `vendor.new.dat.br` (step 1 of §7).
4. Does `adb root` work on a `userdebug` build with Permissive SELinux? Test first, since
   it decides whether Magisk is needed at all.
