# Device state, 2026-10-25: root works, unlock precondition does not match

Written after the tablet was reconnected. Everything here was measured, not inferred.
The point of the file is to record why the install did not start yet.

## What the device is

| field | value |
|---|---|
| serial | redacted in the published tree |
| product | trona / KFTRWI |
| build | Fire OS 7.3.1.9, `PS7319`, incremental `0020367984516` |
| fingerprint | `Amazon/trona/trona:7.0/PS7319/1735N:user/amz-p,release-keys` |
| kernel | 4.4.146+, built 2021-05-29 |
| boot state | `flash.locked=1`, `verifiedbootstate=green` |
| component versions (cmdline) | `pl_version=0x0106`, `lk_version=0x0106`, `tee_version=0x0106`, `sspm/vpu/spm=0x0105` |
| other cmdline facts | `secure_cpu=1`, `prod=1`, `rpmb_state=2`, `selinux=enforcing` |

No TWRP: `adb reboot recovery` never produced an adb device, and the next boot reported
`bootreason=watchdog_sw`, so the installed recovery is stock.

## Root is available now

The persistent service is installed and fired on its own:
`io.github.voidnullvalue.snusnuroot.persistence` (uid 10232) ran at boot, SELinux went
`Permissive`, and `snusnu_hwbinder_root` runs as `system`. The root shell is reachable
without re-running anything:

```
adb shell "printf 'id\n' | toybox nc -w 4 127.0.0.1 4325"
uid=0(root) gid=1000(system) groups=1000(system),2000(shell) context=u:r:time_update:s0
```

There is no `su` binary, so amonet's `unlock.sh` precondition (`su -c id`) does not hold
as written. Running the binary through the 4325 shell is the equivalent.

One leftover had to be handled: an earlier interrupted re-root left
`persist.sys.saved_time` armed with the trigger. `stage_reroot_waiter.sh` refused to
start, so it now recognises its own trigger and recovers instead of deadlocking.

## GhostLock

`ghostlock-trona-v1.0.0` rejects this unit: `[-] profile rejected: no built-in profile
matches this device`. Its table covers `PS7319.1726N / 0020367982212`; this unit is
`0020367984516`. The binary accepts `--profile FILE` and `--check-profile`, so an
external profile is possible, but the profile carries kernel geometry
(`kaslr.kernel_link_base`, heap and slab parameters, structure offsets) and none ships
for 1735. Root does not depend on it: the persistent service already provides uid 0.

## The unlock precondition gap

| image | version tag | notes |
|---|---|---|
| this unit's LK | `_LK_VER: 01 06` | 0x0106, matches `androidboot.lk_version` |
| PS7331 stock LK | `_LK_VER: 01 0a` | 0x010A |
| `trona-kaeru.bin` (shipped) | `_LK_VER: 01 0a` | patched from the PS7331 LK |
| this unit's preloader | 248,540 bytes | PS7319 build |
| PS7331 preloader | 249,340 bytes | not shipped by the unlock |

The release's payload set is PS7331: the TEE is byte-identical to PS7331 stock, and the
kaeru LK is patched from the PS7331 LK (version 0x010A). This unit is PS7319, whose LK and
TEE are version 0x0106. The unlock does **not** write the preloader, so an unlock here would
leave a PS7319 preloader loading a 0x010A LK and a 0x010A TEE.

Whether that mismatch is fatal is the open question. The preloader extracts the version tag
and passes it up as `androidboot.lk_version`; the repository's boot map records the tag
location and the signature relationship but not a fatal comparison. No public report covers
unlocking a PS7319 unit with this release.

## Backed up before any decision

Six partitions were dumped through the root shell and pulled to
`D:/lineage-artifacts/backup-1735`:

| image | bytes |
|---|---|
| boot.img | 33,554,432 |
| lk.img | 1,048,576 |
| misc.img | 1,048,576 |
| preloader.img (mmcblk0boot0) | 4,194,304 |
| tee1.img | 5,242,880 |
| tee2.img | 5,242,880 |

A preloader image is only restorable while the device still boots or while the preloader's
serial protocol answers, so this is insurance rather than a guarantee.

## Options

**A. Align the firmware to PS7331 first.** Apply the stock PS7331 package (or write its
preloader, lk and tee from root), reboot, confirm the device still boots and reports
`0x010A`, then root and unlock. Every step is the official signed image, and the unlock's
payloads then match the unit. Cost: the preloader write, which is the operation with no
recovery path if it goes wrong.

**B. Try the unlock as it is.** It performs the same writes as A's second half, plus TWRP
and a misc flag. If the preloader tolerates the version difference, the result is an
unlocked device and the install continues. If it does not, the device stops booting and the
only hope is the preloader serial path, whose availability depends on the same fuse state
that decides the unlock.

**C. Leave the device rooted and stop.** Root, Magisk and the repo's own stage 4 and 5 work
continue; the LineageOS install waits for a PS7331 unit or for evidence that 0x010A on a
0x0106 preloader boots.

Recommendation: **A**, and specifically by writing only `lk` and `tee1/tee2` first and
rebooting, which tests the version tolerance without touching the preloader. If that boots,
the preloader write is unnecessary and the unlock can follow.
## 2026-10-25, later: the unit is secure, and that closes the unlock

Two independent experiments agree.

**Unsigned Download Agent.** With the tablet looping, the preloader's USB serial
service was caught on three consecutive boot cycles. The handshake completed
(`READY`, then `0xA0 -> 0x5F`, then the three confirmation bytes), the DA header was
accepted with status `0x0000`, and the body was sent. No acknowledgement ever came.
Each attempt hung for about ninety seconds and ended with the USB driver losing the
device, which is what a reset looks like from the host.

That is exactly the shape of the secure branch in the preloader. At `0x5816` it calls
`is_secure_soc()` (SEC_CFG `0x11F10060` bit 2) and branches to `0x5834`, which logs
"Start to authenticate LK DA", calls the verifier at `0x255A4`, and on failure logs
"DA validation fail" and enters the dead loop the repository already recorded for
unsigned DA on a secure part. A non-secure part takes `0x5820` instead, logs
"DA validation disabled on non-secure chip", and skips the verifier.

**Unsigned recovery.** Writing the release's TWRP to `recovery` and setting the
`boot-recovery` flag produced a boot loop with the Amazon logo: LK ran, displayed,
tried the image, and reset. That is the LK's own secure branch, whose strings are
`Error: secure SoC should run signed %s` at `0x560776F0` and
`non secure SoC run with unsigned %s` at `0x56077521`.

Both gates read the same fuse word. Both said no.

### What this means

* **The bootloader unlock does not apply to this unit.** The release writes an unsigned
  LK, and a secure preloader rejects it; the same write on this tablet is the
  documented permanent brick (S2), not an unlock.
* **LineageOS cannot be installed on this unit either**, because its boot image is
  unsigned and the LK verifies boot images with the same gate.
* Root still works and is unaffected: the persistent service provides uid 0 on the
  running Fire OS.

### Current device state

The tablet loops because `misc` still holds `boot-recovery` and the recovery image is
TWRP, which the LK refuses. Both are backed up
(`D:/lineage-artifacts/backup-1735`: `recovery.img` 41 MiB, `misc.img` 1 MiB), and the
preloader still answers on USB serial, so the device is recoverable once a write path
is found. The DA was that path, and the fuse closes it.

Remaining candidate paths for a write, in order of preference:

1. **Fastboot.** Hold Volume Down at power-on and see whether the LK enters fastboot.
   On a locked unit most commands are denied, but recovery and misc are worth testing
   before concluding.
2. **The stock OTA through the system updater.** Needs Android, which needs the loop
   broken first.
3. **A BROM-level tool with hardware access.** Out of scope here.

### Lesson for the repository

The stage 6 plan assumed the tablet was unlockable because the release exists and the
model matches. The decisive variable was the fuse state, and it is now measured twice
over. Any future work on this unit targets rooted Fire OS, not a custom ROM.
