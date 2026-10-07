# Partition dumps: Fire HD 10 11th gen (trona/KFTRWI, PS7319/1735)

## TL;DR: read this first

Partition dumps from **one specific reference unit** (PS7319/1735). They are the ground
truth for boot-chain work on that build: where an OTA-derived figure and a dump
disagree, the dump wins.

- **Core finding**: the installed `lk` (`p5`) and both `tee` slots (`p6`/`p7`) match
  the shipped OTA images **byte-for-byte**, so offline image analysis applies to the
  running device rather than only to the OTA. Both tee slots hold an identical image.
- **Core win**: the GPT plus the boot-chain partitions are captured, which is what
  made the LK signature-boundary and TEE container-length analyses possible.
- **Core dead end**: dumps confer **no recovery**. Possessing an image is not the same
  as having a way to write it back: there is no transport for a bad `lk`, so these are
  evidence, not a restore path.
- **Before sharing**: `mmcblk0boot1` (the IDME database) carries the serial,
  WiFi/BT MAC and PSN/FSN. Never publish it unredacted; see
  [Sharing a dump](#sharing-a-dump--privacy-warning) at the end of this file.

**Captured:** 2026-10-05, via live root (`uid=0`, `u:r:time_update:s0`), read-only
`dd` from `/dev/block/...` to `/data/local/tmp/dumps`, pulled over adb.
**Device:** KFTRWI, Fire OS 7.3.1.9 (PS7319/1735, incremental 0020367984516),
kernel `4.4.146+ #1 SMP PREEMPT Sat May 29 18:57:35 UTC 2021 aarch64`.

These dumps are the **ground truth** for this exact device. They supersede any
OTA-derived analysis for boot-chain work. All dumps are gitignored
(`dumps/` in `.gitignore`), keep local copies safe.

## eMMC hardware

| Property | Value |
|---|---|
| Device | `/dev/block/mmcblk0` |
| eMMC chip | SanDisk `DA4064` (manfid `0x000045`) |
| Capacity | 122,142,720 × 512 B sectors = 62,477,913,600 B (~58.2 GiB) |
| RPMB | present (`mmcblk0rpmb`, 16 MiB); **read denied** without hardware authentication (expected) |
| eMMC boot partitions | `mmcblk0boot0` / `mmcblk0boot1`, 4 MiB each; both dumped |

## GPT layout (from `gpt-primary.bin`)

GPT header at LBA 1, partition table at LBA 2, 128 entries × 128 B.
First usable LBA 64, last usable LBA 122,142,686, backup GPT at LBA 122,142,719.
All partitions use the same type GUID `ebd0a0a2-b9e5-4433-87c0-68b6b72699c7`
(Linux filesystem), Amazon does not distinguish partition types in the GPT.

| # | Name | Block | LBAs | Size | Dump file | SHA256 |
|---|---|---|---|---|---|---|
| 1 | `kb` | mmcblk0p1 | 64–2111 | 1 MiB | `mmcblk0p1.bin` | `aceb42a2…c047f` |
| 2 | `dkb` | mmcblk0p2 | 2112–4159 | 1 MiB | `mmcblk0p2.bin` | `30e14955…fcb58` |
| 3 | `keys` | mmcblk0p3 | 4160–20543 | 8 MiB | `mmcblk0p3.bin` | `1ad7c2d8…a81d` |
| 4 | `misc` | mmcblk0p4 | 20544–22591 | 1 MiB | `mmcblk0p4.bin` | `30e14955…fcb58` |
| 5 | `lk` | mmcblk0p5 | 22592–24639 | 1 MiB | `mmcblk0p5.bin` | `c002d4d6…b4df` |
| 6 | `tee1` | mmcblk0p6 | 24640–34879 | 5 MiB | `mmcblk0p6.bin` | `21192358…028c` |
| 7 | `tee2` | mmcblk0p7 | 34880–45119 | 5 MiB | `mmcblk0p7.bin` | `21192358…028c` |
| 8 | `metadata` | mmcblk0p8 | 45120–110655 | 32 MiB | `mmcblk0p8.bin` | `83ee4724…4302` |
| 9 | `boot_para` | mmcblk0p9 | 110656–112703 | 1 MiB | `mmcblk0p9.bin` | `cc4b0f1b…eeb8b` |
| 10 | `nvcfg` | mmcblk0p10 | 112704–129087 | 8 MiB | `mmcblk0p10.bin` | `68a81631…61a35` |
| 11 | `spmfw` | mmcblk0p11 | 129088–131135 | 1 MiB | `mmcblk0p11.bin` | `cdd93eb2…1db2` |
| 12 | `sspm_1` | mmcblk0p12 | 131136–133183 | 1 MiB | `mmcblk0p12.bin` | `9b1d74e0…517f` |
| 13 | `cam_vpu1` | mmcblk0p13 | 133184–163903 | 15 MiB | `mmcblk0p13.bin` | `8b59a31d…929f` |
| 14 | `cam_vpu2` | mmcblk0p14 | 163904–229439 | 32 MiB | `mmcblk0p14.bin` | `7f5554ed…ce1f` |
| 15 | `cam_vpu3` | mmcblk0p15 | 229440–260159 | 15 MiB | `mmcblk0p15.bin` | `31732468…f9a7` |
| 16 | `boot` | mmcblk0p16 | 260160–325695 | 32 MiB | `mmcblk0p16.bin` | `fa9eaa42…f98e7` |
| 17 | `recovery` | mmcblk0p17 | 325696–409599 | 40 MiB | `mmcblk0p17.bin` | `9921583b…9ac0` |
| 18 | `cache` | mmcblk0p18 | 409600–1523711 | 544 MiB |; (not dumped; ext4, re-creatable) |
| 19 | `system` | mmcblk0p19 | 1523712–8962047 | 3632 MiB |; (not dumped; dm-verity protected, OTA has it) |
| / | `vendor` | mmcblk0p20 | 8962048–9781247 | 400 MiB |; (not dumped; dm-verity protected, OTA has it) |
| 21 | `userdata` | mmcblk0p21 | 9781248–122142686 | 54863 MiB |; (not dumped; user data) |
|; | GPT primary |; | LBA 0–33 | 17 KB | `gpt-primary.bin` | `4880e171…f04f37` |
|; | GPT backup |; | last 33 LBAs | 17 KB | `gpt-backup.bin` | `85a077ea…9ddbf` |
|; | eMMC boot0 | mmcblk0boot0 |; | 4 MiB | `mmcblk0boot0.bin` | `37634088…7d48` |
|; | eMMC boot1 | mmcblk0boot1 |; | 4 MiB | `mmcblk0boot1.bin` | `9e8fb6c0…1fe4f` |
|; | RPMB | mmcblk0rpmb |; | 16 MiB | **read denied** (hardware-authenticated) |; |

Full SHA256s in [SHA256SUMS.txt](SHA256SUMS.txt).

## Boot-chain configuration (from kernel cmdline)

Captured from `/proc/cmdline` at dump time:

```
androidboot.hardware=mt8183
androidboot.unlocked_kernel=false
androidboot.verifiedbootstate=green
androidboot.veritymode=eio
dm="system none ro,0 1 android-verity PARTUUID=6a5cebf8-54a7-4b89-8d1d-c5eb140b095b"
veritykeyid=id:f3530e18f64d11fc25eb2dd762979f078de990bf
androidboot.pl_build_desc=3c174ba-20210329_073626
androidboot.lk_build_desc=2cb0e4b-20210329_073626
androidboot.secure_cpu=1
androidboot.prod=1
androidboot.rpmb_state=2
androidboot.pl_version=0x0106  lk_version=0x0106  tee_version=0x0106
androidboot.sspm_version=0x0105 vpu_version=0x0105  spm_version=0x0105
androidboot.mnt_keys_rw_opts=ro
bl_level=77
androidboot.bootreason=wdt_by_pass_pwk
gpt=1
```

Key facts for unlock/recovery/ROM development:

- **Verified boot is GREEN** with dm-verity on `system` (PARTUUID `6a5cebf8-…`),
  mode `eio` (corrupt data → I/O error, not panic).
- **`androidboot.unlocked_kernel=false`**: the kernel cmdline itself records that
  the boot chain is locked. Any unlock theory must flip this (or its source).
- **All boot-chain components are version-locked at 0x0106** (preloader, LK, TEE),
  SSPM/VPU/SPM at 0x0105. A mismatched-version flash would brick.
- **`bl_level=77`**: bootloader security level; likely the anti-rollback counter
  source. Do not downgrade.
- **`androidboot.rpmb_state=2`**: RPMB in use; TEE-backed anti-rollback likely.
- **`androidboot.mnt_keys_rw_opts=ro`**: the `keys` partition is mounted read-only
  at `/mnt/vendor/keys`.
- **`androidboot.bootreason=wdt_by_pass_pwk`**: last boot was watchdog reset
  (normal for this device's reboot flow).
- **`boot_para`** (p9) holds the boot parameters/DRM flags; the partition Amazon
  uses for boot-arg storage; relevant to any unlock-flag research.
- **`keys` (p3, 8 MiB)**: device keys; mounted RO at `/mnt/vendor/keys`.
- **`nvcfg` (p10, 8 MiB)**: NVIDIA-style config partition (MTK NVRAM-style);
  contains calibration + serial data. **Do not write.**
- **`tee1`/`tee2` are identical** (mirrored TEE OS, 5 MiB each), consistent with
  the mirrored TEE design.
- **`dkb` and `misc` are identical** (both mostly zeros), `misc` is the standard
  Android bootloader-message partition; `dkb` is Amazon's device-key-block.
- **`kb`/`dkb`**: Amazon key-block partitions; `dkb` == `misc` content-wise on
  this unit (both near-empty), suggesting they're provisioned per-unit at factory.

## What was NOT dumped (and why)

| Partition | Size | Reason |
|---|---|---|
| `cache` (p18) | 544 MiB | ext4, re-creatable, no research value |
| `system` (p19) | 3632 MiB | dm-verity protected; the OTA image is the ground truth for its content |
| `vendor` (p20) |  OTAs have it | dm-verity protected; OTA image is ground truth |
| `userdata` (p21) | 54863 MiB | user data; also contains the staged exploit assets |
| RPMB | 16 MiB | hardware-authenticated; read denied even as uid 0 |

## How to re-dump (if root is live)

```bash
# via the root listener (127.0.0.1:4325):
printf 'dd if=/dev/block/mmcblk0p5 of=/data/local/tmp/lk.bin bs=512 count=2048\nexit\n' \
  | adb shell 'toybox nc -w 30 127.0.0.1 4325'
adb pull /data/local/tmp/lk.bin
```

Note: `toybox dd` rejects `bs=1M` suffixes, use explicit byte counts (`bs=512 count=N`).

---

## Sharing a dump: privacy warning

Some of these partitions carry data unique to the unit they came from. Verified on the
reference device (2026-10-06) by scanning every dump for serial/MAC/PSN patterns:

| dump | device-unique data? |
|---|---|
| **`mmcblk0boot1`** (IDME database) | **YES**: unit serial, WiFi MAC, Bluetooth MAC, PSN and FSN |
| `mmcblk0boot0` (preloader) | no |
| `mmcblk0p4`, `p5`, `p6`, `p7` (nvram/proinfo family) | no |
| `gpt-primary`, `gpt-backup` | no |

**Before publishing anything from this folder:**

* never publish `mmcblk0boot1.bin` unredacted. It is the IDME database, and it is where
  the signed `unlock_code` lives, but the same image also carries the identifiers above;
* avoid publishing `userdata` and `metadata` at all. Those hold *personal* data, which is
  a different and more serious problem than hardware identifiers;
* prefer publishing `SHA256SUMS.txt`, or a parsed summary, over the raw image. The IDME
  analysis can be reproduced from a dump of your own device with
  `python ../tools/idme-parse.py`;
* the handoff bundle under `stage2a-unlock/` deliberately **excludes**
  `mmcblk0boot1.bin` for exactly this reason. The rationale is recorded in
  `tools/sync-handoff-bundle.py` so it is not accidentally "fixed" later.
