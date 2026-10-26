# LineageOS 18.1 trona v0.2: artifact assessment

Read-only analysis of the published build, on 2026-10-25. Nothing here was flashed.

## 1. Provenance and integrity

| field | value |
|---|---|
| file | `lineage-18.1-20261024-UNOFFICIAL-trona.zip` |
| size | 766,361,573 bytes |
| SHA-256 | `ECE55B8F66EBA7F37F3F3527804F6C403091D4A67D2B00F39A309C04BE765818` |
| zip comment | `signed by SignApk` |
| metadata | `pre-device=trona`, `post-sdk-level=30`, `post-security-patch-level=2024-02-05` |
| post-build | `Amazon/trona/trona:9/PS7331.4463N/0031575863040:user/amz-p,release-keys` |
| build tag | `eng.r0rt1z.20261024.155253` |

The package is a block-based OTA signed with the LineageOS test keys (SignApk), so it is
flashable from TWRP and from the LineageOS updater only if the keys match a future build.

## 2. What it writes

From `META-INF/com/google/android/updater-script`:

```
assert ro.product.device == "trona"
block_image_update /dev/block/platform/bootdevice/by-name/system  (system.transfer.list)
block_image_update /dev/block/platform/bootdevice/by-name/vendor  (vendor.transfer.list)
package_extract_file boot.img  ->  /dev/block/platform/bootdevice/by-name/boot
```

Three targets only: **system**, **vendor**, **boot**. Recovery, `lk`, `tee1/tee2`,
`preloader`, `sspm`, `spmfw`, `cam_vpu*`, `misc` and the IDME area are untouched, which is
why TWRP survives and why the unlock's boot chain stays as installed.

The device path is `/dev/block/platform/bootdevice/by-name/`, the MTK "bootdevice" layout
that Fire OS 7 uses. Older `/dev/block/by-name` symlinks exist too.

## 3. Size against this unit's partitions

| image | payload | partition | headroom |
|---|---|---|---|
| system | 437,765 blocks = 1,710.0 MiB | 3,632 MiB | 1,922 MiB |
| vendor | 62,425 blocks = 243.8 MiB | 400 MiB | 156 MiB |
| boot | 11,089,920 bytes | 32 MiB | 21.4 MiB |

Every image fits with room to spare, so no repartitioning is required.

## 4. The boot image

Header version 1, 2048-byte pages.

| field | value |
|---|---|
| kernel | 10,248,565 bytes gzip, decompresses to 27,445,504 bytes |
| kernel version | `Linux version 4.4.302-lineage-g942c9dc29f17` built with clang 11.0.2 |
| appended DTB | 748,615 bytes after the gzip stream (magic `d00dfeed`) |
| ramdisk | 837,408 bytes, cpio, contains `init`, `debug_ramdisk`, `fstab.mt8183` |
| cmdline | `bootopt=64S3,32N2,64N2 androidboot.selinux=permissive buildvariant=userdebug` |

Two consequences.

1. The ROM ships its **own kernel**, 4.4.302, newer than the stock 4.4.146. The appended DTB
   carries the device tree, so the boot image is self-contained.
2. `androidboot.selinux=permissive` and `buildvariant=userdebug` are set in the cmdline.
   Permissive SELinux is a boot argument, and `adb root` should work on a userdebug build.

## 4.1 What the vendor image contains

The vendor payload converts cleanly to a 400 MiB ext4 image (label `vendor`,
`s_blocks_count` 102,400) and its root lists `bin`, `etc`, `firmware`, `lib`, `lib64`,
`odm`, `overlay`, `build.prop`, `ueventd.rc`. Reproduce with
[ota-br-to-img.py](../exploits/tools/ota-br-to-img.py) and
[ota-system-read.py](../tools/ota-system-read.py).

**Build identity.** `ro.vendor.build.type=userdebug`, `ro.vendor.build.tags=test-keys`,
`ro.vendor.build.fingerprint=Amazon/trona/trona:9/PS7331.4463N/...`, SDK 30, release 11,
date 2026-10-24. The vendor partition is rebuilt, not stock.

**HAL inventory** in `/bin/hw`: bluetooth 1.0, cas 1.2, drm (widevine 1.1, clearkey 1.3),
gatekeeper 1.0, graphics (allocator 2.0, composer 2.1), **health 2.1**, keymaster 3.0,
light (Amazon), media.omx 1.0, memtrack 1.0, sensors 1.0, thermal 1.0, usb 1.0, wifi 1.0
(lazy), `camerahalserver`, `fireos.hardware.audio.service`, `vendor.mediatek.hardware.power`
2.0 and `vendor.mediatek.hardware.pq` 2.2.

Health is AOSP's `android.hardware.health@2.1-service`, which reads
`/sys/class/power_supply`. The battery gap therefore lives in the driver or in the
calibration path, not in a missing HAL.

**`init.trona.rc`** is present and shows what the port wired:

* zRAM compression set to `zstd`;
* `mount_all /vendor/etc/fstab.nvcfg` at `on fs`;
* kernel modules loaded on boot: `mt6771_common.ko`, then on
  `vendor.connsys.driver.ready=yes` `mt6771_bt.ko`, `mt6771_wlan_adaptor.ko`,
  `mt6771_wlan.ko`. The module names follow MT6771, the sibling MTK platform whose
  connectivity and PMIC code MT8183 shares;
* touchscreen `gesture_wakeup`, camera nodes `/dev/MAINAF`, `/dev/MAINAF2`, `/dev/SUBAF`,
  sensor nodes `/dev/hwmsensor`, `/dev/m_acc_misc`, `/dev/m_als_misc`;
* fuel gauge ownership under `/mnt/vendor/nvcfg/fg` (`car_tune_value`, `old_fg_data`);
* services `wmt_loader` and `wmt_launcher` for connectivity firmware.

**Battery stack.** `/bin/fuelgauged`, `/bin/fuelgauged_nvram`, `/bin/nvram_daemon`,
`fuelgauged_init.rc`, `fuelgauged_nvram_init.rc`. Calibration data lives on the `nvcfg`
partition, which is 8 MiB on this device and mounts through `fstab.nvcfg`.

**Storage layout.** `fstab.mt8183` mounts system and vendor read-only at first stage, data
with `quota,reservedsize=128m` and `encryptable=` pointed at `metadata`, cache with
`discard`, and exposes boot, recovery and misc as `emmc`. External storage is
`voldmanaged=sdcard1:auto` and `usbotg:auto`.

**Key layout.** `/vendor/usr/keylayout` does not exist, so the keymap comes from the kernel
or from the system image. That supports the G4 hypothesis in [gaps.md](gaps.md).

## 5. Compatibility with a PS7319/1735 unit

The release targets PS7331.4463N. This unit runs PS7319/1735. The practical question is
which parts of the firmware the ROM pins.

| area | source after flashing | note |
|---|---|---|
| system, vendor, boot | the ROM | full replacement |
| preloader, lk (kaeru), tee1/tee2, sspm, spmfw, cam_vpu* | this unit, unchanged | none of these are written by the ROM |
| vendor properties | PS7331 values | the ROM's vendor build.prop supplies them |
| security patch | 2024-02-05 | newer than stock 2018-10-05 |
| IDME, misc, RPMB | unchanged | the flash does not touch them |

Expected outcome: boots. The ROM carries the vendor HALs it needs, and the hardware is the
same SoC. The realistic risks are HAL-level rather than boot-level:

* **TEE version coupling, now narrower.** The unlock writes the stock PS7331 TEE and a
  kaeru LK patched from the PS7331 LK, so the TEE matches the ROM's target. The remaining
  skew is the preloader, which keeps the unit's own version. A mismatch here shows up as
  keymaster, gatekeeper or DRM failures rather than a boot failure.
* **Audio and camera HAL tuning.** Both use MTK vendor blobs that expect specific DSP or
  SCP firmware, which comes from this unit.
* **Wi-Fi and Bluetooth** use the CONSYS firmware in this unit's partitions; the ROM's
  vendor blobs must speak the same interface version.

None of these can be settled by reading the package. They are exactly what the validation
matrix in the plan is for.

## 6. Root, given an unlocked bootloader

| option | status |
|---|---|
| **`adb root`** | likely, since the build is `userdebug` with `ro.debuggable=1`. Test first: `adb root` then `adb shell id`. |
| **Magisk** | standard path: install the APK, patch the ROM's `boot.img`, flash the patched image from TWRP or fastboot. The patched LK accepts unsigned images, so this works. |
| **KernelSU** | needs a kernel with KernelSU integrated. Out of scope: it means building the kernel from source. |

Because the bootloader is unlocked and TWRP is installed, root is a maintenance step rather
than a research problem. The only caution is to keep a copy of the original `boot.img` so a
bad patch can be undone.

## 7. What the package does not contain

* No device tree, no defconfig, no `proprietary-files.txt`. The source side is unpublished,
  which is why a rebuild would start from reconstruction (§7 of the plan).
* No recovery image, so TWRP must already be installed.
* No modem or radio images. This is a Wi-Fi tablet, so there is nothing to update.
* No anti-rollback counter handling. The unlock already zeroed RPMB block 0.

## 8. Reproduction commands

```bash
# integrity
certutil -hashfile lineage-18.1-20261024-UNOFFICIAL-trona.zip SHA256

# contents and metadata
7z l lineage-18.1-20261024-UNOFFICIAL-trona.zip
7z e lineage-18.1-20261024-UNOFFICIAL-trona.zip -o out \
   META-INF/com/google/android/updater-script META-INF/com/android/metadata \
   boot.img system.transfer.list vendor.transfer.list

# kernel, DTB and ramdisk facts
python exploits/tools/inspect-lineage-rom.py
```
