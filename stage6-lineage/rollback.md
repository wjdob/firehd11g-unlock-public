# Rollback: why a stock OTA is not a safe rollback vehicle

This corrects the rollback paragraph that was written into the plan on 2026-10-25 before the
stock packages were read. The correction matters because the obvious path is the dangerous one.

## 1. What the stock package actually writes

From `META-INF/com/google/android/updater-script` in
`update-kindle-Fire_HD10-PS7331_user_4463_0031575863172.bin`:

```
block_image_update .../by-name/system   system.new.dat.br
block_image_update .../by-name/vendor   vendor.new.dat.br
package_extract_file boot.img        -> .../by-name/boot
package_extract_file images/preloader.img -> .../by-name/preloader
package_extract_file images/lk.img        -> .../by-name/lk
package_extract_file images/tee.img       -> .../by-name/tee1
package_extract_file images/tee.img       -> .../by-name/tee2
package_extract_file images/spmfw.img     -> .../by-name/spmfw
package_extract_file images/sspm.img      -> .../by-name/sspm_1
package_extract_file images/cam_vpu1.img  -> .../by-name/cam_vpu1
package_extract_file images/cam_vpu2.img  -> .../by-name/cam_vpu2
package_extract_file images/cam_vpu3.img  -> .../by-name/cam_vpu3
```

All four packages in `OTAs/` carry those images:

| package | preloader | lk | tee |
|---|---|---|---|
| PS7319 / 1726 | 248,540 | 604,912 | 2,980,864 |
| PS7321 / 2324 | 248,564 | 604,912 | 2,915,328 |
| PS7326 / 3178 | 249,120 | 604,912 | 2,898,944 |
| PS7331 / 4463 | 249,340 | 617,232 | 2,704,896 |

So flashing a stock OTA from TWRP overwrites the **preloader**, both TEE slots and the LK.
On a device whose boot depends on the patched LK, that is the one write with no recovery
path: a broken preloader means no BROM download mode, no preloader serial protocol, and no
TWRP to fall back to. It also discards the unlock's LK.

The unlock guide's advice to "only flash stock firmware updates via TWRP" describes what to
do to stay on stock. It is not a rollback procedure for an unlocked, modified device.

Two further details in that script:

* Line 1 aborts when the installed build is newer than 2025-05-03
  (`less_than_int(1746234888, ro.build.date.utc)`). A LineageOS build from 2026 fails that
  check, so the stock package refuses to run at all on top of the ROM.
* It never writes `recovery`, so TWRP survives a stock flash. That is the only reassuring
  line in the script.

## 2. Rollback tiers

Work down this list. Tier A is the one to set up before the first flash.

### Tier A: restore the three partitions the ROM touches (recommended)

The LineageOS package writes `system`, `vendor` and `boot` only. Back those three up
before flashing, then a rollback is a restore of the same three.

From TWRP, either use **Backup** and select Boot, System and Vendor, or dump them directly:

```sh
# in TWRP, with the SD card mounted
dd if=/dev/block/by-name/boot    of=/external_sd/backup/boot.img
dd if=/dev/block/by-name/system  of=/external_sd/backup/system.img
dd if=/dev/block/by-name/vendor  of=/external_sd/backup/vendor.img
```

Restoring is the same three commands with `if` and `of` swapped. Size check: system is
3,632 MiB and vendor is 400 MiB, so allow 4.1 GB on the card.

Record the hashes of the three images when you take them, so a later restore can be
verified against the backup rather than against memory.

Also worth dumping once, read-only, for reference rather than for routine restore:
`lk`, `tee1`, `tee2`, `preloader` and `misc`. Keep them labelled with the firmware
version they came from.

### Tier B: trimmed stock package (no backup available)

If the pre-flash backup is missing, restore only system, vendor and boot from a stock OTA by
rebuilding the package with a trimmed script. `make-rollback-zip.py` does this:

```
python stage6-lineage/make-rollback-zip.py \
    --stock OTAs/update-kindle-Fire_HD10-PS7331_user_4463_0031575863172.bin \
    --out D:/lineage-artifacts/rollback-ps7331-system-vendor-boot.zip

# review the generated edify before spending a 1.2 GB repack
python stage6-lineage/make-rollback-zip.py --stock <ota> --dry-run
```

The trimmed script keeps the device assert, drops the build-date check, and keeps only the
system, vendor and boot writes. Everything else in the package is copied through unchanged,
including Amazon's `update-binary`, which is what implements `block_image_update`.

The result is unsigned, so TWRP's zip signature verification must be off. The trade is
deliberate: a package that cannot touch the preloader is worth more than a valid signature.

### Tier C: full stock restore

Running the untouched stock package is a deliberate return to stock, and it rewrites the
preloader, both TEE slots and the LK. Do it only when that is the intent, with the package
matching the unit's firmware family, and with a charger attached. Treat the preloader write
as the point of no return it is.

## 3. Verifying a rollback before trusting it

1. Compare the restored `boot`, `system` and `vendor` hashes against the recorded backup.
2. Boot to system, then `getprop ro.build.version.name` should report the stock version
   again (for example `PS7331.4463N`).
3. Confirm TWRP is still installed (`adb reboot recovery`).
4. Confirm the unlock survived: reboot to the hacked fastboot and check that `fastboot`
   accepts a command it refused while locked.

## 4. What this changes in the plan

The plan's rollback paragraph said to flash a stock OTA. That instruction is withdrawn:
the package writes the preloader. The install runbook now requires a Tier A backup as a
preflight gate, and the plan's P0 section is updated to match.
