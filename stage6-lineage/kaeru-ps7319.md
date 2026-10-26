# Adapting the unlock to PS7319 (0x0106): kaeru, the fuse gate, and a safer test

Question asked: can the repository and the live device adapt the bootloader unlock to this
unit, which is PS7319 (0x0106) rather than the PS7331 (0x010A) the release targets. Answer
with measurements, then the plan that follows from them.

## 1. kaeru already has a trona target, and it is PS7331-only

`refs/kaeru` (cloned from R0rt1z2/kaeru) ships:

* `configs/amazon/trona_defconfig`
* `board/amazon/include/mt8183-trona.h`
* `board/amazon/board-mt8183-common.c`

Those files carry about 64 hard-coded addresses and sizes, from
`FB_CMD_FLASH_FUNC_ADDR 0x56035A14` to `CONFIG_BOOTLOADER_SIZE=0x96910`. kaeru's README
says offsets are specific to the device **and bootloader version**, so the question was
whether they hold for our 0x0106 LK.

They do not. Comparing the 16 bytes at each address in the PS7319 LK against the PS7331 LK:

```
addresses collected: 64
identical code at address: 0   different: 60   beyond image (BSS): 4
```

Even the branch table at `0x56000000` differs from the fourth instruction. A PS7319 kaeru
is therefore a **re-derivation of the whole table**, not a config change. That is real work,
though bounded, because most entries can be found by pattern or by the strings they print.

## 2. The LK carries the same fuse gate as the preloader

The PS7319 LK contains, at the same kind of site as the preloader:

```
0x560776F0  [%s][%s] Error: secure SoC should run signed %s
0x56077521  [%s][%s] non secure SoC run with unsigned %s
```

and the boot path logs `amzn_image_verify: boot image` and
`amzn_image_verify: recovery image` from code at `0x56012F0A` and `0x56013346`
(resolved with `exploits/tools/lk_xrefmap.py`). So the LK decides whether to demand a
signature on a boot or recovery image using the **same secure-SoC condition** that the
preloader uses for the LK itself.

That has a large consequence. If this unit reads as non-secure, the **stock, signed LK
already boots an unsigned recovery and an unsigned boot image**. kaeru is not what makes a
custom ROM boot in that case; kaeru is what provides the unlocked fastboot interface and the
key remapping. The unlock and the ROM install are two separable problems, and the fuse bit
decides both.

The two gate strings have no resolved code reference in the pc-relative map, which sweeps
Thumb only. Locating them exactly is the next piece of work and is not needed for the test
below.

## 3. A safer classifier than patching LK

The earlier plan was: patch an LK for PS7319, then write it. That risks an unbootable boot
chain for a question that can be answered with a partition the device does not need to boot.

**Recovery swap test.**

1. Back up `recovery` (32 MiB) through the root shell, alongside the six partitions already
   saved.
2. Write the shipped `twrp.img` to `recovery`.
3. Set `misc` to `boot-recovery`.
4. Reboot and watch for ADB in recovery.

Outcomes:

| result | meaning | next step |
|---|---|---|
| TWRP answers on adb | the LK accepted an unsigned recovery, so the unit is non-secure | flash the ROM from TWRP; no kaeru, no preloader, no LK write |
| boot continues to Fire OS | the LK rejected the image and fell back | restore `recovery` from the backup, then use the DA test |
| nothing boots | the LK refuses to continue after a bad recovery | restore `recovery` through the root shell if it is still reachable; otherwise the serial path |

The write touches `recovery` and two bytes of `misc`, both backed up, and leaves
`lk`, `preloader`, `tee` and `boot` alone. That is strictly less invasive than the unlock
release, which also rewrites `tee1`, `sspm`, `spmfw` and the camera firmware.

## 4. What is still a real blocker

**The fuse bit.** Everything above branches on it, and it cannot be read from Android.
Two properties of the gate are now established: the preloader uses bit 1 of `0x11F10060`
for unsigned images and bit 2 for Download Agent validation, and the LK mirrors the image
side of that decision. If bit 1 is set, the recovery swap fails and no LK patch helps; if it
is clear, the swap succeeds and the unlock's LK work is optional.

Nothing else is a blocker:

* **kaeru addresses** are work, not a wall, and they may not be needed at all.
* **The packed `unlock` binary** is bypassed: we have uid 0 and can perform the writes.
* **TEE version** is irrelevant if we keep the unit's own TEE.
* **Anti-rollback** is ordered in RPMB, and staying on PS7319 avoids moving it.

## 5. Order of work from here

1. Back up `recovery` (32 MiB).
2. Recovery swap test, fully reversible.
3. If it passes: flash LineageOS from TWRP and run the validation matrix.
4. If it fails: restore `recovery`, then classify the fuse with the preloader DA test before
   considering any boot-chain write.
5. kaeru re-derivation only becomes necessary if the device is non-secure and we want the
   unlocked fastboot interface itself.
