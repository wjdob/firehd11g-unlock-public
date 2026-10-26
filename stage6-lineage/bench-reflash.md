# Bench reflash handoff: recovering the trona unit

**Status:** the tablet loops because `misc` holds `boot-recovery` and `recovery` holds TWRP,
which this unit's LK refuses. Every software write path is closed, so this page gives the
exact hardware procedure and the exact bytes. Give it to whoever has a programmer.

## What is wrong, in one line

The Bootloader Control Block at the start of `misc` says `boot-recovery`, and the LK
re-reads it every boot. Recovery cannot start, so the LK loops. Clearing that command makes
the LK boot the intact `boot` partition again, and Android comes back.

## The minimal fix

Write zeros to the **first 32 bytes** of the `misc` partition (the BCB `command` field),
or zero the whole 1 MiB partition. Both are correct.

**Do not restore the `misc.img` backup wholesale.** Its `command` field held
`bootonce-bootloader` (a leftover from an earlier `adb reboot bootloader`), so flashing it
as-is would boot fastboot rather than Android. The backup is a reference, not the fix.

| item | value |
|---|---|
| partition | `misc` |
| GPT entry | LBA 20544 .. 22591, size 1.0 MiB, first byte 0x00A08000 |
| bytes to zero | offset 0, length 32 (the `command` field), or the whole 1 MiB |
| whole-partition zero hash | 1 MiB of zeros, SHA-256 `30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58` |

`recovery` also needs restoring, and it is not optional. It currently holds TWRP (kernel
size 10,247,597, the 4.4.302-lineage build), which the LK refuses. Clearing `misc` makes
Android boot, but the first `adb reboot recovery` or OTA-triggered recovery would loop the
tablet again. The backup `recovery.img` is the stock image (kernel size 9,812,312, matching
`boot.img`):

| partition | LBA | size | restore from |
|---|---|---|---|
| `recovery` | 325696 .. 409599 | 41.0 MiB | `recovery.img` in the backup |

## Backups (off-device, hashed)

`D:/lineage-artifacts/backup-1735`:

| file | bytes | SHA-256 (first 32) |
|---|---|---|
| misc.img | 1,048,576 | 9017E7C77C741C3C30AFC26ECB51C768 |
| recovery.img | 42,958,848 | 9921583B4E5E856294BC2BF0B51D4FE9 |
| boot.img | 33,554,432 | FA9EAA4238E3ACED79236166734F4308 |
| lk.img | 1,048,576 | C002D4D6614CE68EC56EB73329B2B0BA |
| preloader.img | 4,194,304 | 376340889195A2F3B35A85E459B49E9B |
| tee1.img | 5,242,880 | 21192358B5E24EDF97695BA276B54FE8 |
| tee2.img | 5,242,880 | 21192358B5E24EDF97695BA276B54FE8 |

## Procedure, eMMC ISP (the dependable route)

1. Open the back cover and disconnect the battery flex.
2. Locate the eMMC (BGA) on the board, or its in-system programming pads.
3. Connect an eMMC ISP programmer: UFi Box, Medusa Pro, Easy JTAG with an eMMC ISP adapter,
   or desolder the eMMC and read it in a socket adapter.
4. Read the GPT (header at LBA 1, entries at LBA 2..33) and confirm `misc` is at LBA 20544.
5. Write 32 zero bytes at `misc` LBA 20544 offset 0. Optionally write `recovery.img` at
   LBA 325696.
6. Reassemble and boot. Root returns automatically (the stage 4 service), so the first
   Android boot is the verification.

## BROM route, and why it is not the recommendation

Forcing the SoC into BootROM download (`0e8d:0003`) and driving it with mtkclient plus the
kamakiri BROM payload would also give eMMC access. On this model the factory has patched
that entry on the reference lot: Eric Pardee's work on a 2021-manufacture unit records BROM
download entry disabled, volume-button BROM entry blocked, and the preloader crash rejected.
The kamakiri BROM offsets for MT8183 are genuine (validated in
[../exploits/notes/kamakiri-mt8183-assessment.md](../exploits/notes/kamakiri-mt8183-assessment.md)),
but they need a device that already enumerates as BROM, and this one does not. Eric Pardee's
handoff records the same on a 2021-manufacture LOT 8S132 unit: bootrom download entry patched
shut, volume-button BROM blocked, and the preloader crash rejected. If a bench technician can
force BROM on this specific board, mtkclient plus that payload is the software side and the
fix is the same two writes above.

## Why no software-only route

Each software transport is closed, and the repository plus live measurements agree:

| route | verdict | evidence |
|---|---|---|
| BROM download | factory-patched on the tested lot | [brick-analysis.md](../docs/brick-analysis.md) |
| preloader DA | fuse-gated, dead loop | SEC_CFG bit 2; observed no ack plus reset |
| preloader usbdl | stripped, DA-gated | [stage2-unlock/README.md](../stage2-unlock/README.md) |
| fastboot writes | denied while locked | static deny list; proven live 2026-10-06 |
| recovery clears BCB | recovery is unsigned TWRP, LK refuses it | this session |

The preloader's `READY` and `METAMETA`/\`ADVEMETA\`/\`METAFORB\` strings are the factory
META boot-mode switch, not a flash-write transport.

## Offsets verified against the backups

LBA arithmetic confirmed: `misc` LBA 20544 times 512 equals 0x00A08000 (the GPT first byte),
and `recovery` LBA 325696 times 512 equals 0x09F08000. `recovery.img` is the stock image
(`ANDROID!` magic, full 41 MiB partition).

## Verification after reflash

1. Tablet reaches the Fire OS launcher.
2. `adb shell getprop ro.boot.verifiedbootstate` reads `green`.
3. `adb shell getprop ro.build.version.name` reads `Fire OS 7.3.1.9 (PS7319/1735)`.
4. `adb reboot recovery` enters the stock recovery, proving the restore is complete.
