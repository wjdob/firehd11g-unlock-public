# Brick Analysis: Fire HD 10 (trona/MT8183)

Why this device is uniquely unforgiving, and what the documented failures teach.

> **Status (2026-10-06): partly superseded.** Two claims below written before the
> unlock mechanism was reversed are now known to be **wrong or incomplete**, and are
> corrected inline:
>
> * the XDA "IDME `flash:unlock` flag" theory is **wrong**: no such field exists. The
>   real mechanism is an **Amazon-signed `unlock_code`** verified by RSA-2048-PSS
>   against an embedded Amazon public key, in both the preloader and LK. See
>   [../stage2-unlock/README.md](../stage2-unlock/README.md).
> * "no software transport to restore it" is **too broad**: recovery depends on which
>   partition is damaged (**S1 recoverable, S2/S3/S4 not**), and even for S1 the route is
>   recovery + a newer OTA rather than fastboot, see the recovery matrix in
>   [../stage3-recovery/README.md](../stage3-recovery/README.md#0-read-this-first-the-recovery-matrix).

## The hardware situation

| Escape hatch | Status on this device | Evidence |
|---|---|---|
| MediaTek BootROM (BROM) download mode | **patched shut at factory** | Eric Pardee's research on a 2021-manufacture unit (LOT 8S132): BROM DL entry disabled, volume-button BROM entry blocked (boots recovery instead), preloader crash rejected with `0x1d18` |
| `mtk-su` (alephsecurity) | patched | pre-2021 MTK exploit, closed by Amazon |
| EDL / Qualcomm-style rescue | N/A | MT8183 is MediaTek; no equivalent mode |
| Ammonet-style short-pin (2017/2019 Fires) | not applicable | those SoCs (MT8163/8173) had working BROM; MT8183 does not |

**Consequence:** recovery depends entirely on *which* partition is damaged, and the
chain gets less forgiving the earlier you go:

| damage | recovery |
|---|---|
| `boot` bad (chain otherwise intact) | **recoverable**: recovery mode + a newer OTA (**not** fastboot: see below) |
| `lk` fails preloader validation | **not** recoverable in place; re-enumeration loop only |
| `preloader` / eMMC unreadable | hardware (eMMC ISP) only |

So `tee1/2`, `sspm_1`, `spmfw`, `cam_vpu*` and **`lk`** must be treated as one-shot. A
complete backup does not make experimenting with those safe, because there is no
transport that can write them back.

**Note on the `boot` row.** LK fastboot is reachable (proven 2026-10-06), but the device
is *locked*, and the locked-device gate refuses **every** write-class command at command
dispatch(before partition lookup) not just `flash`. So `fastboot flash boot` is not a
repair path here. The route that works is recovery mode applying a **newer** OTA
(the PS7319/1726 OTA will not apply to a 1735 device: its guard is
`!less_than_int(1619231913, ro.build.date.utc)` and the device reports `1622314026`).

## Documented failure: the XDA LK patch brick (Sept 2026)

From the XDA brainstorming thread (post #123, user BluPhant):

1. Achieved uid=0 via SnuSnuRoot (userland chain, worked fine).
2. Dumped `lk` (1 MB bootloader) via root: `dd if=/dev/block/mmcblk0p6`.
3. Reverse-engineered the IDME unlock check: `amzn_verify_unlock` @ LK offset
   `0x4b254`, gated by the `flash:unlock` flag in the IDME database.
4. Patched LK to force `amzn_verify_unlock()` to return success:
   `mov r0, #1; bx lr` at offset `0x4abe8`.
5. Flashed the patched LK back via root. **Device never booted again**, 
   USB connect/disconnect loop every ~3 s (preloader repeatedly failing LK
   validation and resetting).

A second user (GuestyMC) independently confirmed: *"Patching the BL just sends it
to preloader hell for some reason."*

### Why it failed

The preloader validates LK before handing off. The patched LK no longer matched
whatever integrity check the preloader enforces (signature/hash/anti-rollback, 
exact mechanism still unreversed). The result is a preloader→LK validation loop
with no recovery path.

### Lessons

- **Root does not confer the ability to write boot partitions safely.** uid=0 can
  write the raw block device; nothing validates the write is *acceptable* to the
  earlier boot stages.
- **The preloader is the trust root, and it is not writable.** Any LK modification
  must survive preloader validation, and that path *has* since been reverse-engineered:
  the preloader verifies LK's RSA-2048-PSS signature over `LK[0x200:-0x100)`, with the
  0x200-byte container header deliberately outside the signed extent. See
  [../stage2-unlock/verify-lk-signature.py](../stage2-unlock/verify-lk-signature.py).
- **CORRECTED; the unlock mechanism is not an IDME flag.** The XDA "IDME
  `flash:unlock` flag" theory is **wrong**; no such field exists. The real mechanism is
  an **Amazon-signed `unlock_code`** (RSA-2048-PSS) stored in the IDME database on eMMC
  boot1, verified against an embedded Amazon public key by *both* the preloader and LK.
  An unlocked device accepts an LK image signed by the production key or by the
  alternate key; a locked device that fails PSS verification is rejected by the
  preloader, which is precisely the XDA brick below.
  Forging the code is infeasible without Amazon's private key. Full analysis:
  [../stage2-unlock/README.md](../stage2-unlock/README.md).
- **Does LK (or ATF) re-verify later images?** Unresolved, and now known to be
  **unanswerable offline**: the ATF/TEE bodies are encrypted (2.8 MB at exactly 8.000
  bits/byte) and decryption uses MediaTek's hardware crypto engine with efuse-derived
  keys, which are reachable only over BROM, and BROM is unavailable on this unit.
  Recorded so the question is not re-attempted; see the "Open questions closed" §C in
  [../stage2-unlock/README.md](../stage2-unlock/README.md).

## Documented failure: GhostLock "verified offsets" (Sept 2026)

XDA user BluPhant submitted Fire HD 10 offsets to the GhostLock project
([PR #48](https://github.com/JoinChang/ghostlock-oneplus/pull/48)) claiming
"verified 100% correct via live device testing" for CVE-2026-43499 on kernel
4.4.146. The maintainer **closed the PR** with evidence the offsets were
fabricated:

- CVE-2026-43499 is a race in `rt_mutex_wait_proxy_lock` /
  `__rt_mutex_cleanup_proxy_lock`, **introduced in kernel 5.7**. Kernel 4.4 uses
  the older, safe `rt_mutex_finish_proxy_lock` path. The vulnerable functions
  do not exist in 4.4.
  **Confirmed from the vendor source** (not just from the version number):
  grep of `refs/kernel-7.3.1.9/` (`VERSION=4 PATCHLEVEL=4 SUBLEVEL=146`, the
  running kernel) finds both vulnerable symbols **absent** and
  `rt_mutex_finish_proxy_lock` present, called at `kernel/futex.c:2930`. In 4.4
  that function performs the wait *and* `remove_waiter()` under a single
  `wait_lock` hold, so the split-function window the CVE needs does not exist.
  Full analysis, including why GhostLock's BTF-based tooling also cannot target
  4.4, in
  [../stage2-unlock/README.md](../stage2-unlock/README.md#ghostlock-assessment-cve-2026-43499--not-feasible-and-not-useful).
- All submitted offsets were round-aligned (`0x01800000`, `0x01810000`, ...) and
  ashmem function offsets were 4 bytes apart, impossible for real kernel
  functions.
- **Quantified here** against this project's own measured values: the claimed
  `off_selinux_enforcing = 0x01D00000` versus the true `0x018F1668` for the build
  the PR names; an error of **4.06 MiB** (offset convention) or **3.56 MiB**
  (physical convention), so the table is wrong under either reading. The claimed
  `kernel_phys_load = 0x40000000` is likewise wrong; the true value is
  `0x40080000`, derivable from this project's own `selinux_enforcing` VA for
  PS7326 (`0xffffff8009969668`) plus Eric Pardee's ground-truth PA
  (`0x41969668`).
- **The PR could not have been compiled.** It deleted the
  `STRUCT_OFFSETS_6_12 / 6_6 / 6_1 / 5_10` macros that the other 12 device entries
  reference (`ace6t` and `findx9pro` use `6_12`, `op13` uses `6_6`,
  `xperia1iv` uses `5_10`), together with the struct members those macros assign
  (`mm_owner`, `waiter_compact`, `kimage_text_base`, all `fops_*`). That is the
  cheapest possible falsification of "verified on device": a patch that does not
  build was not tested.
- It also names the wrong device build: the PR declares `PS7331.4463N`, while the
  reference unit runs **PS7319/1735**, and `selinux_enforcing` provably differs
  between those builds by `0xC040`. Even entirely genuine values would be wrong
  for this unit.

Full validation, section by section, in
[../stage2-unlock/README.md](../stage2-unlock/README.md#6-pr-48-validation--the-maintainers-rebuttal-confirmed-and-extended).

**Lesson:** forum-claimed "verified" offsets are not evidence. This repository
only trusts offsets derived from the actual kernel binary or resolved at runtime.

## Risk classification (this device)

| Operation | Assessment |
|---|---|
| Read/dump partitions (rooted) | Safe |
| Query fastboot variables | Safe |
| Userland root chain (SnuSnuRoot) | Low risk; no boot writes, per-boot reversible |
| Persistent root (stage 4) | Low risk; adds only files under `/data`; no boot/recovery/system/vendor write; `--remove` + reboot reverts |
| Mali kernel exploit (CVE-2022-38181) | Medium; ~50% kernel-panic race per attempt, each costs a reboot; no permanent damage observed |
| `fastboot flashing unlock` | Refused (`restricted on locked hw`); the gate blocks every `oem` command, so this cannot run even accidentally. Unlock requires an Amazon-signed `unlock_code` |
| Write `lk` | **Extreme; documented brick** |
| Write `preloader` | **Extreme; certain brick, no recovery** |
| Write `tee*`, `sspm_1`, `spmfw`, `cam_vpu*` | **Extreme; boot-critical** |
| Write `boot` | **High**: AVB rejects a bad image, and on a *locked* device `fastboot flash boot` is refused, so recovery is via recovery mode + a newer OTA. Recoverable, but not from fastboot |
| Erase/write `seccfg` experimentally | High; the partition does not exist on this device (see stage2 unlock assessment) |
| Downgrade Fire OS | Anti-rollback is **not enforced** on LK (proven), but the OTA guard still blocks older builds; do not |
