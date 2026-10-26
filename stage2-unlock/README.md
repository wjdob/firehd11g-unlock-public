# Stage 2: Bootloader Unlock (research only)

## TL;DR: read this first

**There is no bootloader unlock for this device, and there is no prospect of one.**
This document is the evidence for that conclusion. If you came looking for a method,
the honest answer is that it does not exist.

- **Core finding**: the unlock mechanism is an **Amazon-signed `unlock_code`**
  (RSA-2048-PSS) stored in the IDME database. Both the preloader **and** LK verify it
  against an Amazon public key embedded in each. An unlocked device skips LK
  verification entirely; a locked device that fails PSS verification is rejected by the
  preloader, which is the exact cause of the documented XDA brick.
- **Core finding**: this **corrects the widely repeated "IDME `flash:unlock` flag"
  theory**: no such field exists.
- **Core win**: the mechanism, the precise brick cause, the legitimate request flow,
  and the signature boundaries of the shipped images are all established and
  reproducible offline. That is what makes the negative result trustworthy rather than
  a guess, and it is why no speculative write was ever needed.
- **Core dead end**: forging the code requires **Amazon's private key**. The barrier is
  cryptographic, not a privilege check, so no kernel exploit, root, or recovery route
  reaches it. Every external technique surveyed fails here for the same reason
  (the Fire Max 11 exploits do not transfer: this unit's BROM is patched shut and its
  DA-auth path is live).
- **Also dead**: the ATF/TEE vector is **unverifiable offline**: those images are
  encrypted with efuse-derived keys reachable only over BROM.
- **Not established**: "every possible software bypass has been excluded". What *is*
  established is that no *usable* one has been demonstrated, and that the analysed
  paths are closed. See the claim table below before quoting anything in this file.

The detailed TL;DR, the claim-status table, and the full analysis follow. Everything
below is organised so the negative results are checkable, not merely asserted.

**Update (2026-10-06), container-header audit.** The top-priority open lead
from [vectorResearch.MD](vectorResearch.MD) §3, *what the preloader does with
the leading 512-byte LK container header before it authenticates the signed
payload*, is now answered against the **installed** bootloaders and verified
cryptographically. See
[Container-header audit](#container-header-audit--pre-authentication-load-path-2026-10-06).
Answer in one line: the header **is** outside the signature (now proven, not
inferred), it supplies the **length** of the pre-authentication copy, and that
copy happens **before** any signature check; a real pre-auth write primitive
of the Koboreru / CVE-2023-20695 class.

**Update (2026-10-06), live-device session.** With tethered root on the
reference device the DRAM map was collected read-only (no boot/system/vendor
writes) and the preloader's own memory located. Result: the primitive is
*larger* than the LK window (the flash read is bounded by the card, not by the
1 MiB `lk` partition), but the preloader's working set is `g_dram_buf` at
`0x44800000`(**below** the window) so the obvious hijack target is out of
reach. The only identified structure above the window is the MTK context slot
at `0x5f100c00`. See [Live DRAM map](#live-dram-map-2026-10-06) and
[../diagnostics/dram-map-1735.txt](../diagnostics/dram-map-1735.txt).

**Update (2026-10-06), branch/tracer analysis.** The `0x5F100C00` question is
answered and the vector is **closed**: the slot is on the normal boot path
(PICACHU DVFS module, invoked once at 0x19fcc with workspace base 0x5F000000)
but it is written *after* the LK read, its workspace is written before it is
read, and an enlarged copy cannot keep a valid signature, so the failure mode
is the known brick, not a hijack. See
[Branch/tracer analysis](#branchtracer-analysis--the-0x5f100c00-context-slot-2026-10-06).

**Update (2026-10-06), preloader USB audit.** The last open lead from
vectorResearch.MD §5 is done. The USB surface is the *best-hardened* part of
this bootloader: fixed destinations, explicit numeric guards, gated DA entry.
Two defects found, `SEND_DA` copies with a host-supplied length *before*
checking it (the CVE-2022-20055/56/58/59 class; reach is not distance-limited
but no useful consumed target was identified), and an unchecked
`total − sig_len` subtraction (CVE-2022-20073 candidate, no bypass shown). See
[Preloader USB audit](#preloader-usb-audit-2026-10-06).

**Update (2026-10-06), LK certificate/DER audit + live fastboot test.** The
certificate path is **stock LibTomCrypt**, not Amazon-authored code
(`der_decode_sequence_flexi` 0xa06c, `der_length_sequence` 0xaa50,
`der_encode_sequence_ex` 0xa69c), and the 19 type-handler pairs were compared:
dispatch domains identical, length-of-length boundaries agree, every asymmetry in
the safe direction. **No DER length/encode mismatch found ⇒ vector V1 has no
identified bug.** Separately, a live test proved **LK fastboot is reachable**
(`adb reboot bootloader` → USB `VID_1949:PID_05E0`, interface class
`0xFF/0x42/0x03` = fastboot), which makes the S1 recovery route real. See
[LibTomCrypt dependency audit](#libtomcrypt-dependency-audit-offline-2026-10-06)
and [stage3-recovery](../stage3-recovery/README.md).

**Update (2026-10-06), extended bypass analysis.** A widening pass (requested)
produced three results: (1) the load/verify matrix is now **complete and fully
paired**: every image is verified, closing the "unverified load" question;
(2) LK authenticates its images with **certificate chains** (two embedded roots,
`amzn_image_verify` 0x1238, prod/eng selected by 0x1218), not raw keys; (3) a
**new attack surface**: LK's hand-rolled certificate parser (0x14b0), the
CVE-2023-20696 class. Five candidate vectors (V1–V5) are tabulated with their
blockers; none is exploitable without either an eng-signed image, a GPT write,
or a destructive experiment on `boot`. See
[Extended bypass analysis](#extended-bypass-analysis--new-surfaces-2026-10-06).
Read-only device diagnostics were run (IDME field inventory, boot properties,
`force_ro` state, `kb`/`dkb`/`keys`/`misc` partition contents), no writes.
**The minimum-key conclusion stands; the residual risk is now localized to the
certificate parser.**

**Update (2026-10-06), vectorResearch2 evaluation.** The follow-up research's
central claim is **confirmed on this project's own images**: in `tee.img` the
`atf_dram` sub-image has a *copy* length taken from the unsigned outer container
while its *authenticated* length comes from the inner header (`inner[0x08] +
inner[0x18]`), with no equality check, and it loads **after** LK has been
verified, 26 MiB below it. See
[ATF_DRAM: copy length ≠ authenticated length](#atf_dram-copy-length--authenticated-length-2026-10-06).
It is a real validation-order defect, but exploiting it needs `tee1` +
`metadata` writes with an unrecoverable failure mode, so it does not change the
bottom line. The document also caught several arithmetic and scoping errors in
this file; those are corrected in
[§ Corrections](#5-corrections-adopted-from-vectorresearch2md).
**The "no safe unlock" conclusion stands.**

## TL;DR

The XDA "IDME `flash:unlock` flag" theory was **wrong**. The real mechanism is
an **Amazon-signed `unlock_code`** stored in the IDME database. Both the
preloader and LK verify it with RSA-2048-PSS against an Amazon public key
embedded in both bootloaders. An unlock **cannot be forged** without Amazon's
private key, but once a device IS unlocked, the preloader **skips LK
signature verification entirely**, which is why the XDA LK patch bricked:
patched LK + locked device = preloader rejects = boot loop with no BROM escape.

### Claim status (read this before quoting anything below)

| claim | status |
|---|---|
| The intended IDME unlock mechanism requires an accepted Amazon signature | **Established** (mechanism reversed) |
| Stock image signature boundaries and verifying keys identified | **Reproduced independently** |
| The analysed images match the device dumps | **Verified** (image-extent comparison) |
| The preloader path contains no second LK verification | **Established for the preloader path only** |
| Every preloader-loaded image is verified | **Established** (call-site enumeration) |
| A usable software bypass has been demonstrated | **No** |
| Validation requiring boot-critical writes is permitted by this project | **No** (deliberate constraint) |
| **Every possible software bypass has been excluded** | **Not established** |

The last row matters: this project has shown the *intended* mechanism is
cryptographic and that generic published techniques do not transfer; it has
**not** proven that no software bypass exists. Unaudited surfaces remain: LK's
hand-rolled certificate parser ([Extended bypass analysis](#extended-bypass-analysis--new-surfaces-2026-10-06) §3),
the ATF stage after handoff, and the BROM itself (unobservable from this
firmware, see [stage3-recovery](../stage3-recovery/README.md)). Statements
below that read as categorical should be read through this table.

## The boot chain (proven from dumps)

```
masked ROM
  → preloader (mmcblk0boot0, EMMC_BOOT header)
      1. loads the LK *payload* from mmcblk0p5 to RAM 0x56000000, device read
         starts 0x200 bytes in (the container header is consumed, not copied)
         and the length comes from the header's size word (hdr[4])
      2. finds '_LK_VER:' at (base + size - 0x10a); sig = last 0x100 bytes
      3. RSA-2048-PSS verify (SHA-256 over LK[0x200:size-0x100), prod image key
         @ preloader 0x37b98, NOT the unlock key)
      4. if verify FAILS → checks the unlock state (AMZN_UNLOCK):
           - reads IDME 'unlock_code' + 'unlock_version'
           - composes expected code, PSS-verifies the stored unlock_code
           - if UNLOCKED → re-verifies with the alt image key 0x37a98 (0x2d86) and
             rejects on failure
           - if LOCKED → "Only try verify with prod key on locked
             production device" → REJECT → 3-second USB re-enumeration loop
  → LK (mmcblk0p5, loads at VA 0x56000000, ARM32 vectors + Thumb-2 code)
      5. at boot: is_unlocked() = amzn_verify_unlock(unlock_code from IDME)
         OR amzn_verify_temp_unlock_code(tucode/tucert)
      6. prints "UNLOCK STATUS: device is locked/unlocked"
      7. sets androidboot.unlocked_kernel=true/false
      8. fastboot exposes: flash:unlock, flash:tucert, flash:tucode,
         getvar:unlock_code, getvar:unlock_status, oem relock, oem flags
```

## The unlock mechanism (fully reversed)

### IDME database (mmcblk0boot1, magic `beefdeed2.1`)

The IDME lives in **eMMC boot partition 1**: 35 fields, including:

| Field | Offset | Size | This device's value |
|---|---|---|---|
| `serial` | 0x3c | 16 | `<SERIAL>` |
| `unlock_code` | 0x4ec | 1024 | **empty (locked)** |
| `unlock_version` | 0x2afc | 8 | `5fc171a088b05201` |
| `t_unlock_code` | 0x2b20 | 512 | empty |
| `t_unlock_cert` | 0x2d3c | 1024 | empty |
| `dev_flags`/`fos_flags`/`usr_flags` | 0x2274+ | 8 each | `0` |

Parser: [tools/idme-parse.py](../tools/idme-parse.py) (entry format:
name[16] + len[4] + count[4] + type[4] + value[len], 4-byte aligned).

### The unlock flow (LK fastboot command `flash:unlock <blob>`)

1. LK handler (file offset 0xe656): requires arg length > 0xff, calls
   `amzn_verify_unlock(data, 0x100)` (0x1ce0).
2. `amzn_verify_unlock`: gets the unlock key (RSA-2048 SPKI at LK 0x4bab8),
   gets the unlock code, RSA-verifies (`amzn_verify_code_internal`, 0x1ba8, 
   libtomcrypt `rsa_import` + hash + `rsa_verify`).
3. On success: writes the blob to IDME `unlock_code` ("correct signature,
   but update idme failed" if the IDME write fails).
4. On failure: "unlock signature verify failed, do nothing!", **no state
   change; the command is fail-safe.**

The expected unlock code is composed by the preloader (0x3472): `'0x' +
hex(12 bytes)` where the 12 bytes derive from `unlock_version` + device data
(26 chars total, NUL at [0x1a]). The signature is RSA-2048-PSS over that
composed string, verified against the Amazon unlock public key.

### Temporary unlock (`flash:tucert` / `flash:tucode`)

A separate mechanism: `t_unlock_cert` + `t_unlock_code` in IDME, verified with
a **different key** (LK 0x4bcd0, "Device is temporarily unlocked, %d reboots
remaining"). Also Amazon-signed; also not forgeable.

## Key material (extracted)

The preloader holds **three consecutive 256-byte RSA-2048 moduli** (raw, no DER
wrapper). They are distinct keys with distinct jobs; the earlier "one key
does everything" note was wrong:

| Key | Location | Role |
|---|---|---|
| Image-verify, alternate | preloader 0x37a98 (getter 0x2b24) | 2nd verify attempt (0x2d86), tried only when the device is *not* a locked production device |
| Image-verify, prod | preloader 0x37b98 (getter 0x2b30) | **verifies the LK image** (1st attempt 0x2d22 → AMZN_PL_VERIFY 0x2b48) |
| Amazon unlock pubk (RSA-2048 SPKI) | LK 0x4bab8 = preloader 0x37c98 (getter 0x2b3c); **same key** | `unlock_code` verify (LK) + unlock verify (preloader); temp-unlock is a 4th key |
| Temp-unlock pubk | LK 0x4bcd0 | tucert/tucode verify |
| "Common Kernel Signing Production CA" cert | LK 0x4746c | boot image chain |
| "Common Kernel Signing Engineering CA" cert | LK 0x479c4 | eng devices |

Artifacts: [unlock-pubkey.der](unlock-pubkey.der),
[pl-image-verify-pubkey-modulus.bin](pl-image-verify-pubkey-modulus.bin) (0x37b98,
verifies LK), [pl-image-verify-alt-pubkey-modulus.bin](pl-image-verify-alt-pubkey-modulus.bin)
(0x37a98), [pl-unlock-pubkey-modulus.bin](pl-unlock-pubkey-modulus.bin) (0x37c98),
[lk-prod-ca-cert.der](lk-prod-ca-cert.der), [lk-eng-ca-cert.der](lk-eng-ca-cert.der),
[temp-unlock-pubkey.der](temp-unlock-pubkey.der).

> Artifact correction: the file previously shipped as
> `pl-lk-verify-pubkey-modulus.bin` was the **unlock** modulus (0x37c98), so it
> cannot verify LK. It was replaced by the three correctly-named files above.
> Verified by [verify-lk-signature.py](verify-lk-signature.py).

## Why the XDA LK patch bricked (proven)

The preloader's LK loader (0x2c60–0x2d8e):

1. PSS-verifies the LK image (data = everything except the last 0x100 bytes;
   the `_LK_VER:` tag sits just before the signature).
2. **If verification fails, it consults the unlock state.** Locked → reject
   → the observed 3-second USB re-enumeration loop. Unlocked → accept.
3. BROM is factory-patched shut on 2021 units → a rejected LK is
   **unrecoverable by software**.

So: patching LK on a locked device is a guaranteed brick, exactly as the XDA
report described. The preloader does NOT have a "flash:unlock flag" bypass, 
that flag does not exist in this firmware's IDME schema at all.

## What an unlock would actually require

1. **The legitimate path**: obtain a signed `unlock_code` from Amazon for this
   device's `unlock_version`. The request string is exactly what
   `fastboot getvar:unlock_code` returns (proven: the handler calls the same
   compose function the preloader uses, `'0x' + hex(id13) + hex(id12) +
   hex(unlock_version_dword)`, 26 chars). Amazon does not currently issue
   these for Fire tablets. If one were obtained: `fastboot flash:unlock
   <blob>` → verified → stored in IDME → preloader accepts any (even
   modified) LK → true unlock.
2. **No software bypass exists**: the unlock_code is RSA-2048-PSS-signed by
   Amazon; the pubk is in the preloader (not writable) and LK. IDME is
   writable as root, but writing an unsigned/garbage unlock_code changes
   nothing (verification fails → still locked; fail-safe).
3. **Writing IDME fields is low-risk** (it's a data partition the bootloaders
   re-read; malformed values are handled, "field name doesn't match",
   "magic number error" paths all exist), but pointless without a valid
   signature.

## Residual research: COMPLETE (2026-10-07)

All four residual items are now answered (offline RE, no device writes):

### 1. The exact composed unlock request ✅

Both bootloaders compose the **same 26-char string**:

```
'0x' + '%08x' % platform_id_13 + '%08x' % platform_id_12 + '%08x' % unlock_version_dword
```

- **LK** (compose fn @ 0xe43c, format string `'0x%08x%08x%08x'` @ 0x4bbde):
  calls platform-info getters `fn(13)` and `fn(12)` (0x11f70; a runtime
  platform-data table, .bss-initialized, so the values are **not statically
  extractable**), then the first dword of IDME `unlock_version`.
- **Preloader** (AMZN_UNLOCK @ 0x33e0): `fn(13)` → hex at buf+2, `fn(12)` →
  hex at buf+0xa, `unlock_version` → hex at buf+0x12 (hex-encode helper
  0x33a0; 26 chars + NUL at [0x1a]).
- This device's `unlock_version` first dword = **0xa071c15f** (IDME bytes
  `5f c1 71 a0 …`).
- Platform ids 12/13 come from a runtime table (preloader 0x2d5cc switch:
  id 0x1e reads SEC reg 0x11f10050, id 0x1d reads 0x11f107a0/0x11f107cc,
  id 0xa reads 0x56ab0004; ids 12/13 use a .bss table filled at boot).

### 2. `getvar:unlock_code` semantics ✅

**Yes; it returns the exact composed request string.** The handler
(LK 0xe5f0) calls the compose fn (0xe43c) and responds with
`unlock_code: <composed>`; `getvar:unlock_status` responds
`unlock_status: locked/unlocked` (via is_unlocked @ 0xe5a8). So the
legitimate flow is: boot to fastboot → `fastboot getvar:unlock_code` →
send the 26-char string to Amazon → receive the RSA-2048-PSS signature →
`fastboot flash:unlock <blob>`.

### 3. `usr_flags` / `dev_flags` / `fos_flags` effects ✅

The `oem flags` command (LK 0x4b8b4 region) can set **only `usr_flags` on a
locked device**. The boot-security-relevant bits live in the other two
fields, which are **not settable while locked**:

| Field | Bit | Effect (LK 0x2c150–0x2c22c) |
|---|---|---|
| `dev_flags` | 0x20 | `androidboot.selinux=permissive` ("set to permissive mode by dev_flags") |
| `dev_flags` | 0x40 | `androidboot.selinux=enforcing` ("enforced by dev_flags") |
| `fos_flags` | 0x80 | dm-verity off ("verify off by fos_flags") + vendor dm-verity disable path (0x2c240) |
| `fos_flags` | 0x04 | verity-mode selection (`androidboot.veritymode=eio/disabled`, 0x2c3d0) |
| `usr_flags` |; | **no boot-security effect found** (not consulted by the boot path) |

`usr_flags` is a user-scratch field, setting it changes nothing
boot-critical. The SELinux/dm-verity bits are gated behind the lock, as
expected.

### 4. Anti-rollback on LK ✅: NOT ENFORCED

The preloader reads the 2-byte version at `(lk_end − 0x102)` (just after
the `_LK_VER:` tag; ours = 0x0106) and **only logs it**: the orchestrator
(0x2d2a–0x2d4a) stores it to a stack slot that its caller (lk wrapper
0x2f58 → boot flow 0x19d62) never compares. There is **no minimum-version
check** on LK in this preloader build. The GFH_ANTI_INFO (0x848) carries
values (0x90, 0x1388) but no code path compares them against the LK
version. `bl_level=77` on the kernel cmdline is an Android/AVB artifact,
not a preloader gate. **An older *properly signed* LK would be accepted**, 
but no such LK exists outside Amazon, so this doesn't open a path.

## External techniques survey (amonet-sunstone / kaeru, Fire Max 11 MT8188)

Researched for transferability to trona/MT8183. **Verdict: none of the
sunstone entry techniques transfer**: the MT8183 preloader is hardened
where the MT8188's is not:

| Technique (sunstone) | Our preloader (proven by RE) | Transfers? |
|---|---|---|
| Preloader/BROM serial handshake (0xa0…), `send_da`/`jump_da` with **unsigned DA** (`sig_len=0`) | usbdl protocol **is present** (handshake handler 0x17d1c, command loop 0x5658, `usbdl_send_da`/`usbdl_jump_da` @ 0x592e), but DA auth is **enforced**: secure-chip check (0x2d5ac reads SEC_CFG 0x11f10060 bit 2; our production eFuse is secure) → RSA-2048 verify vs the **SBC key in hardware** (SEC key slots 0x11f10594/98, not extractable from the image). Unsigned DA → `SEC_AUTH_FAIL (0x7024)` → "USB Disconnect and Enter Dead Loop" (cmd 0x80 @ 0x599c; the exact 3-second brick loop). | ❌ |
| BROM WRITE32 (0xd4) / READ16 (0xa2) / WRITE16 (0xa1) arbitrary memory R/W | Present but **range-checked** (0x258e4 → 0x25874): reads allow only WDT (0x10007000+0x1000), 0x1001a080+4 (SRAMROM ctrl), SEC_CTRL (0x11f10000+0x1000); writes allow only WDT + 0x1001a080. No arbitrary write. | ❌ |
| Preloader payload with eMMC boot0/boot1/user switch + RPMB R/W + IDME R/W | Requires the DA path (signed) or the memory-write path (range-checked). Neither is open. | ❌ |
| `misc` "FASTBOOT_PLEASE" force-fastboot | Our LK has **no such misc command**: the only misc string checked is `boot-recovery` (0x2c028, reads 0x440 bytes, strcmp @ 0x2c07c → boot mode 2). Fastboot entry is: key combo (platform[0x5b4] bit 13, 0x29a5c), unlocked+mac-mismatch (0x113d0), META from preloader, or IDME-init-failure fallback. | ❌ (but `boot-recovery` via misc **is** root-writable and safe) |
| kaeru-patched LK accepted by preloader | MT8188's preloader evidently doesn't PSS-verify LK (or amonet's DA disables it). Ours **does** (proven, P4) and rejects on locked devices. | ❌ |

**Why sunstone works and trona doesn't**: the Fire Max 11 (MT8188) ships
with the DA-auth path effectively open (non-secure chip / unsigned DA
accepted, "DA validation disabled on non-secure chip" is the exact string
in our preloader at 0x3040b, reached only when the SEC bit is clear). The
2021 Fire HD 10 (MT8183) has the secure eFuse burned, so every sunstone
entry hits a wall. This is a hardware-generation difference, not a
software bug we can exploit.

**Positive takeaway**: the `misc`-partition `boot-recovery` command is a
safe, root-writable way to force a recovery boot on our device (LK reads
misc, strcmp `boot-recovery`, sets boot mode 2). Useful for future
recovery/ROM work, no bootloader unlock required.

> **See also: [../exploits/](../exploits/).** Two further public projects that target
> Amazon MTK bootloaders were examined and tested against this device's real images, 
> `amonet-koboreru` (a preloader exploit giving persistent EL3 code execution) and
> `kaeru` (LK patching, including a port to this platform's `maverick_defconfig`).
> **Neither applies**, and the reason is structural: koboreru's core move is choosing a
> load address from the unsigned container header, while our shared loader takes the
> destination from the *caller* as a literal and only the size from the header. The
> audit is reproducible with `exploits/tools/preloader-audit.py`.

## GhostLock assessment (CVE-2026-43499): not feasible, and not useful

https://github.com/JoinChang/ghostlock-oneplus

**Verdict: the exploit cannot run on this device, and even if it could it would not
advance stage 2.** Unlike the sunstone survey above, this one was not decided by
hardening; the target code is simply **not present**, which is verifiable against the
vendor kernel source we already have.

### What GhostLock is

A kernel LPE ("jailbreak") that gets **temporary root + KernelSU on a device with a
locked bootloader**. CVE-2026-43499 is a futex PI (priority-inheritance)
use-after-free: `pselect6` copies `fd_set` data onto the kernel stack, and if a freed
`rt_mutex_waiter` frame is later reclaimed by that user-controlled region, the rb-tree
rebalance during a PI chain walk writes controlled values to kernel addresses.

Three things about it matter here, in increasing order of importance: its kernel range,
the API contract it depends on, and **what it does not do**.

### 1. The vulnerable code does not exist in this kernel (verified)

Amazon publishes the kernel source for this device, and it is already on disk at
`refs/kernel-7.3.1.9/`. Its `Makefile` reports `VERSION=4 PATCHLEVEL=4 SUBLEVEL=146`, 
the exact running kernel. Grepping that tree:

| symbol | in our 4.4.146 tree |
|---|---|
| `rt_mutex_wait_proxy_lock` | **ABSENT** |
| `rt_mutex_cleanup_proxy_lock` | **ABSENT** |
| `__rt_mutex_cleanup_proxy_lock` | **ABSENT** |
| `rt_mutex_finish_proxy_lock` | **PRESENT** (`rtmutex.c:1729`, `rtmutex_common.h:109`) |

`kernel/futex.c:2930` calls the old API:

```c
ret = rt_mutex_finish_proxy_lock(pi_mutex, to, &rt_waiter);
```

### 2. Why the older API closes the race

This is the structural reason, not just a version-number argument. In 4.4,
`rt_mutex_finish_proxy_lock()` takes `lock->wait_lock`, performs the wait via
`__rt_mutex_slowlock()`, and on failure calls `remove_waiter()` **itself, still under
the same spinlock hold** (`rtmutex.c:1735-1743`):

```c
raw_spin_lock(&lock->wait_lock);
set_current_state(TASK_INTERRUPTIBLE);
ret = __rt_mutex_slowlock(lock, TASK_INTERRUPTIBLE, to, waiter);
if (unlikely(ret))
        remove_waiter(lock, waiter);
```

Wait and cleanup are **one atomic operation**. The 5.7 rework split them into
`rt_mutex_wait_proxy_lock()` + `rt_mutex_cleanup_proxy_lock()` as **separate calls with
`wait_lock` dropped in between**, and that gap is precisely what CVE-2026-43499
exploits. 4.4 has no such gap, so the primitive the exploit needs cannot be created.

Corroborated independently from three directions: the CVE itself is scoped to 5.7–7.1,
GhostLock's own support table spans 5.10–6.12 only, and the vendor source above.

### 3. Its tooling cannot target this kernel either

Even setting the CVE aside, GhostLock's methodology does not reach 4.4:

| requirement | our device |
|---|---|
| BTF for struct offsets (`tools/extract_btf.py`) | **absent**: no `kernel/bpf/btf.c`, `CONFIG_DEBUG_INFO_BTF` and `CONFIG_BPF_SYSCALL` both unset |
| kallsyms recovery for offsets | `kptr_restrict=2` makes `/proc/kallsyms` useless even as root (established in stage 1) |
| "waiter word N" placement analysis | framed around **PGO/LTO inlining** of `do_futex`; a GKI-era build feature that postdates 4.4 by years, so the whole feasibility framework is inapplicable |

`CONFIG_RANDOMIZE_BASE=y`, so KASLR is on and an info leak would be required as well.

### 4. The decisive point: it is a jailbreak, not an unlock

GhostLock's own summary: *"Achieves temporary root + KernelSU installation **without
unlocking bootloader or modifying boot image**."*

It never touches the boot chain. And on this device bootloader unlock is gated by an
**Amazon-signed RSA-2048-PSS `unlock_code`** verified by both the preloader and LK, 
a *cryptographic* barrier, not a privilege barrier. A kernel exploit grants privilege;
it does not grant Amazon's private key. No amount of kernel R/W capability changes that
verification, which happens in earlier boot stages that have already completed by the
time any kernel code runs.

### 5. It is also redundant

Stage 1 already delivers everything GhostLock offers, by a cheaper and safer route:

| capability | stage 1 (SnuSnuRoot port) | GhostLock |
|---|---|---|
| `uid=0` shell | ✅ live-verified | ✅ (claimed) |
| SELinux control | ✅ Permissive, in-memory | ✅ |
| block-device R/W | ✅ | ✅ |
| kernel exploit required | **none** | yes; arbitrary kernel R/W primitive |
| risk of kernel panic | none observed across 18 runs | inherent to the primitive |
| applicable here | ✅ | ❌ |

So the trade would be: accept kernel-exploit risk, to obtain a capability we already
have, while still not unlocking the bootloader.

### 6. PR #48 validation: the maintainer's rebuttal, confirmed and extended

https://github.com/JoinChang/ghostlock-oneplus/pull/48

The PR ("Add device support: Fire HD 10 2021 (trona, MT8183, kernel 4.4.146)",
by BluPhant) claimed *"First verified CVE-2026-43499 exploitation on kernel 4.4.146.
All offsets verified 100% correct via live device testing."* It was opened
2026-09-08 and **closed unmerged on 2026-09-11**. The maintainer's closing comment
gave three reasons. All three are correct, and the analysis below was done from the
PR diff and the vendor source rather than taken from that comment.

#### 6.1 The CVE does not apply: confirmed independently

The maintainer's table is exactly right, and matches the verification in §1–2 above:

| function | in our 4.4.146 | in 5.7+ |
|---|---|---|
| `rt_mutex_wait_proxy_lock` | **does not exist** | vulnerable |
| `rt_mutex_cleanup_proxy_lock` | **does not exist** | vulnerable |
| `__rt_mutex_cleanup_proxy_lock` | **does not exist** | vulnerable |
| `rt_mutex_finish_proxy_lock` | present (`rtmutex.c:1729`), safe | removed |

#### 6.2 The offsets are fabricated: now quantified

The maintainer wrote that the values "appear fabricated" because they are
round-aligned with ashmem entries 4 bytes apart. That observation is right; here is
what the values *should* be, measured, which turns an appearance into a demonstration.

**The single most important symbol.** `off_selinux_enforcing` is the write destination
of the root chain; the one value that must be exact:

| | value |
|---|---|
| PR claims | `0x01D00000` |
| true, PS7331/4463 (the build the PR claims) | `0x018F1668` |
| error, offset convention | **0x40E998 = 4.06 MiB** |
| error, physical convention | **0x38E998 = 3.56 MiB** |

Either reading is wrong by megabytes, and there is no third reading: the values are
inconsistent under both.

**The kernel load address is wrong too.** `kernel_phys_load=0x40000000`, but the true
value is derivable from this project's own verified data, our `selinux_enforcing` VA
for PS7326 is `0xffffff8009969668`, and Eric Pardee's independently reported ground
truth for that same symbol is PA `0x41969668`, so:

```
load PA = 0x41969668 - (0xffffff8009969668 - 0xffffff8008080000) = 0x40080000
```

The PR's `0x40000000` is off by **0x80000 (512 KiB)**. The PR's own deleted comment
warned what that means: *"Wrong value => every write lands in unrelated RAM: no crash,
no effect, very hard to debug."*

**The distribution is wrong.** Of the 28 offsets, **23 are exact multiples of 0x100**,
and the five that are not are the ashmem run. Real symbols are not like that, our own
measured values are `0x018E5628`, `0x018E9668`, `0x018F1668` for the *same* symbol
across three builds, differing by `0x4000` (one page of code growth) and round in no
convention.

**The ashmem spacing, and where the numbers came from.** The six ashmem "function"
offsets are spaced exactly 4 bytes apart:

```
0x01711000 -> 0x01711004 -> 0x01711008 -> 0x0171100C -> 0x01711010 -> 0x01711014
```

Kernel *functions* cannot be 4 bytes apart. For scale, two real adjacent text symbols
in our own extracted data are `0x2B48` apart. But 4-byte spacing is exactly right for
something else: **field offsets within a struct of 32-bit members**. And that is the
tell that explains the fabrication; the upstream `kernel_offsets` struct declared

```c
uint32_t fops_llseek, fops_read, fops_write, fops_read_iter, fops_write_iter;
uint32_t fops_ioctl, fops_compat_ioctl, fops_mmap;
uint32_t fops_open, fops_release, fops_splice_read, fops_show_fdinfo;
```

as **struct-field offsets** (legitimately 4-byte spaced), while the PR assigned those
same magnitudes to `.off_ashmem_*`, which are **symbol offsets**. It is a units
confusion: numbers lifted from one meaning and used in another. That is consistent with
the values having been *constructed to look plausible* rather than read from a binary.

#### 6.3 The PR would have broken every other device

The maintainer noted the PR "deletes all existing `STRUCT_OFFSETS_*` macros,
`waiter_compact`, `kimage_text_base`, and all FOPS override fields". Confirmed against
the live upstream tree; the deleted macros are referenced by the other 12 device
entries:

| device entry | macro it references |
|---|---|
| `ace6t` | `STRUCT_OFFSETS_6_12` |
| `findx9pro` | `STRUCT_OFFSETS_6_12` |
| `op13` | `STRUCT_OFFSETS_6_6` |
| `xperia1iv` | `STRUCT_OFFSETS_5_10` |
| *(and the rest of the 12)* | `6_12` / `6_6` / `6_1` / `5_10` |

Upstream still defines those macros and still has `waiter_compact`, `mm_owner`,
`fops_ioctl`, `fops_mmap` and `kimage_text_base`; upstream has **no**
`STRUCT_OFFSETS_4_4`. So the PR as submitted would not compile for any device other
than the new one, **which means the author never built it.** That is the cheapest and
strongest tell of all, and it is available without any offset analysis: *a patch that
does not compile was not tested,* regardless of what its description says.

#### 6.4 It targets the wrong build for this device anyway

The PR declares `uname_r = "4.4.146+"` with `build_fingerprint = "PS7331.4463N"`
(Fire OS 7.3.3.1). **The reference unit runs PS7319/1735** (Fire OS 7.3.1.9,
incremental `0020367984516`). That is not a cosmetic mismatch: we have measured that
`selinux_enforcing` differs between these builds by **0xC040 (49,216 bytes)**, 
`0x018E5628` on PS7319 versus `0x018F1668` on PS7331.

So even if every value in the PR were genuine, the table would be wrong for this unit.
Note also that PS7331/4463 is the build SnuSnuRoot was validated on, which suggests the
build name was chosen without checking the device it was purportedly tested on.

#### 6.5 What this validates about our own method

Three transferable checks, in increasing order of cheapness:

1. **Try to build it.** A patch that fails to compile was never tested. Costs seconds.
2. **Compare against the real artifact.** `off_selinux_enforcing` being 4 MiB from the
   measured value is decisive, and we could check it because the OTA kernel and the
   vendor source are both on disk. *A claimed offset is only as good as the binary it
   was read from*, and when that binary is obtainable, the claim is falsifiable.
3. **Check applicability first.** The whole exercise was moot: the CVE is 5.7+, so no
   amount of correct offset work would have made it work. We reached that conclusion
   before doing any offset analysis, which is the right order.

There is also a cautionary detail worth keeping: the PR's failure mode would have been
*silent*. With a wrong `kernel_phys_load` the documented symptom is "no crash, no
effect, very hard to debug", so a casual tester could run it, observe nothing, and
still report success. "Verified on device" in a PR description is a claim about the
author's process, not evidence about the code.

### Bottom line

Do not pursue GhostLock on this device, for two independent reasons: the vulnerability
is absent from kernel 4.4.146 (verified against the vendor source), and its success
condition is root without bootloader unlock, which is a state stage 1 already reaches
without a kernel exploit. If the goal is a kernel LPE in its own right, 4.4.146 is
rich in 2016-era CVEs, but it remains a dead end for stage 2: the boot chain is
verified by earlier stages and no kernel primitive reaches it.

## mtkclient / Reddit-guide toolchain assessment (2026-10-08)

The r/androidroot guide (by XDA user Fl0w) bundles a "MediatekBootloaderUnlocker",
an "MTK Auth Bypass Tool", SP Flash Tool v5.2316, `auth_sv5.auth`, and USB
drivers. All archives were obtained and analyzed offline (SHA-256s in
`stage2-unlock/mediatekTools/`; archives gitignored, third-party binaries).
**Verdict: the entire toolchain is inapplicable to this device, for three
independent reasons, each individually sufficient.**

### What the tools actually are

| Guide item | What it really is (proven by inspection) |
|---|---|
| MediatekBootloaderUnlocker.zip (103.6 MB) | Portable Python 3.9 + **mtkclient 1.4**. `UnlockBootloader.bat` = `file\python file\mtk xflash seccfg unlock`; `LockBootloader.bat` = the same with `lock`. Nothing more. |
| MTK Auth Bypass Tool V6.0.0.1 (mtksecbypass.exe) | Bundles per-chip **BROM patcher payloads** (e.g. `mt6771_payload.bin`, 532 B, strings: *"Entered brom patcher. Copyright k4y0z/bkerler 2021"*). Patches the BROM's DA-auth check in SRAM after uploading via the `0xE0` SEND_CERT path. |
| auth_sv5.auth (2256 B) | GFH `FILE_INFO` header (magic `MMM`), identifier **"LenovoAndy"**, followed by a 3-level chain of 256-byte RSA-2048 SBC certificates (hash+signature blocks at 0x1a8/0x3b8/0x5c8, each `02 00 00 00 80 00 00 00 ‖ hash ‖ 01 00 01 00 ‖ sig`). A **Lenovo** SLA/DAA auth file. |
| SP Flash Tool v5.2316 | Standard MTK flasher with signed DAs (`DA_PL.bin` 18.5 MB, `DA_SWSEC.bin`). Needs BROM access or a valid auth file. |
| UsbDk / libusb-win32 / cdc-acm / MTK drivers | USB transport prerequisites only; harmless, but useless without an exploit path. |

### Reason 1: the unlock target does not exist: no `seccfg` partition

mtkclient's `seccfg unlock` reads the GPT, finds the `seccfg` partition,
recomputes its SEJ hash with `lock_state=3` (unlocked), and writes it back
(`xflash_ext.py` `seccfg()`, verified in the bundled 1.4 source). Our GPT
(parsed from `dumps/trona-1735/gpt-primary.bin`) contains **no `seccfg`**:

```
kb dkb keys misc lk tee1 tee2 metadata boot_para nvcfg spmfw sspm_1
cam_vpu1 cam_vpu2 cam_vpu3 boot recovery cache system vendor userdata
```

Amazon replaced the MediaTek seccfg unlock mechanism with their own
**IDME `unlock_code`** system (proven in P4: RSA-2048-PSS over
`'0x'+hex(id13)+hex(id12)+hex(unlock_version)`, verified by preloader
`AMZN_UNLOCK` @ 0x33e0 and LK `amzn_verify_unlock` @ 0x1ce0). The tool
would abort with *"Couldn't detect existing seccfg partition"* even if it
could reach the flash.

### Reason 2: no BROM access: every exploit in the chain is BROM-stage

MT8183 (hwcode `0x788`) **is** in mtkclient's supported list (shared entry
with MT6771/MT8385/MT8666, XFLASH damode, `mt6771_payload.bin` loader), 
it is a legacy-supported chip, not a V6 chip. But every exploit the
toolchain relies on executes in the **BROM** (masked ROM download mode):

- **kamakiri** (CVE-2020-0069 lineage, xyzz): writes the payload pointer to
  `watchdog+0x50` via BROM WRITE32, then uploads the patcher via the
  `0xE0` SEND_CERT command and triggers it with a crafted control transfer
  (`var1=0xA`). Its blacklist/config entries (0x00102834, 0x00106A60) are
  BROM SRAM addresses.
- **kamakiri2/linecode** (`da_read_write`): CDC `SET_LINE_CODING` control
  transfers (0x21/0x20) to overwrite the BROM's `send_ptr`, pure BROM-stage.
- **mtksecbypass payloads**: patch the BROM auth check in SRAM.

On this device the BROM is unreachable: Eric Pardee's research on the same
hardware (KFTRWI, 2021) found the BROM download entry factory-patched
(volume-button entry non-functional, preloader crash does not yield an
exploitable BROM). The guide's step 6 ("hold vol+power to enter BROM mode")
simply does not work on this device; the button combo lands in Amazon's
preloader usbdl, not the BROM.

### Reason 3: the preloader usbdl is stripped and hardened (disassembly-verified)

Our preloader's usbdl command loop (0x5658–0x5c06) was re-disassembled and
cross-checked against mtkclient's command enum. Commands the toolchain
needs that are **absent from the dispatch loop**:

| mtkclient command | Purpose | In our preloader usbdl? |
|---|---|---|
| `0xE0` SEND_CERT | kamakiri payload upload / auth bypass | **No** |
| `0xE2` SEND_AUTH | SLA/DAA auth file upload | **No** |
| `0xE3` SLA | SLA challenge | **No** |
| `0xDA` brom_register_access | kamakiri2 memory access | **No** |
| `0xD6` JUMP_BL | boot-loader jump | **No** |

Commands that ARE present: `0x80` (dead-loop brick), `0xa1/0xa2`
(WRITE16/READ16), `0xc4–0xc7` (PWR/I2C), `0xd0–0xd5` (READ16/READ32/
WRITE16/WRITE32/JUMP_DA), `0xd7` SEND_DA, `0xd8` GET_TARGET_CONFIG, `0xe1`
GET_ME_ID, `0xe7` GET_SOC_ID, `0xf0` ZEROIZATION, `0xfb–0xff` (caps/versions).
Of these:

- `0xd7` SEND_DA / `0xd5` JUMP_DA are **DA-auth-gated** (secure-chip check
  0x2d5ac → RSA-2048 vs the hardware SBC key; unsigned DA → `SEC_AUTH_FAIL
  (0x7024)` → dead-loop brick).
- `0xd4` WRITE32 / `0xd1` READ32 / `0xa2` READ16 are **range-checked**
  (0x258e4 → 0x25874): writes allow only WDT + 0x1001a080. Kamakiri's
  watchdog write would land in-range, but its payload upload needs the
  absent `0xE0`; the chain breaks one step later regardless.
- `0x80` is the **brick command** ("USB Disconnect and Enter Dead Loop"), 
  the exact 3-second loop the XDA device ended in.

And `auth_sv5.auth` is a **Lenovo** auth file ("LenovoAndy"): it can only
verify against a device whose hardware SBC key chains to Lenovo's CA. Ours
is Amazon-provisioned (SEC slots 0x11f10594/98, hardware-burned); the file
is for the wrong vendor entirely.

### Bottom line

| Path | Status on trona/MT8183 |
|---|---|
| mtkclient `seccfg unlock` (the "instant unlocker") | ❌ no `seccfg` partition; unlock lives in IDME `unlock_code` (Amazon-signed) |
| mtkclient BROM exploits (kamakiri/linecode/heapbait) | ❌ BROM unreachable (factory-patched) |
| mtkclient preloader-mode entry | ❌ auth commands stripped from usbdl; DA-auth enforced vs Amazon SBC key; mem R/W range-checked |
| mtksecbypass "Disable Auth" | ❌ BROM-stage patcher; needs `0xE0` + BROM access |
| SP Flash Tool + auth_sv5.auth | ❌ Lenovo auth file vs Amazon key chain |
| Drivers (UsbDk/libusb/cdc-acm) | Transport only; no exploit value |

The only unlock path on this device remains the one proven in P4: an
**Amazon-signed `unlock_code`** written to IDME, which requires Amazon's
private key. No public tool or exploit changes that.

## Container-header audit: pre-authentication load path (2026-10-06)

Answers [vectorResearch.MD](vectorResearch.MD) §3 ("what does the preloader do
with the leading 512-byte LK container header before it authenticates the signed
LK payload?") and its "validate next" item 1, against the **installed**
bootloaders instead of the historical images. Everything below is reproducible
offline with [verify-lk-signature.py](verify-lk-signature.py) (no device writes).

### 1. Signature boundary: proven, not inferred

`AMZN_PL_VERIFY` (preloader 0x2b48 → RSA public op 0x2bc30 + hw SHA-256 0x2bc2a)
with RSA-PSS / SHA-256 / MGF1-SHA-256 / salt 32, signature = last 0x100 bytes:

| key | over `LK[0x000 : 0x939f0)` | over `LK[0x200 : 0x939f0)` |
|---|---|---|
| 0x37a98 alternate image key | rejected | rejected |
| **0x37b98 prod image key** | rejected | **VERIFIES** (604 144 bytes) |
| 0x37c98 unlock key | rejected | rejected |

So the LK image is verified by the **prod image-verify key**, and the leading
0x200-byte container header is outside the signature. Identical for the OTA
`lk.img` and the on-device `mmcblk0p5` dump. This confirms the historical
finding in vectorResearch.MD §1 and corrects this README's earlier attribution
(the `pl-lk-verify-pubkey-modulus.bin` artifact was the unlock key).

### 2. What the loader actually does with the header

Boot flow: `0x19d2e` load → `0x19d40` boundary warning → `0x19d62` verify.
LK loader = wrapper `0x193bc` (lk/lk2 selection, no `lk2` partition exists) →
`0x200f4` ("image with header"), header parser `0x2007c` / `0x18c00`.

* Container magic `0x58881688` at hdr[0] is checked; second magic `0x58891689`
  (hdr[0x30]) selects the container variant. Fields used: hdr[4] = payload
  size, hdr[8] = name ("lk"), hdr[0x28] = requested address, hdr[0x2c] = mode,
  hdr[0x44] = size-alignment unit (0x10 for LK).
* **The header is consumed, not copied**: the device read starts 0x200 bytes
  into the partition (`+0x200` at 0x20180), so only the payload reaches RAM, 
  at the hard-coded `0x56000000` (`mov.w r3, #0x56000000` @ 0x19d20).
* **Destination is not header-controlled on this device.** The header address
  is used only when `hdr[0x2c]==0 && hdr[0x28]!=-1`, in which case 0x200f4
  calls the TEE-reserve helper `0x26064` ("mtktee-reserved", writes
  `0x11db00+0x2c/+0x30`) and uses its result. Every shipped image carries
  `0xffffffff` sentinels in hdr[0x28]/hdr[0x2c] (tee/atf has hdr[0x2c]=0 but
  hdr[0x28]=-1), so the caller-fixed address always wins.
* **Length comes from the unsigned header.** 0x200f4 writes hdr[4] back to the
  caller (`*arg5` @ 0x20278); the boot flow prints "LK addr/size", applies its
  check, and passes that size to the verifier, which derives
  `len = size-0x100`, `sig = base+size-0x100`, tag at `base+size-0x10a`.
  Cross-checked numerically: size = 0x938f0 = hdr[4] is exactly what the
  crypto needs.
* Nuance worth keeping: after the load, 0x200f4 calls `0x2b260`
  ("get_img_size"), which **zeroes and recomputes** the size through a
  *different* parse (`0x18c00`, rounding up to hdr[0x44] alignment). For stock
  LK both parses yield 0x938f0.

### 3. The weakness: a consequential copy before authentication

* The copy precedes every authentication step. The 9 MB window check
  (`0x56000000 ≤ addr && addr+size ≤ 0x56900000`, @ 0x19d40) is printed as
  `Warning: LK out of boundary.` **after** the copy and is **not fatal**.
* The loader's only pre-copy guard is an interval-overlap assert
  (`dram_buf overlap` @ 0x201dc–0x20200, `partition.c:0x4f/0x55`): it computes
  `end = dest + size` (0x201e2) and intersects `[dest, end)` with
  `[g_dram_buf, g_dram_buf + 0x9de40)`. So it *does* cover the length, but it
  protects only that one interval, not DRAM in general (see the correction in
  [§ Corrections](#corrections-2026-10-06)).
* The read itself is a plain block-device read (`0x200f4` → `0x45dc` → misc
  block layer), whose only range check is against the **card**, not the
  partition: 0x1b936 compares the start LBA against the sector count in the
  per-card descriptor (`[0x1afa0(card)] + 4`, a record memset and filled by
  `mmc_init_card` @ 0x1c398), so a read that *starts* inside a partition may run
  past its end (`Out of block range: blknr(%d) > sd_blknr(%d)` @ 0x32fcd).

⇒ An LK partition image whose header declares `hdr[4]` larger than the 9 MB LK
window makes the preloader copy that many bytes from flash to 0x56000000 upward
(over anything living above the window) **before** the signature is checked.
That is the Koboreru / CVE-2023-20695 pattern that vectorResearch.MD §3 ranked
first: the check exists but is ordered after the copy.

### 4. Why it is not yet an unlock

* It requires **write access to the LK partition** (already-rooted Android, per
  `stage1-root`); the same prerequisite the XDA LK patch had, and the same
  unrecoverable-brick risk if the payload does not win during the copy.
* Winning means diverting control (or disarming the verify) *before* the
  verifier's result is used, which needs the DRAM map above 0x56900000
  (preloader stack/heap/scratch, image descriptors, IDME buffer). That map is
  now collected from the live device (see [Live DRAM map](#live-dram-map-2026-10-06)):
  the preloader's own working memory is **below** the window, so the gap is a
  *control-flow target*, not a map (details in the section below).
* Security policy is read live from hardware, so the overflow cannot spoof it:
  the unsigned-image acceptance path (0x2db2, "non secure SoC run with unsigned
  %s") gates on `SEC_CFG(0x11f10060)` bit 1 via 0x2d59c; a register, not a DRAM
  flag (the DA gate is bit 2, 0x2d5ac). No DRAM-cached copy of that bit drives a
  security decision (the only caching sites, 0x2095c/0x20962, build an info
  report).
* ~~Remaining single question: **can the copy length and the verify length be
  made to disagree?**~~ **Resolved (2026-10-06), no, it fails closed.** See
  [Branch/tracer analysis](#branchtracer-analysis--the-0x5f100c00-context-slot-2026-10-06) §5:
  both the copy and the verification are driven by the same `hdr[4]`, and any
  value that keeps the signature valid also keeps the copy inside the LK
  window; every larger value breaks the `_LK_VER:`/signature check first.

> Correction (2026-10-06): an earlier draft of this file cited preloader
> file offsets 0x109ec / 0x2292c / 0x264e0 / 0x20e18 as absolute literals
> implying a link base of 0x483DF000. Those are **byte patterns spanning
> instruction halfwords** (e.g. file 0x109ec = `ef e6 40 48` = halfword
> `0xe6ef` plus `ldr r0, [pc, #0x100]` = `0x4840`), not literals. The
> preloader's link base is therefore **not established**; do not rely on it.
> The PC-relative string resolution done by [pl-disasm.py](pl-disasm.py) is
> unaffected (it never needed the base).

## Live DRAM map (2026-10-06)

Collected read-only from the rooted device over the `stage1-root` uid-0
listener (no boot/system/vendor writes). Raw evidence:
[../diagnostics/dram-map-1735.txt](../diagnostics/dram-map-1735.txt),
[../diagnostics/iomem.txt](../diagnostics/iomem.txt),
[../diagnostics/dt-reserved.txt](../diagnostics/dt-reserved.txt).

### 1. The preloader's DRAM working set is BELOW the LK window

Hard evidence in the preloader itself (file 0x5c34–0x5c8c):

```
005c40  mov.w r3, #0x44800000      ; g_dram_buf = 0x44800000
005c46  ldr   r4, [r4]             ; r4 = &g_dram_buf
005c4c  str   r3, [r4]
005c52  ldr   r0, -> '%s g_dram_buf start addr: 0x%x \n'   ; -> logs it
005c5e  ... g_dram_buf->msdc_gpd_pool  = g_dram_buf + 0x9d000 + 0xd80
005c72  ... g_dram_buf->msdc_bd_pool   = g_dram_buf + 0x9d000 + 0xdc0
005c8c  literal = 0x4487c0a8       ; memset(0x4487c0a8, 0, 0x5cc0)
```

Cross-referenced offsets used elsewhere in the image:

| offset from `g_dram_buf` | use | evidence |
|---|---|---|
| +0x764a0 | 0x200-byte container-header scratch buffer | 0x2011a–0x2012e |
| +0x766a0 / +0x766a4 | loaded-image name counter / names, 0x200-byte entries | 0x2018c–0x201b8 |
| +0x7c0a8 | zeroed structure, 0x5cc0 bytes | 0x5c48, 0x5c4e |
| +0x9de00 | mblock info block, 0x5cc0 bytes | 0x19ffa, 0x1a014 |
| +0x9dd80 / +0x9ddc0 | msdc gpd / bd pools | 0x5c64, 0x5c78 |

So the preloader's own buffer/state footprint starts at `0x44800000`, about
**280 MiB below** 0x56000000 (0x56000000 − 0x44800000 = 0x11800000), and its
image/BSS is far lower still (see §1 of the DRAM-map section). An upward
overflow from the LK window
cannot reach any of it.

### 2. Nothing is reserved between the LK window and the framebuffer

`mblock-1-atf-reserved` is at `0x54600000` (256 KB, *below* the window) and the
next reservation up is `mblock-6-framebuffer` at `0x624e0000`. So the span
`0x56900000 → 0x624e0000` is unreserved DRAM, and it is large:
`0x624e0000 − 0x56900000 = 0xBBE0000` ≈ **188 MiB**, not the ~11.8 MB an earlier
draft of this file stated. An oversized copy crossing the window end therefore
hits nothing that matters until `0x624e0000`, and then `0x64400000` (TEE), both
of which are re-loaded by the preloader *after* LK.

### 3. The read is bounded by the card, not by the partition

`lk` is exactly **1 MiB** (LBA 22592–24639) and the image is 604 912 bytes, so
without a bound the read has ~0.4 MB of slack before leaving the partition.
The block layer's only range check is against the *card*
(`[SD%d] Out of block range: blknr(%d) > sd_blknr(%d)` @ 0x32fcd, used at
0x1b93a/0x1b9b2). The compared value is `[0x1afa0(card) + 4]`, and that record
is a 0x2f4-byte per-card descriptor, `memset` and filled by `mmc_init_card`
(0x1c398), *not* a per-partition extent. A read that starts inside a partition
can therefore run past its end, into the next partition and beyond.

**Source-to-destination mapping** (`dest = DEST_BASE + X`,
`X = flash_offset − SOURCE_FLASH`). This is the table that matters for the
ATF_DRAM copy documented in the next section (source base `0xC1C000`,
destination `0x54600000`):

| flash partition reached | flash offset | lands at RAM |
|---|---|---|
| tee2 | 0x1108000 | 0x54aec000 |
| metadata | 0x1608000 | 0x54fec000 |
| boot_para | 0x3608000 | 0x56fec000 |
| nvcfg | 0x3708000 | 0x570ec000 |
| cam_vpu2 | 0x5008000 | 0x589ec000 |
| boot | 0x7f08000 | 0x5b8ec000 |
| **recovery** | 0x9f08000 | **0x5d8ec000** |
| **cache** | 0xc800000 | **0x601e4000** |
| system | 0x2e800000 | 0x821e4000 |
| userdata | 0x12a800000 | 0x7e1e4000 (mod 2³²) |

**LK's own entry (RAM 0x56000000) corresponds to copy offset `0x1A00000`, i.e.
flash `0x261C000`, inside `metadata`.** So the bytes that would replace LK are
metadata bytes.

Note on "writable": the previous draft said recovery/cache are "unwritable while
locked". That conflated two different mechanisms, locked-fastboot policy versus
raw block-device access from Android root. The correct statement is narrower:
*locked-fastboot* will not flash them; whether root can write the raw block
device is a separate capability question (not tested here).

### 4. The one identified target above the window: the `0x5f100c00` context slot

The preloader contains an MTK save/restore pair referenced by exactly one
constant, `0x5f100c00` (occurring only at 0x291bc and 0x29724):

```
; save                                    ; restore (0x291a4)
0296f2  str   r4,  [r3, #0x00]            0291a4  ldr   r0, [pc, #0x14]  ; = 0x5f100c00
0296fa  str.w r8,  [r3, #0x10]            0291a6  ldm.w r0, {r4-r8, sb, sl, fp, ip}
02970e  str.w sp,  [r3, #0x24]   <- SP    0291aa  ldr.w sp,   [r0, #0x24]
029712  str.w lr,  [r3, #0x28]   <- PC    0291b4  ldr.w lr,   [r0, #0x28]
02971a  str   r1,  [r3, #0x2c]   <- CPSR  0291b0  msr   cpsr_fsxc, r1
029720  bx    r0                          0291b8  bx    lr
```

`0x5f100c00` is in the unreserved span above the LK window, so an oversized
copy **can** reach it. What is *not* yet established is whether this slot is on
the normal LK boot path: no direct branch targets the restore at 0x291a4 (it
must be reached indirectly, or it is a resume trampoline), the constant appears
in no other image (not in LK), and the save function's caller was not located.
Until that is settled, this is a lead, not a confirmed target.

### 5. Also ruled out

* The `lk` partition tail (0x93af0–0x100000) is essentially empty (7 250
  non-zero bytes of 444 176, no container magic), so there is no second
  Amazon-signed image to point `size` at.
* Security policy cannot be spoofed by the copy: the unsigned-image path
  (0x2db2) gates on the `SEC_CFG` register (0x11f10060), read live via 0x2d59c.
* Bootloader logs were not recoverable from the device: `console-ramoops`
  covers only t>31 s of the current boot (uptime ~16 h), so the preloader/LK
  log ring had long been overwritten.

**Net effect on the exploit:** the primitive is confirmed larger than the LK
window, but every preloader structure it could reach either gets reloaded
afterwards or is unreachable (the preloader's own state sits *below* the
window). The blocker was reduced to one specific question, *is 0x5f100c00
consumed on the LK boot path, and can its content be steered from a writable
partition?*, which the next section answers: the slot is on the boot path but
is written after the copy, so the vector closes.

## Branch/tracer analysis: the `0x5F100C00` context slot (2026-10-06)

Resolves the open question from the previous session: **is the MTK context slot
at `0x5F100C00` consumed on the boot path, and can the pre-auth copy reach it
before it is written?**

Method: [pl-cfg.py](pl-cfg.py) (new), which builds branch edges, pc-relative
literals and(critically) **computed code pointers** of the form
`ldr rX,[pc,#imm] / add rX, pc`. None of the addresses below exist as raw u32
words in any image, so a plain data scan finds nothing:

```
> python stage2-unlock/pl-cfg.py build ota-extract/images/preloader.img pl-cfg.json
built: 11441 branch sources, 5395 pc-relative loads, 1461 computed refs
> python stage2-unlock/pl-cfg.py cref pl-cfg.json 0x291a4
   0x0299e0 -> 0x0291a5  (Thumb)         # the *only* reference to RESTORE
> python stage2-unlock/pl-cfg.py cref pl-cfg.json 0x29728
   0x029bb6 -> 0x029729  (Thumb)         # the *only* reference to the module body
> python stage2-unlock/pl-cfg.py callers pl-cfg.json 0x21590
   0x019fcc                              # single caller, in the boot flow
```

### 1. The save/restore pair

| | SAVE | RESTORE |
|---|---|---|
| address | **0x296f0** | **0x291a4** |
| slot | literal `0x5F100C00` @ 0x29724 | literal `0x5F100C00` @ 0x291bc |
| stores | r4-r11 @ +0x00-0x20, **sp @ +0x24**, **lr @ +0x28**, apsr @ +0x2c, `dsb sy` | loads the same, then `msr cpsr_fsxc` + `bx lr` |
| exit | `bx r0`; never returns | returns to the *saved* lr |

So SAVE = "stash my context, then jump somewhere"; RESTORE = "reload it and
resume". SAVE has exactly **one** caller: `0x298b4`, inside the
`PICACHU` DVFS/VPROC module body (fn **0x29728**, `push.w {r4-r11,lr}` @ 0x29728),
called with `r0 = [r4+0x20]` as the jump target.

### 2. Who enters the RESTORE

RESTORE has no direct branch source and no raw pointer. Its one computed
reference is at **0x299e0**, where it is *handed to an external component*:

```
0299d6  ldr   r0, [r3, #4]        ; r3 = *(0x3c2a8) -> external component handle
0299d8  bl    0x2a580             ; getter for that handle
0299dc  ldr   r3, [r0, #4]        ; handler[1]
0299e0  ldr   r0, [pc] / add r0, pc    ; r0 = 0x291a5  (RESTORE, Thumb)
0299e4  blx   r3                  ; handler[1](0x291a5)  -> "resume us here"
```

So the RESTORE is entered **by that external component**, not by any preloader
branch, which is why no branch to it exists.

### 3. Ordering: the slot is written *after* the LK read

The boot flow calls the module exactly once, and strictly after the LK
load/verify (one function, no boundaries between them, verified):

```
019d2e  bl 0x193bc            <- LK load  (read hdr[4] bytes to 0x56000000)
019d40  ... 'Warning: LK out of boundary.'  (non-fatal)
019d62  bl 0x2f58             <- LK verify  (0x2c60 -> AMZN_PL_VERIFY)
   ...
019fcc  bl 0x21590            <- PICACHU module, in the 'trustzone post init' stage
          021592  mov.w r0, #0x5f000000     ; workspace base!
          021598  bl    0x29a44             ; module entry (single caller 0x21598)
              ...
              029df8  bl 0x29954            ; -> arms handler[1] with 0x291a5 (§2)
019ffc  '%s Others, jump to ATF'  -> hand off
```

Both `0x21590` (caller) and `0x29a44` (module entry) have exactly one caller.
Therefore the SAVE that writes `0x5F100C00` runs **after** the LK copy, and the
copy cannot pre-plant the saved context: the SAVE overwrites it afterwards.

### 4. What the workspace actually holds

`0x5F000000` is a transient scratch area, not reserved in the DT (it becomes
ordinary kernel RAM later). The module *builds* its data there before reading
it:

* table build, loop 0x29b4c-0x29b72: `str.w r1,[r7,sb]` with `r4 = 0…0x1000`
  and `sb += 4` → 0x1001 4-byte entries (0x4004 bytes); a DVFS
  frequency/regulator lookup table;
* consume, loop 0x29f3a: `ldr r3,[r7]` / `cbz` / `ldr r3,[r7,#4]` over
  0x38-byte-stride entries, reads its own table.

Write precedes read, so data planted there by the overflow is overwritten
before use.

### 5. Why the copy cannot reach this anyway: the length question

For **LK**, the pre-auth copy and the signature check are driven by **one**
value, `hdr[4]`:

* copy length = `hdr[4]` (the loader reads `hdr[4]` bytes from `offset+0x200`);
* verify length = `size − 0x100`, where `size` is what `get_img_size`
  (0x2b260 → header parse 0x18c00) returns, **`0x938f0` = the payload size**,
  i.e. `hdr[4]` (aligned up to `unit = hdr[0x44] = 0x10`), *not* `hdr[4]+0x200`
  as an earlier draft stated. The leading `0x200` only advances the flash
  cursor to the next component (0x196c0/C4, 0x196f6);
* the verifier additionally requires the `_LK_VER:` tag at
  `base + size − 0x10a` and the RSA-PSS signature at `base + size − 0x100`.

For stock LK, `size` = `hdr[4]` = `0x938f0` and the signed length is
`0x938f0 − 0x100 = 0x937f0` (= 604 144 bytes, exactly what the crypto check
measures; the file is `0x93af0` = `0x938f0 + 0x200` because of the consumed
header). Keeping the signature valid therefore pins `hdr[4]` to the aligned
value `0x938f0`, i.e. `hdr[4] ∈ [0x938e1, 0x938f0]`; the copy stays ≤ 604 KB
inside a 1 MiB partition and never leaves it. Any larger `hdr[4]` moves the tag
and signature positions, so the check fails: the code falls to the "No version
magic" path (0x2db2) which accepts unsigned images **only** on a non-secure SoC
(`is_secure_soc` → `SEC_CFG(0x11f10060)` bit 1, 0x2d59c). This device reports
`androidboot.secure_cpu=1 androidboot.prod=1` on its own kernel cmdline, and
the failing case ends in `mov.w r7, #-1` → reject → the known dead-loop brick.

### Verdict

The slot **is** on the normal boot path, but ordering closes the vector:

1. the LK-header overflow is the *earliest* write in the boot;
2. the only preloader structure above the LK window (`0x5F100C00`) is written by
   the SAVE afterwards, and its workspace is written before being read;
3. the preloader's own image/BSS is far below the window, every pointer in its
   data section (file 0x3c1a0-0x3c2cc) lies in `0x0010xxxx`–`0x0023xxxx`, e.g.
   the external-component handle at file 0x3c2a8 = `0x0023bd80`;
4. and the enlarged-copy case cannot keep a valid signature, so it fails closed.

⇒ **vectorResearch.MD §3 (the top-ranked lead) is now closed, and the failure
mode is a brick rather than a hijack.** The primitive remains interesting only
as documentation of the validation order.

**Important scope limit:** this argument is specific to LK, because LK's copy
length and its authenticated length are *the same value*. It does **not** extend
to components whose copy length and authenticated length come from different
places, see the next section.

## ATF_DRAM: copy length ≠ authenticated length (2026-10-06)

Follows up [vectorResearch2.MD](vectorResearch2.MD) §1, which argued the
`atf_dram` sub-image is the stronger candidate precisely because it is loaded
*after* LK has been authenticated. **All of the structural, cryptographic and
code claims below were re-verified on this project's own images**, not taken
from the document.

### 1. `tee.img` is three separately wrapped components

| # | outer header | component | outer `hdr[4]` | destination |
|---|---|---|---|---|
| 0 | 0x00000 | `atf` | 0x13c00 | **runtime-derived**: the chained loader's incoming `r3` (caller `mov r3, r5` @ `0x19dc0`); *not* the `0x00100800` literal, see the correction below |
| 1 | 0x13e00 | `atf_dram` | 0xda00 | caller literal **`0x54600000`** |
| 2 | 0x21a00 | `tee` | 0x2b6000 | reservation helper (see §4) |

> **Correction (2026-10-06, later pass).** This table previously listed the `atf`
> destination as "caller literal `0x00100800`". **That is wrong**, and the error
> propagated into `exploits/README.md` before being caught by re-reading the code:
>
> * `0x00100800` occurs once in the image (file `0x19eb8`) and is read at file
>   `0x19d80`, which is in the **LK boundary-check path**: it is stored into
>   `[sp,#0x30]`, the slot later compared against `0x56000000` to emit
>   `Warning: LK out of boundary.`
> * The `atf` load's destination is `r4` at `0x19614`, and `r4` is the chained
>   loader's incoming `r3` (`0x195ea mov r4, r3`), set by the caller at `0x19dc0`.
>   So it is **runtime-derived, not a literal**.
>
> Worth recording as a method failure rather than just a typo: the `atf_dram` and LK
> destinations were re-derived from the image and held up, while this one was carried
> over from an earlier note unchecked, precisely the "verify against the code, not the
> notes" rule this repository applies elsewhere. Full write-up:
> [../exploits/README.md](../exploits/README.md), "Retraction".

Each is a `0x58881688` container followed by an inner header at `+0x200`
(`MTK TEE` magic, `inner[0x08]` = 0x240 header size, `inner[0x18]` = body size).
This project's `ota-extract/images/tee.img` hashes to
`c34e2aea1ccc81eb…`, and **`dumps/trona-1735/mmcblk0p6.bin` (tee1) and
`mmcblk0p7.bin` (tee2) both match it byte-for-byte** over the first `0x2d7c00`
bytes, so the analysis applies to the installed device.

### 2. The two lengths are genuinely independent (verified cryptographically)

RSA-2048-PSS / SHA-256 / MGF1-SHA-256 / salt 32 against the modulus at
preloader **`0x388f0`**:

| component | outer `hdr[4]` | inner `[0x08]+[0x18]` | signature at inner `[0x13c:0x23c]`, zeroed for hashing | verify |
|---|---|---|---|---|
| atf | 0x13c00 | 0x13c00 |; | **PASS** |
| atf_dram | 0xda00 | 0xda00 |; | **PASS** |
| tee | 0x2b6000 | 0x2b6000 |; | **PASS** |

The load and the verify use different fields, and **no equality check exists**
(reproduce with `python stage2-unlock/verify-tee-signature.py`, which re-derives
every value below from the local images):

* **copy**: the shared loader 0x200f4 copies `hdr[4]` (unsigned outer field)
  bytes, to the caller-supplied fixed address;
* **verify**: 0x19652 / 0x196ce call 0x26034, which **discards the caller's
  size argument outright** (`ldr r1, [r2]` at 0x2603c replaces it with a cached
  value) and then:
  * 0x2bc08: `ldr r4,[r0]` → `ldr r4,[r4,#0x23c]`, compared with that cached
    value; accepted if equal **or** if the field is the wildcard `0xffffffff`
    (0x2bc14/C6). Stock `atf`/`atf_dram` carry `0xffffffff`; stock `tee`
    carries `0x08c00000`, so the earlier claim that *every* nested header uses
    the sentinel was wrong;
  * 0x2b9cc → 0x2ba92: `ldr r1,[r4,#0x18]` / `ldr r3,[r4,#8]` /
    `add r1, r3` → the authenticated extent is `inner[0x08] + inner[0x18]`,
    computed **from the inner header**, with the signature read from
    `base + 0x13c`.

### 3. Boot order and the absence of re-verification

All call sites checked with [pl-cfg.py](pl-cfg.py) (each has exactly one):

```
019d2e  bl 0x193bc     LK load        (1 caller)
019d62  bl 0x2f58      LK verify      (1 caller)  <- LK authenticated here
019dc2  bl 0x195e4     chained ATF/ATF_DRAM/TEE loader (1 caller)
  01961e  bl 0x200f4   atf       load
  019652  bl 0x26034   atf       verify
  01966e  lit 0x54600000            <- ATF_DRAM destination (file 0x1974c)
  01968e  bl 0x200f4   atf_dram  load   <-- copy, length = outer hdr[4]
  0196ce  bl 0x26034   atf_dram  verify <-- extent = inner header
  0196fc  bl 0x200f4   tee       load
01a00c  ldr r0,[sp,#0x24]  -> 0x19800 -> handoff   ; saved LK address
```

`0x54600000` is 26 MiB below LK's `0x56000000`, the copy starts *after* LK was
authenticated, and nothing re-loads or re-verifies LK afterwards.

### 4. Feasibility: and why it still is not a usable unlock

**Interval convention.** A copy of `N` bytes starting at `B` occupies
`[B, B+N)`; the end is excluded. This matters for the arithmetic below:
`0x56000000 − 0x54600000 = 0x1A00000` is the distance from the ATF_DRAM
destination to LK's **first byte**. A transfer of exactly `0x1a00000` bytes ends
immediately *before* that byte; it **reaches LK's boundary without overwriting
any of LK**. Overwriting requires `N > 0x1a00000` (and `hdr[4]` is aligned to 0x10
by the loader's own arithmetic, so the practical minimum is `0x1a00010`).

With that established: an oversized `atf_dram` outer `hdr[4]` **could** rewrite
already-verified LK in RAM before execution. The geometry, however, only closes
under write conditions this project forbids:

* **the TEE must be relocated.** The chained loader finds the next component at
  `prev_outer + 0x200 + hdr[4]` (0x196ba–C4, 0x196f0–F6). Enlarging `atf_dram`'s
  `hdr[4]` past `0x1a00000` moves the `tee` container beyond the 5 MiB `tee1`
  partition, i.e. into `metadata`;
* **the bytes that land on LK are not attacker-chosen by default.** For
  `N = 0x1a00010` the first byte at LK's entry (`0x56000000`) comes from flash
  `0x261C000` = `metadata+0x1014000`, and the relocated `tee` container must
  begin at `metadata+0x1014200`. A ~3 MiB region of `metadata` would have to be
  laid out so the same bytes serve as (a) the start of LK's replacement and
  (b) a valid relocated `tee` container;
* **the payloads are encrypted.** `atf`, `atf_dram` and `tee` bodies measure
  ~8.0 bits/byte entropy (LK, known plaintext code, measures 7.0). What the
  decrypt path does with an oversized tail is therefore unverified *by static
  reading of the stored bytes*, see the scoping note below;
* **it requires writing boot-critical partitions**: `tee1`, `metadata` (and
  possibly `boot_para`/`nvcfg`), with a single 4-byte error being
  unrecoverable on this unit, and the pay-off being one boot's worth of
  RAM-only code execution.

> **Scoping note (corrected 2026-10-06).** An earlier draft concluded the
> encrypted bodies make the ATF-side question "unresolvable offline". That is
> **too strong**. High entropy means the stored bodies cannot be disassembled
> directly; it does not establish that the *loader's decryption* cannot be
> reproduced. The decrypt routine is ordinary code that can be modelled offline,
> and doing so is the way to settle (i) what an oversized tail decrypts to and
> (ii) whether ATF re-validates LK after handoff. That work is **unfinished**,
> not impossible.

⇒ **Real defect, not a practical unlock.** It is recorded here as a validated
candidate for anyone with a non-production unit or a hardware recovery path.
Of the four conditions vectorResearch2.MD §1 asked to be checked, three are now
checked; the fourth (ATF-side re-verification) needs the decryption model above.

> **Scope limit on the "no later validation" claim.** The claim that nothing
> re-verifies LK is established **for the preloader path only** (every load and
> verify call site was enumerated; there is no second LK verify). It does **not**
> extend past the handoff at 0x1a00c into ATF. An earlier draft stated the
> absence claim without that limit, and simultaneously flagged the ATF side as
> unresolved; an inconsistency. The limit now stands: **preloader path only.**

### 5. Corrections adopted from vectorResearch2.MD

| previous statement | corrected |
|---|---|
| overlap guard "tests the destination, never the length" | it computes `end = dest + size` (0x201e2) and intersects the *interval* with `g_dram_buf`'s; a real length check, but scoped to one region |
| verify size = `hdr[4] + 0x200` | verify size = `hdr[4]` (0x938f0); the `0x200` only advances the flash cursor |
| "every shipped nested header uses the 0xffffffff sentinel" | `tee`'s outer header carries `0x08c00000` with mode 0, so it *does* take the reservation branch |
| `g_dram_buf` "2.5–40 MB below" the LK window | 0x56000000 − 0x44800000 = **0x11800000 ≈ 280 MiB** |
| window-end→framebuffer gap "~11.8 MB" | 0x624e0000 − 0x56900000 = **≈ 188 MiB** |
| source table row "userdata → 0x89c00000 (after wrap)" | recomputed in §3 above; that figure was wrong |
| four-site USB read inventory "proves" completeness | the handshake has a fifth read through a *cached* transport pointer (0x55ca–D2), which the two-load idiom scan does not match; the inventory covered that encoding only |
| "two independent overflow guards" | the `count < count*4` test alone is not a complete overflow detector; the negative result holds via the *combination* of that test and the tiny allowlisted window |

None of these overturn the PICACHU ordering result or the USB audit's
conclusions.

## Preloader USB audit (2026-10-06)

Audits the preloader's `usbdl` command implementation against the MediaTek
preloader-USB CVE classes listed in [vectorResearch.MD](vectorResearch.MD) §5
(CVE-2022-20055/56/58/59 OOB writes; -20060 auth bypass; -20069/-20073 integer
overflow/underflow). Offline analysis only, no device writes.

### Method

1. Enumerate the whole dispatch loop (0x5658-0x5c06) so every command has a
   known handler (table below).
2. Find USB-read call sites with the driver vtable idiom
   `ldr rX,[rY,#8] / ldr rX,[rX,#4] / blx rX` (read; `[+0]` for write). This
   yields **four** sites, but note the scope limit in §"Method limit" below:
   it inventories that *encoding*, not every possible read.
3. For each handler, check the validation order: alignment, zero-length,
   multiplication guards, range containment, and whether any bound is applied
   *after* the copy.

### The four USB read sites found by the idiom scan

| site | length | argument | validated? |
|---|---|---|---|
| 0x5368 | 2 bytes | fixed (`movs r1,#2`) | n/a |
| 0x5398 | 4 bytes | fixed (`movs r1,#4`) | n/a |
| 0x566a | 1 byte | fixed (`movs r1,#1`) | n/a |
| **0x5750** | **host-supplied** | `ldr r1,[sp,#0x28]` | **no; bound checked after the copy** |

So the only variable-length transfer reachable through that idiom is `SEND_DA`.

### Method limit (correction, 2026-10-06)

The idiom scan does **not** prove the inventory is complete. The handshake path
reaches the same read member through a *cached* transport pointer rather than
two adjacent loads:

```
055ac  ldr.w sb, [r7, #8]     ; cache the transport table
055c8  movs  r1, #1
055ca  ldr.w r3, [sb, #4]     ; read callback, loaded earlier
055d2  blx   r3               ; read(buf, 1, 0)   <-- fifth site, fixed at 1 byte
```

That site is fixed-length and harmless, but it is a concrete counterexample to a
completeness claim. A full USB input audit also needs the callback target
followed through wrappers and the lower driver/control-request paths.

### Finding 1: `SEND_DA` (0xD7) copies before validating the length

Protocol (confirmed against the bundled mtkclient
`Library/mtk_preloader.py::send_da` and the echo helpers 0x5388/0x5324, which
read/write big-endian u32s):

```
cmd 0xD7 | address u32 | length u32 | sig_len u32 | status | <length bytes>
```

The handler at 0x5700-0x5754:

```
05700  add  r0, sp, #0x24      ; 0x5388 = read_u32_be (host)
0570c  mov  r0, r5             ; r5 = sp+0x28  (set at 0x55b0/0x55b6)
05718  add  r0, sp, #0x2c
05746  ldr  r0, -> 0x40200000  ; destination: FIXED
0574a  ldr  r1, [sp, #0x28]    ; length: HOST-SUPPLIED
0574e  str  r0, [sp, #0x24]    ; host's address field is overwritten/ignored
05754  blx  r3                 ; read(0x40200000, host_length, 0)   <-- COPY
05756  ...                     ; checksum loop over host_length/2 u16s
05816  bl   0x2d5ac            ; is_secure_soc
05850  cmp.w r3, #0x120000     ; DA_RAM_LENGTH check              <-- BOUND
0585a  -> "da size(0x%x) exceeded the DA_RAM_LENGTH(0x%x)"
```

The bound is real but **ordered after the copy**, and the copy itself is a
single call with the host's value. There is no alignment, zero-length, or
multiplication guard before it (contrast Finding 2). This is the
CVE-2022-20055/20056/20058/20059 pattern; a pre-authentication USB
out-of-bounds write, reached before the DA auth at 0x5834/0x5872.

**Reach is *not* limited by the 70 MiB distance** (correction, 2026-10-06).
The receive loop keeps a 32-bit remaining count and advances the destination
until it is exhausted (0x17cfa–0x17d0c), the buffer checks only bound
individual chunks, and `SEND_DA` passes `r2 = 0` (0x5744) which *disables* the
reader's timeout while a polling path refreshes the watchdog. `g_dram_buf` is
also already live at USB entry (`0x5c34` runs from platform init at 0x21a86,
before the USB entry at 0x19a22). So a declared extent *can* reach
`0x44800000`; the earlier claim that reach is confined to unused DRAM was
wrong.

What still prevents a control-flow primitive:

* the destination is **hard-coded** to 0x40200000; the host's address field is
  silently overwritten at 0x574e, so the write is forward-only;
* the `JUMP_DA` trampoline slot is at **0x401ffff4, 12 bytes *below* the DA
  base**, so a forward write cannot reach it;
* the objects that gate acceptance are in **SRAM below the DA base**
  (DA acceptance flag `0x00115761`, transport pointer `0x00115764`,
  `g_dram_buf` pointer `0x00115768`, receive ring `0x00116d40`, RSA modulus
  buffer `0x001177c4`), so a forward write cannot reach them either;
* and on any failure the handler **zeroes the whole transferred range and
  panics**: `memset([sp+0x24] = original dest, 0, [sp+0x28] = original host
  length)` at 0x590a–0x5910, then 0x216c0 → 0x21670 → the self-branch at
  0x216b4. The acceptance flag is only written on the success path
  (0x5924–0x592a). So nothing that was overwritten survives to be used.

Net: a real validation-order defect. The correct closure is **"no useful
*consumed* target identified"**: **not** "the copy cannot reach working
memory". (An earlier draft's verdict paragraph still said the damaged region was
"unused DRAM"/"does not reach any live structure"; that contradicted the
corrected reach analysis above and has been removed.) The open question the
document poses is the right one: is any reachable object consumed *during* the
transfer, during checksum/key setup, or before the rejection clear destroys the
values?

### Finding 2: the numeric guards are sound (rules out the overflow class)

`READ32` (0xD1) / `WRITE32` (0xD4) validate in this order:

```
05aa4  lsls r3, r0, #0x1e      ; addr & 3
05aa6  bne  -> error -1        ; 1. alignment
05aaa  cmp  r3, #0             ; 2. count != 0
05ab0  cmp  r3, r1             ;    r1 = count*4
05ab2  bhs  -> error -2        ; 3. rejects count >= count*4  (i.e. count >= 2^30)
05ab6  bl   0x258e4            ; 4. range containment, byte length = count*4
```

and the containment helper 0x25848 is itself wrap-safe:

```
02584e  cmp  r3, r4 ; blo -> reject     ; addr >= table.base
025856  cmp  r3, r2 ; bhi -> reject     ; addr <= base+size
02585c  add  r0, r3                        ; end = addr + len
025860  cmp  r0, r4 ; blo -> reject      ; end >= base
025864  cmp  r0, r2 ; bhi -> reject      ; end <= base+size
025866  cmp  r0, r3 ; ite ls               ; end <= addr ?
02586a  movls r0, #0                       ;   yes -> REJECT (catches wrap)
02586c  movhi r0, #1                       ;   no  -> accept
```

The combined arithmetic and containment checks exclude the examined cases, 
note this is a *joint* argument, not two independent ones: the
`count < count*4` test alone is not a complete multiplication-overflow
detector (some overflowing products still exceed `count`), but any count large
enough to overflow is far outside the tiny allowlisted window, so containment
rejects it. **The CVE-2022-20069/-20073 integer overflow/underflow result holds
for this build's memory R/W path**: with the caveat that it covers the
multiplication and address-containment logic, *not* subtraction of DA lengths
(see Finding 5).

The tables (0x3b68c writes / 0x3b69c reads) also confirm the surface is tiny:

| table | entries |
|---|---|
| write | `0x10007000 +0x1000` (WDT), `0x1001a080 +4` (SRAMROM control) |
| read | the same two, plus `0x11f10000 +0x1000` (SEC_CTRL) |

### Finding 3: `JUMP_DA` (0xD5) is auth-gated

```
05930  movw r7, #0x7024        ; SEC_AUTH_FAIL
05940  ldr  r3, [r6, r3]       ; r3 = *(r6 - 0x278)
05942  ldrb r3, [r3]
05944  cmp  r3, #1
05948  moveq r7, #0            ; authenticated -> status 0
0594c  bl   0x52fc             ; reply status
05950  cbz  r7, #0x5970        ; only proceed when authenticated
       ; else -> "usbdl_jump_da: %x" + `download.c:0x354` assert
05970  ldr r1, = 0x58885168
05974  ldr r7, = 0x401ffff4    ; trampoline slot (BELOW the DA base)
05976  ldr r3, = 0x40200000
0597c  stm.w r7, {r1, r2=1, r3=3}   ; 12-byte trampoline
05980-0x598c  cache maintenance
05996  bl  0x197a0             ; (0x40200000, 0x401ffff4, 0xc)
```

So the DA entry path is gated on an authentication flag and is not reachable
from an unauthenticated session. Note the trampoline lives *below* the DA
buffer, which is exactly why Finding 1 cannot be combined with it.

### Finding 4: pre-auth PMIC register access (by design, documented)

`0xC4`/`0xC6`/`0xC7` read and write **PMIC** registers via the PWRAP block
(`0x1000DC20/0x1000DC24/0x1000DC28`), reached through 0x22100/0x22138 →
0x22bf0 → 0x22b54. The address is validated (`lsrs r3,r0,#0x10; cbnz -> error
3`, i.e. must be <= 0xFFFF), so this is confined to the PMIC address space, not
arbitrary register access. The `movw r2,#0xffff` at 0x5b8e is a **field mask**,
not a length (the code does `*buf = (val & (mask<<shift)) >> shift`), so there
is no stack-buffer overflow here despite the promising-looking constant, the
destination `r4 = sp+0x30` is a stack buffer but only 4 bytes are ever stored.

### Finding 5: `SEND_DA` has an unchecked `total − sig_len` subtraction

At 0x5876 the handler computes `body_length = total_length − sig_len` and the
document reports no preceding `total_length >= sig_len` check. The wrapper at
0x255a4 requires `sig_len == 0x100`, which fixes the *signature* size but says
nothing about the total. The result reaches the hash path
(0x58a6 → 0x255a4 → 0x2b108 → 0x2b16a) and the chunked helper at 0x2c4fc keeps
a 64-bit source cursor, so an underflow gives a greatly enlarged hash extent
and a signature pointer below the DA base.

Impact is **not** established: the observable outcomes are a hardware-hash
error or a hang, and if hashing completes the ordinary RSA/PSS validation still
follows. It is also not established as "the" CVE-2022-20073 implementation, 
that CVE is an underflow in preloader USB and MT8183 appears on the affected
list, but the vendor description is an out-of-bounds write, which was not
demonstrated here. Recorded as a concrete arithmetic path outside the
READ32/WRITE32 review, not as an unlock.

### Verdict

| Issue | Present in this build? |
|---|---|
| CVE-2022-20055/56/58/59; USB OOB write | **Partially**: one unchecked pre-auth copy (SEND_DA). Reach is *not* distance-limited (it can reach `g_dram_buf`), but no useful consumed target was identified, and the failure path zeroes the range before panicking |
| CVE-2022-20060; auth/permission bypass | No; DA entry is flag-gated; PMIC access is address-bounded |
| CVE-2022-20069; integer overflow | No; excluded by the joint arithmetic + containment argument |
| CVE-2022-20073; integer underflow | **Candidate**: unchecked `total − sig_len` at 0x5876; no bypass or OOB write demonstrated |

The USB surface is the best-hardened part of this bootloader: fixed
destination, explicit numeric guards, gated DA entry. Two defects were found
(the `SEND_DA` check-after-copy and the unchecked `total − sig_len`). **No useful
consumed target was identified for either**, and the failure path zeroes the
transferred range before panicking, so neither provides a route to bootloader
unlock. Note the precise scope of that statement: it is *"no useful consumed
target identified"*, not *"the defects cannot reach working memory"* (the
`SEND_DA` copy demonstrably can). **The "no safe unlock" conclusion stands.**

## Extended bypass analysis: new surfaces (2026-10-06)

Prompted by a request to widen the search and to look for **new/custom** vectors.
Everything here is offline RE plus read-only device inspection (no writes).

### 1. Complete image load/verify matrix: no unverified image exists

Every image the preloader loads, and its verifier. All four verify wrappers call
the *same* orchestrator (0x2c5c), which uses the same two Amazon image keys
(prod `0x2b30` → 0x37b98, alt `0x2b24` → 0x37a98):

| component | load site | verify wrapper | verify call |
|---|---|---|---|
| `lk` / `lk2` | 0x193aa (0x193bc wrapper) | 0x2f58 | 0x19d62 |
| `sspm` | 0x19b98 | 0x2f8c | 0x19ba0 |
| `cam_vpu1/2/3` | 0x193aa (3-iteration loop) | 0x2fc0 | 0x1952a |
| `spm` (spmfw) | 0x193aa | 0x2ff8 | 0x195c2 |
| `atf` | 0x1961e | 0x26034 | 0x19652 |
| `atf_dram` | 0x1968e | 0x26034 | 0x196ce |
| `tee` | 0x196fc | 0x26034 | 0x19716 |

**Negative result: there is no load-without-verify path.** A component-name
table at 0x2f569 lists eight names (`atf`, `atf_dram`, `mtee`, `sspm`,
`cam_vpu1/2/3`, `spm`); the presence of `mtee` for which no wrapper exists was
checked, and it does not correspond to any additional load site.

### 2. LK authenticates *its* images with certificates, not raw keys

LK contains **zero** calls to the preloader's key-based orchestrator. Its
verification path is entirely different, `amzn_image_verify` at **0x1238**:

```
01246  bl 0x38104            ; malloc(0x20)
0125e  blx 0x38388           ; memset(buf, 0, 0x20)
01268  bl 0x2c408            ; SHA-256(image) -> 32-byte digest
01274  bl 0x14b0             ; cert_verify(1, digest, ...)   <- PRODUCTION root
0127a  bl 0xe420             ; amzn_is_production_device()
01280  bne -> "Image FAILED AUTHENTICATION on PRODUCTION device"
012b4  bl 0x14b0             ; cert_verify(0, digest, ...)   <- ENGINEERING root
012c4  -> "Image AUTHENTICATED with PRODUCTION certificate"
```

Two call sites, 0x130ec and 0x13528, both inside a loop over images (the loop
counter is incremented/decremented around the call).

**Both trust anchors are embedded constants in LK**, selected by 0x1218:

| selector arg | pointer | length | artifact |
|---|---|---|---|
| non-zero | LK 0x4746c | 0x42f = 1071 | [lk-prod-ca-cert.der](lk-prod-ca-cert.der) |
| zero | LK 0x479c4 | 0x431 = 1073 | [lk-eng-ca-cert.der](lk-eng-ca-cert.der) |

(Lengths match the two `.der` files byte-for-byte, so the mapping is confirmed
rather than inferred.) Selection is driven by `amzn_is_production_device()`
(**0xe420**), which reads the byte at `**[0x938a0] + 0x59a7`; the same
platform-structure byte LK exports as `androidboot.prod`.

### 3. NEW ATTACK SURFACE: a hand-rolled certificate parser (LK 0x14b0)

`cert_verify` (0x14b0, ~1.7 KB) hand-parses a certificate chain. Its error
strings are the signature of manually written ASN.1/DER walking:

```
Failed to decode root certificate / user certificate
Unable to compute length of SubjectPublicKey
Failed to import certificate public key
Failed to extract root CA public key
tbsCertificate is empty
Failed to get tbsCertificate length
Failed to malloc tbsCertificate
Failed to encode tbsCertificate
Cannot find signature in user certificate    <- requires tag == 4
Invalid certificate 0 / 1 / 2
Failed to decode signature
Certificate authenticated
```

The flow is structurally correct, root cert public key (imported at 0x15fa via
0xc04c) verifies the user cert's signature over `SHA-256(tbsCertificate)` (hashed
at 0x174c–0x1772 through the `sha256` descriptor from 0x86ac), and the result
must be exactly `1` (`subs r1,#1` / `movne #-1` at 0x1782–0x1786).

**Why this still matters:** this is precisely the class of code where
**CVE-2023-20696** (ASN.1 parsing inconsistency → secure-boot bypass) lives. The
structure(one parse pass that authenticates, another that gets consumed) is
what the string set above hints at (`tbsCertificate is empty` vs
`Failed to get tbsCertificate length` vs `Failed to encode tbsCertificate` are
three *different* treatments of the same field).

### 4. The new vectors, and exactly what blocks each

| # | vector | what it would give | blocker |
|---|---|---|---|
| **V1** | Bug in the cert parser (0x14b0) → forge a boot-image certificate | **Persistent root**: custom `boot` image, dm-verity off, survives reboot (not a bootloader unlock) | Needs to *write* `boot`, and a wrong guess leaves LK rejecting the image. Requires a sacrificial unit or a proven recovery path. Not attempted. |
| **V2** | Flip the production flag (`+0x59a7`) → device reads as *engineering* | LK would accept **eng-CA-signed** images; the preloader would try the **alt** image key | Needs (a) the flag's provenance (fuse vs writable; not yet pinned; no `strb` to that offset was found, so likely fuse/platform-derived) **and** (b) an eng-signed image, which is not obtainable. Currently moot: this device reports `prod=1`. |
| **V3** | `lk2` selection (preloader 0x193bc picks `lk2` when `lk` is inactive) | boot a second LK slot | Dead: the selected image is still verified with **name `lk`** and the LK key, so an unsigned `lk2` cannot pass. Also needs a GPT write to create the partition. |
| **V4** | `-sig_len` underflow (see USB audit, Finding 5) | malformed-input failure | No bypass or write demonstrated; ends in hash error/reject. |
| **V5** | RPMB / `dkb` / `keys` partitions |; | `dkb` is **all-zero** and `keys` is an ext4 DRM filesystem; neither is on a boot verification path. |

### 5. Safe live diagnostics performed (read-only)

| check | result |
|---|---|
| `ro.boot.flash.locked` / `verifiedbootstate` | `1` / `green`; locked |
| `ro.boot.prod`, `ro.boot.secure_cpu` | `1`, `1`; production, secure ⇒ **ENG path unreachable** |
| `ro.boot.rpmb_state`, `mnt_keys_rw_opts` | `2`, `ro` |
| `/sys/block/mmcblk0boot{0,1}/force_ro` | `1` (writable by root via sysfs; IDME access confirmed) |
| listening sockets / root processes | only the known localhost services; no unexpected root listener |
| IDME (35 fields) | `bootmode=1`, `postmode=0`, `bootcount=0`, `unlock_code` empty, `unlock_version=5fc171a088b05201` (value at 0x2b18), `KB` 5120 B `KBPF`, `DKB` empty, `device_type_id`, `board_id`, `manufacturing` |
| `misc` partition (mmcblk0p4) | **entirely zero**: no bootloader control block set |
| `kb` (p1) / `dkb` (p2) / `keys` (p3) | `KBPF` sparse; **all-zero**; ext4 with `amzn_dhav2` DRM files |

### 6. Where this leaves the bypass question

The extended pass **added no working bypass**, but it did two useful things:

1. **Closed the last "is everything verified?" question**: yes, every image is,
   through a single orchestrator with a single pair of Amazon keys.
2. **Relocated the residual risk to a new, narrower place**: LK's hand-rolled
   certificate verifier (V1). That is where a real bug would have to be, it is a
   documented CVE class, and it is auditable offline; but exploiting it means
   writing the `boot` partition with an unproven parser bug, which is a
   destructive experiment.

The cryptographic position is unchanged: **the boot chain cannot be unlocked in
software without Amazon's private key.** What remains genuinely open is whether
the *certificate parser*(not the crypto) contains a logic error.

## LK certificate-parser audit (offline, 2026-10-06)

The follow-up promised in the previous section, plus the risk question that
turned out to matter more. All offline; no writes.

### 1. Structure of the LK image-verification path

| function | role |
|---|---|
| `amzn_image_verify` **0x1238** | SHA-256 the image (0x2c408), then `cert_verify(1, digest)` = **prod root**, else `cert_verify(0, digest)` = **eng root**; via `amzn_is_production_device` 0xe420 |
| `cert_verify` **0x14b0** | ~1.7 KB hand-rolled chain verify; selects the embedded root (0x4746c prod / 0x479c4 eng via 0x1218) |
| DER decoder **0xa06c** | TLV parse: tag, length, dispatch, build a node tree (nodes are **0x20 bytes**: `[0]=type [4]=ptr [8]=len [0xC]=tag [0x14]=next`) |
| length pass **0xaa50** | walks N nodes, computes the total *encoded* length |
| encoder **0xa69c** | re-encodes the node tree |
| tbsCertificate path | 0x1652 (`0xaa50` length) → 0x1666 malloc → 0x168e (`0xa69c` encode) |

### 2. DER length decoder: bounds are correct (negative result)

```
00a0ba  cmp  r1, #1 / ldrb r5,[r6]        ; inlen check, tag = in[0]
00a0c0  ldrb r2, [r6, #1]                 ; length byte
00a0c2  cmp  r2, #0x7f / bhi 0xa138       ; short vs long form
00a0c6  adds r3, r2, #2                   ; short: total = len + 2
00a0cc  cmp  r3, r1 / bhi.w 0xa4c0        ; ** total <= inlen, else error **
...
00a138  and  ip, r2, #0x7f                ; nlen = lenbyte & 0x7f
00a13c  add.w r3, ip, #-1 / cmp r3,#3     ; ** nlen <= 4 **
00a142  bhi  0xa16c                       ; else error
00a144  subs r0, r1, #2 / cmp ip,r0       ; ** nlen <= inlen-2 **
00a148  bhi  0xa16c                       ; else error
00a14a..0xa160                            ; accumulate nlen length bytes
00a162  add  r3, fp                       ; total = payload + header
00a164  b    0xa0cc                       ; same total<=inlen check applies
```

**All four classic guards are present and correct**: length-of-length bounded at
4, enough bytes present for the length field, and the derived total checked
against the input length in *both* forms. The naive "declared length exceeds
buffer" overflow is **not available here**.

One asymmetry worth recording: the long-form size selector
(0xab6c–0xab8e) uses `0xfffe` as the 2-byte threshold rather than `0xffff`, so a
declared length of exactly `0xffff` takes the 5-byte branch. That **over**-counts
by one byte; the safe direction.

### 3. The dual-parse is present but not yet proven unequal

The tbsCertificate path *is* the CVE-2023-20696 shape: one pass computes a
length (`0xaa50`), a buffer is allocated from it, and a **second, independent
pass re-encodes** into that buffer (`0xa69c`). If the two ever disagree, the
encode overflows the allocation.

What I established:

* the type-dispatch bound is **identical** in both, length at 0xaab0
  (`cmp ip, #0x12` → `bhi skip`) and encode at 0xa70c (same), so a
  *type-domain* mismatch (one pass handling a type the other ignores) is
  **excluded**;
* both read the same node layout (`[0]`=type, `[4]`=ptr, `[8]`=len).

What I did **not** establish, and is the remaining work: per-type equality of
`length_added(type)` vs `bytes_written(type)` for all 19 entries. The two
jump tables point at different code by construction, so this needs a
case-by-case comparison (19 handler pairs at table A 0xaac0–0xab0c and table B
0xa71c–0xa768). That is mechanical but not done, **no bug found, no bug
excluded.**

### 4. What LK does when an image fails verification (the risk answer)

This turned out to be more decision-relevant than the parser audit.

```
040504  push                     ; display(name)
040516..04053c  strlen(name), copy into a 0x20 buffer
04054a  bl  0x374e4 / 0x374d8 / 0x374a0   ; framebuffer / logo setup
04056e  print 0x8014e
040576  print "Please download %s image with correct signature"
040580  print 0x8018f
040588  print "Your device will reboot in 5 seconds."
040590  bl  0x19494
040594  movw r0, #0x1388          ; 5000 ms
040598  bl  0x44abc               ; delay
0405a0  mov.w r0, #-1             ; return -1
0405a6  pop
```

Wrapper **0x405c0** (state machine on the global at `0x935b4`): state 1 →
0x404b4 (alternate UI, returns 0); states 2/3 → the failure UI above → `-1`;
otherwise returns 0. The verify wrappers **0x12420 / 0x12450** reset that global,
call the verify at **0x40444**, and on failure call 0x405c0. The boot-image
loader (0x12ac8, called with the string `"boot"` from 0x78605) just returns the
result.

**So: a failed boot-image verification is a display-and-return path, not a
panic.** Contrast the preloader's rejection of LK, which is the dead loop with
no LK running at all. This is a categorical difference in failure severity:

| failure | what is still running | severity |
|---|---|---|
| `lk` fails preloader verification | **nothing** (preloader loop only) | S2; confirmed unrecoverable |
| `boot` fails LK verification | **LK, with its full fastboot** | displays message, 5 s, returns `-1` |

### 5. LK-side recovery affordances (relevant to stage3)

| affordance | string / site |
|---|---|
| fastboot `oem reboot-recovery` | 0x79845 |
| fastboot `reboot-bootloader` | 0x7979e |
| fastboot entry by key combo | 0x29a5c (`platform[0x5b4]` bit 13) |
| **fallback**: `IDME initialize failed, force to fastboot mode` | 0x58909 (code 0x116a4) |
| `=> FASTBOOT mode...` on MAC mismatch | 0x587d9 (code 0x1140e) |
| boot-mode selector (`app/mt_boot/mt_boot.c`) with a **recovery** image load path | 0x3031e loads `"recovery"`; 0x30352 |
| locked-device fastboot gate | 0x313ee → **0xdd00**, message 0x79510 "the command you input is restricted on locked hw" |
| explicit refusals | 0x7a98c "flash preloader is not permitted." (code 0x337c6); 0x4b947 "Only usr_flags can be set for a locked device" |

**Not resolved:** the *contents* of the locked-hw allow/deny lists. The helper
0xdd00 is default-allow with denials coming from tables reached via `add rX, pc`
(0x8386c / 0x83880) and from runtime lists populated by 0x2c868 / 0x2c87c, but
the static tables resolve to libtomcrypt source-path strings, which is
incoherent for a command list. Either 0xdd00 is a generic list-membership helper
whose lists are populated at runtime, or my table base resolution is off. **This
needs a dedicated pass before any conclusion about `fastboot flash boot` on a
locked device is drawn.**

### 6. Net effect on the audit

* The DER decoder's bounds are correct; the naive overflow is ruled out.
* The dual-parse exists and is *not yet excluded*; that is the one open
  parser-audit thread, and it is mechanical to close.
* The failure-mode finding is the actionable one: a bad `boot` image leaves LK
  running, so it is a materially different (and lower) risk class than writing
  `lk`. **But** whether fastboot can then *restore* the image on a locked device
  is unresolved (§5), so "LK still runs" is not yet "we can recover".

## LibTomCrypt dependency audit (offline, 2026-10-06)

Follow-up to the certificate-parser audit, prompted by the observation that one
of the strings I had flagged as a suspect "command table" was
`.../libtomcrypt/src/pk/ecc/ltc_ecc_mul2add.c`. That string was the thread:
**LK's certificate path is stock LibTomCrypt, not Amazon-authored code.**

### 1. What is actually linked into LK

LK contains **60** `/…/features/libtomcrypt/src/…` source paths (the preloader
contains none; it uses its own RSA/PSS path, see "Container-header audit").
Grouped:

| area | modules |
|---|---|
| hashes | `sha2/sha256`, `helper/hash_memory`, `helper/hash_memory_multi` |
| math | `math/ltm_desc`, `math/rand_prime` |
| misc | `base64_decode/encode`, `crypt_find_hash`, `crypt_register_hash`, `mem_neq`, `zeromem` |
| pk/asn1/der | **all** of: bit (+raw), boolean, **choice**, ia5, integer, object_identifier, octet, printable_string, sequence (`_ex`, `_flexi`, `_multi`), **subject_public_key_info**, short_integer, teletex_string, utctime, utf8; each in decode/encode/length form |
| pk/pkcs1 | `pkcs_1_mgf1`, `pkcs_1_pss_decode` |
| pk/rsa | `rsa_exptmod`, `rsa_free`, `rsa_import`, `rsa_make_key`, `rsa_verify_hash` |
| pk/ecc | `ltc_ecc_map`, `ltc_ecc_mul2add`, `ltc_ecc_mulmod_timing`, `ltc_ecc_projective_add_point`, `ltc_ecc_projective_dbl_point` |

Observations:

* The **DER module set is complete for both decode and encode**, which is what
  makes LK able to *re-encode* a parsed structure at all; that capability is the
  precondition for the CVE-2023-20696 class.
* Presence of `der_decode_raw_bit_string` / `der_encode_raw_bit_string` and the
  `LTC_ASN1_RAW_BIT_STRING` node type (**type 0x10** in the tables below) place
  this at **LibTomCrypt ≥ 1.18**.
* `rsa_make_key` + `rand_prime` are present, i.e. a key-*generation* path is
  linked, which is unusual for a bootloader. Not investigated; worth knowing.
* ECC is only a 5-module fragment (point arithmetic, no import/verify/ECDSA), so
  it is unlikely to be an active verification path, but it is why the string I
  first flagged as a "command table" was an ECC source path.

### 2. Function identification (this corrects the previous section)

| address | function | evidence |
|---|---|---|
| **0xa06c** | `der_decode_sequence_flexi` | error path loads `unsigned long der_decode_sequence_flexi(...)`-context strings `in != NULL` / `inlen != NULL` / `out != NULL` and the path `pk/asn1/der/sequence/der_decode_sequence_flexi.c` (0x4a4a5) |
| **0xaa50** | `der_length_sequence` | `list != NULL` / `outlen != NULL` + path `…/der_length_sequence.c` (0x4a711) |
| **0xa69c** | `der_encode_sequence_ex` | `list != NULL` / `out != NULL` / `outlen != NULL` + path `…/der_encode_sequence_ex.c` (0x4a683) |
| 0xaf88, 0x8c40, 0x9a84, 0x9840, 0x9194, 0x9ccc, 0xb0ec, 0xb58c, 0xb8bc, 0x94f8 | per-type DER length primitives | called from the dispatch tables |

So the previous section's description of a "hand-rolled ASN.1/DER parser" was
**wrong in attribution**: it is upstream library code with Amazon build paths
baked in. The node layout is LibTomCrypt's `ltc_asn1_list` (0x20 bytes:
`[0]=type`, `[4]=data`, `[8]=size`, `[0xC]=tag`, `[0x14]=next`).

### 3. The 19 type-handler pairs, compared

Both functions dispatch through a 19-entry jump table (type 1 … type 19):

| | table | bound check |
|---|---|---|
| `der_length_sequence` | 0xaac0–0xab0c | 0xaab0 `cmp ip,#0x12` / `bhi` → skip |
| `der_encode_sequence_ex` | 0xa71c–0xa768 | 0xa70c `cmp ip,#0x12` / `bhi` → skip |

**Identical type bound** → a type-domain mismatch (one pass handling a type the
other silently ignores) is **excluded**.

Per-type findings:

* **Sequence family (types 0x0d/0x0e/0x0f)**: both sides call `der_length_sequence`
  (0xaa50) for the nested content and add the nested total. Consistent.
* **Length-of-length arithmetic**:
  * encoder *outer* header (0xa6f8 → 0xa7d2): `≤0x7f → +2`, `≤0xff → +3`,
    `≤0xffff → +4`, `≤0xffffff → +5`, else `CRYPT_INVALID_ARG` (0xaa30).
  * length *final* header (0xaaa4 → 0xab90): `≤0x7f → +2`, `≤0xff → +3`,
    `≤0x10000 → +4`, `≤0x1000000 → +5`, else `CRYPT_INVALID_ARG` (0xabb2).
  * **The two agree** (0x10000 vs 0xffff is the same boundary).
* **One genuine asymmetry, in the safe direction:** the **CUSTOM_TYPE** length
  handler (0xab6c) uses `0xFFFE` as its 2-byte threshold rather than `0xFFFF`
  (`movw sl,#0xfffe` at 0xaa6e). For a nested content length of exactly `0xffff`
  it therefore computes `+5` where `+4` suffices; it **over**-states the length
  by one byte, i.e. the allocation is one byte larger than the writer needs.
* **Two fail-closed asymmetries:** `der_encode_sequence_ex` returns
  `CRYPT_INVALID_ARG` for **LTC_ASN1_CHOICE (0x0c)** and **LTC_ASN1_TELETEX_STRING
  (0x11)** (both encode-table entries point at 0xaa30, the error return), while
  `der_length_sequence` *does* compute a length for TELETEX. A certificate whose
  re-encoded sequence contains a TELETEX_STRING therefore **errors out rather
  than overflows**. That is the safe direction.

### 4. Result

> **No length/encode mismatch was found.** The dispatch domains are identical,
> the length-of-length boundaries agree, and every asymmetry identified is either
> an over-allocation (CUSTOM_TYPE `0xFFFE`) or a hard error (CHOICE,
> TELETEX_STRING in the encoder).

**Consequences:**

* Vector **V1** (a DER logic bug enabling a custom `boot` image) currently has
  **no identified bug**, so it is not worth a destructive test. The residual
  LibTomCrypt avenue would be a CVE specific to the pinned version, which needs
  the version identified (≥1.18 from the module set) and a matching advisory.
* The failure mode *if* such a bug existed is still bounded and much safer than an
  `lk` write: a failed `boot` verification makes LK display a message, wait 5 s
  and return `-1` (see "LK certificate-parser audit" §4), leaving LK and fastboot
  running. See [../stage3-recovery/README.md](../stage3-recovery/README.md) §3.

### 5. Methodology note

This is the second time a "suspicious custom parser" turned out to be stock
library code (the first being the preloader's generic image loader). Worth
remembering when reading the earlier sections: a hand-rolled-looking error-string
set does not imply hand-rolled code, and **checking the provenance of strings
before auditing the logic** would have saved a pass. The practical version of
that lesson: when a table of strings looks incoherent for its apparent purpose,
suspect a shared literal pool rather than a bug.

## Open questions closed (session 2, 2026-10-06)

Continuation of the ATF_DRAM work above. Two of the outstanding questions are now
answered, and the third is proved **not answerable offline** -- which corrects the
scoping note in section 4 of the ATF_DRAM section.

### A. `boot_para` has exactly one consumer, and it is the DRAM self-test

A full string cross-reference (`tools/pl-xref.py`, 1232 refs in the preloader)
finds **one** reference to the `boot_para` partition name in the entire image:

```
code 016930 -> str 030f6e 'boot_para'
```

It sits in the `[dramc]` cluster, in a function at `0x16920`:

```
016922  movw r0, #0xd8a3      ; PL_VERSION descriptor
016926  bl   #0x20450
01692a  str  r0, [r3]         ; cache PL_VERSION
016930  ldr  r0, -> 'boot_para'
016934  bl   #0x15ebc         ; blkdev lookup BY NAME -> r0:r1 = 64-bit base
016940  strd r2, r3, [r1]     ; cache the partition address
016948  beq  #0x16954         ; address == 0 -> 'init partition address is incorrect !!!'
01694a  -> '[dramc] init partition address is 0x%llx'
016954  -> '[dramc] init partition address is incorrect !!!'
01695c  ... magic compared against 19870611
016994  ldr r2, [r3, #0x18]   ; DRAM_FATAL_ERR_FLAG
016996  str r2, [r3, #0x14]   ; LAST_DRAM_FATAL_ERR_FLAG = previous value
0169ac  str #0x80000000,[r3,#0x18]   ; arm the detection latch (bit 31)
```

The caller graph is a clean funnel -- every consumer lives in one function:

| target | meaning | callers |
|---|---|---|
| `0x16920` | `boot_para` DRAM-exception setup | **0x1ab0a only** |
| `0x16884` | `LAST_DRAM_FATAL_ERR_FLAG` accessor | **0x1ab0e only** |
| `0x16854` | `DRAM_FATAL_ERR_FLAG` accessor | **0x1ac0c only** |

That function (`0x1ab00`-`0x1ac60`) is the **DRAM calibration / complex memory
self-test**:

```
0x1ab0a -> 0x16920   read the boot_para record
0x1ab0e -> 0x16884   read LAST_DRAM_FATAL_ERR_FLAG
0x1ab14  '[save time for cal] dram fatal exception found -> clear calibration data'
0x1ab30  '[save time for cal] clean_dram_calibration_data done (ret=%d)'
0x1ab8a  '[%s] 1st complex R/W mem test pass (start addr:0x%x)'
0x1ab9c  '[%s] 1st complex R/W mem test fail :%x (start addr:0x%x)'
0x1abd2  '[%s] 2nd complex R/W mem test pass (start addr:0x%x, 0x0 @Rank1)'
0x1abe2  '[%s] 2nd complex R/W mem test fail :%x (start addr:0x%x, 0x0 @Rank1)'
0x1ac0c -> 0x16854   read DRAM_FATAL_ERR_FLAG
0x1ac14  '[dramc] fatal dram exception found! reset system..'
```

Semantics: a fatal DRAM error from the previous boot, latched in `boot_para`,
causes the saved calibration data to be discarded so the next boot re-calibrates;
the self-test then runs, and a *new* fatal error resets the system. `boot_para` is
the only place this state survives a reboot, and it is read and written only here.

The accessors mask bit 31 off (`bic r0, r0, #0x80000000`) before testing -- bit 31
is the "armed" flag that `0x169ac` sets, not an error bit. They also mask the low
5 bits.

### B. The RTC "enter first boot/recovery" trigger is four range checks

`0x252c0` is not a branch target inside `rtc_init` -- it is a shared out-of-line
block reached by four long conditional branches from a different function:

```
024f2a  bhi.w #0x252c0
024f36  bhs.w #0x252c0
024f44  bhi.w #0x252c0
024f5a  bhi.w #0x252c0
```

The conditions are four range checks on `u16` values fetched from the RTC
(`bl 0x23bf4` fills a 4 x u16 buffer at `sp+8`):

| value | test | valid range |
|---|---|---|
| `[sp+8]`   | `(v-3) > 4` (unsigned) | `3..7` |
| `[sp+0xa]` | `v >= 0x1f4`           | `0..499` |
| `[sp+0xc]` | `(v-3) > 5` (unsigned) | `3..8` |
| `[sp+0xe]` | `(v-0x12d) > 0x2772`   | `0x12d..0x289f` |

These are the RTC's stored 32K/oscillator calibration values, so this is a
**sanity check on RTC calibration data**. On failure the shared block prints
`[RTC]RTC 32K mode setting wrong. Enter first boot/recovery.`, sets **`r4 = 1`**
(the error flag -- the success path sets `r4 = 0` at `0x24f5e`), and rejoins the
caller at `0x24f60`. It is a warning plus fallback flag, **not** an immediate
reboot.

Earlier in the same function `0x24ed4`-`0x24f0c` compares RTC registers `0x5be`,
`0x5c4`, `0x5b0`, `0x5b2` against `0xa357` and `0x67d2` -- a "has the RTC ever
been initialised" latch.

### C. Why the ATF side is NOT answerable offline (correcting the earlier note)

The ATF_DRAM section says the bodies' high entropy "does not establish that the
*loader's decryption* cannot be reproduced", and that modelling the decrypt
routine "is the way to settle (i) what an oversized tail decrypts to and
(ii) whether ATF re-validates LK after handoff". **That is wrong, and this is the
correction.**

Modelling the routine reproduces its *control flow*; it does not yield plaintext.
Re-measured entropy of the three bodies:

| component | body length | entropy |
|---|---|---|
| `atf` | 0x139c0 | 7.996 |
| `atf_dram` | 0xd7c0 | 7.994 |
| `tee` | 0x2b5dc0 | **8.000** |

2.8 MB at exactly 8.000 bits/byte is encryption, not compression. The key is not
in the images:

* the preloader carries only RSA **public** moduli for verification
  (`pl-image-verify-pubkey-modulus.bin`, `pl-unlock-pubkey-modulus.bin`) and says
  so -- `Error: fail to do rsa2048 public key decryption`, `Succeed to verify %s
  with prod key`, `Only try verify %s with prod key on locked production device`;
* decryption is done by MTK's **hardware crypto engine** using efuse-derived
  secure-boot keys: `sec_boot_check`, `sbc_enabled: 0x%x`, `EFUSE Self Blow`,
  `Efuse status(%x)`, and in LK `[SEC] crypto engine HW disable fail`;
* efuse is only reachable over BROM, and BROM access on this unit is already
  established as unavailable -- every exploit in the mtkclient chain is
  BROM-stage (see the mtkclient assessment above).

=> **(i) and (ii) remain unresolved and are not reachable by offline analysis with
the access this project has.** Both need the ATF/TEE plaintext, which needs a key
this host cannot obtain. The useful consequence: treat the ATF_DRAM vector as
*unverifiable* rather than *promising*, and do not spend effort on a decryption
model.

### D. Tool: `tools/pl-xref.py`, and two silent-failure traps it avoids

Cross-referencing the preloader for the work above was blocked by tooling: the
existing `pl-disasm.py` reports **zero** string references for any range it is not
started on a valid instruction boundary, and `_string_ref`'s inline comment ("the
literal holds a *file offset*, so the resolved value is already the file offset")
contradicts its own module docstring and the actual arithmetic. The arithmetic is
right -- `target = literal + add_pc_addr + 4`; the comment is not.

Two traps worth recording:

1. **Alignment.** Started at `0x800`, capstone desynchronises on the interleaved
   literal pools and decodes the rest of the image to garbage, silently returning
   *zero* references. Disassembly must begin on a function boundary. There are also
   4-byte non-code gaps between functions (e.g. `0x1691c`).
2. **Immediate scaling.** In `LDR` (literal) T1 the immediate is in **words**
   (`imm8 << 2`), not bytes. Scaling it wrong places the literal read 4x too close
   to the instruction, so the displacement is garbage and every reference is missed
   -- again silently.

`tools/pl-xref.py` is alignment-independent (it scans for the halfword encodings
instead of trusting the decoder) and handles both the T1 and Thumb-2 `ldr.w`
forms. It resolves **1232** references in the preloader and **4063** in LK, against
0 for the previous approach, and is validated against the known site:
`0x252c0 -> 0x35af7`.

## Hard rules (unchanged)

- No writes to `lk`, `preloader`, `tee*`, `sspm_1`, `spmfw`, `cam_vpu*`,
  `boot`, or partition-table metadata; the preloader verify is now PROVEN,
  and a failure is a proven unrecoverable brick.
- The pre-auth copy primitive in the section above does **not** relax this: an
  LK image that fails verification still bricks the device, and the primitive is
  only useful if the payload wins *during* the copy, which needs the DRAM map
  first. Treat LK writes as one-shot/high-risk until that map is proven.
- `fastboot flash:unlock <garbage>` is fail-safe per the code (verify → do
  nothing), but there is no reason to test it live.
- IDME writes via root are possible but pointless without a signed code.

## RE artifacts & method

- LK: `dumps/trona-1735/mmcblk0p5.bin` (== OTA `lk.img` byte-for-byte; loads
  at VA 0x56000000; ARM32 vector table at 0x200, Thumb-2 code; string refs are
  PC-relative file offsets: `literal + (add_pc_addr + 4)`).
- Preloader: `dumps/trona-1735/mmcblk0boot0.bin` (== OTA `preloader.img`;
  `EMMC_BOOT` header; Thumb-2; same PC-relative string method).
- IDME: `dumps/trona-1735/mmcblk0boot1.bin`.
- Key function map (file offsets):

| Function | LK | Preloader |
|---|---|---|
| `amzn_verify_unlock` | 0x1ce0 |; |
| `amzn_verify_code_internal` (RSA) | 0x1ba8 |; |
| unlock check (AMZN_UNLOCK) |; | 0x33e0 |
| unlock-code compose | 0xe43c (fmt `'0x%08x%08x%08x'` @ 0x4bbde) | 0x33e0 (hex helper 0x33a0) |
| platform-info getter (ids 12/13) | 0x11f70 | 0x2d5cc (via 0x19378) |
| PSS verify (AMZN_PL_VERIFY) |; | 0x2b48 |
| LK load + verify orchestration |; | 0x2c60 |
| amzn_image_verify (cert-based, LK) | 0x1238 (roots: 0x4746c prod / 0x479c4 eng via 0x1218) |; |
| cert_verify (uses LibTomCrypt DER) | 0x14b0 |; |
| cert verify result check (`== 1`) | 0x1782–0x1786 |; |
| der_decode_sequence_flexi (LibTomCrypt) | 0xa06c |; |
| der_length_sequence (LibTomCrypt) | 0xaa50 |; |
| der_encode_sequence_ex (LibTomCrypt) | 0xa69c |; |
| LK: infinite "no recovery" busy-wait | 0x0b90 (`b 0xb90`) |; |
| amzn_is_production_device | 0xe420 (`**[0x938a0]+0x59a7`) |; |
| verify wrappers (lk/sspm/vpux/spm) |; | 0x2f58 / 0x2f8c / 0x2fc0 / 0x2ff8 |
| generic named-image loader |; | 0x1937c → 0x200f4 |
| `flash:unlock` handler | 0xe656 |; || tucert/tucode writer | 0xe6b4 |; |
| is_unlocked (boot status) | 0xe5a8 |; |
| unlock status → cmdline | 0x13100 region |; |
| `getvar:unlock_code` handler | 0xe5f0 |; |
| usbdl handshake entry |; | 0x17d1c (called from main 0x19a22) |
| usbdl command loop |; | 0x5658–0x5c06 |
| usbdl DA auth (secure-chip gate) |; | 0x5800 (secure check 0x2d5ac) |
| usbdl JUMP_DA0 (cmd 0xd5) |; | 0x592e (DA-auth flag gate) |
| usbdl dead-loop brick (cmd 0x80) |; | 0x599c |
| usbdl mem R/W range check |; | 0x258e4 → 0x25874 (tables @ 0x3b68c/0x3b69c) |
| misc `boot-recovery` check | 0x2c028 (strcmp @ 0x2c07c) |; |
| fastboot key detect | 0x29a5c (platform[0x5b4] bit 13) |; |
| dev/fos flags → cmdline | 0x2c150–0x2c22c |; |
| LK loader wrapper (lk/lk2 select) |; | 0x193bc |
| PICACHU module entry (called with r0=0x5F000000) |; | 0x29a44 (from 0x21590, itself from 0x19fcc) |
| module body w/ context save |; | 0x29728 (SAVE 0x296f0, sole caller 0x298b4) |
| arms RESTORE into external handler |; | 0x29954 (site 0x299e0, handler = *(0x3c2a8)) |
| "image with header" loader |; | 0x200f4 (dest +0x200 read @ 0x20180, size writeback @ 0x20278) |
| container header parse (magic check) |; | 0x2007c (magic const @ 0x200e0) |
| container header parse (variant/align) |; | 0x18c00 (magic const @ 0x18cc4) |
| `get_img_size` (recomputes size) |; | 0x2b260 |
| key getters (alt / prod / unlock) |; | 0x2b24 → 0x37a98, 0x2b30 → 0x37b98, 0x2b3c → 0x37c98 |
| AMZN_PL_VERIFY (PSS + key arg) |; | 0x2b48 (RSA op 0x2bc30, hw SHA-256 0x2bc2a) |
| "no version magic" unsigned-image path |; | 0x2db2 (gated by 0x2d59c = SEC_CFG bit 1) |
| block read helper (unaligned head/tail) |; | 0x45dc → 0x25976 |
| `g_dram_buf` init (= 0x44800000) |; | 0x5c34–0x5c8c |
| mblock info block (g_dram_buf+0x9de00) |; | 0x19ffa / 0x1a014 / 0x1a140 |
| context save / restore (slot 0x5f100c00) |; | 0x296f0 / 0x291a4 (cref from 0x299e0) |
| card block-range check (`sd_blknr`) |; | 0x1b93a, 0x1b9b2 (string @ 0x32fcd) |
| usbdl loop prologue (r4=sp+0x30, r5=sp+0x28) |; | 0x5584 |
| USB read/write vtable helpers |; | read 0x5388 (u32 BE), 0x5358 (u16), write 0x5324 |
| SEND_DA handler (0xD7) |; | 0x5700 (copy 0x5754, bound check 0x5850) |
| DA destination constant |; | 0x40200000 (lit @ 0x59e0) |
| DA auth / "DA authenticated" |; | 0x5834, 0x5850, 0x5872 |
| JUMP_DA handler (0xD5) + trampoline |; | 0x592e, trampoline slot 0x401ffff4 |
| READ32/WRITE32 handlers (0xD1/0xD4) |; | 0x5a84 / 0x5ae0 (guards 0x5aa4-0x5ab2, 0x5b02-0x5b10) |
| PMIC (PWRAP) field read/write |; | 0x22100 / 0x22138 → 0x22bf0 → 0x22b54 (regs 0x1000dc20/24/28) |

Reproduction: `python stage2-unlock/verify-lk-signature.py` (dependency-free
PSS, cross-checked against `cryptography`) proves the key/range facts above
from the local images; `python stage2-unlock/verify-tee-signature.py` does the
same for the three wrapped `tee.img` components (outer vs inner length
separation, reservation field, signature boundary).
