# Stage 3: Recovery, validation, and experiment safety

## TL;DR: read this first

Recovery is **partition-dependent**, and that is the single most important thing this
stage established. Whether a damaged unit can be recovered depends entirely on *which*
partition is damaged, not on how the damage was caused.

| failure state | recovery | verdict |
|---|---|---|
| **S1**: bad `boot`, chain intact | recovery + a newer OTA | **recoverable** |
| **S2**: `lk` fails preloader verification | none software; usbdl is auth-gated | **not recoverable in place** |
| **S3/S4**: `preloader` / eMMC unreadable | eMMC ISP (hardware) | hardware only |

- **Core finding**: every software recovery route (fastboot, recovery, OTA) requires
  **LK to run**, so a bad `lk` closes all of them at once. That is why S2 has no
  software exit and why the documented XDA brick is permanent.
- **Core finding**: LK fastboot **is** reachable and now verified live, but the
  locked-device gate is a strict allowlist: it refuses **every** write and **every**
  `oem` command, evaluated at command dispatch *before* partition lookup. So
  `fastboot flash boot` cannot repair a damaged `boot`, and `oem reboot-recovery`
  cannot reach recovery.
- **Core win**: the S1 route is real (recovery + a **newer** OTA; the PS7319/1726 OTA
  will not apply to a 1735 device), and the gate's fail-closed behaviour means fastboot
  is *safe to probe*; a mistyped destructive command cannot reach flash.
- **Core dead end**: recovery is **not a foundation for further development**. It does
  not unlock experiment safety for `lk`, it cannot be used to iterate, and the one
  remaining route (S2/S3) is hardware.
- **Not claimed**: no recovery path has been exercised end-to-end; only fastboot
  *reachability* is proven. See §6.

Purpose: make risky Stage-2/Stage-2a experiments *decision-safe* by answering,
before each one, "if this goes wrong, how do we get back?" This document is
organised around the three experiment classes the project actually wants to run,
then answers the recovery question for each.

---

## 0. Read this first: the recovery matrix

| failure state | what still runs | recovery routes available | verdict |
|---|---|---|---|
| **S1**: `boot` bad, chain intact | preloader → LK → recovery | **recovery + a newer OTA** (see §0.3). LK fastboot is reachable but **cannot write** while locked (§0.4) | **recoverable** |
| **S2**: `lk` fails preloader verification | **preloader only** (re-enumeration loop) | none software; MTK usbdl is auth-gated | **not recoverable in place** |
| **S3**: `preloader` (boot0) damaged | BootROM only | hardware (eMMC ISP) | hardware only |
| **S4**: eMMC/boot0 unreadable | BootROM only | hardware | hardware only |

**The single most important line in this document:** recovery works for S1 and
not for S2, because *every* software recovery route (fastboot, recovery, OTA)
requires LK to run. This is why the experiment classes below are ordered by
how deep they reach into the chain.

### 0.4 PROVEN (live, 2026-10-06): the locked-device gate refuses every write

Being able to *reach* fastboot is not the same as being able to *write* from it. The
device is locked (`unlock_status: false`), and LK enforces a strict allowlist:

* exactly **six** `getvar` names are readable, `product`, `unlock_status`,
  `unlock_code`, `serialno`, `max-download-size`, `slot-count`. All 42 others tried
  are refused, and so is `getvar all`;
* **every** `oem` command is refused, including `oem device-info`, `oem getvar`,
  `oem lks` and **`oem reboot-recovery`**;
* the refusal is always `FAILED (remote: 'the command you input is restricted on
  locked hw')`, string 0x79510, the gate at LK `0x313ee → 0xdd00`.

**The decisive test.** `erase` and `format` of a deliberately nonexistent partition
were refused *by the gate rather than with "partition not found"*:

```
$ fastboot erase no_such_part_zzz
Erasing 'no_such_part_zzz'                     FAILED (remote: 'the command you input is restricted on locked hw')
```

That ordering proves the gate is evaluated at **command dispatch, before partition
lookup**, i.e. before any write is even considered. Consequences:

* **`fastboot flash boot` cannot repair a damaged `boot` while the device is locked.**
  It is refused before the partition name is resolved, so this is not a
  "correct partition name" problem.
* **`oem reboot-recovery` cannot be used to enter recovery from fastboot**, so the
  S1 "recovery + OTA" route needs a different way in (the BCB in `/misc`, the
  preloader RTC trigger, or a physical key combination).
* It also means fastboot is **safe to probe**: the gate is the first thing that runs,
  so a mistyped destructive command cannot reach flash.

Evidence: [../diagnostics/fastboot-gate-probe.txt](../diagnostics/fastboot-gate-probe.txt).
Note `unlock_code` *is* readable despite the gate, `0x201197ff6793b2aea071c15f` on the
reference unit, a value previously only inferred from the binary.

### 0.1 PROVEN (live, 2026-10-06): LK fastboot is reachable

```
$ adb reboot bootloader
... device disappears from adb ...
[USB] VID_1949 PID_05E0  Class_FF SubClass_42 Prot_03   <- Amazon fastboot
```

* `VID_1949` = Amazon Labs; `PID_05E0` is this device's bootloader mode.
* **`Class_FF / SubClass_42 / Prot_03` is the standard fastboot interface
  signature**: this is fastboot, not some vendor variant.
* The device stayed in fastboot for >4 minutes without self-resetting, and the
  instance ID carries the device serial (`<SERIAL>`), so it is definitely
  this unit.
* **Host blocker, SOLVED (2026-10-06).** Out of the box Windows reports
  `ProblemCode 28` (no driver bound) and `fastboot devices` prints nothing, because
  nothing signed matches: Microsoft's signed `winusb.inf` auto-binds only the **ADB**
  class (`Class_ff&SubClass_42&Prot_**01**`), and Amazon's official kindle driver lists
  **no `PID_05E0`**. A working WinUSB INF plus reproducible build/sign/install tooling
  is in [host/winusb-fastboot/](host/winusb-fastboot/), **Zadig was not needed**, and
  the earlier recommendation of it here was wrong. See that folder's README for the
  one non-obvious requirement: the INF must register Android's interface GUID
  `{F72FE0D4-…}`, or the driver installs and reports working while fastboot stays blind.

**Why this matters:** every S1 recovery route below depends on reaching fastboot.
Until now that was an assumption; it is now an observation, and note that being able
to *reach* fastboot is not the same as being able to *write* from it, which §0.4 covers.

### 0.2 PROVEN (live): the preloader exposes MTK USB on every boot

During the same reboot, the device briefly enumerated as:

```
[USB] VID_0E8D PID_2000   "USB Serial Device (COM3)"   (~2 s window)
```

`0E8D` is MediaTek, and `0x2000` is in mtkclient's preloader/BROM ID table. This
is the **preloader's own `usbdl` interface**: the one audited in stage2-unlock
(SEND_DA/JUMP_DA, DA-auth gated). It confirms the preloader's USB is live on every
boot and that the window is short. It does **not** provide a write path.

### 0.3 The OTA is a full restore: but only from a running system

The OTA updater script writes **everything**:

```
package_extract_file("boot.img",             .../by-name/boot);
package_extract_file("images/preloader.img", .../by-name/preloader);
package_extract_file("images/lk.img",        .../by-name/lk);
package_extract_file("images/tee.img",       .../by-name/tee1);
package_extract_file("images/tee.img",       .../by-name/tee2);
package_extract_file("images/spmfw.img",     .../by-name/spmfw);
package_extract_file("images/sspm.img",      .../by-name/sspm_1);
package_extract_file("images/cam_vpu1..3.img", ...);   + system + vendor
```

So an OTA is a **complete image-level restore** of the boot chain, including
`preloader` and `lk`. Two caveats decide whether it is usable:

**(a) It runs in recovery, which LK boots.** → useless for S2/S3. It is an S1
recovery tool only.

**(b) There is a downgrade guard.** The PS7319/1726 package begins with:

```
(!less_than_int(1619231913, getprop("ro.build.date.utc"))) ||
  abort("E3003: Can't install this package (Sat Apr 24 02:38:33 UTC 2021)
         over newer build (" + getprop("ro.build.date") + ").");
```

This device: `ro.build.date.utc = 1622314026` (2021-05-29, build 1735).
`1619231913 < 1622314026` → the guard **fires** → **the 1726 OTA CANNOT be
applied to this device.** Not a hypothetical; the arithmetic is exact.

| OTA in `OTAs/` | package date | passes guard on this device? |
|---|---|---|
| PS7319 / 1726 | 2021-04-24 | **NO** (device is newer) |
| PS7321 / 2324 | newer | yes |
| PS7326 / 3178 | newer | yes |
| PS7331 / 4463 | newer | yes |

**Consequence:** for S1 recovery the useful packages are the **newer** ones
(PS7321 / PS7326 / PS7331), *not* the 1726 package the project has been
analysing. All target `trona`. Applying one upgrades the device as a side effect.

**So S1 recovery has two independent routes:** fastboot (reflash stock images) or
recovery + a newer OTA. Both need LK alive.

---

## 1. Scenario A: `lk` diagnostics / exploit validation

**What this class means:** experiments that read or modify the `lk` partition, or
that rely on LK's own behaviour (its fastboot, its IDME handling, its image
verification).

| | |
|---|---|
| **Preconditions** | tethered root (stage1-root) to read/write `mmcblk0p5`; full backup of `lk`; fastboot driver installed (§0.1) |
| **Blast radius** | S2 if a modified `lk` fails preloader verification |
| **Recovery** | **none in place**: S2 has no software route |
| **Risk verdict** | **HIGH.** This is the class that produced the XDA brick. Do not run it until S2 recovery exists or the unit is expendable |
| **Safe sub-class** | `lk` reads/dumps/hashing, and LK *runtime* behaviour via fastboot (`getvar`, `oem reboot-recovery`); no writes |

**Worth validating here, safely.** Because fastboot is now reachable, several
LK-side questions can be answered with **no writes at all**:

1. `fastboot getvar all` → the full variable set LK exposes (`unlock_status`,
   `unlock_code`, `secure`, Amazon-specific vars). Empirical counterpart to the
   string-level analysis.
2. Whether the **locked-device fastboot gate** (stage2-unlock "LK
   certificate-parser audit" §5) permits or refuses specific commands. Testing a
   *refused* command is safe; the refusal happens before any write. This is the
   cheapest way to close the question that decides whether `boot` is restorable.
3. `fastboot oem reboot-recovery` → proves recovery is reachable from fastboot.
   A round trip, not a write.

**Do not** attempt `fastboot flash lk` for any reason. Even writing a stock
`lk.img` is a boot-critical write with an S2 failure mode and no in-place
recovery.

---

## 2. Scenario B: the "bricked" re-enumeration loop

**What the XDA reporter saw.** USB disconnects and re-enumerates every few
seconds, no display. That is the preloader's rejection path:

* the preloader verifies `lk`, verification fails;
* the locked-device branch prints
  `Only try verify %s with prod key on locked production device` and rejects;
* the failure path ends in `USB Disconnect and Enter Dead Loop` (the same
  dead-loop target is reached on failed image verification);
* because the preloader's USB re-enumeration is what the SoC retries, an attached
  host sees a repeating ~3-second USB cycle.

**Crucially: the device is not dead.** The preloader is running, its USB stack is
alive, and(per §0.2) it enumerates as `VID_0E8D`. What it will *not* do is
serve an unauthenticated write.

**Recovery options for this state, honestly:**

| route | why it does / does not work |
|---|---|
| fastboot | **No**: LK never ran, so nothing serves fastboot |
| recovery / OTA | **No**: recovery is loaded by LK |
| MTK usbdl (preloader) | reached, but `SEND_DA`/`JUMP_DA` require RSA auth against a hardware key; no unsigned DA is accepted |
| preloader fatal-loop key escape | reachable only from a *fatal error* path, and the "Force brom download recovery" routine does not itself request download mode (call-graph verified) |
| **hardware (eMMC ISP)** | **Yes**: the only guaranteed route |

**Therefore: state B on a locked device is terminal for software recovery.** That
is exactly why Scenario A is gated the way it is.

**One cheap, write-free test:** hold the power key during the loop. The preloader's
fatal handler polls key 8 (`0x10010004` bit 8, active-low) for up to 3×5 s and
prints `PL delay for Long Press Reboot`. If a press changes the loop's behaviour
that is new information about the escape hatch; if not, it closes a lead. Both
outcomes are useful.

---

## 3. Scenario C: `boot` diagnostics / exploit validation

**What this class means:** the `boot` partition; the lead from stage2-unlock's
extended bypass analysis (vector **V1**: a logic bug in LK's certificate/DER
verification that would allow a custom `boot` image and give persistent root). It
is *not* a bootloader unlock.

### 3.1 Why the blast radius is materially smaller than Scenario A

Proven by disassembly (stage2-unlock, "LK certificate-parser audit" §4):

```
040504  display(name)  ...  "Please download %s image with correct signature"
040588                    "Your device will reboot in 5 seconds."
040594  movw r0,#0x1388 ; bl 0x44abc      ; 5000 ms
0405a0  mov.w r0, #-1                     ; return -1  -- no panic
```

**A failed `boot` verification makes LK display a message, wait 5 s, and return
`-1`. LK stays alive.** Compare Scenario A, where a failed `lk` verification
leaves nothing running:

| | `lk` write | `boot` write |
|---|---|---|
| failure state | **S2** (preloader loop only) | LK alive, fastboot available |
| in-place recovery | none | **plausible** (fastboot / recovery / OTA) |
| verdict | do not attempt | **the preferred experiment class** |

### 3.2 The firmware agrees: `boot` is a first-class safe target

* The boot-mode selector (0x30352, `app/mt_boot/mt_boot.c`) explicitly loads a
  **recovery** image as an alternative target, and `oem reboot-recovery` exists.
* The OTA re-flashes `boot` unconditionally *before* it touches `preloader`/`lk`
  , in the vendor's own design, `boot` is the low-risk image.

### 3.3 What must be closed before running Scenario C

1. **Does the locked-device fastboot gate allow `flash boot`?** If yes, recovery
   from a bad `boot` is one command. If no, recovery is: `oem reboot-recovery`
   then a **newer** OTA (§0.3b). Either answer is a recovery route, which is why
   this question is worth closing *before* the experiment.
2. **Confirm the recovery path once, non-destructively:** boot into recovery,
   confirm it starts, confirm the OTA is recognised (a 1726 package stopping at
   the version guard is itself a useful confirmation), then reboot. No writes.
3. **Back up `boot` and verify the backup** by re-reading and comparing hashes.

### 3.4 The V1 lead itself is currently closed (negative)

The certificate parser is **stock LibTomCrypt**, not custom code (stage2-unlock
"LibTomCrypt dependency audit"): `der_decode_sequence_flexi` (0xa06c),
`der_length_sequence` (0xaa50), `der_encode_sequence_ex` (0xa69c). The 19
type-handler pairs were compared: dispatch bounds match, and **every identified
asymmetry is in the safe direction** (over-allocation, or a hard
`CRYPT_INVALID_ARG` for types the encoder refuses). No length/encode mismatch was
found. So the V1 experiment currently has **no identified bug to exploit**, 
Scenario C is, for now, a *capability* (a safe experiment class), not a pending
test. Do not write `boot` speculatively.

---

## 4. Recovery tooling: status of each route

| route | status | notes |
|---|---|---|
| **LK fastboot** | **PROVEN reachable** (§0.1) | driver bundled in-repo. **Read-only in practice**: the locked-device gate refuses every write (§0.4) |
| `oem reboot-recovery` | **PROVEN REFUSED** (§0.4) | the gate blocks *all* `oem` commands on a locked device, so recovery is **not** reachable from fastboot |
| recovery + OTA | scripts present, **version-guarded** | usable **only** with a newer OTA (PS7321/7326/7331); useless for S2/S3 |
| MTK preloader usbdl | reached (§0.2), auth-gated | no unauthenticated write |
| MTK BROM / EDL | **not observed** | `adb reboot bootloader` produced *fastboot*, not BROM. BROM entry was not achieved |
| eMMC ISP (hardware) | not attempted | the only guaranteed route for S2/S3 |

**Note on "BROM is patched shut".** The earlier framing (Pardee's result) concerns
BROM *download entry*. This session adds a data point: `adb reboot bootloader`
lands on the **preloader/LK** path, and the observed MTK USB ID (`0E8D:2000`, ~2 s
window) is the preloader's, not a persistent BROM mode. So the observation neither
confirms nor refutes BROM accessibility; it shows the automatic routes land on the
preloader.

---

## 5. Pre-flight checklist (run before ANY class-A or class-C experiment)

1. **Back up every image you could touch**, plus `mmcblk0boot0/1` and both GPT
   copies, with SHA-256 recorded. Re-read and compare; a backup you have not
   verified is not a backup.
2. **Bind a driver for `USB\VID_1949&PID_05E0`** and confirm `fastboot devices`
   lists the unit. Without this you cannot recover from S1.
3. **Capture the recovery baseline (read-only):** `fastboot getvar all`, then
   `fastboot oem reboot-recovery`, confirm recovery starts, then return to
   Android. This validates the S1 route *before* you need it.
4. **Confirm a usable OTA**: verify a newer package passes the version guard.
5. **Only then** run a Scenario C experiment, and never a Scenario A one.

---

## 6. What this stage does not claim

* It does **not** claim any recovery path has been exercised end-to-end. Only the
  *reachability* of fastboot is proven.
* It does **not** claim S2 is recoverable. On the evidence, it is not.
* It does **not** claim BROM/EDL is available. It was not observed.
* It does **not** supersede Stage 2's conclusion: no demonstrated software unlock,
  and the minimum-key position is unchanged.

---

## 7. Next steps

Items 1-4 were the software plan and are now **done**: with a negative result, which is
why the list collapses to one item.

1. ~~Bind a WinUSB/libusb driver to `VID_1949&PID_05E0` so `fastboot` can talk to the
   device~~, **done** ([host/winusb-fastboot/](host/winusb-fastboot/)).
2. ~~Close the locked-device gate question by testing commands that are *refused*
   before any write~~, **done, and the answer constrains recovery**: the gate refuses
   every write and every `oem` command at dispatch, so fastboot is read-only in
   practice (§0.4).
3. ~~Validate the S1 round trip: `oem reboot-recovery` → recovery → reboot~~, 
   **answered**: `oem reboot-recovery` is itself **refused**, so recovery is not
   reachable from fastboot at all. The S1 route therefore depends on the BCB in
   `/misc`, the preloader RTC trigger, or a physical key combination.
4. ~~Audit the RTC recovery trigger (preloader 0x252c0) and the `boot_para`
   DRAM-fatal-flag consumers~~, **done** (see
   [../stage2-unlock/README.md](../stage2-unlock/README.md), "Open questions closed").
5. **(hardware) eMMC ISP reconnaissance**: **the only remaining route**, covering
   S2/S3, and the only one that could ever reach the efuse keys that ATF/TEE
   decryption depends on. Everything doable with software and a USB cable has now
   been done; this is the frontier, and it needs equipment rather than more analysis.
