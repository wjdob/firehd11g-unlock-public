# RESUME HERE: next session

> **Scope note.** These are the author's session-continuity notes for the *private*
> research repository, included for transparency about how the work progressed. They
> reference tooling and state belonging to that repository rather than to this public
> baseline (`stage2a-unlock/`, `tools/sync-handoff-bundle.py`,
> `tools/check-bundle-drift.py`). The technical findings they summarise are written up
> in full in [HANDOFF.md](HANDOFF.md) and
> [../stage2-unlock/README.md](../stage2-unlock/README.md).


> ## CURRENT STATE (2026-10-08); the exploit research now has its own entry point
>
> The 2026-10-08 session ran an MT8183 exploit search and produced a self-contained
> research hub under [exploits/](../exploits/). **Start there, not here:**
>
> * [exploits/CONTEXT-ANCHOR.md](../exploits/CONTEXT-ANCHOR.md), device state, hard
>   guardrails, a **STOP LIST** of every vector already evaluated, the open leads, and a
>   device-touch log. It exists so a long-running or compacted session never re-derives
>   work that is already done.
> * [exploits/EXPLOIT-REGISTER.md](../exploits/EXPLOIT-REGISTER.md), every finding with
>   a confidence rating and an explicit *does-it-unlock* verdict.
> * [exploits/MT8183-BOOT-MAP.md](../exploits/MT8183-BOOT-MAP.md), stage-by-stage trace
>   with the offset/VA/RAM conversions and the attacker-influenced read/write table.
>
> What that session settled: the main unlock PSS verifier has **no bypass** (17/17
> RFC 8017 checks, positive control on the real code, 1,000,000 fuzzed signatures with
> zero accepts); the LK certificate parser's length asymmetry is **not** an
> authentication bypass (the SAN digest is covered by Amazon's signature over the
> original DER); the temp-unlock verifier shows no reachable path that skips its RSA
> check; **unlock does not disable verification** (an unlocked preloader still
> re-verifies `lk` with the alternate Amazon key, which corrects the wording used in
> several documents in this repository); and the locked-device fastboot gate is a
> *denylist* whose model reproduces all 48 live probe verdicts. Four to six kernel
> exploits are reachable on the unit, none of which unlocks anything.
>
> The device was left healthy and untouched: `verifiedbootstate=green`,
> `flash.locked=1`, root persistent, no boot-critical partition written.
>
> ## CURRENT STATE (2026-10-07), read this before the rest
>
> **Persistent root is achieved and measured.** [stage4-persistent/](../stage4-persistent/)
> restores uid 0 automatically after a reboot with **no host PC attached**: verified
> over **13/13 consecutive reboots** on the reference unit. Everything lives under
> `/data`; no boot, recovery, system, vendor or partition-table write is involved, so
> it cannot brick the device and `install-persistence.sh --remove` + reboot reverts it.
>
> What changed since this file was written, in one line each:
>
> * **Root is no longer per-boot.** Upstream/SnuSnuRoot root reverts every reboot and
>   needs a host; stage 4 makes it survive. That is the one genuinely new capability in
>   the repo.
> * **Bootloader unlocking is still blocked**, with the same cryptographic barrier as
>   before (§5 below): an Amazon-signed `unlock_code` verified by both preloader and LK.
>   Nothing here changes that.
> * **A documented claim was disproven.** A lost ENODATA carrier race was recorded as
>   terminal for the boot; it is not; an in-boot retry wins. That single fact is what
>   turns a ~67%-per-boot gamble into a reliable chain. See
>   [ENODATA-ANALYSIS.md §12](ENODATA-ANALYSIS.md).
> * **Four silent failures had to be fixed first**, none of them the exploit: a wrong
>   SELinux label on the trigger payload, a state directory the actor's own domain
>   cannot read, Amazon's `TimeService` erasing the boot trigger on its NTP sync, and
>   the single-shot carrier. Details and measurements are in
>   [stage4-persistent/README.md](../stage4-persistent/README.md).
> * **New gate:** run `python stage4-persistent/preflight.py` before spending a root
>   cycle. It enforces seven invariants, each of which was a real bug that cost at
>   least one boot, including the CRLF and parse traps that repeatedly killed
>   multi-minute runs.
>
> The sections below are **kept as written** and remain accurate for the fastboot/OTI
> work they describe; only their "current state" framing is superseded.


**Written 2026-10-06.** Updated at the end of the follow-up session that solved the
fastboot driver blocker (SS3) and answered every fastboot question (SS4). Read this
file first; it is self-contained, so a fresh session needs no other context.

**2026-10-07:** a later session added persistent root (see the block above) and
superseded the state-of-play in §0 and §1. Those two sections describe the device as it
was before that work; treat them as history, not as current condition.

---

## 0. One-paragraph state of play

The tablet (Amazon Fire HD 10 11th-gen, `trona` / MT8183, Fire OS 7.3.1.9
PS7319/1735, serial `<SERIAL>`) is **healthy and booted into Android**, with
its boot chain untouched (`verifiedbootstate=green`, `flash.locked=1`, SELinux
`Enforcing`). **Nothing was ever written to the device** -- every operation this
session was read-only apart from reboots.

The blocker was purely host-side: the fastboot USB interface had **no Windows driver
bound** (`ProblemCode 28`), because Microsoft's signed `winusb.inf` auto-binds only
the ADB class (`Class_ff&SubClass_42&Prot_**01**`), never fastboot (`Prot_**03**`).
**That is fixed -- see SS3 -- and `fastboot devices` now returns the unit.** SS4
records everything fastboot revealed, and SS7 item 1 (the locked-device gate) is now
closed. The LibTomCrypt audit, the stage3 recovery restructure and the OTA analysis
were already complete and verified in the repo.

---

## 1. Device state

**At the end of this session the tablet is booted into Android normally, ADB works,
and the boot chain is stock** (`verifiedbootstate=green`, `flash.locked=1`, SELinux
`Enforcing`, no `su`). Fastboot is one command away when needed.

```powershell
& 'C:\Users\<user>\adb\adb.exe' devices                                    # -> <SERIAL>   device
& 'C:\Users\<user>\adb\adb.exe' shell getprop ro.boot.verifiedbootstate    # -> green
```

To go **back into LK fastboot** (the §3 driver is installed and will just re-bind):

```powershell
& 'C:\Users\<user>\adb\adb.exe' reboot bootloader
& 'C:\Users\<user>\adb\fastboot.exe' devices      # -> <SERIAL>   fastboot
```

Identity: Fire HD 10 11th-gen, `trona` / MT8183, Fire OS 7.3.1.9 (PS7319/1735),
build `0020367984516`, serial `<SERIAL>`.

* `VID_1949` = Amazon Labs. `PID_05E0` = fastboot, `PID_05E8` = ADB.
* The fastboot interface's `CompatibleIds` include
  `USB\COMPAT_VID_1949&Class_FF&SubClass_42&Prot_03` -- the standard fastboot
  signature, so this is genuine fastboot and not a vendor variant.
* `adb devices` is **empty** while in fastboot, and `fastboot devices` is **empty**
  while in Android. Both are expected.
* On every boot the MTK preloader's `VID_0E8D:PID_2000` interface appears briefly
  (measured this session: visible 2.9 s -> 5.9 s after `fastboot reboot`).

## 2. Host state after the reboot

| item | state |
|---|---|
| **UsbDk 1.0.22 x64** | **installed and Running** (deliberately left installed; it is signed, benign, and is what `mtkclient` wants for future preloader/BROM work) |
| WinUSB function driver for `VID_1949:PID_05E0` | **BOUND**: `oem113.inf` v1.0.0.1, service `WINUSB`, `CM_PROB_NONE` (see §3) |
| `fastboot` | 36.0.2-14143358, at `C:\Users\<user>\adb\fastboot.exe` |
| `7-Zip` | present (`C:\Program Files\7-Zip\7z.exe`) |
| `signtool.exe` | present (Windows Kits `10.0.26100.0\x64`) |
| `Inf2Cat.exe` | **absent**: this is why a hand-made INF cannot be signed locally |
| reboot | was requested by the UsbDk MSI (`REBOOT=ReallySuppress` was set by us); the reboot clears that pending state |

Confirm after reboot that UsbDk is still fine:

```powershell
sc.exe query UsbDk          # expect STATE: 4 RUNNING
```

---

## 3. THE TASK THAT WAS BLOCKING: bind WinUSB: **DONE**

**`fastboot devices` returns `<SERIAL>  fastboot`.** The device is fully
reachable. Full reproducible procedure: `stage3-recovery/host/winusb-fastboot/README.md`.

Zadig was **not** needed. Three blockers, all solved:

**(a) Nothing signed matched the interface.** Microsoft's signed `winusb.inf` has
exactly one Android generic entry, `USB\Class_ff&SubClass_42&Prot_01`, protocol
`01` is ADB. That is why the ADB interface (`PID_05E8`) auto-bound and ADB always
worked with no vendor driver. Our fastboot interface is protocol `03`, for which
Microsoft ships no generic entry. Amazon's official
`kindle_fire_usb_driver.zip` does **not** cover `PID_05E0` either (it lists only
ADB PIDs plus one HTC fastboot ID), and it cannot be extended without breaking its
catalog.

**(b) The hand-made INF had no catalog.** `Inf2Cat.exe` is genuinely absent, but it
is only a wrapper around **`makecat.exe`**, which *is* present:
`C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\makecat.exe`.
`fastboot-amzn.cdf` now ships in this repo, so the catalog builds with built-in
tools only:

```
makecat -v fastboot-amzn.cdf
signtool sign /fd sha256 /sha1 723E91CFC4F3DA99716F21640DF954B7E4C43DD3 fastboot-amzn.cat
```

The self-signed cert `CN=Local Fastboot WinUSB Signing` (thumbprint
`723E91CF…`, valid to 2027-10-06) **survived the reboot with its private key**, so no
`.pfx` was needed. Its public half is now in `LocalMachine\Root` +
`LocalMachine\TrustedPublisher`, which is what lets `pnputil` accept the package.

**(c) The interface GUID had to be Android's.** This was the subtle one, and it is
worth remembering. `fastboot.exe` enumerates by device interface GUID. Binary
search of `fastboot.exe` for each candidate:

| GUID | occurrences |
|---|---|
| `{F72FE0D4-CBCB-407d-8814-9ED673D0DD6B}` (Android) | **1** |
| `{5F5F6A1E-…}` (what our INF originally registered) | 0 |
| `{A5DCBF10-…}` (USB device interface) | 0 |
| `{DEE824EF-…}` (WinUSB device interface) | 0 |

With the private GUID the driver installed cleanly and Device Manager said the
device was **working properly**, yet `fastboot devices` still printed nothing.
`DeviceInterfaceGUIDs` is now `{F72FE0D4-…}`, matching Google's own
`android_winusb.inf`. **Symptom to remember: driver bound + device OK + fastboot
sees nothing ⇒ wrong interface GUID.**

Installed package: `oem113.inf` (ours) v1.0.0.1. The earlier `oem89.inf` v1.0.0.0
carries the wrong GUID and was deleted from the driver store. Bump `DriverVer` on
every INF change or Windows silently keeps the old package.

**Side effect worth knowing:** the ~10 s USB re-enumeration loop (the repeating
"connected" sound) was a *symptom of the failed driver start*. It stopped the
moment a driver bound, one state change in 75 s, continuously `[OK]`. It was never
a cable/port/hub fault.

## 4. What to do once fastboot works (all READ-ONLY: no writes)

In priority order:

0. **RESULT, `getvar all` is itself refused.** `getvar:all` returns
   `FAILED (remote: 'the command you input is restricted on locked hw')`. The gate
   will not enumerate the variable set.

1. **RESULT; the locked-device gate is a strict allowlist, and it is CLOSED.**
   Probed 48 variables (`diagnostics/fastboot-gate-probe.txt`). Only **6** are
   readable; all **42** others are refused with string 0x79510:

   | allowed variable | value |
   |---|---|
   | `product` | `trona` |
   | `unlock_status` | `false` |
   | `unlock_code` | `0x201197ff6793b2aea071c15f` |
   | `serialno` | `<SERIAL>` |
   | `max-download-size` | `0x8000000` |
   | `slot-count` | `0` |

   Also refused: `partition-size:boot`, `partition-type:boot`, `downloadsize`,
   `max-fetch-size`, `secure`, `unlocked`, `lock_state`, `build-date`,
   `dram_fatal`, `boot_para`, `token`, `imei`, `cpuid`, and every `oem` command
   tried (`oem device-info`, `oem getvar`, `oem lks`).

   **The decisive test:** `erase no_such_part_zzz` and `format no_such_part_zzz`
   were refused *by the gate*, not with "partition not found". That proves the gate
   is evaluated at **command dispatch, before partition lookup**: before any write
   is even considered. **Therefore repairing a damaged `boot` with
   `fastboot flash boot` is not possible while the device is locked.** S1 recovery
   must go through recovery + a newer OTA (see §5). This was the last open question
   for S1 restorability.

   Note `unlock_code` *is* readable despite the gate; a device-specific value
   previously only inferred from the binary.

2. **RESULT -- `fastboot oem reboot-recovery` is REFUSED**, with
   `FAILED (remote: 'the command you input is restricted on locked hw')` -- the same
   refusal as every other `oem` command. **Recovery is therefore NOT reachable from
   fastboot while the device is locked.** This narrows the S1 plan: the
   "recovery + newer OTA" route needs a different way in -- the BCB in `/misc`, the
   preloader RTC "enter first boot/recovery" trigger (preloader 0x252c0), or a
   physical key combination.

3. **RESULT -- `fastboot reboot` works.** `Rebooting OKAY [0.005s]`; the tablet
   booted Android normally and ADB returned. Observed sequence: fastboot ->
   `VID_0E8D:PID_2000` (preloader, ~3 s) -> `VID_1949:PID_05E8` (ADB) at ~17 s.
   `verifiedbootstate=green`, `flash.locked=1`, `getenforce=Enforcing`, no `su` --
   boot chain untouched. `stage1-root` must be re-run for further root work.

**Hard rules (unchanged and non-negotiable):** no writes to `lk`, `preloader`,
`tee*`, `sspm_1`, `spmfw`, `cam_vpu*`, `boot`, or partition-table metadata. A
failed bootloader verification on this SoC is an unrecoverable brick (the XDA
case, and the reason stage3 exists).

---

## 5. What was already established (do not redo)

Full detail lives in `stage2-unlock/README.md`, `stage3-recovery/README.md` and
`docs/HANDOFF.md`. Summary of the newest results:

* **Fastboot is reachable** (proven, §1 above); this makes S1 recovery real.
* **LibTomCrypt audit (complete).** LK's certificate path is **stock LibTomCrypt**,
  not Amazon code: `der_decode_sequence_flexi` 0xa06c, `der_length_sequence`
  0xaa50, `der_encode_sequence_ex` 0xa69c (identified by their NULL-check error
  strings and their own source paths; 60 ltc modules are linked; version ≥ 1.18).
  **The 19 type-handler pairs show no length/encode mismatch**: dispatch bounds
  are identical (`type-1 <= 0x12`), length-of-length boundaries agree, and every
  asymmetry found fails *safe* (CUSTOM_TYPE `0xFFFE` over-allocates by 1 byte;
  CHOICE/TELETEX_STRING make the encoder return `CRYPT_INVALID_ARG`).
  ⇒ **vector V1 (a DER bug enabling a custom `boot` image) currently has no
  identified bug.** Do not write `boot` speculatively.
* **OTA reality check.** The OTA restores *everything* including `preloader` and
  `lk`, but it runs in recovery, which LK boots ⇒ useless for an `lk` failure.
  **And the PS7319/1726 OTA will NOT apply to this device**: its guard is
  `(!less_than_int(1619231913, ro.build.date.utc)) || abort(E3003)` and the device
  reports `1622314026`. The usable recovery OTAs are the newer ones in `OTAs/`:
  **PS7321/2324, PS7326/3178, PS7331/4463**.
* **Brick taxonomy** (`stage3-recovery/README.md` §0): S1 (`boot` bad) →
  recoverable via fastboot or recovery+newer-OTA. **S2 (`lk` bad) → not
  recoverable in place.** S3/S4 → hardware (eMMC ISP) only.
* **The preloader's MTK USB** (`VID_0E8D:PID_2000`, ~2 s window; re-measured this session at ~3 s) enumerates on
  every boot; that is the `usbdl` interface audited earlier; DA-auth gated, no
  unauthenticated write. `adb reboot bootloader` did **not** enter BROM/EDL.
* **LK has an infinite hang** at `0x0b90` (`b 0xb90`), reached when an mblock/DT
  node overflows a 0x6000-byte buffer, after printing `"Will enter into busy wait
  loop with no recovery!!"` (string 0x4685a).

---

## 6. Repo state / housekeeping

Uncommitted work (working tree, nothing committed this session):

```
 M docs/HANDOFF.md
 M stage2-unlock/README.md
?? diagnostics/dram-map-1735.txt
?? diagnostics/dt-reserved.txt
?? diagnostics/iomem.txt
?? stage2-unlock/pl-cfg.py
?? stage2-unlock/pl-disasm.py
?? stage2-unlock/vectorResearch.MD
?? stage2-unlock/vectorResearch2.MD
?? stage2-unlock/verify-lk-signature.py
?? stage2-unlock/verify-tee-signature.py
?? stage2a-unlock/
?? stage2a-unlock10062026.zip      <-- regenerated this session (49 files)
?? stage3-recovery/
```

**Verification (all currently PASS):**

```powershell
cd stage2a-unlock ; python verify-manifest.py           # 47 files, SHA-256
cd .. ; python stage2-unlock\verify-lk-signature.py     # header outside signature
python stage2-unlock\verify-tee-signature.py            # outer vs inner lengths
```

**Cleanup status:**

1. ~~`stage2a-unlock10062026.zip` was a stale export~~ -- **done.** Regenerated this
   session from the refreshed bundle (49 files, 13.3 MB, includes `fastboot-amzn.cdf`
   and the gate-probe diagnostics). Regenerate again after any further doc change.
2. `stage2a-unlock/` is the refreshed handoff bundle for external review. It now
   also contains `stage3-recovery/host/winusb-fastboot/`. Sync + regenerate the
   manifest with the committed tool (do **not** hand-copy files):
   ```
   python tools/sync-handoff-bundle.py          # copies + rewrites MANIFEST.txt
   python stage2a-unlock/verify-manifest.py
   python tools/check-bundle-drift.py
   ```

**Note on the signing certificate.** The throwaway self-signed code-signing cert
`CN=Local Fastboot WinUSB Signing` (thumbprint `723E91CFC4F3DA99716F21640DF954B7E4C43DD3`,
valid to 2027-10-06) **survived the reboot with its private key** in
`Cert:\CurrentUser\My`. Its public half is **now installed** into
`LocalMachine\Root` and `LocalMachine\TrustedPublisher`, and that trust is what makes
`pnputil` accept `fastboot-amzn.inf`. No `.pfx` was needed.

**Leave it in place while the fastboot driver is installed.** If the driver package
is removed later, remove the cert too, while it is trusted, any driver package
signed with it would be accepted:
```powershell
Get-ChildItem Cert:\LocalMachine\Root,Cert:\LocalMachine\TrustedPublisher |
    Where-Object Subject -like '*Local Fastboot WinUSB Signing*' | Remove-Item
```

---

## 7. Known-open questions

1. ~~**Locked-device fastboot gate semantics**~~, **CLOSED.** Strict 6-variable
   allowlist; every write-class command refused at dispatch *before* partition
   lookup. See §4 item 1.
2. ~~**`boot_para` DRAM-fatal-flag consumers**~~, **CLOSED.** `boot_para` has
   exactly **one** consumer in the whole preloader (`0x16930`), and both DRAM-fatal
   accessors have exactly one caller each, all inside the single DRAM
   calibration/self-test function at `0x1ab00`-`0x1ac60`. Full trace in
   `stage2-unlock/README.md`, "Open questions closed", section A.
3. ~~**RTC "enter first boot/recovery" trigger**~~, **CLOSED.** `0x252c0` is a
   shared out-of-line block reached by four `bhi.w`/`bhs.w` from `0x24f2a` /
   `0x24f36` / `0x24f44` / `0x24f5a`: four range checks on RTC calibration `u16`s.
   It prints, sets the error flag `r4 = 1`, and rejoins at `0x24f60`; a warning,
   not a reboot. Section B.
4. **Does ATF re-validate LK after handoff, and what does an oversized `atf_dram`
   tail decrypt to?**: **NOT ANSWERABLE OFFLINE. Do not spend effort here.**
   Both need ATF/TEE plaintext. The bodies are encrypted (2.8 MB of `tee` at
   exactly **8.000** bits/byte), the images carry only RSA *public* moduli, and
   decryption uses MTK's **hardware crypto engine with efuse-derived keys**
   (`sec_boot_check`, `sbc_enabled`, `EFUSE Self Blow`, `[SEC] crypto engine HW
   disable fail`). Efuse needs BROM, and BROM is unavailable on this unit. This
   **corrects** the earlier claim that modelling the decrypt routine would settle
   it, modelling control flow does not produce plaintext. Section C. Net effect:
   treat the ATF_DRAM vector as **unverifiable**, not promising.
5. **ATF_DRAM candidate layout**: the geometry is fully characterised (section 4
   of the ATF_DRAM section): the `tee` container must be relocated into
   `metadata`, and it needs boot-critical writes. Given item 4 it cannot be
   validated, so it is recorded as a documented dead end rather than a plan.
6. **Hardware:** eMMC ISP reconnaissance; the only route covering S2/S3, and now
   also the only route that could ever obtain the efuse keys. Unchanged.

### Tooling added this session

`tools/pl-xref.py` resolves PC-relative string references across the preloader and
LK (1232 and 4063 refs respectively; the previous approach yielded **0**). Use it
before any further code archaeology, two silent-failure traps (disassembly
alignment, and `LDR` T1 immediate scaling) otherwise make whole images look empty.
Validated against `0x252c0 -> 0x35af7`.

---

## 8. Suggested opening line for the next session

> "Read `docs/RESUME-HERE.md`. Fastboot works (§3) and the fastboot side is done
> (§4). The open-question list in §7 is now almost entirely closed, **read §7
> item 4 before proposing any ATF/TEE work, it is a proven dead end offline**.
> The only remaining route to anything deeper is §7 item 6: hardware / eMMC ISP,
> which is also the only way to reach the efuse keys. Otherwise the useful work is
> on the host side: the signing certificate in `LocalMachine\Root` +
> `TrustedPublisher` should be removed if the fastboot driver is no longer
> needed."

**State of the boot-chain attack surface.** After this session the position is
that every software route has been either exhausted or proved to need a key we
cannot obtain: the fastboot gate is closed (locked), the container-header copy
primitive is real but unreachable without boot-critical writes, the ATF/DRAM path
is encrypted with efuse keys, and BROM is gated. The honest summary is that
**further progress requires hardware**, not more static analysis.






