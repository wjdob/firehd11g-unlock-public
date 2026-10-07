# Fire HD 10 (11th Gen, 2021): Root & Bootloader Unlock Research

**Device:** Amazon Fire HD 10 11th generation, `trona` / KFTRWI, MediaTek MT8183, Mali-G72 MP3
**Target firmware:** Fire OS 7.3.1.9 (PS7319/1735, kernel 4.4.146, Android 9)

## Bottom line

This repository maps the `trona` boot chain from the mask ROM to Android: what each
stage loads, where it verifies a signature, which memory and registers it touches, and
the evidence behind every claim. The table below carries the conclusions a reader needs
first; the stage directories and [exploits/](exploits/) carry the work itself.

| question | what the evidence shows |
|---|---|
| **Can the bootloader be unlocked?** | The gate is an Amazon-signed `unlock_code` (RSA-2048-PSS) that both the preloader and LK verify against an embedded public key. Producing that signature takes Amazon's private key, so the gate stands at the cryptographic level rather than the privilege level, and privilege escalation runs into it without moving it. Mechanism in full: [stage2-unlock/](stage2-unlock/). |
| **Where did root come from?** | [SnuSnuRoot](https://github.com/voidnullvalue/SnuSnuRoot). `stage1-root/` ports that chain to PS7319 and adds per-firmware carriers for the PS732x/PS733x range, with the credit upstream's. |
| **Which software routes stay open?** | BROM download entry is closed at the factory, the preloader's `usbdl` requires an authenticated Download Agent, and the ATF/TEE images are encrypted with efuse-derived keys that only BROM can reach. Each route, its rating and its evidence: [exploits/EXPLOIT-REGISTER.md](exploits/EXPLOIT-REGISTER.md). |
| **What does recovery support?** | Recovery is partition-dependent; the matrix is below. LK fastboot is reachable, and its locked-device gate refuses every write and every `oem` command, `oem reboot-recovery` included. |
| **Can a damaged unit be repaired?** | A bad `boot` (S1) recovers through recovery plus a newer OTA. A bad `lk` (S2), a damaged `preloader` (S3) or an unreadable eMMC (S4) need hardware. Matrix below. |
| **Is root persistent?** | Yes. [stage4-persistent/](stage4-persistent/) restores root after a reboot with no host attached, measured over 13 consecutive reboots. It runs in userland and reverts with a factory reset. |

What the repository holds: a verified reverse-engineering record of the boot chain, a
proven brick taxonomy, worked refutations of several claims that circulate as folklore
(including a fabricated offset PR, [checked against the vendor source](stage2-unlock/README.md)),
and tooling for offline symbol extraction. Each finding is written so that a reader can
check it, and disprove it where it is wrong.

> **Where to start.** [exploits/CONTEXT-ANCHOR.md](exploits/CONTEXT-ANCHOR.md) is the entry
> point for the exploit research: device state, the hard guardrails, a **STOP LIST** of
> every vector already evaluated (so nothing is re-derived), the genuinely open leads,
> and a device-touch log. It is backed by
> [exploits/EXPLOIT-REGISTER.md](exploits/EXPLOIT-REGISTER.md) (every finding with a
> confidence rating and an explicit *does-it-unlock* verdict),
> [exploits/MT8183-BOOT-MAP.md](exploits/MT8183-BOOT-MAP.md) (stage-by-stage call and
> read/write map), and the evidence under [exploits/notes/](exploits/notes/).

### Open invitation: hardware work is the frontier

The one remaining direction is **hardware**. An eMMC in-system-programming (ISP) or
chip-off read is the only approach that reaches S2 and S3, and the only route that
could obtain the efuse keys that ATF/TEE decryption depends on. Everything in this
repository has been done with software and a USB cable; that has now been exhausted.

If you have that capability, ISP adapters, a rework station, BGA experience, or a
sacrificial unit, your findings would be worth more than anything else that could be
added here. **Corrections and counter-evidence are equally welcome**; if something here
is wrong, that is worth knowing.

> [!IMPORTANT]
> **Treat boot-critical writes as one-shot, but know which ones.** The MediaTek
> BootROM download entry is patched shut at the factory (2021 manufacture, LOT 8S132+),
> so there is no low-level escape hatch. What is recoverable in place depends entirely
> on *which* partition is damaged:
>
> | damage | recovery |
> |---|---|
> | **S1**: bad `boot`, chain otherwise intact | **recoverable**: recovery + a newer OTA (**not** fastboot: the gate refuses writes while locked) |
> | **S2**: `lk` fails preloader verification | **not** recoverable in place |
> | **S3/S4**: `preloader` / eMMC unreadable | hardware (eMMC ISP) only |
>
> A bad `boot` is survivable. **`lk` is not**: the preloader validates it, and a failed
> verification leaves a re-enumeration loop with no software exit. See
> [docs/brick-analysis.md](docs/brick-analysis.md) for the documented XDA failure case
> and [stage3-recovery/](stage3-recovery/) for the full matrix.
>
> **Stages 0, 1, 3 and 4 write nothing to any boot-critical partition.** Stage 1 is
> userland-only and reverts per boot; Stage 4 adds only files under `/data` (verified:
> no boot, recovery, system, vendor or partition-table write) and reverts with
> `install-persistence.sh --remove` plus a reboot; Stage 3 is analysis plus read-only
> diagnostics. The brick risk belongs to Stage 2, which is research-only and is
> expected to stay that way.

## Stage overview

| Stage | Status | Risk | Entry point |
|---|---|---|---|
| **0; Diagnostics** | works; read-only fingerprint + compatibility gate | none | [stage0/](stage0/) |
| **1; Root** | **ported and working** on the reference unit; *upstream work, not new* | low (userland, reverts per boot) | [stage1-root/](stage1-root/) |
| **2; Bootloader unlock** | **dead end**: no method exists, and none is in prospect | extreme (brick) | [stage2-unlock/](stage2-unlock/) |
| **3; Recovery & brick taxonomy** | characterised, but does not unlock further work | none (analysis + read-only) | [stage3-recovery/](stage3-recovery/) |
| **4; Persistent root** | **working and measured**: root returns after reboot with no host attached; 13/13 boots | low (all state under `/data`, revertible) | [stage4-persistent/](stage4-persistent/) |

## Quick start

### Step 0: Diagnostics (safe, read-only, ~1 min)

```powershell
# Windows, device connected via ADB with USB debugging
.\stage0\run-diagnostics.ps1
```

Produces a device fingerprint + compatibility report in `diagnostics/stage0-report.json`
and prints a **PASS/FAIL compatibility verdict for Stage 1**. Writes nothing.

**Do not proceed unless every check passes.** The script validates your device against
the compatibility matrix below.

### Step 1: Root (userland, ~10–40 min, reversible)

Requirements: [Git Bash](https://git-scm.com/) (for the POSIX scripts), `adb` on PATH
(or `$env:ADB` pointing at it), one authorized device, and a Stage 0 PASS.

```powershell
.\stage1-root\run-root.ps1            # prints an explanation, asks you to type ROOT
# or, non-interactive:
.\stage1-root\run-root.ps1 -ConfirmRoot
```

What it does (full detail in [stage1-root/README.md](stage1-root/README.md) and
[docs/root-method.md](docs/root-method.md)):

1. Stages exploit carriers to app-private storage (one-shot zygote channel)
2. Arms the `time_update` waiter (`persist.sys.saved_time` command injection)
3. Reboots the device
4. On the fresh boot: hwbinder NULL-write → SELinux Permissive → uid-0 listener
   on `127.0.0.1:4325`

**It never writes to boot, recovery, system, vendor, preloader, lk, tee, or any
partition table entry.** Everything reverts on reboot; `.\stage1-root\run-root.ps1 -Disarm`
restores stock state.

Verify root (from any shell):

```bash
printf 'id\nexit\n' | adb shell 'toybox nc -w 3 127.0.0.1 4325'
# expected: uid=0(root) gid=1000(system) ... context=u:r:time_update:s0
```

Useful read-only commands through the root listener:

```bash
printf 'cat /proc/partitions\nexit\n' | adb shell 'toybox nc -w 3 127.0.0.1 4325'
printf 'ls -la /dev/block/by-name/\nexit\n' | adb shell 'toybox nc -w 3 127.0.0.1 4325'
```

To have root come back by itself after a reboot, with no PC attached, add
[stage 4](stage4-persistent/), see its README for the install steps and the
`acceptance-test.ps1` harness that measures it over N reboots.

### Expect: probabilistic leak, automatic retries

The hwbinder leak step is a **kernel race; it is probabilistic, not deterministic**.
Observed success rate on the reference device: ~57% per fresh boot pre-patch
(run-16: attempt 1; run-17: attempt 4); **after the 10 ms wait rescale (run-18):
attempt-1 hit**. Stage 1's orchestrator **automatically reboots and retries up to 6
fresh-boot attempts**; a miss (ENODATA) is normal and leaves the device booting
normally with the waiter still armed. Total wall time is therefore ~10 min (lucky) to
~40 min (several retries). **A failed attempt does not mean a broken device.**

> [!NOTE]
> **A miss is retryable, which supersedes the original analysis.** This repository
> previously recorded that a lost ENODATA race was terminal until reboot. Measured on
> 2026-10-07: on a boot whose first attempt had already returned ENODATA, re-running the
> carrier **succeeded on the next attempt in the same boot**. The JNI carrier cannot use
> this (it holds the probe port), so stage 1 still reboots on a miss; the statically
> linked carrier that [stage 4](stage4-persistent/) runs *can*, and retries 5× in-boot, 
> which is what turns the chain from a per-boot coin flip into something that returns
> root reliably. Mechanism, probe and raw output:
> [docs/ENODATA-ANALYSIS.md §11–§12](docs/ENODATA-ANALYSIS.md).

### What root gives you (and what it doesn't)

| You get | You don't get |
|---|---|
| `uid=0` shell on `127.0.0.1:4325` after each boot | Bootloader unlock; verified boot stays green |
| **Unattended across reboots** with [stage 4](stage4-persistent/); 13/13 measured, no host needed | Persistent Magisk (the stage-4 waiter reports `magisk=skipped`) |
| SELinux Permissive (in-memory, reverts on reboot) | Ability to flash unsigned boot/recovery images |
| Read/write access to all block devices (`/dev/block/...`) | dm-verity removal (system stays read-only verified) |
| `pm uninstall --user 0` debloating, partition dumps | Any permanent change; a factory reset reverts all of it |

## Compatibility matrix

Stage 1 is **ported and verified on exactly one** configuration (the reference row).
The chain now supports a firmware range via per-version carrier variants
(selected automatically by build token, see
[stage1-root/README.md](stage1-root/README.md#firmware-compatibility-matrix)),
but only the PS7319 row has live proof. Run Stage 0 first; it gates on the
carrier registry and fails closed for unregistered firmware.

| Property | Reference device (verified) | How to check | Mismatch means |
|---|---|---|---|
| Device codename | `trona` | `getprop ro.product.device` | Different hardware; do not proceed |
| Model | `KFTRWI` (3 GB) | `getprop ro.product.model` | `KFTRPWI` (4 GB) untested |
| Fire OS | `7.3.1.9` / `PS7319` | `getprop ro.build.version.name` | PS7321/PS7326/PS7331 have carriers built but are **untested live**; anything else fails closed |
| Build incremental | `0020367984516` (1735) | `getprop ro.build.version.incremental` | Same PS but different build; verify `selinux_enforcing` (see below) |
| Kernel | `4.4.146+ #1 SMP PREEMPT Sat May 29 18:57:35 UTC 2021 aarch64` | `uname -a` | Different kernel build; `selinux_enforcing` VA may differ |
| ABI list | `arm64-v8a,armeabi-v7a,armeabi` | `getprop ro.product.cpu.abilist` | 32-bit-only would reject the primitive |
| SELinux mode (stock) | `Enforcing` | `getenforce` | Already-Permissive devices are untested |
| `persist.sys.saved_time` | numeric (e.g. `1791219606604`) | `getprop persist.sys.saved_time` | Non-numeric = arming precondition fails |
| `hidden_api_blacklist_exemptions` | `null` | `settings get global hidden_api_blacklist_exemptions` | Stale value = zygote injection precondition fails |
| `timeupdate.rc` | present | `ls /system/etc/init/timeupdate.rc` | No `time_update` service = no injection target |
| `selinux_enforcing` VA | `0xffffff8009965628` | Stage 0 reads it from the carrier registry | **Wrong address = wrong kernel write.** The chain fails closed on unknown builds |

**Key address facts** (full derivation in [tools/kernel-symbols.md](tools/kernel-symbols.md)):

| Build | `selinux_enforcing` | Source |
|---|---|---|
| PS7319/1726 (OTA kernel) | `0xffffff8009965628` | offline extraction, validated method |
| PS7319/1735 (**running**, verified) | `0xffffff8009965628` | boot-partition dump + offline resolution; matches 1726 |
| PS7321/2324 (OTA kernel) | `0xffffff8009969668` | offline extraction, `enforcing_setup` anchor |
| PS7326 (Eric Pardee) | `0xffffff8009969668` | ground truth; identical to PS7321 |
| PS7331 (SnuSnuRoot upstream) | `0xffffff8009971668` | ground truth |

`kptr_restrict=2` on this firmware makes `/proc/kallsyms` useless even as root, so the
address is resolved **offline from the OTA kernel** (or a post-root dump of the running
`boot` partition), never trusted from another build. For a firmware version not in the
table, obtain its OTA and run
`python stage1-root/make-carrier.py --ota <update-kindle-*.bin>`; the address cannot be
auto-grabbed from the device pre-root.

## Repository layout

```
stage0/           Read-only device diagnostics + compatibility guardrails
stage1-root/      SnuSnuRoot port for PS7319 (upstream work; see NOTICE)
stage2-unlock/    Bootloader unlock research, mechanism reversed; no unlock exists
stage3-recovery/  Brick taxonomy (S1–S4), LK fastboot access, experiment safety gates
stage4-persistent/ Host-free persistent root, boot actor + carrier, all state under /data
exploits/         MT8183 exploit research: continuity anchor, rated exploit register,
                  boot-chain map, evidence under notes/ and tooling under tools/
docs/             Technical context, brick analysis, handoff, references
tools/            Offline analysis tooling (symbol extraction, dex patching, boot-chain xref)
dumps/            Partition dumps + partition metadata (gitignored, see below)
diagnostics/      Generated device reports
```

### House style

Prose here reads as statements of what a thing is, and it uses no em dashes. Run
`python tools/style-pass.py --dry-run` to see any that have crept back in; `--apply`
rewrites them. `python exploits/tools/qa-docs.py` checks that every relative link in the
headline documents resolves, and `python exploits/tools/id-sweep.py` refuses to pass if a
device serial, MAC or personal path is present anywhere in the tree.

`dumps/`, `OTAs/`, `ota-extract/`, `refs/` and `stage2a-unlock/` are **gitignored**:
they hold partition images, multi-GB vendor packages and device-unique data that must
not be redistributed. `dumps/README.md` documents how to regenerate them locally with
`dumps/dump-small.sh`.

## What this repository established

The negative results are the substantive contribution; the ordering below reflects
that.

- **No bootloader unlock exists, and here is why (proven).** The mechanism is an
  Amazon-signed `unlock_code` (RSA-2048-PSS) verified by *both* the preloader and LK
  against an embedded Amazon public key; the code lives in the IDME database on eMMC
  boot1. A locked device that fails PSS verification is exactly the documented XDA
  brick. Forging the code needs Amazon's private key. Full analysis:
  [stage2-unlock/README.md](stage2-unlock/README.md). *This corrects the widely
  repeated "IDME `flash:unlock` flag" theory, no such field exists.*
- **Correction (2026-10-08): unlock does *not* disable verification.** An earlier
  revision of this README said an unlocked device "skips LK verification entirely".
  It does not. On an unlocked unit the preloader falls through to a **second
  verification with the alternate Amazon image key** and still rejects on failure,
  so a patched `lk` cannot run even on an unlocked device. Unlock changes *which*
  Amazon key is acceptable, not whether a signature is required, which lowers what
  the unlock this device cannot obtain would actually have bought.
  ([exploits/EXPLOIT-REGISTER.md](exploits/EXPLOIT-REGISTER.md) U14.)
- **Every pre-gate verifier has now been audited to instruction level (2026-10-08).**
  The unlock PSS decoder passes 17/17 RFC 8017 §9.1.2 checks with a positive control
  running the real preloader code and 1,000,000 fuzzed signatures producing zero
  accepts; the LK certificate parser's encoder/decoder length asymmetry is real but
  **not** an authentication bypass, because the SAN digest is covered by Amazon's
  signature over the original DER (verified against the genuine certificate); the
  temp-unlock verifier shows no reachable path that skips its RSA check, although its
  own crypto could not be positively validated. The one genuinely unauthenticated
  write reachable on a locked device is `flash:tucert`/`flash:tucode` into IDME, 
  recorded, with its verifier analysed, in [exploits/](exploits/).
- **Recovery is partition-dependent, not general (proven).** S1 (`boot`) is
  recoverable via recovery plus a newer OTA; S2 (`lk`) and S3/S4 (`preloader`/eMMC)
  are not. The matrix and the evidence for each class are in
  [stage3-recovery/](stage3-recovery/). This is the finding that rules out recovery as
  a foundation for further development.
- **The ATF/TEE path is unverifiable offline (proven).** The bodies are encrypted
  (2.8 MB at exactly 8.000 bits/byte) and decrypt with efuse-derived keys via the
  hardware crypto engine, reachable only over BROM, which is closed. This closes the
  most promising-looking remaining vector rather than leaving it open.
- **A fabricated offset PR, refuted from source.** GhostLock PR #48 claimed
  "verified 100% correct via live device testing" for kernel 4.4.146. The target CVE
  does not exist in 4.4, the offsets are wrong by megabytes, and the patch could not
  have compiled. Validation: [stage2-unlock/README.md](stage2-unlock/README.md).
- **Root is a port, not a discovery.** Stage 1 is the SnuSnuRoot chain
  ([upstream](https://github.com/voidnullvalue/SnuSnuRoot), GPL-3.0) adapted to
  PS7319/1735, CVE-2024-31317 zygote injection → `time_update` uid-0 waiter →
  hwbinder NULL-write to `selinux_enforcing`, with per-firmware carriers for the
  PS732x/PS733x range. The port runs without touching any boot partition; the
  technique belongs to upstream.
- **Symbol extraction reproduces both public ground truths exactly (validated 3/3).**
  [tools/extract-symbols.py](tools/extract-symbols.py) matches Eric Pardee's PS7326
  value and SnuSnuRoot's PS7331 constant, and resolves the running 1735 kernel to the
  same value as the 1726 OTA. See [tools/kernel-symbols.md](tools/kernel-symbols.md).
  This is what made the PR #48 refutation above possible.
- **The kernel attack surface is characterised, and two earlier verdicts were wrong
  (2026-10-08).** Four to six unprivileged local-privilege-escalation exploits are
  reachable on this unit, CVE-2022-38181 (Mali kbase r14p0 JIT UAF),
  CVE-2026-43499 / GhostLock (`rtmutex.c` `remove_waiter()` stack UAF),
  CVE-2021-0920 (AF_UNIX GC vs `MSG_PEEK`) and CVE-2020-0069 (MediaTek CMDQ), plus two
  binder UAFs at medium confidence. Two of those correct earlier statements in this
  repository: GhostLock's vulnerable code **is** present (the earlier audit examined
  functions that do not exist in 4.4), and the CMDQ driver **is** reachable from an app
  (`ioctl` needs no write mode and the stock policy allows it). **None of them unlocks
  anything**: the unlock gate resolves in the preloader, before the kernel runs.
  Ratings and evidence: [exploits/EXPLOIT-REGISTER.md](exploits/EXPLOIT-REGISTER.md).
- **The locked-device fastboot gate is now modelled exactly (2026-10-08).** It is a
  *denylist*, not a command allowlist: 15 commands are registered at runtime,
  `boot`/`verify`/`env`/`ultraflash` are not registered at all, `flash`/`erase`/`oem`
  are denied, and `download:`(although allowed) validates its size into a fixed
  128 MiB buffer with no wrap. A simulator reproduces all 48 live probe verdicts
  ([exploits/tools/lk-gate-sim.py](exploits/tools/lk-gate-sim.py)). The one
  unauthenticated persistent write reachable while locked is
  `flash:tucert`/`flash:tucode` into IDME, whose verifier was audited separately.
- **The hwbinder leak is probabilistic, and its failure mode is root-caused.**
  ENODATA misses come from an RCU-delayed epitem free outrunning the race window; the
  carrier's wait is rescaled 1 ms → 10 ms to cover the tail.
  [docs/ENODATA-ANALYSIS.md](docs/ENODATA-ANALYSIS.md).
  **Corrected in stage 4:** a miss is *not* terminal for the boot as previously
  documented; a retry in the same boot succeeds, which is what makes the persistent
  chain reliable rather than a per-boot gamble
  ([docs/ENODATA-ANALYSIS.md §12](docs/ENODATA-ANALYSIS.md)).
- **Root survives reboot without a host (new, measured).** Stage 1's root reverts on
  every boot. [stage4-persistent/](stage4-persistent/) restores it unattended:
  **13/13 consecutive reboots** with no PC attached, using only files under `/data`.
  Four independent silent failures had to be fixed first; a wrong SELinux label on the
  trigger payload, a state directory the actor's own domain cannot read, Amazon's
  `TimeService` erasing the boot trigger on its NTP sync, and the single-shot carrier
  above. None of them was the exploit, which is the usual reason this kind of work
  stalls.
- **LK fastboot is reachable, and the Windows driver problem is solved.** This is the
  one piece of *host* engineering here, and it cost three separate blockers:
  `adb reboot bootloader` enters genuine LK fastboot (`USB\VID_1949&PID_05E0`, the
  standard `Class_FF/42/03` signature), but Windows binds no driver to it, Microsoft's
  signed `winusb.inf` only covers the **ADB** class (`Prot_01`), and Amazon's official
  driver lists **no `PID_05E0`**. A working WinUSB INF plus reproducible
  build/sign/install tooling is in
  [stage3-recovery/host/winusb-fastboot/](stage3-recovery/host/winusb-fastboot/).
  The non-obvious part: the INF **must** register Android's interface GUID
  `{F72FE0D4-…}`, with any other GUID the driver installs and Device Manager reports
  the device as working, while `fastboot devices` still prints nothing.
- **The locked-device fastboot gate is a strict allowlist, so fastboot is read-only
  in practice.** Exactly six `getvar` names are readable (`product`, `unlock_status`,
  `unlock_code`, `serialno`, `max-download-size`, `slot-count`); every other variable,
  and **every** `oem` command, is refused with `the command you input is restricted on
  locked hw`. The decisive result: `erase`/`format` of a nonexistent partition are
  refused *by the gate rather than with "partition not found"*, proving the check runs
  at command dispatch **before partition lookup**. Consequence: `fastboot flash boot`
  cannot repair a damaged `boot` while locked, and `oem reboot-recovery` cannot reach
  recovery. Evidence:
  [diagnostics/fastboot-gate-probe.txt](diagnostics/fastboot-gate-probe.txt).

## References

See [docs/references.md](docs/references.md) for the full list (XDA thread,
SnuSnuRoot, Eric Pardee's Mali exploit write-up, Amazon kernel sources, OTAs).
Agent-to-agent context: [docs/HANDOFF.md](docs/HANDOFF.md).
Session continuity notes: [docs/RESUME-HERE.md](docs/RESUME-HERE.md).

## Scope, safety and legal

This is **independent security research on hardware the author owns**, published so
that others can reproduce it and so that the *limits* are on the record. It is not
affiliated with, endorsed by, or supported by Amazon, MediaTek or Google.

- **Nothing here is a bootloader unlock.** The unlock mechanism is documented and
  proven to require an Amazon-signed `unlock_code`; forging it is infeasible without
  Amazon's private key. See [stage2-unlock/README.md](stage2-unlock/README.md).
- **No proprietary firmware or vendor tooling is redistributed.** Partition images,
  OTA packages and third-party MTK tools are gitignored; `dumps/README.md` and
  `docs/references.md` say where to obtain them. The `.der` files under
  `stage2-unlock/` are Amazon's **public** CA certificates and RSA public keys, which
  are required to verify a dump you made yourself.
- **No device-unique secrets are published.** Dumps, calibration data and IDME
  contents stay out of the repo. Where a device serial appears in the research notes
  it is the author's own reference unit and can be treated as a fixed test constant.
- **Read the recovery matrix above before running anything from Stage 2.** The author
  accepts no responsibility for bricked hardware: this device has no software
  recovery for a bad `lk`, and that failure is not recoverable in place.
- Logs under `diagnostics/` are raw output from the reference unit and may contain
  that unit's serial; they are included as evidence for the findings above.

**Expectation-setting, stated plainly:** this repository does not unlock this device,
and it does not establish that the device *can* be unlocked with the means documented
here. Its value is the map of dead ends and the evidence for each one. If you arrive
looking for a jailbreak, the honest answer is that there is not one, and the sections
above explain why, so that the effort is not spent twice.

### Licence and third-party material

Original work here (the analysis, tooling and documentation) is **MIT**: see
[LICENSE](LICENSE). Third-party and vendor material is redistributed under its own
terms and is **not** covered by that licence: **see [NOTICE](NOTICE)** for the complete
component list, which includes GPL-3.0 binaries from SnuSnuRoot and Magisk (full text in
[licenses/GPL-3.0.txt](licenses/GPL-3.0.txt)) and firmware-derived material whose
copyright remains with Amazon/MediaTek.

Per [NOTICE](NOTICE) §8, if you are a rights holder and want something removed, open an
issue; it will be removed without argument.
