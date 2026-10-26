# Stage 1: Root (SnuSnuRoot port to trona)

## TL;DR: read this first

**Status: ported and working on PS7319/1735.** Root reached three times end-to-end on
the reference device (run-16 first-attempt; run-17 via the automatic retry loop; run-18
first-attempt with the 10 ms wait patch). Entry point: [run-root.ps1](run-root.ps1),
gated behind a typed confirmation.

**This is upstream work, ported, not a discovery of this project.** The chain is
[SnuSnuRoot](https://github.com/voidnullvalue/SnuSnuRoot) (GPL-3.0), by
voidnullvalue. What is added here is adaptation to PS7319 plus per-firmware carriers
for the PS732x/PS733x range, and the ENODATA root-cause and fix.

- **Core finding**: the chain's only kernel interaction is a NULL byte-write to
  `selinux_enforcing`, whose **address differs per firmware build**. That address is
  resolved from the OTA kernel **offline** and the chain ships one carrier per address
  group, selected at runtime from the device's PS token. OTA-derived values are
  predictions and are sanity-checked, never trusted blindly for a write.
- **Core win**: root with **no writes to any boot partition**, reversible per boot,
  and SELinux reverts on reboot. It does not weaken verity or unlocked-boot state
  (`verifiedbootstate` stays `green`). This stage's own flow needs a host each boot;
  [stage 4](../stage4-persistent/) makes root come back unattended (10/10 reboots).
- **Core dead end**: root does **not** lead to a bootloader unlock. The unlock gate is
  cryptographic (Amazon-signed `unlock_code`), checked by the preloader and LK before
  any kernel code runs, so privilege escalation cannot reach it. See
  [../stage2-unlock/README.md](../stage2-unlock/README.md).
- **Known flakiness**: the hwbinder leak is a race, not deterministic; expect misses
  and automatic retries. A miss **is** retryable (measured), so it is a delay, not a
  failure. Read
  [The probabilistic leak](#the-probabilistic-leak-read-this-before-running) before
  running.

## Firmware compatibility matrix

The chain's one kernel interaction is a NULL byte-write to `selinux_enforcing`,
whose **address differs per firmware build**. The chain therefore ships one
carrier binary per address group and selects the right one at runtime from
your device's `ro.build.id` PS token (registry:
[carriers/carriers.tsv](carriers/carriers.tsv)). **Run Stage 0
([../stage0/run-diagnostics.ps1](../stage0/run-diagnostics.ps1)) first, it
gates on this table and fails closed for unregistered firmware.**

| Fire OS | Build token | Carrier variant | `selinux_enforcing` | Live-verified? |
|---|---|---|---|---|
| 7.3.1.9 | PS7319 | `ps7319` | `0xffffff8009965628` | ✅ **run-16/17/18** (reference device) |
| 7.3.2.1 | PS7321 | `ps7321-ps7326` | `0xffffff8009969668` | ⚠️ address extracted + carrier built; flow untested live |
| 7.3.2.6 | PS7326 | `ps7321-ps7326` | `0xffffff8009969668` | ⚠️ address extracted + carrier built; flow untested live |
| 7.3.3.1 | PS7331 | `ps7331` | `0xffffff8009971668` | ⚠️ address extracted + carrier built; flow untested live (upstream SnuSnuRoot proven on PS7331) |

Notes on the untested rows:

- The **exploit primitives** (CVE-2024-31317 zygote injection, time_update
  trigger, hwbinder NULL-write) are firmware-independent userland/kernel
  mechanisms; upstream SnuSnuRoot is proven on PS7331 and the PS7331 system
  image contains all chain prerequisites (verified offline).
- The **webview uid** is resolved at runtime (`pm list packages -U`), not
  hardcoded; it may differ across firmware or factory resets.
- The **settle times** (120 s / 45 s) were tuned on PS7319 only; other builds
  may need adjustment via `SNUSNU_BOOT_SETTLE`.
- **Unknown firmware fails closed**: no write happens. To add support for a
  new build, obtain its OTA and run
  `python stage1-root/make-carrier.py --ota <update-kindle-*.bin>` (see
  [make-carrier.py](make-carrier.py); it extracts the address from the OTA
  kernel, builds the carrier variant, and prints the registry line to append
  to [carriers/carriers.tsv](carriers/carriers.tsv)).

## What root looks like

The chain is documented in [../docs/root-method.md](../docs/root-method.md). In
short: a userland exploit sequence that ends with a uid-0 listener on
`127.0.0.1:4325` and SELinux Permissive, **without writing any boot,
system, or vendor partition**. Everything lives on `/data` and reverts on
reboot (with an optional per-boot re-arm).

```
locked Amazon boot chain
        ↓
normal Fire OS boots
        ↓
CVE-2024-31317 zygote injection (one-shot per boot)
        ↓
uid-1000 system_app channel → arm time_update waiter
        ↓
reboot → time_update.sh fires the armed trigger as uid 0
        ↓
carrier (uid 10161) → hwbinder NULL-write to selinux_enforcing
        ↓
SELinux Permissive → trigger's getenforce loop breaks → nc listener on 4325
```

## Why it's safe relative to the alternatives

- No kernel-panic race (unlike the Mali CVE-2022-38181 route: ~50% crash
  per attempt).
- No boot-partition writes (unlike the LK-patch route that bricked two XDA
  devices).
- Fully reversible: `disarm` returns the device to stock.
- The one kernel interaction is a single NULL byte-write to
  `selinux_enforcing`, in-memory only.

## Verification status

| Item | Status |
|---|---|
| Kernel prerequisites verified in PS7319 source | ✅ done |
| Device preconditions verified (Stage 0) | ✅ done; all PASS |
| `selinux_enforcing` from OTA kernel (1726) | ✅ `0xffffff8009965628` |
| `selinux_enforcing` from **running** kernel (1735, boot-partition dump) | ✅ `0xffffff8009965628`; matches 1726 |
| Extraction pipeline validated against ground truths | ✅ 3/3 exact (PS7326, PS7331, method) |
| Ported scripts + patched carrier (dex path + address) | ✅ done |
| On-device validation | ✅ **root achieved** (run-16, run-17, run-18) |
| Reproducibility (P2) | ✅ full re-run from cold boot succeeded (run-17, attempt 4/6) |
| ENODATA remediation | ✅ root-caused; 10 ms rescale applied to **both** carriers (JNI `.rodata` literal + the standalone's inline timespec); **a miss is retryable in-boot**: [../docs/ENODATA-ANALYSIS.md](../docs/ENODATA-ANALYSIS.md) |
| Persistent root (no host) | ✅ **done**: [../stage4-persistent/](../stage4-persistent/); 10/10 consecutive reboots unattended |

## The probabilistic leak (read this before running)

The hwbinder leak (`HWBINDER_STATEFUL`) is a kernel race. Observed success rate:
~57% per fresh boot pre-patch; **after the 10 ms rescale (run-18): attempt-1 hit**.
A miss returns `ENODATA` (`result=0x5000003d...`) and **spends that boot's binder-node
state**: the orchestrator ([root_poc.sh](port/scripts/root_poc.sh))
automatically reboots and retries, up to `SNUSNU_ROOT_ATTEMPTS` (default 6) fresh-boot
attempts. A miss is normal, not a failure of your device. Each retry costs ~5 min
(two reboots + settle waits). The miss mechanism (RCU-delayed epitem free vs the race
window) and the rescale are documented in [../docs/ENODATA-ANALYSIS.md](../docs/ENODATA-ANALYSIS.md).

**A miss is retryable; the reboot here is a limitation of this flow, not of the
exploit.** On 2026-10-07 a boot whose first carrier attempt had already returned
`ENODATA` succeeded on the **next attempt in the same boot**. This flow cannot use
that: its JNI carrier holds the probe port, so a second injection has nowhere to
land. The statically linked carrier that [stage 4](../stage4-persistent/) runs can,
and retries 5× in-boot, see [ENODATA-ANALYSIS.md §12](../docs/ENODATA-ANALYSIS.md).

Tunables (environment variables):

| Variable | Default | Meaning |
|---|---|---|
| `SNUSNU_ROOT_ATTEMPTS` | `6` | max fresh-boot leak attempts |
| `SNUSNU_BOOT_SETTLE` | `120` | seconds to settle after `boot_completed` (zygote observer + time service) |

## The 1726/1735 problem and its resolution

The available OTA is build **1726**; the device runs **1735**. Eric Pardee's
experience suggested same-version builds can shift kernel layout. Resolution:

1. **Boot-partition dump (done):** the running `boot` partition was dumped via
   live root and `selinux_enforcing` resolved offline with
   [../tools/resolve-from-bootimg.py](../tools/resolve-from-bootimg.py):
   `0xffffff8009965628`, identical to the OTA-derived 1726 value. The compiled-in
   address is correct for the running build.
2. **`kptr_restrict=2`:** `/proc/kallsyms` is zeroed even for uid 0 on this
   firmware, so runtime kallsyms resolution is **not viable**. Offline resolution
   from the OTA kernel (or a post-root boot dump) is the method; this is why
   the compatibility matrix above is per-build, and why unknown firmware fails
   closed rather than guessing.

## Layout

```
stage1-root/
  README.md          this file
  run-root.ps1       the gated entry point (typed confirmation required)
  make-carrier.py    builds a carrier variant for a new firmware version (OTA or address)
  patch-address.py   rewrites selinux_enforcing VA in the prebuilt carriers
  patch-wait.py      applies the 10 ms ENODATA rescale to a JNI carrier (.rodata literal)
  patch-wait-inline.py  same rescale for the statically linked snusnu_hwbinder_root
  carriers/          per-version carrier registry + variants (committed)
  port/              the ported SnuSnuRoot scripts + PS7319-ADAPTATION.md
  prebuilt-ps7319/   patched carriers (gitignored)
```

## Authorization gate

Running the root chain involves: one or more reboots, a boot-time uid-0 script,
one in-memory kernel NULL-write, and (optionally) installing a persistence
APK. It does **not** touch boot/system/vendor partitions and is reversible
via `disarm` + reboot. The entry point requires a typed confirmation before
doing anything.
