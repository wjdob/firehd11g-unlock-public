# Kernel Symbol Extraction: Method & Results

How kernel addresses were derived offline from Amazon's own OTA image, with
cross-build validation. This is the "theory-proof before live test" core of
the repository's approach.

## Pipeline

```mermaid
flowchart LR
    A['update-*.bin OTA<br/>(ZIP)'] -->|unzip| B['boot.img']
    B -->|parse ANDROID! header| C['gzip kernel blob']
    C -->|zlib inflate| D['raw ARM64 Image']
    D -->|vmlinux-to-elf| E['vmlinux ELF<br/>(kallsyms reconstructed,<br/>49,040 symbols)']
    E -->|capstone adrp-scan| F['data-symbol addresses<br/>(selinux_enforcing etc.)']
```

Tools: Python 3.14, `vmlinux-to-elf` 1.3.6 (+ `peewee`, `lz4`, `click`),
`capstone`. Script: [extract-symbols.py](extract-symbols.py).

### The kallsyms limitation

`CONFIG_KALLSYMS=y` but `CONFIG_KALLSYMS_ALL` is **not** set, only *text*
symbols are in kallsyms. Data symbols (`selinux_enforcing`, `init_cred`,
`modprobe_path`) are absent. They are recovered by disassembling known
readers/writers and resolving their `adrp + ldr/str` pairs:

- `selinux_capable` contains `if (!selinux_enforcing) return 0;` → the
  `adrp x, page; ldr w, [x, #off]; cbz` pattern identifies the address.
- A whole-`.kernel` scan for all `adrp+ldr/str` pairs referencing the
  candidate address counts its users, 7 references, all in SELinux hook
  code, confirms the identification.

### File-offset mapping gotcha

The reconstructed ELF's `.kernel` section starts at file offset `0x240`
(VA `0xffffff8008080000`). VA→file is `va - 0xffffff8008080000 + 0x240`.
Getting this wrong silently disassembles the wrong bytes; a lesson learned
the hard way here (and the same class of error as Eric Pardee's +0x5c000
build-shift trap).

## Results

### `selinux_enforcing` across builds (all via `enforcing_setup` writer anchor)

| Build | VA | Ground truth | Match |
|---|---|---|---|
| PS7319/1726 | `0xffffff8009965628` |; (this device's version; prediction) |; |
| PS7326/3178 | `0xffffff8009969668` | Eric Pardee HANDOFF (PA `0x41969668`) | ✅ exact |
| PS7331/4463 | `0xffffff8009971668` | SnuSnuRoot hardcoded constant | ✅ exact |

**The pipeline reproduces both independent ground truths exactly.** The
values sit in the same BSS region and advance monotonically with build
date, consistent with incremental code growth.

Notably, the PS7331 OTA is build **4463** while SnuSnuRoot's device ran
**4460**: the address matched anyway. Same-version builds have so far
proven layout-stable for this symbol, which de-risks (but does not
eliminate) the 1726→1735 delta concern.

### PS7319/1726 full symbol set (the device runs 1735)

| Symbol | VA | Notes |
|---|---|---|
| kernel base | `0xffffff8008080000` | no KASLR seed (LK boot path) |
| `selinux_enforcing` | `0xffffff8009965628` | 7 code refs, all SELinux hooks |
| `commit_creds` | `0xffffff80080cb6e4` | |
| `avc_denied` | `0xffffff8008334cd0` | |
| `selinux_capable` (enforcing check) | `0xffffff8008334f04` | reads the above |
| `kbase_ioctl` | `0xffffff80086e7de0` | Mali route only |
| `kbase_mmap` | `0xffffff80086e5298` | Mali route only |

### The 1726 vs 1735 caveat

The device runs PS7319/**1735** (built 2021-05-29); the OTA is **1726**
(built 2021-04-24). Same version, different build; the same class of
delta that made Eric Pardee's static offsets wrong by `+0x5c000` (his was
a cross-*version* difference; the PS7331 4460/4463 match suggests
same-version deltas are benign, but that is one data point). Therefore:

- OTA-derived addresses are **predictions**, never trusted for a write.
- Stage 1 resolves `selinux_enforcing` **at runtime** (uid-0 `/proc/kallsyms`
  read via the `time_update` foothold) and uses the OTA value only as a
  pre-flight sanity check.
- If a 1735 OTA/image surfaces, re-run the extraction to close the delta.

## Reproducing

```powershell
# Prereqs: pip install vmlinux-to-elf peewee lz4 click capstone
python .\tools\extract-symbols.py <path-to-ota.bin> <output-dir>
```

Extracts `boot.img` → kernel → ELF → symbols, and prints the
`selinux_enforcing` candidates with reference counts.
