# References

## Primary sources

### SnuSnuRoot (root chain: Stage 1 basis)
- Repo: https://github.com/voidnullvalue/SnuSnuRoot
- Write-up: https://voidnullvalue.github.io/SnuSnuRoot/
- Verified on: trona/KFTRWI, Fire OS 7.3.3.1 (PS7331.4460N), 2026-09-06
- Chain: CVE-2024-31317 (zygote) + CVE-2019-2181-family (hwbinder) +
  `time_update` injection. GPL-3.0.
- Local clone: `refs/SnuSnuRoot/` (gitignored; re-clone as needed)

### Eric Pardee: Mali exploit (alternative root route, not chosen)
- Blog: https://ericpardee.github.io/fire-hd-ownership/
- Full technical handoff: https://ericpardee.github.io/fire-hd-ownership/HANDOFF.html
- Repo: https://github.com/ericpardee/fire-hd-ownership
- CVE-2022-38181 (Mali kbase JIT UAF) on Fire OS 7.3.2.6, kernel 4.4.146,
  MT8183, Mali-G72 (kbase r14p0, UAPI 11.11). Rooted 2026-08-16.
- Key lessons: OTA kernel ≠ running kernel (+0x5c000 build shift); MTK r14p0
  uses a different L3 ATE encoding (`PA | 0x400000000000c1`); runtime anchor
  discovery (init_task scan, modprobe_path hunt, selinux_enforcing hunt) is
  mandatory; ~50% kernel-panic race per attempt.
- Local clone: `refs/fire-hd-ownership/` (gitignored)

### XDA brainstorming thread
- https://xdaforums.com/t/fire-hd-10-11th-generation-2021-bootloader-unlock-root-brainstorming.4509197/
- Page 7 contains: the LK-patch brick report (BluPhant, post #123), the
  GhostLock offset submission and its aftermath, and confirmation that
  SnuSnuRoot works on this hardware.
- Note: XDA returns 403 to direct fetches; use a reader proxy.

### GhostLock PR #48 (rejected offsets: cautionary)
- https://github.com/JoinChang/ghostlock-oneplus/pull/48
- Closed by maintainer: CVE-2026-43499 does not exist in kernel 4.4
  (vulnerable functions introduced in 5.7); submitted offsets were
  round-aligned fabrications. See docs/brick-analysis.md.

## Amazon official sources

### Kernel sources (GPL)
- https://github.com/vendor-mtk-sources/Amazon-Fire_HD10_11th_Gen
- Branch used: `Amazon-Fire_HD10_11th_Gen-7.3.1.9-20210414` (matches this
  device's firmware version)
- Local clone: `refs/kernel-7.3.1.9/` (gitignored)
- Verified from this source: binder secctx UAF pattern, `hlist_del`
  NULL-write site, Mali r14p0 JIT code (for the alternative route),
  ioctl UAPI numbers.

### OTA firmware
- `OTAs/` (gitignored) holds three full OTAs, all targeting `trona`:
  - `update-kindle-Fire_HD_11-PS7319_user_1726_0020367982212.bin`, 
    Fire OS 7.3.1.9. Note: the earlier copy under `7.3.1.9/` was labeled
    "Fire_HD_11_Plus" by the Softpedia mirror; **byte-identical** to this
    one (SHA-256 `CF17F1F0...553AA2`); there is no separate HD 10 Plus
    11th-gen; the label was a misnomer. All analysis applies.
  - `update-kindle-Fire_HD10-PS7326_user_3178_0025602845316(1).bin`, 
    Fire OS 7.3.2.6 (the build Eric Pardee's device ran)
  - `update-kindle-Fire_HD10-PS7331_user_4463_0031575863172.bin`, 
    Fire OS 7.3.3.1 (the build SnuSnuRoot was verified on; their device
    ran the adjacent 4460 build)
- Each contains: `boot.img` (kernel), `images/lk.img`,
  `images/preloader.img`, `system.new.dat.br`, `vendor.new.dat.br`, and
  the updater-script mapping every partition.
- ⚠️ The device runs PS7319/**1735** (incremental 0020367984516, built
  2021-05-29); a newer build of the same version than the 1726 OTA.
  OTA-derived kernel offsets are predictions, not ground truth, though
  the PS7331 4460/4463 cross-build match (see
  tools/kernel-symbols.md) suggests same-version deltas are benign for
  `selinux_enforcing`. Runtime resolution remains the Stage-1 design.

## CVEs involved

| CVE | Component | Fixed in | Relevance |
|---|---|---|---|
| CVE-2024-31317 | Zygote `hidden_api_blacklist_exemptions` | Android 12+ | P1; affects Fire OS 7 / Android 9 |
| CVE-2019-2181 (family) | Binder `binder_transaction` | upstream 2019 | P2; Amazon's 4.4 kernel retains the vulnerable secctx pattern |
| CVE-2022-38181 | Mali kbase JIT UAF | Fire OS 7.3.2.9 (June 2024) | Alternative route; unpatched on 7.3.1.9 |

## Exploit-search sources (2026-10-08 session)

Added by the MT8183 exploit search; each entry was read for applicability and the
verdict is recorded in [../exploits/](../exploits/), most are **not** applicable, and
that is the point of listing them.

### MediaTek preloader / BROM
- `amonet` / `kamakiri` (xyzz, R0rt1z2), BROM-stage payloads.
  https://github.com/xyzz/amonet · https://github.com/R0rt1z2/kamakiri
  Branch `kamakiri-mt8183` is a **partial** MT8183 port: the BROM half is genuine
  (UART `0x11002000`, SEJ `0x1000A000`, MSDC0 `0x11230000`, `var1 = 0x0A`), the LK half
  is still mantis (`LK_BASE 0x41E00000` vs our `0x56000000`), and it contains **no
  BROM-entry logic**. Assessment: [../exploits/notes/kamakiri-mt8183-assessment.md](../exploits/notes/kamakiri-mt8183-assessment.md).
- `amonet-koboreru` (R0rt1z2, Ben Grisdale), preloader EL3 code execution via an
  unsigned TEE sub-image header. https://github.com/R0rt1z2/amonet-koboreru
  Targets mt8163/mt8173/mt8516 only; the vulnerable guard generation is **absent** on
  trona (`exploits/tools/preloader-audit.py` returns guard generation B).
- `kaeru` (R0rt1z2), patches LK and assumes the preloader will accept it.
  https://github.com/R0rt1z2/kaeru · Refuted here: the preloader PSS-verifies `lk`.
- `mtkclient` (bkerler), https://github.com/bkerler/mtkclient. MT8183 appears only as
  the shared MT6771-family entry (`dacode 0x6771`, `damode=XFLASH`); XFLASH needs a
  signed OEM DA, and no MT8183 BROM payload ships.
- MediaTek preloader USB CVE class audited in [../stage2-unlock/README.md](../stage2-unlock/README.md):
  CVE-2022-20055/20056/20058/20059 (OOB write), -20060 (missing auth), -20069
  (integer overflow), -20073 (underflow).

### Kernel
- GhostLock / **CVE-2026-43499**: rtmutex `remove_waiter()` stack UAF.
  https://github.com/R0rt1z2/GhostLock · https://github.com/JoinChang/ghostlock-oneplus
  Fix `3bfdc63936dd` (v7.1). The vulnerable code **is present** in this tree
  (`kernel/locking/rtmutex.c:1079-1090`); the earlier assessment in this repository
  audited functions that do not exist in 4.4 and is corrected.
- **CVE-2021-0920**: AF_UNIX garbage collector vs `MSG_PEEK`.
  Project Zero RCA: https://googleprojectzero.github.io/0days-in-the-wild//0day-RCAs/2021/CVE-2021-0920.html
  Upstream fix `cbcf01128d0a` touches only `net/unix/af_unix.c` (adds `unix_peek_fds`);
  this tree still carries the pre-fix `scm_fp_dup` call sites at `af_unix.c:2253`/`:2498`.
- CVE-2022-38181 PoCs for this SoC: https://github.com/Pro-me3us/CVE_2022_38181_Gazelle ·
  https://github.com/soralis0912/CVE-2022-38181-aristotle · Eric Pardee's handoff above.
- Amazon vendor kernel source: https://github.com/vendor-mtk-sources/Amazon-Fire_HD10_11th_Gen
  (local clone in `refs/kernel-7.3.1.9/`, gitignored).

### Amazon unlock policy
- "Bootloader unlock wall of shame", Amazon entry documents the official mechanism
  (a signed `unlock.bin` flashed to `idme`) and the absence of any developer programme:
  https://github.com/zenfyrdev/bootloader-unlock-wall-of-shame/blob/main/brands/amazon/README.md
  No process, support channel or reported success was found for Fire tablets.

## Device identification

- Amazon device spec table: https://www.developer.amazon.com/docs/device-specs/ft-identify-tablet-devices.html
  (KFTRWI = Fire HD 10 2021, 11th gen)
- This unit: serial `<SERIAL>`, model KFTRWI, device `trona`,
  Fire OS 7.3.1.9 (PS7319/1735), kernel 4.4.146+ (built 2021-05-29),
  security patch 2018-10-05, Android 9 / API 28.
