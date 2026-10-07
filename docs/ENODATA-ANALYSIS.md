# ENODATA Deep-Dive: Root Cause and Remediation

**Scope:** why `HWBINDER_STATEFUL` misses with `-ENODATA` on ~43% of fresh-boot
attempts, and how to make the root chain reliable without live
experimentation. All analysis below is offline: kernel source
([refs/kernel-7.3.1.9](../refs/kernel-7.3.1.9)), the live carrier binary, and
existing run logs. Nothing in this document requires touching the device.

> **Two amendments postdate the body of this document and supersede parts of it.**
> §11: the *standalone* carrier (`snusnu_hwbinder_root`, which stage 4 executes)
> needed the same rescale by a different mechanism, and was left unpatched by the
> original work. §12: **a lost ENODATA race is recoverable in-boot**: a retry
> succeeded on a boot whose first attempt had already failed, which invalidates
> the "terminal for the boot" premise that §5 and §7 were written around. Read
> both before using the sections above as a reliability plan.

**Artifact analyzed:** `stage1-root/port/prebuilt/device/arm64-v8a/libhwbinder_target.so`
(36008 bytes, sha256 `e298c1f73cc45bd36e978c5f9efe58210533bf0f4889e77986b6ba2bf344298e`)
, byte-identical to the artifact staged on the device (verified via
`stage_initial_root_assets.sh` hash flow).

---

## 1. Failure signature

Every observed miss logs the same shape (run-17 attempts 1–3; run-15 att 1):

```
HWBINDER_STATEFUL result=0x5000003d00000000 file=0xffffffc00e2779d8 node=0xdead000000000200
```

Every observed hit (run-14/16 att 1; run-17 att 4):

```
HWBINDER_STATEFUL result=0x5000000000000000 file=0x4444444444444444 node=0x22cf
```

Status word decode: `(stage << 56) | (errno << 32) | aux`.

| Field | Miss | Hit | Meaning |
|---|---|---|---|
| stage | `0x50` | `0x50` | both fail/pass at the same stage; the replace race |
| errno | `61` (ENODATA) | `0` | miss = `leak0 != REPLACE_MARKER` check at [controlled_target.c:1801](../refs/SnuSnuRoot/poc/hwbinder-secctx-exploit/controlled_target.c) |
| aux | `0` | `0` | **no worker's send completed early in either case**: all 192 stayed blocked |
| file | stale kernel ptr (varies) | `0x4444…` (REPLACE_MARKER) | epitem `+0x58` (`fllink.next` / forged `ptr`) |
| node | `0xdead000000000200` | worker TID | epitem `+0x60` (`fllink.prev`→LIST_POISON2 / forged `cookie`) |

The miss values are the exact post-`list_del_rcu` content of a freed `epitem`:
`list_del_rcu` poisons `prev` (+0x60 = `LIST_POISON2 = 0xdead000000000200`,
constant) and leaves `next` (+0x58 = a real, boot-varying kernel pointer).
SLUB's freepointer overlays offset 0, so +0x58/+0x60 stay pristine after
`kmem_cache_free`.

**Conclusion from the signature alone:** at delivery time the reader found the
epitem still in its *closed-but-unreplaced* state. No worker's `ctl_buf`
(kmalloc-128, forged content) ever occupied that slot during the entire
~400 ms race window. This is not a partial/corrupted replacement; the slot
was never re-allocated at all.

## 2. The stage-0x50 race (what must happen)

From [controlled_target.c:1766–1810](../refs/SnuSnuRoot/poc/hwbinder-secctx-exploit/controlled_target.c):

1. `prepare_replace_workers()`, 192 workers, each pinned to **CPU 0**, each
   with a socketpair pre-filled to EAGAIN, forged 0x80-byte ctl_buf content
   (`+0x58 = REPLACE_MARKER`, `+0x60 = TID`), blocked on `go`.
2. `close(retained_nodes[1].epoll_fd)` → `ep_free` → `ep_remove` →
   `list_del_rcu(&epi->fllink)` → **`call_rcu(&epi->rcu, epi_rcu_free)`**
   ([eventpoll.c:716,734](../refs/kernel-7.3.1.9/src/kernel/mediatek/mt8183/4.4/fs/eventpoll.c)).
3. 10 × 1 ms wait (~10 ms).
4. `start_replace_workers()`, releases workers 1 ms apart (~192 ms) plus a
   200 ms tail. Each released worker does a **blocking** `sendmsg` whose
   control buffer is `sock_kmalloc(0x80)` → kmalloc-128, claiming the freed
   slot if it is on the freelist, and holding it indefinitely.
5. Reader released → `binder_thread_read` re-reads `target_node->ptr/cookie`
   fresh at delivery ([binder.c:4295–4304](../refs/kernel-7.3.1.9/src/kernel/mediatek/mt8183/4.4/drivers/android/binder.c)).
   Hit ⇔ the slot now holds a worker's forged content.

The critical, often-missed detail: **the free is RCU-delayed**. Between step 2
and the slot actually reaching the kmalloc-128 freelist there is a full RCU
grace period (`call_rcu` → `epi_rcu_free` → `kmem_cache_free`). The race is
therefore:

```
close ──► list_del_rcu ──► call_rcu ──► [RCU GRACE PERIOD: variable] ──► free ──► freelist
                                                                              │
worker releases span ~192 ms + 200 ms tail ◄──────────────────────────────────┘
        a worker's sock_kmalloc must land AFTER the free, BEFORE the read
```

## 3. Root cause

The freed slot is never re-allocated before the reader's delivery read. Two
sub-cases, indistinguishable in the log (both leave the pristine poison
signature), and both consistent with the evidence:

- **(i) RCU grace period exceeds the window.** The kernel is
  `CONFIG_PREEMPT_RCU=y` with `CONFIG_HZ=250`. RCU callbacks are processed by
  per-CPU kthreads/softirqs. During the race there are **193 CPU-0-pinned
  threads** (main + 192 workers) plus the reader, CPU 0 is saturated, and
  the RCU callback for our epitem competes for CPU time. A grace period that
  normally takes tens of ms can stretch to hundreds of ms under this load.
- **(ii) Free completed but no worker claimed the slot in time.** SLUB is
  LIFO per-CPU: once freed, the *next* kmalloc-128 on CPU 0 claims it. All
  192 workers allocate on CPU 0, so this sub-case requires the free to land
  after the last worker allocation (~200 ms in), i.e. it collapses into
  sub-case (i) in practice. The 10 ms post-close wait and the ~192 ms release
  span are simply too short to reliably cover the grace period.

`aux=0` in every miss confirms no worker errored early; the workers did
exactly what they were told; the window was just too small.

**Why the upstream defaults are fragile here:** the 1 ms constants were tuned
on the upstream author's device/load. On trona (8-core MT8183, PREEMPT,
HZ=250, 193 pinned threads on CPU 0) the RCU grace period distribution has a
long tail. ~43% of boots the tail wins.

## 4. Evidence chain

| Claim | Source |
|---|---|
| Miss = unreplaced freed epitem | run-17 log L38/82/126 vs `LIST_POISON2` semantics |
| Free is RCU-delayed | `ep_remove` → `call_rcu` at [eventpoll.c:716,734](../refs/kernel-7.3.1.9/src/kernel/mediatek/mt8183/4.4/fs/eventpoll.c); `epi_rcu_free` L689 |
| Reader re-reads node fresh | [binder.c:4295–4304](../refs/kernel-7.3.1.9/src/kernel/mediatek/mt8183/4.4/drivers/android/binder.c) |
| Workers pin CPU 0, blocking sendmsg | [controlled_target.c:1355–1380](../refs/SnuSnuRoot/poc/hwbinder-secctx-exploit/controlled_target.c) |
| 1 ms waits are real (not jiffy-quantized) | `diagnostics/config`: `CONFIG_HIGH_RES_TIMERS=y` (HZ=250 would otherwise quantize to 4 ms) |
| Wait constants live in ONE shared literal | carrier disassembly, §6 |
| All waits in the carrier consume it | 15 load sites enumerated, §6 |

## 5. Quantification

> **Read §12 first if you are here for the reliability plan.** The numbers below
> measure *per-boot* success and were written on the assumption that a miss was
> terminal for the boot. That assumption is false (§12): a miss is retryable, so
> the per-boot rate is not the metric that governs reliability; the number of
> attempts available in a boot is. This section is kept for the race analysis,
> which stands.

Dataset (fresh-boot attempts): run-14 att1 HIT, run-15 att1 MISS, run-16 att1
HIT, run-17 att1–3 MISS + att4 HIT → **4 hits / 7 attempts ≈ 57% per-boot
success** (95% CI roughly 25–85%, small n). The existing 6-attempt retry
loop gives a point-estimate cumulative success of
$1 - 0.43^6 \approx 99.4\%$, but each retry costs a full reboot cycle
(~2–3 min), and the CI upper bound on miss rate (~80%) would put 6 attempts
at only ~74%. The retry loop is load-bearing and must stay; the goal of the
remediation is to move the per-boot success high enough that most runs
finish on attempt 1.

## 6. The patch point (verified in the live carrier)

The carrier's `wait_one_millisecond()` is `raw_syscall6(NR_NANOSLEEP=101,
&{tv_sec=0, tv_nsec=1000000})`. The compiler placed the 16-byte timespec in
**one shared literal** and fully unrolled the fixed 10-iteration loops:

- **Literal:** file offset **0x11c0** (= vaddr 0x11c0, inside the RX LOAD),
  bytes `0000000000000000 40420f0000000000` = `{tv_sec=0, tv_nsec=1000000}`.
  It is the **only** occurrence of this 16-byte pattern in the file.
- **tv_nsec lives at file offset 0x11c8** (8 bytes, LE).
- **15 load sites** consume it (verified by adrp/add/ldr register tracking):
  0x220c (G1), 0x2c2c, 0x2ca0, 0x5784, 0x5868, 0x599c+0x59a4 (split qword
  loads), 0x5ab4, 0x5ce4, 0x5d0c, 0x5db0, 0x5fe8, 0x61ac, 0x62f4, 0x6504.
- **36 nanosleep call sites** (`movz w8,#101`) rescale with it: three fully
  unrolled 10× groups plus the looped poll sites.

The three unrolled groups map to source:

| Group | Sites | Source function | Role |
|---|---|---|---|
| G1 | 0x2250–0x2394 | `controlled_stateful_run` L1780 | **the stage-0x50 post-close wait** (markers: `mov w8,#0x50`@0x21e4, close svc@0x222c, `bl start_replace_workers`@0x239c) |
| G2 | 0x5af0–0x5c34 | `retained_epitem_alloc` L1485 | setup-phase post-close wait (per `retained_uaf_create` attempt) |
| G3 | 0x6530–0x6674 | `spray_epitems` L1096 | spray post-close wait |

Looped consumers (early-exit in practice): `read_next` EAGAIN poll (5000×),
`prepare_replace_workers` ready-poll (5000×), `start_replace_workers`
release spacing (192×) + tail (200×), worker/reader `go`-spins (parallel,
no wall-clock impact).

**One 8-byte patch at file offset 0x11c8 rescales every wait in the carrier.**

## 7. Remediation options

### (a) Global literal rescale 1 ms → 10 ms: RECOMMENDED

Rewrite tv_nsec at offset 0x11c8: `1000000` → `10000000`
(`40420f0000000000` → `8096980000000000`).

| Timing element | Current | Patched |
|---|---|---|
| G1 post-close wait | 10 ms | 100 ms |
| Worker release span | ~192 ms | ~1920 ms |
| Release tail | 200 ms | 2000 ms |
| G2/G3 setup waits | 10 ms each | 100 ms each |
| Poll loops (worst case) | 5 s | 50 s (early-exit in practice) |
| **Typical stage-0x50 wall time** | **~0.4–1 s** | **~4–5 s** |

Why it fixes both miss sub-cases:

- **(i)** the RCU grace period now has ~4 s to complete instead of ~0.4 s, 
  two orders of magnitude more margin against the PREEMPT_RCU tail;
- **(ii)** the spray window widens from ~192 ms to ~1.92 s, if the free
  lands anywhere in that span, subsequent workers claim the slot.

Side effects are benign or beneficial: G2/G3 setup waits also get more RCU
margin (strictly more deterministic setup); poll loops early-exit; go-spins
run parallel. The write stage (0x51) contains **no waits** and is unaffected.

**Required companion change:** [reroot_after_boot.sh](../stage1-root/port/scripts/reroot_after_boot.sh)
sends the leak with `toybox nc -w 6` (L229). A patched carrier answers in
~4–5 s, which races the 6 s timeout. **Raise the leak (and write, for
margin) `nc -w` to 20.** The PING/ID probes (L123/126, `-w 3`) precede the
leak and are unaffected.

**Deployment:** patch the prebuilt in place; delete
`stage1-root/port/.assets-staged.sha256` (the host-side "already staged"
marker, `repo_dir` = `stage1-root/port`); the next `root_poc.sh` run
restages automatically because `stage_initial_root_assets.sh` computes the
expected hash **from the source file at runtime** (L49), so the new hash is
picked up with no other edit.

Risk: minimal. The patch touches data, not code; verification is trivial
(exactly one literal, old absent, new present); the carrier is otherwise
byte-identical; and a mistimed carrier cannot brick anything, worst case is
another ENODATA and a retry.

### (b) Surgical G1-only rescale: rejected

Would keep setup waits at 1 ms and only stretch the race. Infeasible
cleanly: the loaded segments contain no free slot for a second literal, and
retargeting G1's `adrp/add` pair to a new page requires writable slack that
isn't there (bytes after file offset 0x6cd8 are section-header content,
never loaded). The global patch's "extra" effects are beneficial anyway.

### (c) Rebuild from source (Docker + NDK/musl): highest confidence, heavy lift

Edit `wait_one_millisecond()` in
[controlled_target.c](../refs/SnuSnuRoot/poc/hwbinder-secctx-exploit/controlled_target.c)
and rebuild per upstream `build.sh`. Produces a carrier that no longer
matches the analyzed binary (new toolchain, new codegen), so all the
offset/address verification in this document would need to be redone.
Only worth it if we later need *structural* changes, not a constant change.

### (d) Script-level only (status quo): superseded by §12

Keep the 6-attempt reboot retry (point estimate ~99.4% cumulative, but
CI-bounded worst case ~74%). No offline work needed, but each miss costs a
~2–3 min reboot cycle and the per-boot rate stays a coin flip.

**§12 changes this option's cost, not its validity.** Because a miss is
retryable in the same boot, retries need not cost a reboot at all, which is
what makes the cheap option the *final* answer for stage 4, with option (a)
still worthwhile for raising the first-attempt hit rate. The cross-boot retry
loop remains the safety net for any residual miss mode.

## 8. Verification plan (no live test required to establish confidence)

1. Patch tool (patch-address.py pattern): assert exactly one
   `{0,1000000}` literal; rewrite tv_nsec; assert exactly one
   `{0,10000000}` and zero `{0,1000000}`; re-disassemble the 15 load sites
   and confirm they still resolve to 0x11c0.
2. Confirm the ELF is otherwise byte-identical (only 8 bytes differ).
3. Confirm script timeouts: leak/write `nc -w 20`.
4. Marker deleted → next run restages and hash-verifies the patched carrier
   on-device (the staging flow itself proves delivery).
5. Live validation (only with explicit authorization, since root is
   currently live and a re-run costs reboot cycles): expect attempt-1 hits
   on consecutive boots; a miss under the widened window would indicate a
   third miss mode worth investigating (none is currently known).

## 9. Out of scope / notes

- The 32-bit `libhwbinder_target.armeabi-v7a.so` is never selected on this
  device (arm64-only; 32-bit carriers are rejected for stateful before any
  wait matters). Not patched.
- The standalone `snusnu_hwbinder_root` was not patched at the time of this
  analysis, on the stated assumption that it was JNI-carrier-only. **That
  assumption no longer holds**: the Stage-4 boot actor executes
  `/data/snusnu_hwbinder_root stateful-root-hold`, and it needed the same
  rescale by a different mechanism. See §11.
- `aux=0` on every miss also rules out worker early-error modes
  (`-EIO`/`-EPIPE` would set `result` and increment `aux`).

## 10. Outcome: patch applied and live-validated (run-18)

Option (a) was implemented and validated end-to-end on 2026-10-05:

- **Patch tool:** [stage1-root/patch-wait.py](../stage1-root/patch-wait.py)
  (asserts exactly one `{0,1000000}` literal, rewrites tv_nsec at 0x11c8,
  verifies exactly one `{0,10000000}` / zero old, and that only bytes inside
  the tv_nsec field differ).
- **Host prebuilt patched in place:**
  `e298c1f73cc45bd36e978c5f9efe58210533bf0f4889e77986b6ba2bf344298e`
  → `8b71c71da7b8b77fcaa854b013b5f87054e3881e60918ced3c18af4b20586696`.
- **Companion change:** [reroot_after_boot.sh](../stage1-root/port/scripts/reroot_after_boot.sh)
  leak and write `nc -w 6` → `nc -w 20` (patched carrier answers in ~4–5 s).
- **On-device mirror:** both staged copies
  (`libhwbinder_target.so` and `libhwbinder_target.arm64-v8a.so` in
  `/data/user/0/com.amazon.webview.chromium/files/sn/`) patched in place via
  the live root listener (`dd seek=4552 conv=notrunc`, 8 bytes), preserving
  inode/owner/SELinux label and the staging marker. Device hashes verified
  equal to the patched host hash. Script:
  [mirror_wait_patch_on_device.sh](../stage1-root/port/scripts/mirror_wait_patch_on_device.sh).
- **Live validation (run-18, `diagnostics/root-run-18.log`):** full chain
  from a fresh boot, **attempt 1/6 HIT**. Leak returned
  `result=0x5000000000000000 file=0x4444444444444444` on the first fresh-boot
  attempt; write `0x51` clean; SELinux Permissive; uid-0 listener live.
  The leak stage took ~4–5 s (as predicted) inside the raised 20 s timeout.

Pre-patch per-boot rate: 4/7 ≈ 57% (CI 25–85%). Post-patch: 1/1 on the
validation boot. One hit does not tighten the CI meaningfully; the retry
loop stays as the safety net, but the widened window covers the RCU
grace-period tail that caused every observed miss, and the validation run
behaved exactly as the timing model predicted (no new miss mode surfaced).

**Note for future runs:** the patched carrier's stage-0x50 takes ~4–5 s
(was ~0.4–1 s). Any tooling that talks to the carrier's probe port must
use a timeout ≥ 20 s for the leak/write commands.

## 11. Addendum: the standalone carrier, and why it needed a different patch

Stage 4 (persistent root) made the standalone `snusnu_hwbinder_root` load-bearing:
the installed boot actor spawns it as `system_app` and greps its output for
`__SNU_NATIVE_0__`. It was therefore running **unpatched**, and it duly returned
the §1 failure signature on device:

```
snusnu_native_result = HWBINDER_STATEFUL result=0x5000003d00000000
```

`patch-wait.py` cannot fix it. It searches for the shared 16-byte
`{tv_sec=0, tv_nsec}`, and the standalone, same `controlled_target.c`, but
statically linked and built with different register allocation, builds the same
wait **inline** as two instruction immediates instead of a `.rodata` literal:

```asm
mov  x7, #0x4240          ; movz  imm16 = 0x4240
movk x7, #0xf, lsl #16    ; movk  imm16 = 0xf  ->  x7 = 0xF4240 = 1 ms
stp  xzr, x7, [sp, #0x20] ; the timespec
mov  x8, #0x65            ; __NR_nanosleep
svc  #0
```

The two halves are **not reliably adjacent**: the compiler schedules other
instructions between them at most sites, so pairing is by register: each
`movz Rd,#0x4240` takes the nearest following `movk Rd,#0x16,lsl #16`. In this
binary the signature is unambiguous: 9 `movz` sites, 9 `movk` sites, one `movk`
per `movz`, registers x7/x9/x10/x13, matching the 9 `nanosleep` sites exactly.

**Patch tool:** [stage1-root/patch-wait-inline.py](../stage1-root/patch-wait-inline.py).
Same verification discipline as `patch-wait.py` (old count, new count, no stale
sites, no bytes changed outside the immediate fields), plus a `--verify` mode so
`stage4-persistent/preflight.py` can gate a root cycle on it.

| | |
|---|---|
| sites | 9 (x7 ×3, x9 ×4, x10 ×1, x13 ×1) |
| instruction offsets | `0x8f4 0xab8 0x14b0 0x25a0 0x2b08 0x3168 0x31f4 0x3240 0x3288` |
| bytes changed | 36 (4 per pair) |
| sha256 before | `543ae663c1b8ef5657f2b10b4d56cbb25355c13824c06335808233b017deb70c` |
| sha256 after | `eabd30cb23b99d7f8820639f008193453f30d4584c8b69680f4717bae5d2ef18` |

Verified after patching by disassembly rather than by the tool's own report:

```asm
0x0008f4  mov   x7, #0x9680
0x000900  movk  x7, #0x98, lsl #16   ; x7 = 0x989680 = 10 000 000 ns = 10 ms
0x000924  stp   xzr, x7, [sp, #0x20]
```

No companion `nc -w` change is needed here: the boot actor polls the carrier's
output file and its process liveness for up to 180 s, rather than timing a socket
read, so the ~4–5 s stage-0x50 is well inside its window.

## 12. Correction: ENODATA *is* recoverable in-boot

Stage 1 asserted the opposite, in
[reroot_after_boot.sh](../stage1-root/port/scripts/reroot_after_boot.sh):

> This boot's binder-node state is spent; NULL write requires a fresh kernel boot
> (in-boot carrier respawn cannot clear ENODATA/EALREADY).

**That does not hold on trona.** Measured 2026-10-07 on a boot whose first
attempt had already returned `0x5000003d00000000`: re-running
`snusnu_hwbinder_root stateful-root-hold` from the same live `system_app` channel
succeeded on the **very next attempt**:

```
attempt 1: HWBINDER_STATEFUL result=0x5000000000000000;
           HWBINDER_STATEFUL_WRITE result=0x5100000000000000;
           __SNU_NATIVE_0__;
enforce_after=Permissive
```

Probe: [stage4-persistent/inboot-retry-probe.sh](../stage4-persistent/inboot-retry-probe.sh).

This changes the reliability model completely. §5 measured 4 hits / 7 fresh-boot
attempts ≈ 57%, and §7 treated the retry loop as load-bearing precisely because a
miss was believed to be terminal for that boot. If a miss is instead retryable,
the per-boot rate stops mattering, only the per-boot *number of attempts* does.

Confirmed in production: after the stage-4 actor was changed to retry in-boot,
one boot's recorded result was

```
__SNU_CARRIER_ATTEMPT_1__;__SNU_CARRIER_MISS_1__;__SNU_CARRIER_ATTEMPT_2__;
HWBINDER_STATEFUL result=0x5000000000000000; ... __SNU_NATIVE_0__
```

; a boot that the single-shot design would have failed, rescued by attempt 2.

**Caveat on the mechanism.** The probe's successful retry happened several
minutes into the boot, while the failing first attempt ran ~5 s after
`boot_completed`. So the data prove retrying *works*, but do not separate
"the retry cleared the spent state" from "a later attempt in a settled boot
succeeds more often". The stage-4 actor does not need to distinguish them: it
retries up to 5 times with 12 s spacing, which covers both. Anyone tightening
that loop should re-run the probe to see which effect dominates.
