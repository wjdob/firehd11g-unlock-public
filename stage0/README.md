# Stage 0: Diagnostics (read-only)

## TL;DR: read this first

Device fingerprint and precondition check. **Writes nothing, arms nothing**: this is
the only component here that is unconditionally safe to run.

- **Core win**: it gates Stage 1. It validates every precondition the root chain needs
  and **fails closed** on unregistered firmware rather than letting a later stage write
  to a guessed `selinux_enforcing` address, which would be a wrong-kernel-address bug.
- **Core finding**: on PS7319/1735 every check passes, which is what makes the root
  port safe to attempt on this build.
- **Core dead end**: none. There is nothing to lose by running it; it exists to stop
  you proceeding when you should not.

**Risk: none.** Everything here reads from the device. Nothing is written,
pushed, set, or armed.

## What it does

1. Verifies exactly one authorized adb device is attached.
2. Fingerprints the device: model, firmware, kernel, ABI, verity state.
3. Checks every Stage-1 (root) precondition **without arming anything**:
   - `timeupdate.rc` service exists (the P3 uid-0 carrier)
   - `persist.sys.saved_time` is a clean numeric value (safe to arm)
   - `hidden_api_blacklist_exemptions` is `null` (P1 not spent/stale)
   - SELinux is Enforcing (stock state)
4. Records the partition map (`/dev/block/by-name/`) and mounts.
5. Pulls the kernel config (`/proc/config.gz`) if permitted.
6. Emits a JSON report + pass/fail verdict to `diagnostics/stage0-report.json`.

## Run

```powershell
.\stage0\run-diagnostics.ps1
```

Optional: `-OutDir <path>` to redirect the report.

## Interpreting results

- All `[PASS]` → the SnuSnuRoot chain's preconditions hold; Stage 1 is a
  candidate (still requires your explicit authorization, see
  [../stage1-root/README.md](../stage1-root/README.md)).
- `[FAIL] saved_time is numeric` → the property holds a non-numeric value.
  **Do not proceed**: investigate what set it before anything else.
- `[FAIL] exemptions clean` → a stale `hidden_api_blacklist_exemptions`
  value exists. This is the soft-bootloop guard; it must return to `null`
  (usually clears after a reboot) before any Stage-1 attempt.
- `[FAIL] Device is trona` → wrong device; stop.

## Why these specific checks

The root chain (see [../docs/root-method.md](../docs/root-method.md)) has
two one-shot-per-boot primitives. Running diagnostics *first* guarantees
neither is accidentally spent or left in a bad state, and that the boot-time
uid-0 carrier (`time_update`) exists on this exact firmware build.
