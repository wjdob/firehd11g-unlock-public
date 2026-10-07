# Stage 4: Persistent root

Goal: **root that comes back on every boot with no PC attached.**

Stage 1 gives root, but the SELinux flip that makes it possible is performed by the
*host* on each boot (`reroot_after_boot.sh`). Unplug the cable and root is gone. This
stage wires up the on-device chain instead.

Status: **mechanism established; three real gaps found and fixed; blocked on one
directory-permission issue.** Not yet returning unattended root, see
[Validation](#validation) for exactly how far it gets and the one command left.

---

## TL;DR

| question | answer |
|---|---|
| Does unattended root survive a reboot? | **Yes.** Verified over **13 consecutive reboots** across runs (10 earlier + 3 on the final build), no host PC attached: uid-0 shell on `127.0.0.1:4325` as `u:r:time_update:s0`, SELinux Permissive, carrier resident. |
| Does anything boot-critical get written? | **No.** Every file lives under `/data`. No boot, system, vendor, recovery or partition-table write; nothing outside `/data` is touched. |
| How does it work? | Amazon's `persist.sys.saved_time` command-injection fires `/system/bin/sh .../w/b` as **uid 0** at boot; that waiter runs `/data/snusnu_hwbinder_root`, which flips SELinux Permissive via the hwbinder leak, then starts the uid-0 listener. |
| What was actually broken? | **Five separate silent failures**, each found by measurement, none of them the exploit: a wrong SELinux label on the trigger payload, a state directory the actor's domain cannot read, an NTP sync that erases the boot trigger, a single-shot carrier that loses its race ~1 boot in 3, and a fresh install that never receives the boot broadcast. |
| Biggest surprise | The documented claim that *"in-boot carrier respawn cannot clear ENODATA"* is **false on this device**. A retry in the same boot succeeded where the first attempt failed; which is what turns a 67%-per-boot gamble into a reliable chain. See [docs/ENODATA-ANALYSIS.md §12](../docs/ENODATA-ANALYSIS.md). |
| Cost of a failure | Low. A failed boot just boots normally with no root; the trigger stays armed, so the next reboot tries again. `--remove` + reboot reverts, and a refused build gate is recoverable. |

---

## Why stage 1 alone is not persistent

Stage 1's boot chain has three parts, and only the middle one lives on the device:

| part | where it runs | persistent? |
|---|---|---|
| uid-0 listener on `127.0.0.1:4325` | `time_update` (uid 0), driven by `persist.sys.saved_time` | trigger persists, but… |
| **the SELinux flip** | **host**, via `reroot_after_boot.sh` → zygote injection → carrier → hwbinder NULL-write | **no; needs a PC each boot** |
| carrier binaries | `/data` | yes |

So the trigger is armed and *does* fire every boot, but it waits for `getenforce` to read
`Permissive`, and nothing on the device makes that happen. Hence: host required.

## The missing piece already existed

Two prebuilt artifacts in `stage1-root/port/prebuilt/` were never referenced by any
script in this repository:

**`snusnu-persistence.apk`** (16 KB), package
`io.github.voidnullvalue.snusnuroot.persistence`. Its manifest declares exactly what a
boot-time actor needs:

```
permission  : WRITE_SECURE_SETTINGS, RECEIVE_BOOT_COMPLETED, FOREGROUND_SERVICE, INTERNET
attributes  : directBootAware, defaultToDeviceProtectedStorage
receiver    : BootReceiver   <- LOCKED_BOOT_COMPLETED, BOOT_COMPLETED, MY_PACKAGE_REPLACED
service     : PersistenceService (persistent)
other       : BootstrapActivity
```

`directBootAware` + `LOCKED_BOOT_COMPLETED` means it runs *before* user unlock, early
enough for the one-shot zygote injection.

**`snusnu_hwbinder_root`** (214 KB); the native carrier the app calls. Verified to
contain every symbol the app expects:

```
stateful-root-hold          <- the subcommand the app invokes
__SNU_NATIVE_0__            <- the sentinel the app waits for
controlled_stateful_leak0/1, controlled_stateful_write, controlled_stateful_status, ...
```

## What the app does at boot

Both commands below were extracted verbatim from the APK's `classes.dex`.

**1. The injected command** (reaches the device via the zygote injection that the app
triggers with its `WRITE_SECURE_SETTINGS` call):

```sh
for i in $(seq 1 120); do [ "$(getprop sys.boot_completed)" = 1 ] && break; sleep 1; done
sleep 5
out=/data/securedStorageLocation/snusnu/state/native_result
/data/snusnu_hwbinder_root stateful-root-hold </dev/null >"$out" 2>&1 &
for i in $(seq 1 180); do
  if grep -q __SNU_NATIVE_0__ "$out"; then cat "$out"; exit; fi
  if ! kill -0 $keeper; then cat "$out"; exit; fi
  sleep 1
done
```

That is the hwbinder NULL-write → SELinux Permissive, performed on-device.

**2. The re-arm command**, which persists the trigger for the next boot:

```sh
now=$(getprop persist.sys.saved_time)
if [ "$now" != 'x[$(sleep 30;/system/bin/sh /data/securedStorageLocation/w/b)]000' ]; then
    setprop persist.sys.saved_time 'x[$(sleep 30;/system/bin/sh /data/securedStorageLocation/w/b)]000'
fi
```

## The one thing that was broken, and the fix

That trigger runs `/system/bin/sh` over `/data/securedStorageLocation/w/b` as
`time_update`. Stage 1 had already established, and documented in
`stage_reroot_waiter.sh`; that **the file-based form cannot work here**:

> The upstream file-based bootstrap (`/data/securedStorageLocation/w/b`) cannot work on
> PS7319: the live binary policy grants `time_update` **no read** on
> `assetstorage_data_file`, `cache_file`, or any other staging-writable location. Its
> readable set is only `shell_exec`, `toolbox_exec`, `time_update_exec`,
> `time_update_tmpfs`, `sysfs_devinfo`.

So the app would arm a trigger that silently fails, every boot, forever. That is the gap
between "the app exists" and "persistence works".

**The fix is one relabel, not a patch.** A file's SELinux label is an xattr stored with
the file on `/data`, and `shell_exec` is in the readable set:

```sh
chcon u:object_r:shell_exec:s0 /data/securedStorageLocation/w/b
```

Then `sh` can read it as `time_update`, and the app's own trigger works unmodified.

Three reasons this is preferable to patching the APK:

1. **No signature problem.** Modifying `classes.dex` invalidates the APK's v1 signature,
   so it would have to be re-signed with a different key, doable but more moving parts.
2. **No dex surgery.** Changing the trigger string changes its length, which shifts every
   offset after it in the dex (string pool + `string_ids` + checksum + SHA-1). Avoiding
   that entirely is worth a lot.
3. **It survives reboot.** The label is on the file. Nothing runs `restorecon` on this
   path, because it is not in `file_contexts`.

Everything touched is under `/data`. **No boot, system, vendor or partition-table write
is involved**, so this stays inside stage 1's safety envelope.

## Resulting boot chain

```
power on
  └─ Fire OS boots; SELinux Enforcing
      ├─ time_update.sh (uid 0) evaluates persist.sys.saved_time
      │     └─ sleep 30, then `sh /data/securedStorageLocation/w/b`   [chcon'd readable]
      │           └─ waits for Permissive, then binds 127.0.0.1:4325  -> uid-0 shell
      └─ PersistenceService / BootReceiver (directBootAware)
            └─ sets hidden_api_blacklist_exemptions  -> zygote injection
                  └─ /data/snusnu_hwbinder_root stateful-root-hold
                        └─ hwbinder NULL-write -> SELinux Permissive
                              └─ (unblocks the trigger above)
            └─ re-arms persist.sys.saved_time for the next boot
```

Two independent mechanisms, either of which can fail without bricking anything: the
property trigger is restored by the app, and the app is retried by its own
`snusnu_retry_count` logic.

## The five silent failures, and how each was found

Every one of these failed *silently* -- the chain looked wired up and did nothing,
or worked on some boots and not others. Each was resolved by measurement, not by
retrying harder. They are listed in the order they were hit.

### 1. The trigger payload had the wrong SELinux label

`time_update` (the uid-0 boot service) has **no read access** to
`assetstorage_data_file`, `cache_file` or any other staging-writable location.
Its readable set is only `shell_exec`, `toolbox_exec`, `time_update_exec`,
`time_update_tmpfs`, `sysfs_devinfo`. Upstream's trigger points at
`/data/securedStorageLocation/w/b`, which is `assetstorage_data_file`, so `sh`
could not read it and the trigger died every boot.

**Fix -- one relabel, no APK patch and no re-signing:**

```sh
chcon u:object_r:shell_exec:s0 /data/securedStorageLocation/w/b
```

A label is an xattr on `/data`, so it survives reboot, and nothing runs
`restorecon` on that path because it is not in `file_contexts`.

### 2. The actor's state directory is unreachable for its own domain

The app writes `native_result` into its state directory and **reads it back** to
look for `__SNU_NATIVE_0__`. Upstream puts that under
`/data/securedStorageLocation/snusnu/state`. Measured, under Enforcing:

```
avc: denied { search } for name="securedStorageLocation"
    scontext=u:r:system_app:s0  tcontext=u:object_r:assetstorage_data_file:s0  tclass=dir
```

`system_app` (the domain the actor's UID-1000 channel runs in) is denied even
`search` on that tree, so `rm`, create and read all returned `EACCES` and every
boot ended in `system_native_failed`. The state now lives in
`/data/cache/snusnu/state` -- `cache_file`, which `system_app` may search, create
and unlink in -- and the app creates it on demand, because `/data/cache` is
scratch space and is not guaranteed to survive an OTA.

Two related, non-obvious details, both measured:

* **Do not point `native_result` at `/dev/null`.** Redirection to an *existing*
  file needs write on the file, which looks like it dodges the directory problem,
  but the app reads the file back, `/dev/null` always reads empty, and every boot
  then reports `system_native_failed`. This mistake cost several boots.
* **`$STATE` must stay root-owned.** `time_update` is DAC-exempt but has **no
  `CAP_FOWNER`**, so its boot-time `chmod 0777 $STATE` on a UID-1000-owned
  directory is denied with `{ fowner }`. Mode `0777` owned `root:root` satisfies
  both sides.

### 3. Amazon's time service erases the boot trigger

This is the one that produced the classic "works every other boot" symptom.

`persist.sys.saved_time` is **not** durable. Amazon's
`com.amazon.fireos.service.timeservice` performs an NTP sync ~20 s and ~130 s
after boot and writes the synced millisecond clock into that property, clobbering
the armed value. Measured in logcat:

```
TimeService.clockWrapper: broadcastTimeUpdate: isTrusted = true syncMethod = NTP
    oldTimeMillis = 1791389093864   newTimeMillis = 1791389093870
```

`1791389093870` is byte-for-byte the numeric value left in the property
afterwards. `time_update.sh` itself never writes it -- its entire source only
reads, runs `date -u @`, and logs -- so `TimeService` is the sole writer.

Consequence: the trigger is armed for the current boot, NTP makes it numeric, and
the **next** boot's `load_persist_props_action` finds nothing to evaluate. The
waiter never starts, no listener appears, and the app still reports
`kernel_write_ok` because SELinux really was flipped. Alternating boots.

**Fix -- a re-arm watchdog.** The actor spawns a detached `setsid` shell that
re-arms the property within 2 s of any mismatch. A single restore would be racy
against an NTP write at an unknown moment; polling makes the value armed at every
instant, so whichever moment the user reboots, the next boot fires. Verified: it
survives the channel disconnecting, and restores the property within 7 s of a
deliberate clobber. Cost is one `getprop` per 2 s.

### 4. The carrier loses its race about 1 boot in 3, and a retry fixes it

`HWBINDER_STATEFUL result=0x5000003d00000000` -- `0x3d` is `ENODATA`: the
stage-0x50 replace race was lost, the freed `epitem` slot never reclaimed by a
worker's spray. Measured over 15 boots, single-shot carries about 67% per boot
(patched; roughly 33-57% unpatched). Not a reliable chain.

Stage 1 asserted this was terminal for the boot:

> NULL write requires a fresh kernel boot (in-boot carrier respawn cannot clear ENODATA/EALREADY)

**That is false here.** On a boot whose first attempt had already returned
ENODATA, re-running the carrier from the same live channel succeeded on the next
attempt:

```
attempt 1: HWBINDER_STATEFUL result=0x5000000000000000;
           HWBINDER_STATEFUL_WRITE result=0x5100000000000000;
           __SNU_NATIVE_0__;
enforce_after=Permissive
```

So the actor now retries up to 5 times with 12 s spacing, and the recorded result
of a real boot shows the retry doing the work:

```
__SNU_CARRIER_ATTEMPT_1__;__SNU_CARRIER_MISS_1__;__SNU_CARRIER_ATTEMPT_2__;
HWBINDER_STATEFUL result=0x5000000000000000; ... __SNU_NATIVE_0__
```

Two of the final six accepted boots needed exactly this. The probe is kept as
[inboot-retry-probe.sh](inboot-retry-probe.sh).

### 5. A freshly installed package never receives the boot broadcast

`adb install` of a *new* package leaves it in Android's **stopped** state, and a
stopped package receives **no broadcasts at all**, so `BOOT_COMPLETED` never
reaches the actor: no watchdog, no status writes, no root. Every install check
still passes, so nothing looks wrong until the next boot. Measured after an
uninstall-then-reinstall:

```
stopped=true notLaunched=true      # dumpsys
0 logcat matches for the package   # it never ran
setprop: failed to set property    # and adb shell cannot arm the trigger either
```

An upgrade (`install -r` over an existing package) clears the flag; a
uninstall/reinstall does not. `BootstrapActivity` exists precisely for this, 
its manifest comment says "used by the installer to clear package stopped state", 
but the installer never called it, so the first boot after a fresh install was
silently rootless.

**Fix:** the installer launches `BootstrapActivity` when it finds the package
stopped, refuses to continue if it cannot clear it, and verification reports
`actor not stopped`. This is worth knowing even outside this script: any manual
install needs that one explicit launch.

## The exploit itself, and one more patch

The carrier the actor runs is `snusnu_hwbinder_root` -- statically linked, built
from the same `controlled_target.c` as Stage 1's JNI carrier
(`#define REPLACE_WORKERS 192` is shared), and **domain-agnostic**: it reads
`/proc/self/attr/current` and computes its security-context allocation from the
live process rather than baking in a domain string.

It was nonetheless running **unpatched**. Stage 1's
[ENODATA-ANALYSIS.md](../docs/ENODATA-ANALYSIS.md) documents a `1 ms -> 10 ms`
rescale of the shared `{tv_sec, tv_nsec}` literal, applied to
`libhwbinder_target.so` only -- the standalone was explicitly out of scope on the
assumption it was unused, an assumption that stopped being true when this stage
wired it up.

`patch-wait.py` cannot patch it: the standalone builds the same wait **inline**
rather than from `.rodata`:

```asm
mov  x7, #0x4240          ; movz  imm16 = 0x4240
movk x7, #0xf, lsl #16    ; movk  imm16 = 0xf  ->  x7 = 0xF4240 = 1 ms
stp  xzr, x7, [sp, #0x20] ; the timespec
mov  x8, #0x65            ; __NR_nanosleep
svc  #0
```

The two halves are not reliably adjacent, so
[patch-wait-inline.py](../stage1-root/patch-wait-inline.py) pairs each
`movz Rd,#0x4240` with the nearest following `movk Rd,#0xf,lsl #16` and rescales
all 9 sites (36 bytes), verifying old count, new count, no stale sites, and no
bytes changed outside the immediate fields. Confirmed by disassembly, not by the
tool's own report:

```asm
0x0008f4  mov   x7, #0x9680
0x000900  movk  x7, #0x98, lsl #16   ; 10 000 000 ns = 10 ms
```

This is a real but *partial* improvement: single-shot went from roughly 33-57% to
roughly 67% per boot. The retry loop is what makes the chain reliable.

## Install

Three steps, and the APK needs a build first because the stock prebuilt is not
usable on this firmware.

```sh
# 0. build the patched actor (needs an Android SDK; SNUSNU_SDK or ANDROID_HOME)
sh stage4-persistent/app/build.sh
#    it prints the signing SHA-1; it must match the prebuilt's so that
#    `adb install -r` upgrades in place: 6bac00df293be88c48e950e83280dae2f03688a1

# 1. install the app and grant its permission
adb install -r stage4-persistent/app/build/snusnu-persistence.apk
adb shell pm grant io.github.voidnullvalue.snusnuroot.persistence \
    android.permission.WRITE_SECURE_SETTINGS

# 2. check every invariant BEFORE spending a root cycle
python stage4-persistent/preflight.py        # must print "RESULT: clean"

# 3. get root for this boot (host, one time)
powershell -File stage1-root/run-root.ps1 -ConfirmRoot

# 4. wire up the on-device chain (needs root: /data writes + setprop)
sh stage4-persistent/install-persistence.sh

# 5. validate with the host DISCONNECTED
adb reboot
# root appears ~45-60 s after boot; then:
printf 'id\nexit\n' | adb shell 'toybox nc -w 3 127.0.0.1 4325'
```

### A fresh install needs one explicit launch

`adb install` of a *new* package leaves it in Android's **stopped** state, and a
stopped package receives **no broadcasts at all**, so `BOOT_COMPLETED` never
reaches the actor: no watchdog, no status writes, no root, while every install
check still passes. An upgrade over an existing install clears the flag; an
uninstall-then-reinstall does not, which is how this was found (it cost two boots
to notice and two more to recover).

`install-persistence.sh` now clears it (it launches `BootstrapActivity`, which is
what that activity exists for) and refuses to proceed if it cannot, and
`--status`/verification report `stopped=false`. If you ever install the APK by
hand, launch it once:

```sh
adb shell am start -n io.github.voidnullvalue.snusnuroot.persistence/.BootstrapActivity
adb shell dumpsys package io.github.voidnullvalue.snusnuroot.persistence | grep -o 'stopped=[a-z]*'
```

Step 0 exists because upstream's checked-in APK hardcodes a state path this
firmware denies, and upstream's checked-in carrier has no ENODATA rescale, see
§2 and "The exploit itself" above. The fork carries three source changes, all
commented in `app/src/.../PersistenceService.java`.

```sh
sh stage4-persistent/install-persistence.sh --status   # report only
sh stage4-persistent/install-persistence.sh --remove   # revert

# measure repeatability (reboots N times, requires unattended root each time)
powershell -File stage4-persistent/acceptance-test.ps1 -Reboots 6
```

### Removal does more than delete files

`--remove` stops things in a specific order, because the obvious order does not
work:

1. **Writes the disable sentinel** (`/data/cache/snusnu/disable`), then kills the
   watchdog. The watchdog re-armed the property every 2 s, so deleting payloads
   first meant the property was immediately re-armed to point at a file that no
   longer existed, while the script still printed "reverted".
2. **Disables the actor through the ordinary settings interface.** The previous
   version used the root listener, which cannot reach the settings service at all
   (`Can't find service: settings`), so those deletes silently did nothing.
3. **Restores `persist.sys.saved_time`** from the value recorded at install time.
   Only the uid-1000 channel may write that property; if the channel is gone,
   removal says so and fails rather than claiming success.
4. **Removes payloads**, then **uninstalls the actor**: reporting the failure
   instead of ignoring it.

It then points you at `stage1-root -Disarm`, which owns Stage 1's own state.

### The build gate, and what it will not do for you

Before launching the carrier the boot actor checks `/data/cache/snusnu/expected-build`,
written by the installer, which records the PS token, `ro.build.version.incremental`
and the deployed carrier's SHA-256. On mismatch it refuses and reports
`build_mismatch` / `carrier_mismatch` / `guard_missing` instead of running the
carrier.

That matters because the carrier writes to a kernel address derived from a
specific build's `selinux_enforcing`. An OTA can change the kernel while `/data`
keeps the old carrier, and nothing about file permissions or SELinux labels would
notice. Measured on device by corrupting the recorded incremental:

```
status  = build_mismatch
native  = __SNU_BUILD_MISMATCH__ wanted=9999999999999 got=0020367984516
carrier = (not launched)      enforce = Enforcing
root    = refused             boot_completed = 1     trigger = still armed
```

The device boots and works normally, minus root.

**What the gate is not.** It is a consistency check against OTA drift, not a
security boundary. Anything running as the actor's uid can already execute the
carrier directly (`/data/snusnu_hwbinder_root` is group-`system`), so the guard
does not restrict that uid. It is deliberately left replaceable by that uid
because it makes the fail-closed state recoverable on-device.

**If the build gate refuses**, the device is in a fail-closed state by design and
there is no root to fix it with. Recovery, in order of preference:

1. **Re-derive the address for the new build** and register it; the correct fix
   when the OTA is real. `python stage1-root/make-carrier.py --ota <update-*.bin>`,
   then add the incremental to `stage1-root/carriers/carriers.tsv`.
2. **Roll the guard back** if the mismatch was a mistake. Anything running as the
   actor's uid can rewrite the guard, and the armed trigger still fires, but there
   is no uid-1000 channel without the actor, so in practice this means the host:
   `powershell -File stage1-root/run-root.ps1 -ConfirmRoot`.
3. If `/data/cache` was cleared (the guard is gone), reinstall Stage 4, which
   also needs root, so also via the host flow.

The watchdog is installed by root at `/data/snusnu_root/bin/watchdog.sh`
(root:root, `0755`, in a root-owned `0755` directory) and **executed** from there.
It is not generated by the actor and not read from the actor's `0777` scratch
directory. The earlier design wrote the script into that writable directory and
ran it, which would have let any app able to write there substitute code running
as uid 1000; a direct route back to re-arming root. That directory now holds only
output (`native_result`, logs, pidfile), and nothing treats its contents as
trusted input.

### Which step needs what

Measured on the device, and relevant to how the installer must run:

| operation | shell (uid 2000) | needed |
|---|---|---|
| `pm install` | **works**: in either SELinux state |; |
| `pm grant WRITE_SECURE_SETTINGS` | **works** (`granted=true`) |; |
| `setprop persist.sys.saved_time` | **denied** | root |
| write `/data/snusnu_hwbinder_root` | **denied** | root |

So step 1 is host-only, step 4 needs root, and neither needs `/system`.

Throughout development this stage installed the APK from a **clean (Enforcing)** boot,
because that is the easiest state to verify an install from. An earlier revision of this
file went further and recorded that `pm install` **hangs indefinitely** once SELinux is
Permissive. Re-tested 2026-10-07, twice on the same unit: it **succeeded** both times
while Permissive. The original observation was the wedged device state described under
"Risks" below, not a property of package installation. The instruction to install before
rooting is kept as convenience, not as a hard requirement.

## Risks and limits

* **Install ordering**: not a correctness requirement (see above), but installing
  before rooting is easier to verify and to retry.
* **Carrier race, now retried.** The hwbinder leak is a per-attempt race; measured
  single-shot success is about 67% per boot. The actor retries up to 5 times with
  12 s spacing, which is what the acceptance runs (10 earlier, 3 on the final build) exercises. Residual risk is
  a boot that loses all five attempts, which is recoverable: the trigger stays
  armed and the next reboot tries again.
* **The app is only `PARTIALLY_DIRECT_BOOT_AWARE`** (verified via `dumpsys package`), not
  fully. That is sufficient for a `LOCKED_BOOT_COMPLETED` receiver, but it is a weaker
  guarantee than full direct-boot awareness, and it means the receiver depends on the
  direct-boot-aware subset of the app only.
* **The listener accepts any local connection.** `waiter.sh` starts
  `nc -L /system/bin/sh` as uid 0 and the actor starts a uid-1000 shell the same
  way, neither with authentication. Binding `127.0.0.1` keeps them unreachable
  from another machine, but **does not authenticate apps on the tablet**: any
  app that can open a network socket can use the root shell while SELinux is
  Permissive. The watchdog script and the success markers are no longer part of
  this exposure; the script is now root-owned `0755` outside the writable state
  directory, and nothing treats the writable directory as trusted input, but the
  listener itself is unchanged from upstream's design.

  Authenticating it is a deliberate open item rather than an oversight: the
  repo's own tools and documentation all speak the unauthenticated protocol, so
  gating it is a breaking change to every caller and needs its own
  boot-order/loopback testing. A token guard is cheap to add (the actor can read
  a file that `untrusted_app` cannot) but it must land together with the callers,
  not before them. Use `--remove` when the shell is not wanted.
* **The watchdog's re-arm guarantee is "armed at every instant" by design, not by
  measurement.** The loop has a gap between the property check and the 2 s sleep;
  an NTP write landing in that gap is corrected on the next tick. That is
  precisely why the actor retries the carrier in-boot instead of assuming the
  trigger survived, and why `acceptance-test.ps1` exists; the end-to-end
  property is tested, the intermediate one is only argued. Its cost is one
  `getprop` per 2 s, and one guard per boot is enforced by a pidfile.
* **The carrier cannot run from the trigger itself.** Verified on the device: the
  `time_update` domain gets `cmd: Can't find service: settings` and `activity`, so the
  trigger cannot perform the injection on its own. An app really is required; this was
  tested rather than assumed, because it would have been a much smaller design.
* **The device can wedge.** During development, three consecutive software reboots
  silently failed after a failed boot left the carrier exited, requiring a manual power
  cycle. Root data was unaffected. Treat "no adb response" as "power-cycle", not "brick".
* **`/data`-resident, therefore survivable but not permanent.** A factory reset removes
  it. That is the correct trade: nothing here can brick the device.

## Validation

### Proven on the device (reference unit, PS7319/1735)

| check | result |
|---|---|
| `chcon u:object_r:shell_exec:s0` on the `/data` payload | **succeeds**: `assetstorage_data_file` → `shell_exec`, the core fix |
| the payload path really is `assetstorage_data_file` by default | **confirmed**: exactly why the app's trigger could never have worked |
| `pm grant WRITE_SECURE_SETTINGS` | **`granted=true`** |
| APK install, SELinux Enforcing | **`Success`** |
| APK install, SELinux Permissive | **`Success`** (2026-10-07) -- re-tested; the earlier "hangs" note was a wedged device |
| app's declared capabilities | `WRITE_SECURE_SETTINGS`, `RECEIVE_BOOT_COMPLETED`, `directBootAware`, `BootReceiver` |
| `snusnu_hwbinder_root` matches app expectations | contains `stateful-root-hold` and `__SNU_NATIVE_0__` |
| `time_update` cannot self-inject | `Can't find service: settings` / `activity` -- so an app really is required |
| app's `BootReceiver` fires at boot | yes -- `Start proc ... for broadcast .../.BootReceiver` |
| global settings survive reboot | **yes** -- verified with a canary; a write immediately before reboot can be *lost* unless `sync` runs first |
| the app's enable gate | `snusnu_persist_enabled` -- the app exits early with `disabled by global setting` until it is `1` |
| uid-1000 channel can `setprop persist.*` | **yes** -- this is why arming must go through the channel, not the root listener |
| `time_update` (root) can `setprop persist.*` | **denied** -- measured; the root listener is not a usable arm path |

### Correction: `pm install` in the exploited state

**Folded into "Which step needs what" above**: kept here only as a pointer, because the
disproven claim ("hangs indefinitely" while Permissive) was load-bearing for a while:
`pm install` succeeds in either SELinux state, and the observed hang belonged to the
wedged device, not to package installation.

## Evidence, end to end

### Every component exercised on the device (2026-10-07)

The persistent chain was already measured; this is the validation of the
installer, watchdog, build gate and removal path that followed the external
assessment's fixes.

| component | how it was exercised | result |
|---|---|---|
| installer | run end-to-end three times, twice with root live and twice from a clean slate | 14/14 checks pass, including the two new ones |
| watchdog | started as uid 1000, property clobbered, sentinel written | runs from the root-owned path; re-arms within 6 s; stops on the sentinel and stays stopped |
| watchdog identity | stale pidfile holding a **live PID** from another boot | starts anyway (boot-id mismatch); the recycled-PID case does not kill the guard |
| watchdog dedup | second start in the same boot | exits, same PID keeps guarding |
| build gate (positive) | 4 uninterrupted boots with a correct guard | carrier launched, root returned |
| build gate (refusal) | guard incremental corrupted to simulate an OTA | `build_mismatch`; carrier **not** launched; Enforcing; no root; device boots normally and the trigger stays armed |
| removal | `--remove` with root live | sentinels written, watchdog stopped, settings cleared (incl. the boot-id key), `saved_time` restored to the recorded value, all payloads gone, package uninstalled |
| reinstall | install + grant + installer after a full removal | installer cleared `stopped=true` itself; **root returned on the very next boot** |
| stability | `acceptance-test.ps1 -Reboots 3` on the final build | 3/3 pass |

Three defects were found *by* this validation and fixed, none of which any host-side
check would have caught: the watchdog's parent directory was `0700`, so uid 1000
could not reach the script it was supposed to run; the guard-file write piped into
a helper that does not forward stdin, producing an empty guard; and `Mktemp`'s
`/tmp` path was handed to Windows `adb.exe` and `python`, which cannot resolve it.

### Acceptance test: consecutive reboots, no host attached (10, then 3 on the final build)

`acceptance-test.ps1` reboots and requires unattended uid-0 on 4325 after each
one. No boot in the final run needed a host action; the only interaction was the
reboot itself.

| run | boots | passed |
|---|---|---|
| retry build | 4 | **4** |
| retry build (marker fix) | 6 | **6** |
| **total** | **10** | **10** |

Two of those boots are known to have failed their *first* carrier attempt and
been rescued by the in-boot retry -- see §4 above. This is why the number is
meaningful: the chain is not passing because the race happens to be won.

### The chain's own log, on a boot that needed a retry

```
__SNU_CARRIER_ATTEMPT_1__;__SNU_CARRIER_MISS_1__;__SNU_CARRIER_ATTEMPT_2__;
HWBINDER_STATEFUL result=0x5000000000000000;
HWBINDER_STATEFUL_WRITE result=0x5100000000000000;
__SNU_NATIVE_0__
```

then, from the waiter:

```
REROOTWAIT:   started uid=0 ctx=u:r:time_update:s0
SNUSNU_WAITER: uid=0 start saved_time=1791363697112
SNUSNU_WAITER: uid=0 selinux_permissive
SNUSNU_WAITER: uid=0 ok listener=uid0 magisk=skipped
REROOTWAIT:   waiter.sh rc=0
```

and the live state:

```
$ printf 'id\nexit\n' | toybox nc -w 3 127.0.0.1 4325
uid=0(root) gid=1000(system) groups=1000(system),2000(shell) context=u:r:time_update:s0

$ getenforce
Permissive

$ ps -A -o PID,USER,ARGS | grep -E 'hwbinder_root|watchdog.sh|nc -s'
1446 system   sh /data/cache/snusnu/state/watchdog.sh          # re-arms the trigger
1885 system   snusnu_hwbinder_root stateful-root-hold          # holds the exploit state
2153 root     toybox nc -s 127.0.0.1 -p 4325 -L /system/bin/sh -l   # root shell
```

The carrier staying resident is required, not incidental:
`controlled_target.c` notes that letting the process exit on trona "wedges a
kernel path and the MTK software watchdog resets the tablet".

### Regression gate

`preflight.py` must report clean before a root cycle is spent. It currently
enforces seven invariants, each of which was a real bug that cost at least one
boot:

| gate | catches |
|---|---|
| PowerShell parse (incl. untracked stage4 scripts) | the wildcard/heredoc errors that killed multi-minute runs |
| `sh -n` + no CRLF (incl. untracked) | a CRLF payload fails *on-device* after the push |
| `$STATE` prepared before the Permissive wait | the ordering deadlock in the waiter |
| APK carries the `/data/cache` state path, not upstream's | silent `system_native_failed` on every boot |
| carrier carries the 10 ms rescale, none at 1 ms | the ~1-in-3 ENODATA rate |
| app spawns the watchdog from the root-owned path | NTP silently deleting the trigger, and executing a script from a world-writable directory |
| app retries the carrier in-boot | regression to single-shot |
| app gates on build id + carrier digest | launching a stale carrier after an OTA changes the kernel address |
| installer clears the package stopped state | a fresh install that never receives the boot broadcast |
| installer makes the watchdog reachable by uid 1000 | a root-owned script the actor cannot execute |
| watchdog has a sentinel and a boot-id pidfile | `--remove` leaving the trigger re-armed; a recycled PID killing the guard |

## What this does and does not claim

**Does:** root returns automatically after a reboot, with no host PC attached, and
survives repeat reboots. Nothing outside `/data` is written; no boot, recovery,
system, vendor or partition-table state changes, so it cannot brick the device
and `--remove` + reboot reverts it.

**Does not:** unlock the bootloader, install a custom kernel, or install Magisk.
It is uid 0 in the `time_update` domain on a Permissive SELinux system -- the
same privilege stage 1 gives, now available without a host. Bootloader unlocking
remains blocked; see the repository README.

**Caveats worth knowing:**

* The listener is uid 0 on `127.0.0.1` only. It is not reachable off-device, but
  any local process that can open a TCP socket to loopback can reach it. That is
  inherent to a root shell over a socket; use `--remove` when it is not wanted.
* If a boot fully fails all five carrier attempts, the trigger stays armed and
  the next reboot tries again. A factory reset removes everything.
* `/data/cache` is scratch space: if the platform clears it, the watchdog script
  is gone until the next boot re-creates it from the APK, which is by design.
* `magisk=skipped` -- Magisk restore is out of scope for this stage
  (`$SNS/magisk_restore.sh` is referenced by the waiter but not installed here).

## Bottom line on this stage

**Persistent root is working and measured: 13 of 13 reboots, no host attached**,
and every component(installer, watchdog, build gate, removal) has now been
exercised on the device rather than only argued from source. What made it work was
not tuning the exploit but finding five independent silent failures around it, one
wrong assumption in the project's own documentation (a lost ENODATA race is *not*
terminal), and three defects that only a live run could expose.
