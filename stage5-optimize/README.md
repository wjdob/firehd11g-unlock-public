# Stage 5: Root runtime optimization and reversible debloating

`fireopt.py` provides root runtime trials and data-preserving package optimization.
The root layer configures bounded zRAM, supports explicit VM experiments, isolates
selected telemetry UIDs with IPv4/IPv6 rules, and samples privileged kernel counters.
The package layer retains reversible ADB disables. It uses Python 3.10+ and ADB,
with no Python dependencies. Executing changes require a plan, journal and readback.

The supported hardware is `trona` / KFTRWI with Android 9/API 28, Owner user 0.
Plans bind to the serial, full firmware identity and current boot. This is an
optimization tool for an already rooted tablet, not a root installer.

## Get the optimization branch

This suite is published on `root-optimizations` in both repositories. For the
public version:

```powershell
git clone --branch root-optimizations https://github.com/wjdob/firehd11g-unlock-public.git
cd firehd11g-unlock-public
python .\stage5-optimize\fireopt.py --help
```

Use the same branch name with the private repository if you have access. The
Python source and optimization guides are the same in both versions. Neither
version includes another device's inventories, plans or restore journals.

## Root optimization workflow

Root trials use the existing uid-0 channel and last for the current boot. They do
not install boot hooks or change the validated root actor. From the repository:

```powershell
python .\stage5-optimize\fireopt.py root-assess
python .\stage5-optimize\fireopt.py sample --seconds 30 --out .\stage5-optimize\runs\baseline.json
python .\stage5-optimize\fireopt.py root-plan --zram-mib 256
python .\stage5-optimize\fireopt.py root-apply .\stage5-optimize\runs\RUN\root-plan.json
python .\stage5-optimize\fireopt.py root-apply .\stage5-optimize\runs\RUN\root-plan.json --execute
```

`root-apply` previews unless `--execute` is supplied. The executing command prints
a **new journal path**. Use that journal for verification and restoration:

```powershell
python .\stage5-optimize\fireopt.py root-verify .\stage5-optimize\runs\TRANSACTION\journal.json
python .\stage5-optimize\fireopt.py sample --seconds 30 --out .\stage5-optimize\runs\trial.json
python .\stage5-optimize\fireopt.py root-restore .\stage5-optimize\runs\TRANSACTION\journal.json --execute
python .\stage5-optimize\fireopt.py root-verify .\stage5-optimize\runs\TRANSACTION\journal.json
```

The first trial provides 256 MiB logical zRAM with a 128 MiB allocator cap. An
explicit 512 MiB trial uses a 256 MiB cap. The suite refuses already initialized or
active zram0. It verifies the block node's major/minor against the virtual zRAM
sysfs device, requires no holders or flash backing, and checks memory headroom at
execution. It preserves the selected compressor and streams, and reads back the
size and cap before swap activation. The cap bounds allocator use, not all kernel
overhead; hitting it can cause swap writes to fail. Inspect allocation and I/O
statistics as well as workload behavior.

Swappiness stays at the observed 60 for the first trial. A later plan can request
`--swappiness 80` within Linux 4.4's 0–100 range. Change one variable at a time.
Swappiness without swap does not create capacity or establish a speed improvement.

**Swap teardown is conditional.** Before swapoff, the suite requires swap Used
plus 256 MiB of available-memory headroom. This cannot guarantee success while
other processes allocate. A failed or unknown swapoff never permits reset. Close
the workload and retry restoration after commands settle, or deliberately reboot
to clear volatile state. Restore reapplies the saved inactive compressor, stream
count and memory limit, which reset can change. It cannot recreate page placement,
process state or accumulated counters. An old journal refuses to overwrite a
different runtime configuration on a later boot.

## Root network isolation

The optional firewall retains an installed telemetry package while rejecting its
UID's non-loopback IPv4 and IPv6 egress, without occupying Android's VPN slot.
Eligible packages are exactly `com.amazon.client.metrics`, `com.amazon.device.metrics`
and `com.amazon.wirelessmetrics.service`. They must have unique Owner UIDs and no
protected roles; shared SDK libraries and system UIDs remain excluded.

```powershell
python .\stage5-optimize\fireopt.py root-plan --network-packages com.amazon.client.metrics
# Review/apply with root-apply; restore using its root runtime journal.
```

The rules block both foreground and background traffic for that UID; work delegated
to another UID is outside them. Loopback remains available. Dedicated `FOPT_UID...`
chains use owner matches, RETURN and REJECT, with no broad ACCEPT rules. Both IP
families are staged before activation. Rollback removes only exact owned rules and
chains, including partial setup, and preserves existing Android/netd/VPN policy. It never
flushes tables or replays an old full-table snapshot.

Validate VPN and normal networking during each trial. A service may retry rejected
requests more often, so compare CPU/wakeups as well as bytes. Restore before package
updates or uninstall/reinstall; changed UID/version or foreign rule edits are
conflicts. A deliberate reboot clears the volatile rules. Unknown transport outcomes
remain unresolved until explicit recovery; root-verify refuses unresolved journals.

## Measurements and reference tools

`sample` records memory, faults, swap/reclaim, CPU ticks, disk counters, zRAM
allocation/I/O, thermal readings and wakeup sources where available. Unsupported
diagnostics are recorded as unavailable. Samples run 1–60 seconds and remain private
under `runs/`. Match screen, power, VPN, workload and duration. App retention/reloads
and responsiveness still need observation; no synthetic OOM workload is used.

The [Fire-Tools comparison](../docs/fire-tools-comparison.md) explains why its
disable-and-clear and blanket Undo paths were not imported. Fire Toolbox's official
XDA thread could not be fetched, so its current internals were not verified.
[Root options research](../docs/root-optimization-options.md) records Linux 4.4
semantics, measured capabilities and the limits of CPU/storage recipes.

## Start with the connected device

From the repository directory in PowerShell:

```powershell
python .\stage5-optimize\fireopt.py assess
python .\stage5-optimize\fireopt.py plan --profile google --animations 0
```

Both commands are read-only on the tablet. They save private JSON under
`stage5-optimize/runs/`, which is ignored by Git. The assessment includes firmware,
package overrides, protected roles, root asset hashes, persistence health, memory,
storage, battery, process memory and running processes. Keep these files private:
they include the serial and application inventory.

Use global options **before** the command when necessary:

```powershell
python .\stage5-optimize\fireopt.py --adb C:\tools\adb.exe --serial YOUR_SERIAL assess
```

`ADB` environment-variable overrides are also supported. An explicit serial is
required when more than one authorized device is connected.

## Choose only the features you do not use

| Profile/group | Effect |
| --- | --- |
| `conservative` profile | Optional Amazon consumer apps, retail demo and shopping UI |
| `google` profile | Conservative groups plus optional Alexa/voice/kids communication apps |
| `ads` group | Special-offer lock-screen UI; separately opt in and check locking/unlocking |
| `store` group | Amazon Appstore; separately opt in because Amazon app licensing/updates may need it |
| `metrics` group | Three telemetry clients; separately opt in, dependency effects remain unverified |

`--groups` replaces the profile's group selection. Available groups are `apps`,
`shopping`, `alexa`, `ads`, `store`, `metrics`. There are no package-prefix removals.

```powershell
# Add only groups whose feature loss you accept.
python .\stage5-optimize\fireopt.py plan --groups apps,shopping,alexa,metrics

# Start with a single optional app.
python .\stage5-optimize\fireopt.py plan --groups apps --only com.amazon.imdb.tv.mobile.app
```

The tool skips absent, hidden, suspended and already disabled packages. It protects
core Android and Google packages, privileged/system UIDs, packages sharing a UID,
device administrators, the selected launcher, keyboards, accessibility and voice
services, the selected WebView provider, and known root dependencies. Fire and
Android launcher packages are protected, and their existing enabled states are
preserved. OTA package state is preserved. Unknown Amazon frameworks and shared SDK
libraries are outside the catalog.

Shared UIDs can prevent complete Alexa removal. The plan lists the skip instead of
disabling a shared system dependency. Disabling an optional app can still affect a
caller: package roles are not a complete runtime dependency graph. Validate one
small group before expanding.

## Review, apply, verify and restore

Review the JSON file and printed feature consequences. `apply` previews by default:

```powershell
python .\stage5-optimize\fireopt.py apply .\stage5-optimize\runs\RUN\plan.json
python .\stage5-optimize\fireopt.py apply .\stage5-optimize\runs\RUN\plan.json --execute
```

The executing command prints a **new journal path before its first mutation**.
Keep that path. Each mutation is recorded before it is sent, saved atomically with
`fsync`, and checked by reading the state back. Normal command failures trigger
rollback of attempted changes. The suite checks device identity, package policy,
protected roles and existing root/persistence health before proceeding.

```powershell
python .\stage5-optimize\fireopt.py verify .\stage5-optimize\runs\TRANSACTION\journal.json
python .\stage5-optimize\fireopt.py restore .\stage5-optimize\runs\TRANSACTION\journal.json
python .\stage5-optimize\fireopt.py restore .\stage5-optimize\runs\TRANSACTION\journal.json --execute
```

Restore returns each changed package to its original enabled override, including
`default-state` versus explicitly enabled. It restores settings presence and exact
values; an originally absent setting is deleted. Restore works after a reboot on
the same firmware and uses normal ADB even if root is unavailable. Changed app
versions/UIDs, a different device/firmware, or later settings edits are reported as
conflicts rather than overwritten. Restoration concerns enabled overrides/settings;
it cannot recreate killed processes or all transient app runtime state.

A timeout, disconnect or missing completion marker can leave a command running on
the tablet. Such an operation stays **unresolved**, even if an immediate readback
looks unchanged; automatic rollback does not claim completion. Reconnect, allow the
remote command to finish, then explicitly run `restore --execute` and `verify`.
An unresolved journal blocks another apply. A process crash may also leave a local
`.lock` file: confirm that its PID is no longer running, inspect the journal, and
remove only that lock before restoring. The lock coordinates this suite on one host;
other ADB tools must not change the tablet during a transaction.

`verify` checks the journal's expected configuration and current root/persistence
health. If configuration restored successfully but root is absent, verification
reports that separately as a failure. A current root probe does not prove the next
boot will regain root. After choosing to apply a profile, manually test launcher,
keyboard, Wi-Fi, VPN, Play Store, notifications, lock/unlock, media audio and the
apps you use. Reboot acceptance testing remains a separate, deliberate action.

## Optimization limits

Animation scales are optional: `--animations 0`, `0.5` or `1`. This changes transition
duration, not processor speed. Existing equivalent scales are skipped. The reference
tablet already had all three at `0.0` when assessed.

Measure the same workload, screen state and power conditions before comparing
assessment snapshots or the journal's `baseline` and `after` measurements. A single
free-memory reading or USB-charging battery reading is not a benchmark. Disabled
system APKs still occupy their verified system partition; this is primarily a way
to reduce unwanted services/features, not reclaim that storage.

The suite excludes boot/recovery/system/vendor edits, storage block-device writes,
OTA changes, root actor lifecycle changes, cache cleaning, process killing,
CPU/thermal tuning, blanket background limits and Magisk modules. Root trials use
only the validated virtual zRAM block device. A journal is a configuration rollback,
not a full-device backup or repair route for boot damage.

The prerequisite is the validated [Stage 4](../stage4-persistent/README.md)
root installation, including its protected watchdog at
`/data/snusnu_root/bin/watchdog.sh`. The suite checks that existing root mechanism
and preserves it. It does not install, repair or migrate the root method.

## Validation

```powershell
python -B -m unittest discover -s .\stage5-optimize -p 'test_*.py' -v
```

The host tests use fake devices. They exercise protection, journals, exact
configuration restoration, conditional swap teardown, partial firewall setup,
unknown outcomes, drift and boot/identity changes. The
[implementation validation report](../docs/root-optimization-validation.md)
records 41 passing tests, restored root trials and a subsequent live application
of 256 MiB zRAM plus five optional package disables. The kernel configuration
remains volatile; the package disabled overrides survive reboot. The observed
idle samples establish operation and recovery, not a performance improvement.
