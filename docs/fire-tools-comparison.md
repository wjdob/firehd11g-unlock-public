# Fire optimization tools compared with Stage 5

Reviewed 2026-10-07 for the rooted Fire HD 10 (2021), `trona` / `KFTRWI`, API 28. This review inspected upstream source and primary documentation; it did not run either tool, install an APK, or send a command to the tablet. The user's previously remediated root-method assessment is outside this review.

The useful distinction is between additional Fire OS customization and privileged runtime optimization. Fire-Tools supplies a broader feature/package catalog, but its inspected optimization commands use ordinary ADB shell privileges. Stage 5 already has stronger preservation and rollback rules. The most useful root extension is a measured, bounded memory experiment plus privileged diagnostics, rather than transplanting a broad debloat script.

The implemented root capabilities and live apply/restore results are recorded in
the [validation report](root-optimization-validation.md).

## Source and scope

- **Fire-Tools:** [mrhaydendp/Fire-Tools](https://github.com/mrhaydendp/Fire-Tools), pinned to [`3a03e71b792878ec24d7118a6aeac0c7237a1431`](https://github.com/mrhaydendp/Fire-Tools/tree/3a03e71b792878ec24d7118a6aeac0c7237a1431), commit dated 2026-01-05, version `26.01`. It is a research reference, not an application dependency.
- **Fire Toolbox:** [Datastream33's official XDA thread](https://xdaforums.com/t/windows-linux-tool-fire-toolbox-v39-1.3889604/). The thread returned HTTP 403 and a JavaScript security challenge through both web retrieval and a normal HTTP request. Exact current release, presets, and executable internals could not be verified. No download mirror or repackaged binary was used.
- **Toolbox feature corroboration:** the author's [port tracker](https://datastream33.wordpress.com/2021/11/16/fire-toolbox-port-tracker/), last updated 2023-05-17, documents Amazon app management, privacy controls, launchers, Google services, density, system settings and backups. It says the Python port was closed source at launch. This establishes historical feature categories, not today's implementation or a current license.
- **Starting implementation:** Stage 5 began with 26 curated packages, exact enabled-state/settings restoration, identity and root-health checks, protected roles/shared UIDs, and interrupted-operation handling. That layer uses `pm` and animation settings. The delivered suite also adds root zRAM/VM trials, UID firewall rules and privileged measurements; see its [guide](../stage5-optimize/README.md).

## What Fire-Tools actually does

| Capability | Source evidence at the pinned commit | Relevance to Stage 5 |
| --- | --- | --- |
| Broad package selection | [`Debloat.txt`](https://github.com/mrhaydendp/Fire-Tools/blob/3a03e71b792878ec24d7118a6aeac0c7237a1431/Fire-Tools/Debloat.txt) contains 114 unique package names | A discovery list only; each candidate needs firmware, component, UID and feature review |
| Disable/enable | [`debloat.sh` lines 10–18](https://github.com/mrhaydendp/Fire-Tools/blob/3a03e71b792878ec24d7118a6aeac0c7237a1431/Fire-Tools/Scripts/Posix/debloat.sh#L10) and [`debloat.ps1` lines 8–16](https://github.com/mrhaydendp/Fire-Tools/blob/3a03e71b792878ec24d7118a6aeac0c7237a1431/Fire-Tools/Scripts/PowerShell/debloat.ps1#L8) run `pm disable-user`, then `pm clear`; enable uses `pm enable` | Keep Stage 5's data-preserving disable and exact numeric override restoration |
| Privacy and lock screen | `debloat.sh` lines 42–50 writes Fire-specific telemetry, location, lockscreen-ad and lockscreen-search keys | Optional settings candidates, with exact presence/value journals and behavior checks; these are not root-only |
| Animation scales | `debloat.sh` lines 52–54 writes all three scales to `0.50` | Already covered; this tablet's recorded `0.0` would actually become longer |
| Private DNS | [`main.py` lines 105–117](https://github.com/mrhaydendp/Fire-Tools/blob/3a03e71b792878ec24d7118a6aeac0c7237a1431/Fire-Tools/main.py#L105) sets `private_dns_mode=hostname` and a resolver hostname | Optional privacy/network feature, not a general speed improvement; validate DNS and VPN behavior |
| OTA suppression | `main.py` lines 126–129 calls the same disable-and-clear path for three OTA packages | Preserve existing update state; do not alter it as an incidental optimization |
| Launcher replacement | [`appinstaller.sh` lines 20–28](https://github.com/mrhaydendp/Fire-Tools/blob/3a03e71b792878ec24d7118a6aeac0c7237a1431/Fire-Tools/Scripts/Posix/appinstaller.sh#L20) grants widget binding, attempts Fire launcher disable, then may install LauncherHijack | The connected tablet already uses Nova; do not add a second launcher interception service |
| APK extraction/install | `main.py` uses `pm path` plus `adb pull`; installer scripts use `adb install` / `install-multiple` | Useful maintenance, but not proof of application-data backup or runtime optimization |

The privacy-key names are evidence of writes, not proof that this exact Fire build consumes them. In particular, `limit_ad_tracking=1` is not demonstrated to reset the advertising ID, despite the script's status message. Readback establishes a stored value; lockscreen and telemetry behavior require separate observations.

## Behaviors to avoid carrying over

**Data clearing is not reversible debloating.** Both upstream scripts clear a package immediately after disabling it. Re-enabling cannot reconstruct logins, local databases, configuration or downloads. The Android command help describes `pm clear` as deleting package data. Preserve installed APKs and application data. [Android 9 package shell source](https://github.com/aosp-mirror/platform_frameworks_base/blob/android-9.0.0_r1/services/core/java/com/android/server/pm/PackageManagerShellCommand.java).

**Upstream Undo creates a different state.** The bulk Enable branch sets Private DNS off, location on, and explicitly enables the Fire launcher and OTA packages (`debloat.sh` lines 29–38; the PowerShell path is equivalent). It does not restore saved privacy/animation values. On this device that could reactivate a previously disabled update path or replace intentional launcher configuration. A factory reset is not an acceptable restoration mechanism for a working rooted device.

**A large catalog is not a dependency policy.** The upstream list includes authentication (`com.amazon.identity.auth.device.authorization`), messaging (`com.amazon.device.messaging`), setup (`com.amazon.kindle.otter.oobe`), media-session monitoring, parental controls, VoiceView, framework contracts, metrics APIs, factory-reset management and sync providers. Some names identify capabilities other software depends on. Stage 5 should keep its protected actors/roles/system and shared UIDs. `amazon.speech.sim` shares a UID with an Amazon media component on the recorded device; independent removal cannot be assumed safe. Upstream itself notes that disabling OOBE affects date/time settings. [Pinned catalog](https://github.com/mrhaydendp/Fire-Tools/blob/3a03e71b792878ec24d7118a6aeac0c7237a1431/Fire-Tools/Debloat.txt), [pinned README](https://github.com/mrhaydendp/Fire-Tools/blob/3a03e71b792878ec24d7118a6aeac0c7237a1431/README.md).

**Presence checks and status text are insufficient.** The POSIX bulk loop iterates `app` but greps `package`, a different variable; when unset, the empty search matches the package list (`debloat.sh` lines 25–27). The scripts suppress most command output and have no transaction journal, firmware binding or root-health gate. This review did not test which commands a particular Fire build accepts. Stage 5 should retain command completion markers, readback, preconditions and unresolved-transport handling.

## Root opportunities beyond these tools

| Priority | Capability | What root adds | Required limits |
| --- | --- | --- | --- |
| First | Privileged bottleneck inventory and repeated snapshots | Access to restricted kernel logs, wakeup sources, process memory and runtime configuration | Read only; record unavailable nodes without treating absence as healthy |
| First | Bounded zRAM trial | Configures the kernel's compressed RAM swap device and activates swap | Inactive `zram0` only; explicit capacity; no flash backing device; same-boot journal and guarded teardown |
| After evidence | Small, reversible VM parameter trials | Writes to allowlisted `/proc/sys/vm` nodes | Keep existing values initially; change one variable; validate kernel-version bounds; exact readback and restore |
| Later, if a measured service warrants it | Component-specific debloating using root for restricted controls | Can target an unnecessary receiver/service while retaining its package/provider | Inspect component dependencies; preserve original component override; exclude shared/system UIDs and root actors |
| Later, if requested | UID-specific network policy | Root-managed rules can enforce restrictions without occupying the VPN slot | Exclude networking, persistence and push/auth UIDs; IPv4/IPv6 parity; never flush Android/netd chains |

For this API 28 / Linux 4.4 tablet, zRAM is the clearest candidate for a real privileged optimization. The current development inventory reports an existing inactive `zram0`, disk size zero, and LZ4 selected. That supports capability discovery and a reversible experiment; it does not establish that more swap will improve the user's workload.

Use the kernel's existing compression algorithm. A modest explicit logical capacity, such as 512 MiB, plus a compressed-allocation limit can bound an initial trial. The Linux 4.4 driver exposes `disksize`, `mem_limit`, compression selection and statistics; initialization precedes `mkswap` and `swapon`. Validate every operation and inspect actual device nodes before using them. An initialized or active device owned by another actor must be rejected. [Linux 4.4 zRAM documentation](https://raw.githubusercontent.com/torvalds/linux/v4.4/Documentation/blockdev/zram.txt).

Record `/proc/swaps`, original sysfs configuration, boot ID, root health and available memory before a trial. Compare the same app-switching workload and durations, retained/reloaded apps, reclaim/swap activity, UI frame timing and errors. More free RAM alone is not success. Teardown must successfully remove swap before resetting the device, with enough headroom to bring swapped pages back; a failed or uncertain `swapoff` must not be followed by reset. Keep the first trial confined to the current boot. Do not graft a tuning hook onto the validated root waiter/watchdog merely to make a trial persistent.

Linux 4.4 uses different zRAM semantics from current guides, including compression-stream behavior. Its swappiness handler permits values from 0 through 100; modern recommendations above 100 should not be copied to this kernel. Preserve VM defaults until measurements show a benefit. `page-cluster` changes swap readahead; reducing it trades initial fault latency against later faults, so it also needs an isolated trial. [Linux 4.4 sysctl implementation](https://raw.githubusercontent.com/torvalds/linux/v4.4/kernel/sysctl.c), [Linux 4.4 VM documentation](https://raw.githubusercontent.com/torvalds/linux/v4.4/Documentation/sysctl/vm.txt).

Keep verified partitions, boot/recovery, block storage, thermal policy, CPU voltage/frequency, root actors, `persist.sys.saved_time`, and root asset ownership/labels outside these profiles. Avoid broad cache deletion, repeated `drop_caches`, process killers and system-wide background limits. These do not become good optimizations just because root makes them possible. The kernel warns that cache dropping can increase subsequent CPU and I/O work. [Linux VM documentation](https://www.kernel.org/doc/Documentation/sysctl/vm.txt).

## Reuse and delivery

Fire-Tools' [MIT license](https://github.com/mrhaydendp/Fire-Tools/blob/3a03e71b792878ec24d7118a6aeac0c7237a1431/LICENSE) permits source reuse with the copyright and permission notice retained in copies or substantial portions. This review does not import its code or catalog. Reusing a substantial catalog requires the same notice. Its license is not a redistribution grant for bundled Google apps, launchers or other third-party APKs; inspect each artifact's own terms rather than relying on the surrounding repository license.

No Fire Toolbox source or binaries were copied. Its author's historical closed-source statement and the inaccessible current thread do not establish current reuse terms. Take feature ideas as research inputs and implement documented Android/Linux interfaces locally; do not treat a free download as permission to copy implementation or redistribute dependencies.

The source review establishes useful customization candidates and specific conflicts to avoid. Runtime improvements still need device capability checks, a concrete plan/journal and measured workload validation. No performance gain or successful live application is claimed by this report.
