# Root optimization options for the connected Fire HD 10

Research date: 2026-10-07. Scope: `trona` / KFTRWI, Fire OS 7 / Android 9
(API 28), vendor Linux 4.4.146, locked bootloader and verified system content.
The repository assessment remediations are accepted as the current baseline;
optimization must preserve the working root and recovery mechanisms.

The runtime implementation and completed device trials are recorded in the
[validation report](root-optimization-validation.md). This document describes
the research rationale and options, including capabilities deferred for lack of
workload evidence.

The strongest addition is a small, measurable **runtime zRAM trial**. A second
useful capability is **optional per-UID telemetry egress filtering**, with its own
dependency and VPN checks. Root also enables better memory, I/O, thermal and
process diagnostics. CPU and storage recipes should follow an observed bottleneck
rather than become a new default profile. These are design recommendations, not
claims that any trial improved this device.

## Current capability evidence

These observations come from the initial read-only tablet assessment. The
subsequent apply/restore checks and live deployment are described in the
[validation report](root-optimization-validation.md).

| Capability | Observed state | Consequence |
| --- | --- | --- |
| RAM | 2,863,632 KiB total; 1,065,100 KiB available in one snapshot | Approximately 2.73 GiB usable RAM; one snapshot does not establish pressure |
| Swap | None enabled | Swappiness alone cannot create swap capacity |
| zRAM | `/dev/block/zram0` exists, major 253; `disksize=0`, inactive; statistics zero | Existing device can be evaluated without adding a kernel module |
| Compressor | `lzo [lz4]` | Preserve selected LZ4 for the first comparison |
| Kernel config / tools | `/proc/config.gz` readable; `mkswap`, `swapon`, `swapoff` available through Toybox | Check `CONFIG_SWAP`, `CONFIG_ZRAM` and runtime command outcomes before claiming usability |
| VM defaults | Swappiness 60; dirty ratio 20; dirty background ratio 5; VFS cache pressure 100 | Capture actual values; there is no demonstrated reason to replace them together |
| CPU | Policies 0 and 4, vendor `schedplus`, 793000–1989000 kHz | Vendor behavior must be assessed before substituting a generic governor |
| eMMC queue | `noop deadline [cfq]`; read-ahead 128 KiB | Several schedulers exist; availability does not establish which is faster |
| Networking | Android `fw_*` / `bw_*` chains; active VPN `tun0` | Any additional firewall must coexist with netd and VPN policy |
| OTA | Previously disabled state preserved | Keep it outside optimization mutations |

Presence of a sysfs node and uid 0 does not prove that a write is allowed in the
current SELinux domain. Check the result and read back each requested setting;
do not make SELinux permissive to obtain an optimization.

## 1. Runtime zRAM trial

zRAM stores compressed pages in RAM, trading CPU work for greater effective memory
capacity. Android's own guidance calls for measuring that tradeoff. Its older
integration examples edit fstab/init and policy; this project should instead use
the already present device through the established root channel, leaving verified
partitions untouched. [AOSP low-memory and zRAM guidance](https://android.googlesource.com/platform/docs/source.android.com/+/3587851127f0703f29ac921d44c8696315a693b0/en/devices/tech/perf/low-ram.html).

The minimum first trial is **256 MiB logical swap**, retaining LZ4 and swappiness
60. A subsequent explicit 512 MiB trial can test a heavier app-switching workload.
These sizes are conservative experimental limits chosen for this project, not
vendor recommendations. Avoid disk swap, backing-device writeback and active
zRAM resizing. The upstream 4.4 interface supports initialization with `disksize`,
followed by `mkswap` and `swapon`; changing its compressor requires an uninitialized
device. [Linux 4.4 zRAM interface](https://raw.githubusercontent.com/torvalds/linux/v4.4/Documentation/blockdev/zram.txt).

Before activation, bind the journal to serial, firmware and boot ID. Require that
the device is the expected zRAM node, is absent from `/proc/swaps`, has zero
logical size and no mount or other owner. Save compressor, compression streams,
memory limit and any VM setting touched. Refuse to replace existing swap or another
tool's initialized zRAM. Record intent before each mutation and verify completion
markers and readback after it.

An optional physical allocation cap needs separate validation: `mem_limit` is
different from logical `disksize`, and hitting it can make a swap write fail.
Report the allocator's `mem_used_total`, not just compressed payload size; the
upstream driver counts allocator use separately and exposes failed reads/writes.
Do not promise a fixed compression ratio or describe the cap as free extra RAM.
[Linux 4.4 zRAM driver](https://raw.githubusercontent.com/torvalds/linux/v4.4/drivers/block/zram/zram_drv.c).

Compare the same real app-switching workload before and during the trial. Capture
swap occupancy, compressed/original bytes, allocator usage, failed I/O, major page
faults, swap-in/out, direct reclaim, CPU time, app reloads, frame timing where
available, temperature and root health. More swap usage by itself is not success.
Keep the trial only if app retention or response time improves without sustained
reclaim, increased stalls or root instability.

### zRAM recovery is conditional

Restoring a sysctl can be exact; migrating already swapped pages back into RAM is
not an exact restoration of runtime state. `swapoff` can run slowly or fail when
memory is insufficient. A check such as `MemAvailable > swap Used + reserve`
reduces exposure but cannot guarantee success while other processes allocate.
Require headroom, remove only the suite's own swap, and reset zRAM only after
successful completion and confirmed absence from `/proc/swaps`. Never reset an
active swap device. Preserve an unresolved journal after a timeout rather than
infer that teardown completed. [util-linux swapoff documentation](https://man7.org/linux/man-pages/man8/swapoff.8.html).

Reset can also change configuration: upstream 4.4 resets `mem_limit` to zero and
`max_comp_streams` to one. Restore saved inactive-device settings afterward and
verify the vendor's actual behavior. [Linux 4.4 reset implementation](https://raw.githubusercontent.com/torvalds/linux/v4.4/drivers/block/zram/zram_drv.c).

A reboot normally clears these volatile settings if no startup hook exists, but
reboot is a separate deliberate action with this device's restrictive recovery.
Neither a journal nor zRAM teardown recreates previous page placement, caches,
process lifetimes or application state.

## 2. VM experiments after the first trial

Use one knob per comparison. Swappiness adjusts reclaim preference, not the amount
of RAM or a trigger percentage. Upstream Linux 4.4 bounds it to **0–100**; newer
guides recommending 150 or 200 are inapplicable unless a verified vendor backport
changes that contract. Start from the observed 60 and offer a bounded experiment
only with active swap and measurable reclaim. [Linux 4.4 swappiness bounds](https://raw.githubusercontent.com/torvalds/linux/v4.4/kernel/sysctl.c),
[Linux 4.4 reclaim behavior](https://raw.githubusercontent.com/torvalds/linux/v4.4/mm/vmscan.c).

`page-cluster=0` is another possible isolated zRAM experiment: AOSP documents
single-page reads for compressed RAM under extreme pressure. Save and restore its
actual value, and leave it unchanged for the first zRAM baseline. Keep minfree,
OOM priorities, overcommit and dirty/writeback settings at their observed values.
Android 9 can use an in-kernel low-memory killer or userspace lmkd depending on
kernel support, so inventory the actual implementation before considering policy
changes. Current PSI-based recipes need newer kernel features and are not an
automatic fit for this tablet. [AOSP memory-killer documentation](https://source.android.com/docs/core/perf/lmkd).

Do not repeatedly drop caches or make VFS cache pressure zero. Linux documents
the cost of rebuilding dropped caches and the memory risk of retaining all
directory/inode caches. [Linux 4.4 VM documentation](https://raw.githubusercontent.com/torvalds/linux/v4.4/Documentation/sysctl/vm.txt).

## 3. Optional per-UID telemetry egress filtering

Root can add output filtering without occupying Android's VPN slot. Netfilter's
owner match identifies locally generated socket traffic by UID; it does not
identify a package name or distinguish foreground from background use. Consequently
the honest feature is **blocking the selected UID's egress**, not background-only
blocking or complete telemetry elimination. Traffic delegated to another UID is
outside that rule. [Linux 4.4 owner match](https://raw.githubusercontent.com/torvalds/linux/v4.4/net/netfilter/xt_owner.c).

The minimum safe plan should:

1. Resolve every selected package's current UID and every package sharing it.
   Refuse shared UIDs, core/platform UIDs, other users, root/control actors,
   active launcher/input/WebView, VPN packages, messaging and other protected
   services. Selecting a telemetry package is not sufficient evidence that its
   UID is disposable.
2. Require IPv4 and IPv6 tooling and owner-match support; refuse a partial-family
   result. Use a dedicated suite chain in `filter/OUTPUT`, placed before any
   earlier terminal accept that would bypass it. Return immediately for loopback
   and return for every unselected UID; never accept general traffic ahead of the
   existing Android/VPN policy.
3. Add only the reviewed UID reject rules. Keep Android `fw_*`, `bw_*`, routing,
   DNS, VPN and connection-tracking state intact. Read back exact suite rules,
   record counters and validate normal network/VPN/root behavior. A blocked
   service can retry more frequently, so assess wakeups and CPU as well as bytes.
4. Roll back by removing only the exact owned hook/rules/chain. Treat unexpected
   references or edits as conflicts. Restoring a complete old iptables dump would
   overwrite netd or VPN changes made since the snapshot.

The active VPN session requires explicit compatibility validation. Rules are
runtime-only initially. UIDs can be reused after package removal/reinstallation;
remove or regenerate rules before such changes. Firewall rollback restores rule
configuration, not missed requests or application state. If the suite cannot
validate these conditions, report capability and defer mutation.

## 4. Diagnostics first for CPU, I/O and process control

| Option | Minimum useful root contribution | Decision / rollback limit |
| --- | --- | --- |
| CPU policies | Read each policy, available frequencies/governors, time-in-state and temperature alongside one workload | Keep vendor `schedplus`; trial a documented frequency ceiling only if heat/energy is the problem, with observed original values and readback |
| Storage queue | Map `/data` to its real backing device and sample block statistics, faults and queue pressure | Preserve CFQ and 128 KiB initially; compare one supported scheduler or read-ahead value only after demonstrating I/O stalls |
| Process activity | Attribute CPU, memory, wakeups and network use to package/UID; inspect protected root process health | Avoid global process killing, cached-process limits and altered OOM scores; Android may restart killed services |
| Component control | Review named components, providers and callers for an optional unused feature | Use the existing package-state journal where sufficient; privileged component disabling adds dependency risk, not an automatic performance gain |
| App compilation | Inspect dexopt state and offer targeted `speed-profile` maintenance for a heavily used app | ADB already exposes this API; compilation is not a root-only differentiator and compiled artifacts are not exactly rollbackable |

CPUFreq exposes policy limits and governors, but a vendor governor's behavior is
not defined by a stock governor name. Never disable thermal protection or set all
cores permanently to maximum frequency. [Linux 4.4 CPUFreq interface](https://raw.githubusercontent.com/torvalds/linux/v4.4/Documentation/cpu-freq/user-guide.txt).
Read-ahead sets the maximum filesystem read-ahead and scheduler selection applies
to the backing queue; changing a partition alias without checking that mapping
can affect the wrong scope. [Linux 4.4 block queue interface](https://raw.githubusercontent.com/torvalds/linux/v4.4/Documentation/block/queue-sysfs.txt).

Android 9 exposes `cmd package compile -m speed-profile -f PACKAGE`. Its `--reset`
also clears profiles and recompiles for the installation reason; it does not
restore the previous bytes or accumulated profile. Prefer targeted maintenance
with visible CPU/storage cost over compiling every package with `speed`.
[Android 9 package shell source](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-9.0.0_r1/services/core/java/com/android/server/pm/PackageManagerShellCommand.java).

## Startup persistence comes after measured runtime acceptance

Do not alter the boot trigger, root waiter, watchdog, actor permissions or protected
state directories for an optimization. Do not add Magisk, modify boot images,
replace init or edit fstab. Runtime trials already exercise the advanced root
capability without coupling device recovery to experimental tuning.

If a successful trial later needs persistence, make it a separate opt-in mechanism
in private `/data` storage, invoked only after the existing root channel is healthy.
It should recheck device/build, capabilities, original ownership and fresh UID
mappings, honor an emergency disable sentinel, apply once per boot and fail open
on incompatibility. Provide a command that first disables future application,
then conditionally restores current runtime state. Validate a deliberate reboot
and next-boot root recovery before describing that profile as persistent.

Initial delivery should therefore combine root capability assessment, repeatable
sampling, a bounded zRAM plan with conditional teardown, and a narrowly guarded
telemetry firewall plan. Broader tuning becomes justified by those measurements.
