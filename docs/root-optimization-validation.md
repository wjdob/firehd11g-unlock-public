# Root optimization implementation and live validation

Validated 2026-10-07 on the connected Fire HD 10 11th generation, `trona` /
KFTRWI, Fire OS 7.3.1.9 (PS7319/1735), API 28, vendor Linux 4.4.146.
The prerequisite is the validated [Stage 4](../stage4-persistent/README.md)
root installation with its protected watchdog and healthy persistent actor.
The bootloader remains locked. No reboot or root-method modification was needed.

## Delivered root capabilities

The [Stage 5 guide](../stage5-optimize/README.md) documents these commands:

| Capability | Implementation | Limits |
| --- | --- | --- |
| Root inventory | `root-assess` | Root health, inactive zRAM identity, VM settings, dual-stack firewall, CPU/I/O configuration and privileged counters |
| Compressed RAM swap | `root-plan --zram-mib 256` or `512` | Existing unused virtual `zram0` only; LZ4 preserved; allocator cap of 128 or 256 MiB; no flash backing |
| VM experiment | `root-plan --swappiness VALUE` | Explicit Linux 4.4 range 0–100; original value restored; no benefit claimed without swap/reclaim |
| Telemetry UID filtering | `root-plan --network-packages PACKAGE` | Three allowlisted clients; unique unprotected app UID; IPv4 and IPv6 rejection except loopback; existing Android/VPN rules retained |
| Workload sampling | `sample --seconds N` | Read-only memory, reclaim, faults, swap, CPU, disk, zRAM, thermal and available wakeup counters; 1–60 seconds |
| Transaction recovery | `root-apply`, `root-restore`, `root-verify` | Intent saved before mutation, completion marker, readback, device/firmware/boot binding, unresolved-outcome handling and foreign-state conflicts |

Root trials affect the current boot. They do not install startup hooks. The
existing package/settings layer remains available for data-preserving debloating.

## Initial apply/restore trials

All trials used the existing uid-0 listener. Apply and restore used the same
public CLI paths that the guide documents, with journals saved before mutation.

| Trial | Applied state verified | Restored state verified |
| --- | --- | --- |
| zRAM | 256 MiB logical swap active at priority 100; 128 MiB allocator cap; LZ4, one compression stream, swappiness 60 | No active swap; disk size/init state/memory limit all zero; LZ4 and one stream retained |
| VM setting | Swappiness 80, read back from `/proc/sys/vm/swappiness` | Original 60, read back |
| UID firewall | `com.amazon.client.metrics`, its resolved unique app UID; exact owned OUTPUT hook and loopback/reject chain in both filter tables | Both owned chains/hooks removed; complete IPv4 and IPv6 filter-rule lists equal their captured baselines |

`root-verify` passed with each journal applied and again after restoration. Both
journals finished `restored`, with every operation restored and no unknown outcomes.

The final assessment matched both trial baselines for device/firmware/boot
identity, all four root asset hashes, package inventory and per-user states,
animation settings, selected home activity and persistence health. The root
carrier and watchdog remained resident, the trigger stayed armed, and the actor
remained enabled with its required grant. At the end of these restored trials,
the device had 265 installed packages, 30 disabled packages, zero active swap and
swappiness 60.

The existing VPN-related policy was present during the firewall trial and
preserved by the final full-rule comparison. `tun0` remained present afterward.
This establishes rule coexistence and configuration restoration; it is not a
complete VPN traffic, routing or leak test. No package was disabled or cleared.
These initial trials left no experimental optimization active.

## Measurement interpretation

Two short idle samples requested five seconds each:

| Sample | CPU busy | Major page faults | Swap pages in/out |
| --- | --- | --- | --- |
| Original baseline | 3.9% | 0 | 0 / 0 |
| zRAM enabled | 3.8% | 0 | 0 / 0 |

Available memory remained around 1.2 GiB. These samples confirm counter collection
and lack of pressure during the trial. They do **not** show a speed, battery or
app-retention improvement. The firewall's IPv4 and IPv6 chain counters were zero
when captured, so no actual metrics traffic rejection was observed in this trial.

The 512 MiB configuration is implemented and covered by host tests; it was not
applied to this tablet. Teardown under significant swap occupancy, real traffic
rejection, long workloads and next-boot behavior remain unmeasured. Runtime
restoration does not reconstruct page placement, counters or past requests.

## Subsequent authorized live application

Later on 2026-10-07, the 256 MiB zRAM configuration was applied for continued use,
with LZ4, one compression stream, priority 100 and a 128 MiB allocator cap.
Swappiness remained at 60. The Google-oriented profile also disabled five optional
packages while preserving their app data:

- `com.amazon.imdb.tv.mobile.app`: Amazon streaming app.
- `com.amazon.kor.demo`: retail demonstration app.
- `amazon.speech.davs.davcservice`: Alexa voice assets.
- `amazon.speech.audiostreamproviderservice`: Alexa audio stream service.
- `com.amazon.comms.kids`: kids communication app.

Both new journals finished `applied`; package `verify` and `root-verify` passed.
The final snapshot contained 265 installed packages and 35 disabled packages.
Only the five planned package policies changed. Root hashes, persistent actor
health, carrier/watchdog liveness, armed trigger, launcher, animation settings,
firmware/boot identity and both firewall tables matched the captured baseline.
Android reported a validated network and the VPN `tun0` interface remained present.

The post-application ten-second idle sample reported 2.9% CPU busy, three major
page faults, no swap-in/out during the interval and zero zRAM I/O errors. Those
observations establish operation under the sampled conditions. They do not
establish workload performance, app behavior, battery gains or a VPN leak test.

At deployment completion, zRAM and the five package disables were left active.
The root tuning lasts for that boot; package disabled overrides survive reboot.
No startup hook or root-method change was introduced. Restore journals remain
local; a clone cannot restore another device without its own original-state journal.

## Automated checks and evidence

All **41 host tests passed**: 17 package/journal tests, 9 network tests and 15 root
runtime tests. They cover exact restoration, protection changes, partial setup,
failed swapoff without reset, insufficient headroom, unknown transport outcomes,
boot ownership, foreign rule edits and multi-UID hooks. `git diff --check` passed.

Private evidence is retained locally under ignored `stage5-optimize/runs/`:
plans, original-state snapshots, trial/deployment journals, before/after samples,
firewall counters and final configuration/network comparisons.

Those artifacts contain device identifiers or inventories and are not repository
deliverables. The [Fire-Tools comparison](fire-tools-comparison.md) and
[kernel options research](root-optimization-options.md) explain the source
evaluation and why generic CPU/storage recipes were left outside the profiles.

The next performance comparison should use a representative app-switching workload
with matched screen, power and VPN conditions. Start with 256 MiB zRAM at the
original swappiness 60 and evaluate app reloads, responsiveness, allocator use,
swap errors and CPU/temperature before selecting a lasting configuration.
