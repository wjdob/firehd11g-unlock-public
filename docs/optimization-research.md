# Fire HD 10 optimization research

Research date: 2026-10-07. Scope: Fire HD 10 (2021, 11th generation),
`trona` / `KFTRWI`, Fire OS 7.3.1.9 / PS7319, Android 9 / API 28 and vendor
Linux 4.4. This note records the preservation and rollback rules for the delivered
optimization suite. It accepts the validated root method as the operating baseline.

The [Stage 5 guide](../stage5-optimize/README.md) documents the available commands.
The [validation report](root-optimization-validation.md) separates successful live
apply/restore checks from performance improvements that remain unmeasured.
[Root options](root-optimization-options.md) gives the rationale for the runtime
zRAM and telemetry-filtering experiments.

## Recommended approach

Use Android's package and settings interfaces, a narrowly reviewed package catalog, a preview of each proposed change, and a journal that records the original value before execution. Keep APKs and application data in place with `pm disable-user --user 0`; default optimization should not uninstall applications, clear data, modify verified partitions, install modules, alter the root mechanism, or reboot the tablet. The Fire HD 10 has Android 9 / API 28, a 3 GB or 4 GB memory variant, and MT8183 hardware; newer Android tuning guides are not automatically applicable. [Amazon device specifications](https://www.developer.amazon.com/docs/device-specs/ft-device-specifications-firehd-models.html), [Fire OS 7](https://developer.amazon.com/docs/fire-tablets/fire-os-7.html).

Treat the assessed launcher, applications and OTA configuration as the starting
state. An optimization restore should return to that state, rather than enable
every Amazon application. Root runtime trials are separately selected and do not
install startup hooks or change the persistent root mechanism.

## Dependencies to protect

| Package, setting, or resource | Why it must remain intact |
| --- | --- |
| `io.github.voidnullvalue.snusnuroot.persistence` | Its Direct Boot receiver starts the persistent root flow. Do not disable, uninstall, clear, force-stop, remove its granted permissions or impose background restrictions on it. |
| `WRITE_SECURE_SETTINGS` grant and `snusnu_*` global settings | The actor checks its enable flag and permission; its globals also expose health and retry state. |
| `hidden_api_blacklist_exemptions` | The root actor briefly uses this setting to establish its system channel, then removes it. Generic settings cleanup can interfere with that sequence. |
| `persist.sys.saved_time` and `com.amazon.fireos.service.timeservice` | The property is the boot trigger, re-armed after time synchronization overwrites it. Preserve time service and leave re-arming alone. |
| `/data/snusnu_hwbinder_root` | The native root carrier must remain resident. Process cleanup or background limits can remove required state. |
| `/data/securedStorageLocation/w/b`, `/data/securedStorageLocation/snusnu/` | Boot-entry script, waiter and disable sentinel. Do not delete, relabel, remount over or include them in cleanup routines. |
| `/data/snusnu_root/bin/watchdog.sh` and its protected parent directories | The installed re-arm watchdog resides here, separately from the actor's scratch state. Preserve its contents, ownership, permissions and SELinux label. |
| `/data/cache/snusnu/state` and other root metadata under `/data/cache/snusnu/` | Scratch state, carrier/health records and installation metadata remain necessary. The watchdog executable is outside this tree. Broad cache deletion can still break persistence. |
| `com.amazon.webview.chromium` and its app-private data | Preserve the WebView provider and the existing bootstrap/reroot fallback that stages its carrier in this package's data. |
| Active HOME, input method, selected WebView, device administration and accessibility services | Retain a launcher, keyboard, rendering provider and configured control/accessibility tools. Resolve active roles instead of assuming package names. |
| Framework, System UI, Settings, package installer, storage/media/download providers, networking and credential services | Dependencies exceed what a package name reveals. Exclude core services and privileged/shared system UIDs from automatic debloating. |

The repository deliberately uses Direct Boot and device-protected storage. Android makes this storage available before credential unlock when `directBootAware` components receive `LOCKED_BOOT_COMPLETED`. Preserve both the application and its device-protected data. [Android Direct Boot documentation](https://developer.android.com/privacy-and-security/direct-boot).

## Exact rollback

Capture the **per-user numeric application enabled override** from `dumpsys package PACKAGE` before changing it. Android distinguishes a manifest default from an explicit enable. Restoring every disabled package with `pm enable` would change the original override. [PackageManager enabled-state reference](https://developer.android.com/reference/android/content/pm/PackageManager#COMPONENT_ENABLED_STATE_DEFAULT).

| Saved override | Restore command for the same user and package |
| --- | --- |
| `0`, default | `pm default-state --user 0 PACKAGE` |
| `1`, enabled | `pm enable --user 0 PACKAGE` |
| `2`, disabled | `pm disable --user 0 PACKAGE` |
| `3`, disabled by user | `pm disable-user --user 0 PACKAGE` |
| `4`, disabled until used | `pm disable-until-used --user 0 PACKAGE` |

These command mappings exist in the Android 9 shell implementation. Check the Fire build's own help and read back the numeric state after execution. Skip packages that are absent, not installed for user 0, or already effectively disabled. [Android 9 PackageManagerShellCommand source](https://github.com/aosp-mirror/platform_frameworks_base/blob/android-9.0.0_r1/services/core/java/com/android/server/pm/PackageManagerShellCommand.java).

For settings, save `{present, value}`. Use the exact `KEY=` prefix in the supported
`settings list NAMESPACE` output to determine presence; `settings get` alone cannot
distinguish an absent key from a stored string `null`. Restore missing keys with
`settings delete`; restore present keys with their exact string value. Split list
records only at the first equals sign and quote values as shell data. The list
implementation enumerates provider rows as key/value pairs.
[Android 9 SettingsService source](https://github.com/aosp-mirror/platform_frameworks_base/blob/android-9.0.0_r1/packages/SettingsProvider/src/com/android/providers/settings/SettingsService.java).

Before mutation, write the journal to a new local file, bind it to serial and build fingerprint, and record each intended action before sending it. Verify each change and root/launcher health. Roll back completed actions if a later operation fails. During an explicit restore, reject unexpected intervening package or setting state instead of overwriting user changes. Configuration snapshots do not capture application databases or constitute an image-level backup.

Live Fire OS deviation: this tablet rejects `--user` for settings `list` and `delete`.
The suite requires Owner user 0 to be active and uses the vendor-supported bare
`settings list`/`delete` forms. It uses explicit `--user 0` for package operations.
If a mutation loses transport without a completion marker, its outcome remains
unresolved: allow the remote command to finish, then explicitly restore and verify.

## Improvements with a useful cost/benefit ratio

- **Disable unused optional applications by named feature.** A catalog can cover unused Amazon shopping, media, recommendations and child/family features. Each entry needs a concrete consequence and live presence check. Prefer the smallest group, assess it, then broaden. Do not infer safety from `com.amazon.*` or advertise a performance percentage without measurements.
- **Reduce window, transition and animator scales to 0.5 as an optional preference.** This makes transitions shorter; it does not increase CPU throughput. Save and restore original values individually. Android documents `window_animation_scale` as a float animation multiplier. [Settings.Global reference](https://developer.android.com/reference/android/provider/Settings.Global#WINDOW_ANIMATION_SCALE).
- **Measure idle services, wakeups and memory before tuning.** Compare the same workload, screen state, uptime and USB/power conditions. Use `MemAvailable`, swap usage, package processes and relevant diagnostic output; free RAM alone is a poor success metric. Android reclaims clean pages and prioritizes processes under memory pressure; zRAM can compress anonymous pages when it is enabled. [Android memory management](https://developer.android.com/topic/performance/memory-management).
- **Preserve Android's existing power behavior.** Doze already defers background CPU/network activity. Global forced-idle, aggressive app background limits, and process killing can delay notifications and root recovery. Battery behavior needs an unplugged idle measurement; USB-connected readings are not evidence of improved standby. [Doze and App Standby](https://developer.android.com/training/monitoring-device-state/doze-standby).
- **Leave ART compilation as an optional, measured maintenance action.** Profile-guided compilation can optimize frequently used methods while limiting storage overhead. Compiling every installed package with `speed` consumes CPU and storage and lacks the suite's exact configuration rollback property. [AOSP ART configuration](https://source.android.com/docs/core/runtime/configure).
- **Use root for bounded runtime experiments.** The delivered suite can initialize only the validated, unused virtual `zram0`, with an explicit logical capacity and allocator cap. It preserves the selected compressor, checks memory headroom, and conditionally tears down swap before restoring inactive configuration. Root telemetry filtering is separately selected and checks both IP families, package/UID protection and exact rule ownership. Configuration validation is not proof of improved app retention, speed or battery life. [Linux 4.4 zRAM interface](https://raw.githubusercontent.com/torvalds/linux/v4.4/Documentation/blockdev/zram.txt), [Stage 5 guide](../stage5-optimize/README.md).

Avoid default CPU/governor/thermal changes, replacing another actor's swap or
resizing active zRAM, blanket swappiness/minfree values, repeated cache dropping,
build.prop edits, forced GPU flags and broad Magisk modules. These add hardware and
firmware assumptions without a measured bottleneck. Linux specifically warns that
`drop_caches` can increase CPU and I/O as cached data is rebuilt.
[Linux 4.4 VM documentation](https://raw.githubusercontent.com/torvalds/linux/v4.4/Documentation/sysctl/vm.txt).

## OTA, backups and recovery limits

Preserve the tablet's current OTA disabled state in optimization profiles. Blocking updates helps retain the tested root chain, while foregoing vendor updates carries a security cost. An update may change the kernel, SELinux policy, property behavior, or vulnerable framework code. CVE-2024-31317 was fixed in Android's June 2024 bulletin, but its published Android-version list does not establish whether a particular Fire OS build includes the fix; check that build rather than infer from a Fire version number. [Android June 2024 bulletin](https://source.android.com/docs/security/bulletin/2024-06-01).

A package-state/settings journal is the appropriate first rollback for this suite. APK copies and root reads of application data can assist recovery, but app databases should not be copied while being written, and restored data also needs correct ownership, SELinux labels and any encryption context. The persistence APK declares `allowBackup=false`. Platform Auto Backup excludes cache and does not automatically preserve enabled-component configuration. Fire uses its own backup transport, so do not promise Google-style full-device backup. [Android Auto Backup](https://developer.android.com/identity/data/autobackup), [Fire tablet backup transport](https://developer.amazon.com/docs/fire-tablets/fire-os-7.html#fire-tablet-auto-backup).

Keep boot/recovery/system/vendor content and physical storage block-device writes
outside suite mutations. The sole block-device exception is the verified,
RAM-only virtual zRAM device used by an explicit runtime trial. dm-verity validates
partition contents against a signed hash tree; root access alone does not make
arbitrary partition edits bootable.
[AOSP dm-verity](https://source.android.com/docs/security/features/verifiedboot/dm-verity).

The bootloader remains locked and recovery is restrictive. A configuration journal
restores the settings or owned runtime configuration it records; it is not a
device image, a complete application-data backup or a boot-repair route. Runtime
swap restoration cannot recreate earlier page placement or process state, and
firewall restoration cannot replay missed requests. The
[validation report](root-optimization-validation.md) records the live checks and
the workload and recovery conditions that remain unmeasured.
