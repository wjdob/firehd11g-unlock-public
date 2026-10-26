#Requires -Version 5.1
<#
.SYNOPSIS
  Read-only validation collector for the trona LineageOS build (stage 6).

.DESCRIPTION
  Captures the evidence the validation matrix in README.md needs, then writes a
  markdown report plus a raw log. It runs read commands only. Pass or fail stays a
  human judgement recorded in the report, because most rows need eyes on screen.

  Run it after the first boot, and again after any fix, so reports can be diffed.

.PARAMETER OutDir
  Where to write the report. Defaults to stage6-lineage/reports/<timestamp>.

.PARAMETER Serial
  Optional adb serial, for more than one attached device.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File stage6-lineage/validate-device.ps1
#>
param(
    [string]$OutDir,
    [string]$Serial
)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutDir = Join-Path $PSScriptRoot "reports\$stamp"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$report = Join-Path $OutDir 'report.md'
$raw = Join-Path $OutDir 'raw.log'

$adb = (Get-Command adb -ErrorAction SilentlyContinue).Source
if (-not $adb) { $adb = Join-Path $root 'dumps\platform-tools\adb.exe' }
if (-not (Test-Path $adb)) {
    Write-Host '(!) adb not found. Install platform-tools or set PATH.' -ForegroundColor Red
    exit 2
}
$adbArgs = @()
if ($Serial) { $adbArgs = @('-s', $Serial) }

function Sh($cmd) {
    $a = $adbArgs + @('shell', $cmd)
    $o = & $adb @a 2>&1 | Out-String
    return $o.TrimEnd()
}

function Sec($title, $cmd) {
    Add-Content -Path $report -Value "### $title"
    Add-Content -Path $report -Value ''
    if ($cmd) {
        $o = Sh $cmd
        Add-Content -Path $raw -Value ''
        Add-Content -Path $raw -Value "===== $title ====="
        Add-Content -Path $raw -Value $cmd
        Add-Content -Path $raw -Value '---'
        Add-Content -Path $raw -Value $o
        Add-Content -Path $report -Value '```'
        Add-Content -Path $report -Value $o
        Add-Content -Path $report -Value '```'
        Add-Content -Path $report -Value ''
    }
}

$state = (& $adb @adbArgs get-state 2>&1 | Out-String).Trim()
if ($state -notin @('device', 'recovery')) {
    Add-Content -Path $report -Value '# trona validation report'
    Add-Content -Path $report -Value ''
    Add-Content -Path $report -Value "No device. adb get-state returned '$state'."
    Add-Content -Path $report -Value ''
    Add-Content -Path $report -Value 'Connect the tablet with USB debugging enabled, or boot TWRP, then re-run.'
    Write-Host "(!) no device (state: '$state'). Wrote $report" -ForegroundColor Yellow
    exit 1
}

Add-Content -Path $report -Value '# trona validation report'
Add-Content -Path $report -Value ''
Add-Content -Path $report -Value "- generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
Add-Content -Path $report -Value "- adb state: $state"
Add-Content -Path $report -Value "- host: $env:COMPUTERNAME"
Add-Content -Path $report -Value "- adb: $adb"
Add-Content -Path $report -Value ''
Add-Content -Path $report -Value 'Verdicts stay pending until a human records them at the bottom.'
Add-Content -Path $report -Value ''

Sec 'Build identity' 'getprop ro.lineage.version; getprop ro.lineage.build.version; getprop ro.build.fingerprint; getprop ro.build.version.security_patch; getprop ro.build.type; getprop ro.debuggable'
Sec 'Kernel' 'uname -a; cat /proc/version'
Sec 'Kernel cmdline' 'cat /proc/cmdline'
Sec 'SELinux (G1)' 'getenforce; cat /sys/fs/selinux/enforce 2>/dev/null'
Sec 'Uptime and boot' 'cat /proc/uptime; getprop sys.boot_completed; getprop ro.boot.bootreason'
Sec 'Display' 'wm size; wm density; dumpsys display | grep -m5 -E "mDisplayId|state=|mBaseDisplayInfo"'
Sec 'Touch input devices' 'getevent -pl 2>/dev/null | grep -E "add device|name:|ABS_MT|KEY_"'
Sec 'Wi-Fi' 'dumpsys wifi | grep -m6 -E "Wi-Fi is|mNetworkInfo|SSID|supplicant"'
Sec 'Bluetooth' 'dumpsys bluetooth_manager | grep -m4 -E "enabled|state|address"'
Sec 'Audio' 'dumpsys media.audio_flinger | grep -m8 -E "Output thread|Input thread|sample rate|HAL"'
Sec 'Camera' 'dumpsys media.camera | grep -m8 -E "Camera [0-9]|Device [0-9]|facing|status"'
Sec 'Sensors' 'dumpsys sensorservice | grep -m8 -E "Sensor List|[0-9]+\)|active"'
Sec 'Storage' 'df -h /data /cache /system /vendor 2>/dev/null; mount | grep -E " /data | /vendor | /system "'
Sec 'Power supply (G3)' 'ls /sys/class/power_supply/; for d in /sys/class/power_supply/*; do echo "== $d"; cat $d/uevent 2>/dev/null; done'
Sec 'Suspend state (G2)' 'cat /sys/power/state; cat /sys/power/mem_sleep 2>/dev/null; cat /sys/kernel/debug/suspend_stats 2>/dev/null || echo "suspend_stats unreadable without root"'
Sec 'Wakelocks (G2)' 'cat /sys/kernel/debug/wakeup_sources 2>/dev/null | head -20 || echo "unreadable without root"'
Sec 'Key layout (G4)' 'ls -l /vendor/usr/keylayout/ 2>/dev/null; for f in /vendor/usr/keylayout/*.kl; do echo "== $f"; cat $f; done'
Sec 'SELinux denials (G1)' 'dmesg 2>/dev/null | grep -c avc: ; logcat -d -b main -b system 2>/dev/null | grep -c -i "avc: denied"'
Sec 'Recent kernel messages' 'dmesg 2>/dev/null | tail -60'
Sec 'Boot errors' 'logcat -d -b main *:E 2>/dev/null | tail -80'
Sec 'Properties of interest' 'getprop | grep -i -E "trona|amazon|fire|mt8183|vendor|treble|vndk"'

Add-Content -Path $report -Value '## Verdict matrix'
Add-Content -Path $report -Value ''
Add-Content -Path $report -Value 'Record pass or fail beside each row, with a note. Rows that need eyes on the'
Add-Content -Path $report -Value 'screen cannot be filled by this script.'
Add-Content -Path $report -Value ''
Add-Content -Path $report -Value '| area | verdict | note |'
Add-Content -Path $report -Value '|---|---|---|'
foreach ($row in @('Boot','Kernel','Display','Touch','Wi-Fi','Bluetooth','Audio','Camera','Sensors','Storage','Charging','Sleep','SELinux','Performance')) {
    Add-Content -Path $report -Value "| $row | pending | |"
}

Write-Host "report: $report"
Write-Host "raw:    $raw"
exit 0
