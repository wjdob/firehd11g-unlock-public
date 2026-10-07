# Stage 0: Read-only device diagnostics for Fire HD 10 (trona/KFTRWI)
# Collects device identity, firmware, kernel, SELinux, partition map, and
# Stage-1 compatibility preconditions. WRITES NOTHING TO THE DEVICE.
#
# Usage: .\run-diagnostics.ps1 [-OutDir <path>]
# Requires: adb on PATH (or $env:ADB), one connected device, USB debugging authorized.

param(
    [string]$OutDir = "$PSScriptRoot\..\diagnostics"
)

$ErrorActionPreference = 'Stop'
$adb = if ($env:ADB) { $env:ADB } else { 'adb' }

function Invoke-AdbShell {
    param([string]$Command, [switch]$Raw)
    $result = & $adb shell $Command 2>&1 | Out-String
    if ($Raw) { return $result }
    return ($result -replace "`r", '').Trim()
}

# --- checks -------------------------------------------------------------------
Write-Host '== Stage 0: Fire HD 10 (trona) diagnostics ==' -ForegroundColor Cyan
Write-Host 'Read-only. No writes to the device.' -ForegroundColor DarkGray

New-Item -ItemType Directory -Force $OutDir | Out-Null
$report = [ordered]@{}
$warnings = @()
$fatal = @()

# 1. Device connectivity (serials redacted in the stored report)
$devices = & $adb devices 2>&1 | Out-String
$report['adb_devices'] = ($devices -replace 'G001[A-Z0-9]+', 'G001<REDACTED>').Trim()
$attached = ($devices -split "`n" | Where-Object { $_ -match '^\S+\s+device\s' }).Count
if ($attached -eq 0) {
    Write-Host 'FATAL: no adb device in "device" state. Connect and authorize USB debugging.' -ForegroundColor Red
    exit 1
}
if ($attached -gt 1) { $warnings += "Multiple devices attached ($attached); results may mix. Set ANDROID_SERIAL." }

# 2. Identity
$report['model']        = Invoke-AdbShell 'getprop ro.product.model'
$report['device']       = Invoke-AdbShell 'getprop ro.product.device'
$report['fingerprint'] = Invoke-AdbShell 'getprop ro.build.fingerprint'
$report['version_name'] = Invoke-AdbShell 'getprop ro.build.version.name'
$report['incremental']  = Invoke-AdbShell 'getprop ro.build.version.incremental'
$report['build_date_utc'] = Invoke-AdbShell 'getprop ro.build.date.utc'
$report['kernel']       = Invoke-AdbShell 'uname -a'
$report['first_api']    = Invoke-AdbShell 'getprop ro.product.first_api_level'
$report['abis']         = Invoke-AdbShell 'getprop ro.product.cpu.abilist'

Write-Host "`nDevice: $($report['model']) / $($report['device'])" -ForegroundColor Green
Write-Host "Firmware: $($report['version_name']) (incremental $($report['incremental']))"
Write-Host "Kernel: $($report['kernel'])"

# 3. Compatibility guardrails
if ($report['device'] -ne 'trona') {
    $fatal += "Device is '$($report['device'])', expected 'trona'. This toolkit is trona/KFTRWI-specific."
}
if ($report['model'] -ne 'KFTRWI') {
    $warnings += "Model is '$($report['model'])' not KFTRWI (3GB variant). KFTRPWI (4GB) untested."
}

# 3b. Firmware-version gate (cross-version carrier selection).
# The root chain's kernel write targets selinux_enforcing, whose address
# differs per firmware build. The chain selects a carrier variant from
# stage1-root/carriers/carriers.tsv by the device's PS build token; a build
# that is not registered has NO verified address and must not proceed.
$buildId = Invoke-AdbShell 'getprop ro.build.id'
$report['build_id'] = $buildId
$carrierInfo = $null
$carrierTsv = Join-Path $PSScriptRoot '..\stage1-root\carriers\carriers.tsv'
if (Test-Path $carrierTsv) {
    foreach ($line in (Get-Content $carrierTsv)) {
        if ($line -match '^\s*#' -or -not $line.Trim()) { continue }
        $cols = $line -split "`t"
        # 5th column (comma-separated live-verified ro.build.version.incremental)
        # is optional; requiring exactly 4 silently skipped every row once the
        # column was added, which read as "no registered firmware".
        if ($cols.Count -eq 4) { $cols += '' }
        if ($cols.Count -ne 5) { continue }
        if ($buildId -like "$($cols[0])*") {
            $carrierInfo = [pscustomobject]@{
                Token = $cols[0]; Variant = $cols[1]; Addr = $cols[2]
                Sha256 = $cols[3]; Verified = $cols[4]
            }
            break
        }
    }
}
if ($carrierInfo) {
    $carrierPath = Join-Path $PSScriptRoot "..\stage1-root\carriers\$($carrierInfo.Variant)\libhwbinder_target.so"
    if ((Test-Path $carrierPath) -and
        ((Get-FileHash $carrierPath -Algorithm SHA256).Hash -eq $carrierInfo.Sha256)) {
        $report['carrier_variant'] = $carrierInfo.Variant
        $report['selinux_enforcing'] = $carrierInfo.Addr
        Write-Host "Carrier variant for ${buildId}: $($carrierInfo.Variant) (selinux_enforcing $($carrierInfo.Addr))" -ForegroundColor Green
        # Exact-build gate, mirroring version_env.sh. The PS token identifies an
        # address family; the address belongs to the exact build.
        $incremental = Invoke-AdbShell 'getprop ro.build.version.incremental'
        $report['build_incremental'] = $incremental
        $verified = @()
        if ($carrierInfo.Verified) { $verified = $carrierInfo.Verified -split ',' | ForEach-Object { $_.Trim() } }
        if ($verified -contains $incremental) {
            Write-Host "  Build $incremental is live-verified for this variant." -ForegroundColor Green
        } else {
            $fatal += "Build '$incremental' ($buildId) is NOT live-verified for variant '$($carrierInfo.Variant)'. " +
                      "Registered incremental(s): $(if ($verified.Count) { $verified -join ', ' } else { '<none>' }). " +
                      "selinux_enforcing is build-specific, so an unverified address may corrupt kernel memory. " +
                      "Derive and register it: python stage1-root/make-carrier.py --ota <update-kindle-*.bin>, then add " +
                      "the incremental to the verified-incrementals column of stage1-root/carriers/carriers.tsv. " +
                      "To proceed deliberately instead, set SNUSNU_ALLOW_UNVERIFIED_BUILD=1 when running stage 1."
        }
    } else {
        $fatal += "Carrier variant '$($carrierInfo.Variant)' for $buildId is missing or hash-mismatched (expected $($carrierInfo.Sha256)). Re-run stage1-root/make-carrier.py."
    }
} else {
    $fatal += "Firmware $buildId has no registered carrier variant. The kernel-write address is build-specific; obtain the OTA for your build and run: python stage1-root/make-carrier.py --ota <update-kindle-*.bin>"
}

# 4. Stage-1 preconditions (read-only)
$report['selinux_mode'] = Invoke-AdbShell 'getenforce'
$report['saved_time']   = Invoke-AdbShell 'getprop persist.sys.saved_time'
$report['exemptions']   = Invoke-AdbShell 'settings get global hidden_api_blacklist_exemptions'
$report['verity_state'] = Invoke-AdbShell 'getprop ro.boot.verifiedbootstate'
$report['verity_mode']  = Invoke-AdbShell 'getprop ro.boot.veritymode'

# time_update service definition (existence check only; content is SELinux-blocked for shell)
$timeupdateRc = Invoke-AdbShell 'ls /system/etc/init/timeupdate.rc'
$report['timeupdate_rc_present'] = ($timeupdateRc -notmatch 'No such file')

# saved_time must be numeric (arming precondition)
$savedTimeOk = $report['saved_time'] -match '^\d+$'
$exemptionsOk = ($report['exemptions'] -eq 'null')

# 5. Partition map (by-name symlinks: readable without root)
$report['partitions'] = Invoke-AdbShell 'ls -la /dev/block/by-name/'
$report['mounts'] = Invoke-AdbShell 'cat /proc/mounts'

# 6. Kernel config (pulled read-only via exec-out, binary-safe)
& $adb exec-out cat /proc/config.gz > "$OutDir\config.gz" 2>$null
if ((Test-Path "$OutDir\config.gz") -and ((Get-Item "$OutDir\config.gz").Length -gt 1000)) {
    $report['config_pulled'] = $true
} else {
    $report['config_pulled'] = $false
    $warnings += 'Could not pull /proc/config.gz (expected on locked-down user builds).'
}

# --- compatibility verdict ------------------------------------------------------
Write-Host "`n== Stage 1 (root) compatibility ==" -ForegroundColor Cyan
$checks = [ordered]@{
    # name = @(passed, blocking)
    #
    # "Blocking" means the root chain cannot proceed on this device. Advisory
    # checks are informational and must not fail the run.
    #
    # These used to be recorded as warnings regardless, and the script exited 0
    # whenever $fatal was empty -- so a caller that checked only the exit code
    # would proceed on a device that had failed the gate it was run for.
    'Device is trona'             = @(($report['device'] -eq 'trona'), $true)
    'Firmware has carrier variant' = @(($null -ne $carrierInfo), $true)
    'timeupdate.rc present'       = @($report['timeupdate_rc_present'], $true)
    'exemptions clean (null)'     = @($exemptionsOk, $true)
    # Not blocking: the chain arms saved_time itself, and an already-armed value
    # is a supported starting state ("waiter already ARMED; skipping staging").
    'saved_time is numeric'       = @($savedTimeOk, $false)
    # Not blocking: an already-rooted device is Permissive by design.
    'SELinux Enforcing (stock)'   = @(($report['selinux_mode'] -eq 'Enforcing'), $false)
}
$failedBlocking = @()
foreach ($k in $checks.Keys) {
    $ok = $checks[$k][0]
    $blocking = $checks[$k][1]
    $mark = if ($ok) { '[PASS]' } elseif ($blocking) { '[FAIL]' } else { '[warn]' }
    $color = if ($ok) { 'Green' } elseif ($blocking) { 'Red' } else { 'Yellow' }
    $suffix = if ($blocking) { '' } else { ' (advisory)' }
    Write-Host "  $mark $k$suffix" -ForegroundColor $color
    if (-not $ok) {
        if ($blocking) { $failedBlocking += "Stage-1 precondition failed: $k" }
        else { $warnings += "Stage-1 precondition not met (advisory): $k" }
    }
}

# --- output --------------------------------------------------------------------
$report['warnings'] = $warnings
$report['blocking_failures'] = $failedBlocking
$report['generated'] = (Get-Date).ToString('o')
$reportPath = Join-Path $OutDir 'stage0-report.json'
$report | ConvertTo-Json -Depth 4 | Out-File $reportPath -Encoding utf8

Write-Host "`nReport: $reportPath" -ForegroundColor Cyan
if ($fatal.Count -gt 0) {
    Write-Host "`nFATAL:" -ForegroundColor Red
    $fatal | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 2
}
if ($failedBlocking.Count -gt 0) {
    # Distinct exit code from FATAL: the device is recognisable but a
    # precondition the root chain depends on is not met.
    Write-Host "`nBLOCKING PRECONDITION FAILURES:" -ForegroundColor Red
    $failedBlocking | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 3
}
if ($warnings.Count -gt 0) {
    Write-Host "`nAdvisory warnings:" -ForegroundColor Yellow
    $warnings | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
}
Write-Host "`nStage 0 complete: $(if ($warnings.Count -eq 0) {'device is fully compatible'} else {'compatible; advisory notes above'})."
