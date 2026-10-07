# Stage 1: Root entry point (PS7319 port of SnuSnuRoot)
#
# GATED: requires explicit typed confirmation. The chain:
#   - stages carrier assets to /data (via a one-shot uid-1000 zygote channel)
#   - arms the time_update waiter (persist.sys.saved_time)
#   - reboots the device
#   - on the fresh boot: hwbinder NULL-write -> SELinux Permissive ->
#     uid-0 listener on 127.0.0.1:4325
#   - NO boot/system/vendor partition is ever written; everything reverts
#     on reboot (disarm restores stock state)
#
# Usage:
#   .\run-root.ps1 -ConfirmRoot        # full root flow (staging + reboot + chain)
#   .\run-root.ps1 -Status             # read-only state report
#   .\run-root.ps1 -Disarm             # revert to stock
#
# Requires: Git Bash (for the POSIX scripts), adb, one authorized device.

param(
    [switch]$ConfirmRoot,
    [switch]$Status,
    [switch]$Disarm,
    [string]$Serial,
    [string]$ADB,
    [string]$Bash = 'C:\Program Files\Git\bin\bash.exe'
)

$ErrorActionPreference = 'Stop'
$portDir = Join-Path $PSScriptRoot 'port'

if (-not (Test-Path $Bash)) { $Bash = 'bash.exe' }

# Run a native tool without letting its stderr abort the script. adb writes
# ordinary diagnostics to stderr, and with ErrorActionPreference=Stop PowerShell
# promotes that to a terminating error.
function Invoke-Native {
    param([string]$Exe, [string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $text = (& $Exe @Arguments 2>&1 | Out-String)
    } finally {
        $ErrorActionPreference = $previous
    }
    return $text.Trim()
}

# Git Bash wants /c/... paths; native adb.exe wants C:\... paths.
function ConvertTo-BashPath {
    param([string]$Path)
    $full = (Resolve-Path -LiteralPath $Path).Path
    return '/' + $full.Substring(0, 1).ToLower() + ($full.Substring(2) -replace '\\', '/')
}

# Resolve adb ONCE, here, and hand it to the POSIX layer through the environment.
#
# The previous version interpolated `ADB=${ADB:-$HOME/adb/adb.exe}` into a
# PowerShell double-quoted string. PowerShell parsed `${ADB:-$HOME/adb/adb.exe}`
# as a variable reference with that literal name, which does not exist, so it
# always expanded to the empty string -- `ADB=` -- silently discarding any
# override the caller had set. It appeared to work only because two independent
# fallbacks downstream happened to catch the empty value.
function Resolve-Adb {
    $candidates = @()
    if ($ADB) { $candidates += $ADB }
    if ($env:ADB) { $candidates += $env:ADB }
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { return (Resolve-Path -LiteralPath $c).Path }
        Write-Warning "ignoring ADB='$c': not a file"
    }
    # No usable override: leave $env:ADB unset so the shared POSIX resolver
    # (port/tools/adb-portable.sh) applies its own PATH/default search.
    foreach ($guess in @("$HOME\adb\adb.exe", 'C:\platform-tools\adb.exe')) {
        if (Test-Path -LiteralPath $guess) { return (Resolve-Path -LiteralPath $guess).Path }
    }
    $onPath = Get-Command adb -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    throw "adb not found. Pass -ADB <path>, set `$env:ADB, or put adb on PATH."
}

# Exactly one authorized device, always, and that serial is propagated to every
# adb subprocess so a second attached unit cannot receive a boot-partition read
# or a reboot intended for the reference device.
function Select-Device {
    param([string]$AdbExe)
    $text = Invoke-Native $AdbExe @('devices')
    $rows = @()
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -match '^\s*(\S+)\s+(device|unauthorized|offline|bootloader|recovery)\s*$') {
            $rows += [pscustomobject]@{ Serial = $Matches[1]; State = $Matches[2] }
        }
    }
    if ($Serial) {
        $match = $rows | Where-Object { $_.Serial -eq $Serial }
        if (-not $match) {
            throw "requested -Serial $Serial is not attached; attached: $(($rows | ForEach-Object { "$($_.Serial) [$($_.State)]" }) -join ', ')"
        }
        if ($match.State -ne 'device') { throw "-Serial $Serial is in state '$($match.State)', not 'device'" }
        return $Serial
    }
    $ready = @($rows | Where-Object { $_.State -eq 'device' })
    if ($ready.Count -eq 0) {
        $seen = ($rows | ForEach-Object { "$($_.Serial) [$($_.State)]" }) -join ', '
        throw "no authorized device. Attached: $(if ($seen) { $seen } else { 'none' })"
    }
    if ($ready.Count -gt 1) {
        # Never guess: a wrong device here means reboots and partition reads on
        # hardware the caller was not looking at.
        throw "more than one device is in state 'device': $(($ready | ForEach-Object { $_.Serial }) -join ', '). Re-run with -Serial <serial>."
    }
    return $ready[0].Serial
}

function Invoke-PortScript {
    param([string]$Script, [string[]]$Arguments)
    $winPath = Join-Path $portDir "scripts\$Script"
    $bashPath = ConvertTo-BashPath $winPath
    # Pass the script and its arguments as real argv entries rather than
    # interpolating them into a shell string, so nothing here can be re-parsed
    # as shell syntax.
    & $Bash -lc 'exec "$0" "$@"' $bashPath @Arguments
    return $LASTEXITCODE
}

$adbExe = Resolve-Adb
$serial = Select-Device -AdbExe $adbExe
# adb itself honours ADB / ANDROID_SERIAL, so exporting these pins every
# subprocess the POSIX layer starts, without it needing to know how they were found.
$env:ADB = ConvertTo-BashPath $adbExe
$env:ANDROID_SERIAL = $serial
Write-Host "adb    : $adbExe" -ForegroundColor DarkGray
Write-Host "device : $serial" -ForegroundColor DarkGray

if ($Status) {
    Write-Host '== Stage 1 status (read-only) ==' -ForegroundColor Cyan
    Invoke-PortScript 'root_poc.sh' @('status')
    exit $LASTEXITCODE
}

if ($Disarm) {
    Write-Host '== Stage 1 disarm (revert to stock) ==' -ForegroundColor Yellow
    Invoke-PortScript 'root_poc.sh' @('disarm')
    exit $LASTEXITCODE
}

# --- root flow: authorization gate -------------------------------------------
Write-Host @'
== Stage 1: ROOT, authorization required ==

This will:
  1. Stage exploit carriers to /data/securedStorageLocation/ (via a one-shot
     uid-1000 zygote channel; consumes this boot's CVE-2024-31317 injection)
  2. Arm the time_update waiter (persist.sys.saved_time command injection)
  3. REBOOT the device
  4. On the fresh boot: run the hwbinder NULL-write (CVE-2019-2181 family)
     -> SELinux Permissive -> uid-0 listener on 127.0.0.1:4325

What it will NOT do:
  - Write to boot, recovery, system, vendor, preloader, lk, tee, or any
    partition table entry
  - Modify verified-boot state
  - Anything irreversible (disarm + reboot returns to stock)

Risk profile (from upstream verification on PS7331 and this port's analysis):
  - The kernel write is a single NULL to selinux_enforcing (in-memory only)
  - The hwbinder leak is one-shot per boot; a miss means reboot and retry
    (the script auto-retries up to 6 fresh boots)
  - A failed attempt leaves the device booting normally; the waiter stays
    armed and re-fires next boot

'@ -ForegroundColor White

if (-not $ConfirmRoot) {
    $reply = Read-Host 'Type ROOT to proceed (anything else aborts)'
    if ($reply -cne 'ROOT') {
        Write-Host 'Aborted.' -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host 'Proceeding (confirmation supplied via -ConfirmRoot).' -ForegroundColor Yellow
}

Write-Host "`nStarting root flow...`n" -ForegroundColor Cyan
Invoke-PortScript 'root_poc.sh' @('root')
$code = $LASTEXITCODE
if ($code -eq 0) {
    Write-Host @'

ROOT FLOW COMPLETE.
Verify with:  printf 'id\nexit\n' | adb shell 'toybox nc -w 3 127.0.0.1 4325'
Expected:     uid=0(root) ... context=u:r:time_update:s0

'@ -ForegroundColor Green
} else {
    Write-Host "`nRoot flow exited with code $code (see output above).`n" -ForegroundColor Yellow
}
exit $code
