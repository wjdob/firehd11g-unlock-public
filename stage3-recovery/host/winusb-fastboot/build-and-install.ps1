<#
.SYNOPSIS
  Build, sign, trust and install the WinUSB driver for the Amazon/LK fastboot
  interface (USB\VID_1949&PID_05E0), then verify that fastboot can see the device.

.DESCRIPTION
  Reproduces exactly the procedure that made `fastboot devices` work here. This is
  the scripted form of the "Working procedure" section of README.md.

  Steps:
    1. copy fastboot-amzn.inf + fastboot-amzn.cdf into a scratch build directory
    2. build the catalog with makecat.exe      (Inf2Cat is NOT required)
    3. sign the catalog with signtool.exe
    4. trust the signing certificate in LocalMachine\Root + TrustedPublisher
    5. pnputil /add-driver ... /install, then /scan-devices
    6. verify: catalog signature, device problem code, driver INF, `fastboot devices`

  Elevation is required for steps 4-5. If the script is not already elevated it
  relaunches itself, so expect one UAC prompt (accept it once; steps 1-3 do not
  need it but are cheap to repeat).

  Re-running is safe and is the correct way to apply a changed INF -- but REMEMBER
  to bump DriverVer in the INF each time. Windows treats an equal-or-lower version
  as "no update" and silently keeps the already-installed package.

.PARAMETER CertThumbprint
  Thumbprint of the code-signing certificate to sign with. If omitted, a
  certificate matching -CertSubject is used; if none exists, make-signing-cert.ps1
  is invoked first.

.PARAMETER BuildDir
  Scratch directory for the built package. Defaults to a temp path.

.PARAMETER SkipInstall
  Only build and sign the catalog; do not trust or install. Useful to check that
  the toolchain works without touching the machine's certificate stores.

.EXAMPLE
  .\build-and-install.ps1

.EXAMPLE
  .\build-and-install.ps1 -BuildDir C:\tmp\fbdrv -SkipInstall
#>
[CmdletBinding()]
param(
    [string] $CertThumbprint,
    [string] $CertSubject = 'CN=Local Fastboot WinUSB Signing',
    [string] $BuildDir    = (Join-Path $env:TEMP 'fastboot-drv\build'),
    [switch] $SkipInstall
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-KitTool {
    param([Parameter(Mandatory)][string] $Name)
    $roots = @(
        'C:\Program Files (x86)\Windows Kits\10\bin',
        'C:\Program Files\Windows Kits\10\bin'
    )
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        $verDirs = Get-ChildItem $root -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^\d+(\.\d+)+$' } |
            Sort-Object { [version]$_.Name } -Descending
        foreach ($v in $verDirs) {
            $p = Join-Path $v.FullName "x64\$Name"
            if (Test-Path $p) { return $p }
        }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Locate the Windows Kits tooling.  Inf2Cat is deliberately not used -- it is
# absent on this host and makecat is all it wraps.
# ---------------------------------------------------------------------------
$makecat  = Find-KitTool 'makecat.exe'
$signtool = Find-KitTool 'signtool.exe'
if (-not $makecat)  { throw "makecat.exe not found under 'Windows Kits\10\bin\*\x64'. Install the Windows SDK." }
if (-not $signtool) { throw "signtool.exe not found under 'Windows Kits\10\bin\*\x64'. Install the Windows SDK." }
Write-Host "makecat : $makecat"
Write-Host "signtool: $signtool"

# ---------------------------------------------------------------------------
# Resolve the signing certificate (create one if necessary).
# ---------------------------------------------------------------------------
if (-not $CertThumbprint) {
    $cert = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $CertSubject -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) } |
        Select-Object -First 1
    if (-not $cert) {
        Write-Host "No usable certificate found; running make-signing-cert.ps1..." -ForegroundColor Yellow
        & (Join-Path $here 'make-signing-cert.ps1')
        $cert = Get-ChildItem Cert:\CurrentUser\My |
            Where-Object { $_.Subject -eq $CertSubject -and $_.HasPrivateKey } |
            Select-Object -First 1
    }
    if (-not $cert) { throw "Could not obtain a signing certificate." }
    $CertThumbprint = $cert.Thumbprint
}
Write-Host "cert    : $CertSubject ($CertThumbprint)"

# ---------------------------------------------------------------------------
# 1. stage the package
# ---------------------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
foreach ($f in 'fastboot-amzn.inf', 'fastboot-amzn.cdf') {
    $src = Join-Path $here $f
    if (-not (Test-Path $src)) { throw "Missing $src" }
    Copy-Item $src $BuildDir -Force
}
$inf = Join-Path $BuildDir 'fastboot-amzn.inf'
$cat = Join-Path $BuildDir 'fastboot-amzn.cat'
Write-Host "`n=== 1. staged into $BuildDir ===" -ForegroundColor Cyan
Get-ChildItem $BuildDir | Select-Object Name, Length | Format-Table -AutoSize | Out-String | Write-Host

# ---------------------------------------------------------------------------
# 2. build the catalog
# ---------------------------------------------------------------------------
Write-Host "=== 2. makecat ===" -ForegroundColor Cyan
Push-Location $BuildDir
try   { & $makecat -v 'fastboot-amzn.cdf' }
finally { Pop-Location }
if (-not (Test-Path $cat)) { throw "makecat did not produce $cat" }

# ---------------------------------------------------------------------------
# 3. sign it
# ---------------------------------------------------------------------------
Write-Host "`n=== 3. signtool sign ===" -ForegroundColor Cyan
& $signtool sign /fd sha256 /sha1 $CertThumbprint $cat
if ($LASTEXITCODE -ne 0) { throw "signtool sign failed (exit $LASTEXITCODE)" }

if ($SkipInstall) {
    Write-Host "`n-SkipInstall set: catalog built and signed, machine untouched." -ForegroundColor Yellow
    Write-Host "Verify with:  & '$signtool' verify /pa '$cat'"
    return
}

# ---------------------------------------------------------------------------
# 4-5. trust + install (elevated)
# ---------------------------------------------------------------------------
$needsElevation = -not (Test-Elevated)
$elevatedLog    = Join-Path $BuildDir 'elevated-log.txt'

if ($needsElevation) {
    Write-Host "`n=== 4-5. relaunching elevated for trust + install (accept the UAC prompt) ===" -ForegroundColor Cyan
    $psArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $MyInvocation.MyCommand.Path),
        '-CertThumbprint', $CertThumbprint,
        '-CertSubject',    ('"{0}"' -f $CertSubject),
        '-BuildDir',       ('"{0}"' -f $BuildDir)
    ) -join ' '
    $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $psArgs -Verb RunAs -PassThru -Wait
    Write-Host "elevated child exit code: $($p.ExitCode)"
    if (Test-Path $elevatedLog) { Get-Content $elevatedLog }
} else {
    Write-Host "`n=== 4. trusting the certificate (LocalMachine Root + TrustedPublisher) ===" -ForegroundColor Cyan
    $cer = Join-Path $BuildDir 'signing-public.cer'
    Export-Certificate -Cert "Cert:\CurrentUser\My\$CertThumbprint" -FilePath $cer -Force | Out-Null
    foreach ($store in 'Root', 'TrustedPublisher') {
        $loc = "Cert:\LocalMachine\$store"
        $already = Get-ChildItem $loc -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $CertThumbprint }
        if ($already) {
            Write-Host "  $loc : already trusted"
        } else {
            Import-Certificate -FilePath $cer -CertStoreLocation $loc | Out-Null
            Write-Host "  $loc : imported" -ForegroundColor Green
        }
    }

    Write-Host "`n=== 5. pnputil ===" -ForegroundColor Cyan
    pnputil /add-driver $inf /install
    pnputil /scan-devices
    Start-Sleep -Seconds 3
}

# ---------------------------------------------------------------------------
# 6. verify
# ---------------------------------------------------------------------------
Write-Host "`n=== 6. verification ===" -ForegroundColor Cyan

Write-Host "-- catalog signature --"
& $signtool verify /pa $cat

Write-Host "`n-- device --"
$dev = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
    Where-Object { $_.InstanceId -match 'VID_1949&PID_05E0' }
if ($dev) {
    $dv  = (Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_DriverVersion' -ErrorAction SilentlyContinue).Data
    $dp  = (Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_DriverInfPath' -ErrorAction SilentlyContinue).Data
    Write-Host ("  {0}" -f $dev.InstanceId)
    Write-Host ("  status       : {0}  ({1})" -f $dev.Status, $dev.ProblemDescription)
    Write-Host ("  driver INF   : {0}   version {1}" -f $dp, $dv)
    $iface = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\$($dev.InstanceId)\Device Parameters" -ErrorAction SilentlyContinue).DeviceInterfaceGUIDs
    Write-Host ("  interface GUID(s): {0}" -f ($iface -join ', '))
    if ($iface -notmatch 'F72FE0D4') {
        Write-Host "  WARNING: the Android interface GUID {F72FE0D4-...} is NOT registered." -ForegroundColor Red
        Write-Host "           fastboot.exe enumerates by that GUID only, so it will see nothing." -ForegroundColor Red
        Write-Host "           Check [Dev_AddReg] in fastboot-amzn.inf." -ForegroundColor Red
    }
} else {
    Write-Host "  (device not in fastboot mode right now -- run: adb reboot bootloader)"
}

Write-Host "`n-- fastboot devices --"
$fastboot = Join-Path $env:USERPROFILE 'adb\fastboot.exe'
if (-not (Test-Path $fastboot)) {
    $fastboot = (Get-Command fastboot.exe -ErrorAction SilentlyContinue).Source
}
if ($fastboot) {
    & $fastboot devices
} else {
    Write-Host "  fastboot.exe not found; check manually."
}

Write-Host "`nDone. If 'fastboot devices' printed nothing:" -ForegroundColor Cyan
Write-Host "  - device bound to OK but fastboot blind  => interface GUID is not {F72FE0D4-...}"
Write-Host "  - device still Code 28                   => certificate not trusted, or INF version not bumped"
Write-Host "  - see the 'Root cause' section of README.md"
