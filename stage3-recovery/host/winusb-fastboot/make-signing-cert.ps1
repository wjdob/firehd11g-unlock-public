<#
.SYNOPSIS
  Create the throwaway self-signed code-signing certificate used to sign
  fastboot-amzn.cat.

.DESCRIPTION
  Windows will not accept fastboot-amzn.inf unless its catalog (.cat) is signed
  AND the signing certificate is trusted. `makecat.exe` builds the catalog but
  cannot create a certificate, so we need one.

  No private key is committed to this repository, deliberately. Run this once per
  machine that needs to build/install the driver; build-and-install.ps1 will call
  it automatically if no suitable certificate exists.

  Requires no elevation: the certificate is created in the *CurrentUser* store.
  Trusting it is a separate, elevated step performed by build-and-install.ps1.

  The certificate is a local development artifact with no security value beyond
  this driver. Remove it (and the trust granted in LocalMachine) once the driver
  is no longer needed.

.EXAMPLE
  .\make-signing-cert.ps1
#>
[CmdletBinding()]
param(
    [string] $Subject = 'CN=Local Fastboot WinUSB Signing',
    [int]    $Years   = 2
)

$ErrorActionPreference = 'Stop'

$existing = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq $Subject -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) }

if ($existing) {
    Write-Host "Reusing existing certificate (nothing created):" -ForegroundColor Yellow
} else {
    Write-Host "Creating code-signing certificate..." -ForegroundColor Cyan
    New-SelfSignedCertificate `
        -Type              CodeSigningCert `
        -Subject           $Subject `
        -CertStoreLocation Cert:\CurrentUser\My `
        -NotAfter          (Get-Date).AddYears($Years) `
        -KeyUsage          DigitalSignature `
        -KeyAlgorithm      RSA `
        -KeyLength         2048 `
        -KeyExportPolicy   NonExportable `
        -ErrorAction Stop | Out-Null

    $existing = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $Subject -and $_.HasPrivateKey }
    Write-Host "Created." -ForegroundColor Green
}

foreach ($c in $existing) {
    Write-Host ""
    Write-Host ("  Subject      : {0}" -f $c.Subject)
    Write-Host ("  Thumbprint   : {0}" -f $c.Thumbprint)
    Write-Host ("  NotAfter     : {0}" -f $c.NotAfter)
    Write-Host ("  HasPrivateKey: {0}" -f $c.HasPrivateKey)
    Write-Host ("  EKU          : {0}" -f (($c.EnhancedKeyUsageList | ForEach-Object { $_.FriendlyName }) -join ', '))
}

Write-Host ""
Write-Host "Next: .\build-and-install.ps1   (accept the UAC prompt)" -ForegroundColor Cyan
Write-Host "Thumbprint for -CertThumbprint: $($existing[0].Thumbprint)"
