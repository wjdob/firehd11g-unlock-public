# Host driver for the Amazon/LK fastboot interface

## TL;DR: read this first

**Status: WORKING.** `fastboot devices` lists the unit. This folder is the complete,
reproducible fix for Windows refusing to talk to the device's fastboot interface.

- **Core finding**: three independent blockers, all now solved, and the third is the
  one nobody expects:
  1. **Nothing signed matched.** Microsoft's signed `winusb.inf` auto-binds only the
     **ADB** class (`Class_ff&SubClass_42&Prot_**01**`). The fastboot interface is
     `Prot_**03**`, for which no generic entry exists, and Amazon's official kindle
     driver lists **no `PID_05E0`** either.
  2. **`Inf2Cat` is absent**, but it only wraps `makecat.exe`, which *is* present. The
     catalog can be built with tooling that already ships.
  3. **The interface GUID must be Android's.** `fastboot.exe` enumerates by GUID.
     With any other GUID the driver installs and Device Manager reports the device
     **working properly**, while `fastboot devices` prints **nothing**. That silent
     half-failure is the trap.
- **Core win**: `fastboot` access, obtained with built-in tooling and **no Zadig**.
  Side benefit: the device's ~10 s USB re-enumeration loop was a *symptom* of the
  failed driver start and stops entirely once a driver binds.
- **Core dead end**: fastboot access is **read-only in practice**. The locked-device
  gate refuses every write and every `oem` command, so this does not enable flashing,
  repair, or `oem reboot-recovery`. It is a diagnostic channel, not a recovery tool.
  See [../../README.md](../../README.md) §0.4.

**The device** (`adb reboot bootloader`) enumerates as:

```
USB\VID_1949&PID_05E0        (Amazon Labs)
CompatibleIds: USB\COMPAT_VID_1949&Class_FF&SubClass_42&Prot_03
```

`Class_FF / SubClass_42 / Prot_03` is the standard fastboot interface signature.
Google's `fastboot` matches on class/subclass/protocol, not vendor ID, so it will
talk to this device **once a driver is bound to the interface**.

Out of the box Windows reports `ProblemCode 28` and `fastboot devices` prints
nothing.

---

## Root cause (established definitively)

Three separate blockers, all now solved.

### 1. No signed driver package matched the interface

Microsoft ships a signed `C:\Windows\INF\winusb.inf` that auto-binds Android
interfaces generically, but it has **exactly one** Android entry:

```
%USB\MS_COMP_ADB.DeviceDesc% = ADB,USB\Class_ff&SubClass_42&Prot_01
```

`Prot_**01**` is ADB -- which is why `PID_05E8` (the ADB interface) auto-bound and
ADB worked with no vendor driver ever installed. The fastboot interface is
`Prot_**03**`, for which Microsoft ships no generic entry. The vendor drivers do
not help either:

* **Amazon's official driver** (`kindle_fire_usb_driver.zip`, linked from
  <https://developer.amazon.com/docs/fire-tablets/connecting-adb-to-device.html>)
  does contain a signed catalog, but its INF dates from 2016 and lists **only ADB
  IDs** (`VID_1949&PID_0006` ... `PID_0401&MI_01`) plus one HTC fastboot ID
  (`VID_0BB4&PID_0C01`). It has **no `PID_05E0`** and no
  `Class_FF&SubClass_42&Prot_03` entry, and it cannot be extended without
  invalidating its catalog.
* **Google's `android_winusb.inf`** is signed, but every entry is VID/PID specific
  to `VID_18D1`.

Hence the hand-made INF in this folder.

### 2. Windows refused the hand-made INF (missing catalog)

`pnputil /add-driver` reported:

```
The third-party INF does not contain digital signature information.
```

`Inf2Cat.exe` is **not** installed on this host -- but it is only a wrapper around
**`makecat.exe`**, which **is**:

```
C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\makecat.exe
```

So the catalog can be built with tooling already present. `fastboot-amzn.cdf` in
this folder is the catalog definition.

### 3. The interface GUID must be Android's

The subtle one. Binding *a* WinUSB driver is not sufficient -- the device must also
publish the **right device interface GUID**, because `fastboot.exe` enumerates by
GUID. Binary search of `C:\Users\<user>\adb\fastboot.exe` for each candidate GUID:

| GUID | occurrences in `fastboot.exe` |
|---|---|
| `{F72FE0D4-CBCB-407d-8814-9ED673D0DD6B}` (Android) | **1** |
| `{5F5F6A1E-...}` (the private GUID an earlier revision used) | 0 |
| `{A5DCBF10-6530-11D2-901F-00C04FB951ED}` (USB device interface) | 0 |
| `{DEE824EF-729B-4A0E-9C14-B7117D33A817}` (WinUSB device interface) | 0 |

With the private GUID registered, the driver installed cleanly and Device Manager
reported the device **working properly**, yet `fastboot devices` still printed
nothing. Changing `DeviceInterfaceGUIDs` to Android's GUID fixed it immediately.
This matches `[Dev_AddReg]` in Google's own `android_winusb.inf`.

**Symptom to remember:** driver bound + device reports OK + `fastboot devices`
shows nothing => wrong interface GUID.

---

## Working procedure

**Two ways to do this.** Either run the one-shot script (recommended, it performs
all six steps and verifies the result, including a warning if the wrong interface
GUID is registered):

```powershell
cd stage3-recovery\host\winusb-fastboot
.\build-and-install.ps1            # one UAC prompt; -SkipInstall to just build+sign
```

...or do it by hand with the commands below. The script is a straight transcription
of these steps, so the two are interchangeable.

Replacing `PID_05E0` with another PID is all that is needed for a different
interface.

```powershell
$kit = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64'
$src = 'stage3-recovery\host\winusb-fastboot'
$b   = "$env:TEMP\fastboot-drv\build"
New-Item -ItemType Directory -Force -Path $b | Out-Null
Copy-Item "$src\fastboot-amzn.inf","$src\fastboot-amzn.cdf" $b -Force

# 1. build the catalog  (elevation NOT required)
Push-Location $b; & "$kit\makecat.exe" -v fastboot-amzn.cdf; Pop-Location

# 2. sign it with an existing code-signing cert that has a private key
& "$kit\signtool.exe" sign /fd sha256 /sha1 <thumbprint> "$b\fastboot-amzn.cat"
```

Then, **elevated**:

```powershell
# 3. trust the signing cert (both stores, or Windows refuses the package)
Export-Certificate -Cert "Cert:\CurrentUser\My\<thumbprint>" -FilePath "$b\signing-public.cer" -Force
Import-Certificate -FilePath "$b\signing-public.cer" -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath "$b\signing-public.cer" -CertStoreLocation Cert:\LocalMachine\TrustedPublisher

# 4. confirm the catalog now verifies, then install
& "$kit\signtool.exe" verify /pa "$b\fastboot-amzn.cat"
pnputil /add-driver "$b\fastboot-amzn.inf" /install
pnputil /scan-devices

# 5. verify
fastboot devices          # -> <SERIAL>   fastboot
```

**Bump `DriverVer` in the INF whenever the INF changes**, otherwise Windows keeps
the already-installed package (equal version = no update) and the change silently
does not apply.

Version history: `1.0.0.0` private GUID (broken), `1.0.0.1` Android GUID (working).

After changing the INF you must rebuild **and** re-sign the catalog, then delete
the superseded package, or a later scan may re-select the stale one:

```powershell
pnputil /enum-drivers                      # find both fastboot-amzn entries
pnputil /delete-driver oemNN.inf /force    # delete the OLD one only
```

## Verified result

```
$ fastboot devices
<SERIAL>         fastboot

$ fastboot getvar product
product: trona

$ fastboot getvar unlock_status
unlock_status: false

$ fastboot getvar unlock_code
unlock_code: 0x201197ff6793b2aea071c15f
```

Full gate probe: `docs/../diagnostics/fastboot-gate-probe.txt`.

---

## Reversing / clean-up

```powershell
# remove the driver package (elevated)
pnputil /enum-drivers                                  # find the fastboot-amzn entry
pnputil /delete-driver oemNN.inf /uninstall /force

# remove the now-unused signing cert from the trust stores (elevated)
Get-ChildItem Cert:\LocalMachine\Root,Cert:\LocalMachine\TrustedPublisher |
    Where-Object Subject -like '*Local Fastboot WinUSB Signing*' | Remove-Item
```

The cert is a throwaway self-signed code-signing certificate
(`CN=Local Fastboot WinUSB Signing`, valid to 2027-10-06). While it sits in
`LocalMachine\Root` + `TrustedPublisher`, *any* driver package signed with it would
be accepted -- remove it when work here is finished.

---

## Files here

| file | purpose |
|---|---|
| `fastboot-amzn.inf` | WinUSB function-driver INF for `USB\VID_1949&PID_05E0`; registers Android's interface GUID |
| `fastboot-amzn.cdf` | catalog definition consumed by `makecat` |
| `build-and-install.ps1` | one-shot: stage - build catalog - sign - trust - install - verify. `-SkipInstall` builds and signs only |
| `make-signing-cert.ps1` | creates the throwaway code-signing certificate if none exists. Called automatically by `build-and-install.ps1` |
| `fastboot-amzn-nocat.inf` | historical: the same INF with `CatalogFile` commented out, kept to document the failed unsigned attempt. **It still carries the old private GUID and must not be used.** |

**No private key and no built `.cat` are committed, deliberately.** The private key
is a secret, and a committed `.cat` would silently go stale against the INF (the
catalog is a hash of the INF, so it must be rebuilt whenever the INF changes).
`make-signing-cert.ps1` regenerates the key on any machine in seconds, and
`build-and-install.ps1` rebuilds the catalog. That combination is reproducible
without either artifact being stored here.

---

## Side effect: the device stops re-enumerating

Before a driver was bound, the device **re-enumerated on a steady ~10.1 s cycle**
(present ~9.5 s, absent ~0.7 s), which Windows plays as a repeating "USB connected"
sound. Once a driver bound successfully this stopped completely -- a single state
change in 75 s, continuously `[OK]`. The cycling was a symptom of the failed driver
start, not a cable, port or hub fault. It is a direct root port
(`USB\ROOT_HUB30`, `Port_#0002`, `HS02`), not behind an external hub.

---

## What this unlocks

`fastboot` access, and with it the locked-device gate experiment. Headline result
already obtained: the gate is a **strict allowlist** -- only `product`,
`unlock_status`, `unlock_code`, `serialno`, `max-download-size` and `slot-count`
can be read, and **every** write-class command (`erase`, `format`, `flash`) is
refused at dispatch *before* partition lookup. So `flash boot` cannot be used to
repair a damaged `boot` while the device is locked.
