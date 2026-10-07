#!/usr/bin/env python3
"""Preflight: validate every script before spending a root cycle.

A root cycle costs several minutes (reboot, probabilistic hwbinder race, retries). A
PowerShell parse error or a CRLF-mangled shell script wastes the whole cycle for a
one-second fix. This catches both first.

    python preflight.py

Checks:
  1. every .ps1 in the repo parses (PowerShell AST)
  2. every .sh in the repo passes `sh -n` (real POSIX shell)
  3. no shell script carries CRLF line endings -- shell scripts shipped with CRLF fail
     on-device with "not found" errors that look like missing binaries
  4. device-side payloads referenced by stage4 exist and are LF-only
  5. stage4's install paths match what upstream SnuSnuRoot actually does (the values
     below were read from refs/SnuSnuRoot/runme.sh, not guessed)

Exit 0 = safe to spend a root cycle.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
STAGE4 = REPO / "stage4-persistent"

# From refs/SnuSnuRoot/runme.sh + notes/persistence-v2.md (authoritative upstream).
UPSTREAM = {
    "carrier_path": "/data/snusnu_hwbinder_root",
    "carrier_owner": "0:1000",          # root:system
    "carrier_mode": "0750",
    "carrier_label": "system_data_file",
    "water_file": "/data/securedStorageLocation/w/b",
    "water_mode": "0644",
    "state_dir": "/data/securedStorageLocation/snusnu/state",
    "state_mode": "0777",
}


def find(exe: str) -> str | None:
    p = shutil.which(exe)
    if p:
        return p
    for c in (rf"C:\Program Files\Git\usr\bin\{exe}.exe",
              rf"C:\Program Files\Git\bin\{exe}.exe"):
        if Path(c).exists():
            return c
    return None


def has_crlf(p: Path) -> bool:
    return b"\r\n" in p.read_bytes()


def tracked_files() -> list[Path]:
    """Only files git tracks. refs/ holds third-party clones (gitignored) whose CRLF is
    not ours to fix and can never reach the device."""
    try:
        out = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True,
                             text=True, check=True).stdout
    except Exception:  # noqa: BLE001
        return []
    return [REPO / p for p in out.splitlines() if p]


def main() -> int:
    problems: list[str] = []
    notes: list[str] = []
    tracked = tracked_files()

    # ---- 1. PowerShell ------------------------------------------------------
    # Includes untracked stage4 scripts: a brand-new test or installer script is
    # exactly the one that has not been parsed yet, and a parse error found here
    # costs nothing while the same error mid-run costs a full root cycle.
    ps = [p for p in tracked if p.suffix.lower() == ".ps1" and p.exists()]
    ps += [p for p in STAGE4.glob("*.ps1") if p.exists() and p not in ps]
    pwsh = find("powershell")
    if pwsh:
        script = (
            "$bad=0; @(%s) | ForEach-Object { "
            "$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile("
            "$_,[ref]$null,[ref]$e); "
            "if($e.Count){ $bad++; Write-Output ('PARSE ' + $_); "
            "$e | ForEach-Object { Write-Output ('   ' + $_.Message) } } }; "
            "if($bad -eq 0){ Write-Output 'PS_OK' }"
            % ",".join("'%s'" % str(p).replace("'", "''") for p in ps)
        )
        out = subprocess.run([pwsh, "-NoProfile", "-Command", script],
                             capture_output=True, text=True).stdout
        if "PS_OK" in out:
            notes.append("PowerShell: %d file(s) parse clean" % len(ps))
        else:
            for line in out.splitlines():
                if line.strip():
                    problems.append(line.rstrip())

    # ---- 2 + 3. shell scripts ---------------------------------------------
    # Untracked stage4 scripts are included for the same reason as the PowerShell
    # section: a brand-new payload is the one nobody has syntax-checked, and CRLF
    # in a device-side payload fails on-device with nonsense like
    # "sh: <stdin>[18]: : not found" after the file has already been pushed.
    sh = find("sh")
    shs = [p for p in tracked if p.suffix == ".sh" and p.exists()]
    shs += [p for p in STAGE4.glob("*.sh") if p.exists() and p not in shs]
    if sh:
        bad = 0
        for p in shs:
            r = subprocess.run([sh, "-n", str(p)], capture_output=True, text=True)
            if r.returncode != 0:
                bad += 1
                problems.append("SH_SYNTAX %s: %s" % (p.relative_to(REPO).as_posix(),
                                                      (r.stderr or "").strip()[:100]))
        if bad == 0:
            notes.append("shell: %d tracked script(s) pass sh -n" % len(shs))

    crlf = [p for p in shs if has_crlf(p)]
    for p in crlf:
        problems.append("CRLF %s" % p.relative_to(REPO).as_posix())
    if not crlf:
        notes.append("line endings: no tracked shell script uses CRLF")

    # ---- 4. stage4 on-device payloads must exist and be LF ----------------
    # These are the files that get pushed to the device. waiter-payload.sh and
    # snusnu_hwbinder_root.wrapper.sh were superseded once the actor ran the real
    # carrier, so they are no longer required here.
    for name in ("boot-entry.sh", "waiter.sh", "install-persistence.sh"):
        p = STAGE4 / name
        if not p.exists():
            problems.append("MISSING stage4-persistent/%s" % name)
        elif has_crlf(p):
            problems.append("CRLF stage4-persistent/%s" % name)

    # ---- 5. stage4 must match upstream's install ---------------------------
    inst = STAGE4 / "install-persistence.sh"
    if inst.exists():
        t = inst.read_text(encoding="utf-8", errors="ignore")
        for label, needle, why in [
            ("carrier label", UPSTREAM["carrier_label"], "upstream installs system_data_file"),
            ("carrier mode", UPSTREAM["carrier_mode"], "upstream uses 0750"),
            ("carrier owner", "0:1000", "upstream uses root:system"),
            ("state mode", UPSTREAM["state_mode"], "upstream uses 0777"),
        ]:
            if needle not in t:
                notes.append("CHECK  %s not found in install script (%s)" % (label, why))
        code_lines = [l for l in t.splitlines() if not l.lstrip().startswith("#")]
        badlink = [l.strip() for l in code_lines
                   if "/dev/null" in l and ("ln -s" in l or "symlink" in l)]
        if badlink:
            problems.append(
                "DEVNULL SYMLINK in install script (%s) -- this BREAKS the app: it "
                "reads native_result back to look for __SNU_NATIVE_0__, and /dev/null "
                "always reads empty, so every boot reports system_native_failed"
                % badlink[0][:60])

    # ---- 6. waiter.sh ordering invariant ----------------------------------
    # The actor's UID-1000 channel needs $STATE writable BEFORE its kernel write
    # can make getenforce readable. Preparing $STATE after the Permissive wait is
    # a deadlock: the actor gets EACCES, never writes, the waiter times out.
    # This exact ordering cost several root cycles, so it is a hard blocker now.
    w = STAGE4 / "waiter.sh"
    if w.exists():
        lines = w.read_text(encoding="utf-8", errors="ignore").splitlines()
        prep = next((i for i, l in enumerate(lines) if "chmod 0777" in l), None)
        wait = next((i for i, l in enumerate(lines)
                     if "= Permissive" in l and not l.lstrip().startswith("#")), None)
        if prep is None:
            problems.append("waiter.sh never re-asserts the $STATE mode")
        elif wait is None:
            notes.append("CHECK  waiter.sh Permissive wait not found")
        elif prep > wait:
            problems.append(
                "ORDERING DEADLOCK in waiter.sh: $STATE prepared (line %d) after the "
                "Permissive wait (line %d); the actor needs it prepared first"
                % (prep + 1, wait + 1))
        else:
            notes.append("waiter.sh: $STATE prepared (line %d) before the Permissive "
                         "wait (line %d)" % (prep + 1, wait + 1))

    # ---- 7. installer must keep $STATE root-owned, and sync ---------------
    # time_update is DAC-exempt but has no CAP_FOWNER, so its boot-time
    # `chmod 0777 $STATE` is denied with { fowner } if $STATE is owned by 1000.
    if inst.exists():
        t = inst.read_text(encoding="utf-8", errors="ignore")
        # A chown is only harmful if it hands $STATE to a non-root owner;
        # chowning it TO root is the deliberate fix (see the installer comment).
        # The install line legitimately chowns waiter.sh and also mentions $STATE.
        bad_chown = []
        for line in t.splitlines():
            if line.lstrip().startswith("#"):
                continue
            for segment in line.split("&&"):
                if "chown" not in segment or "$STATE" not in segment:
                    continue
                owner = segment.split("chown", 1)[1].strip().split()[0]
                if owner not in ("0:0", "root", "root:root", "0", "root:0"):
                    bad_chown.append(segment.strip())
        if bad_chown:
            problems.append("install-persistence.sh leaves $STATE owned by a non-root "
                            "user (%s) -- time_update has no CAP_FOWNER so its "
                            "boot-time chmod is denied" % bad_chown[0][:60])
        if "chmod 0777 $STATE" not in t:
            problems.append("install-persistence.sh never leaves $STATE at 0777")
        if "&& sync" not in t:
            problems.append("install-persistence.sh does not sync after metadata changes")
        if "STATE=/data/cache/snusnu/state" not in t:
            problems.append("$STATE is not on /data/cache -- system_app cannot search "
                            "/data/securedStorageLocation on this firmware")
        if "stage4-persistent/app/build/snusnu-persistence.apk" not in t:
            problems.append("install script does not reference the patched APK build")

    # ---- 8. the built APK must carry the STATE_DIR patch and the watchdog -
    apk = STAGE4 / "app" / "build" / "snusnu-persistence.apk"
    if not apk.exists():
        problems.append("patched APK not built -- run: sh stage4-persistent/app/build.sh")
    else:
        import zipfile
        dex = zipfile.ZipFile(apk).read("classes.dex")
        if b"/data/cache/snusnu/state" not in dex:
            problems.append("built APK lacks the /data/cache state path")
            dex = None
        if dex and b"/data/securedStorageLocation/snusnu/state" in dex:
            problems.append("built APK still contains upstream's unreachable state path")
        if dex:
            notes.append("APK: STATE_DIR patch present, upstream path absent (%d bytes)"
                         % len(dex))

    # ---- 9. the boot actor's carrier must carry the 10 ms ENODATA rescale ---
    # The stage-0x50 race needs a ~4 s window, not ~0.4 s; without the rescale the
    # leak misses with ENODATA on a large fraction of boots, the app reports
    # system_native_failed, and no uid-0 listener appears even though the trigger
    # fired. This is the single most expensive silent failure in this stage.
    carrier = REPO / "stage1-root" / "port" / "prebuilt" / "device" / "arm64-v8a" / "snusnu_hwbinder_root"
    patcher = REPO / "stage1-root" / "patch-wait-inline.py"
    if not carrier.exists():
        problems.append("staged carrier missing: %s" % carrier.relative_to(REPO).as_posix())
    elif not patcher.exists():
        problems.append("stage1-root/patch-wait-inline.py missing; cannot check the carrier")
    else:
        r = subprocess.run([sys.executable or "python", str(patcher),
                            "--bin", str(carrier), "--verify"],
                           capture_output=True, text=True)
        msg = (r.stdout or r.stderr or "").strip().splitlines()
        if r.returncode != 0:
            problems.append("carrier not ENODATA-rescaled (%s) -- run: python %s --bin %s"
                            % (msg[-1] if msg else "verify failed",
                               patcher.relative_to(REPO).as_posix(),
                               carrier.relative_to(REPO).as_posix()))
        else:
            notes.append("carrier: " + (msg[-1] if msg else "10 ms rescale verified"))

    # ---- 10. the APK source must spawn the re-arm watchdog -----------------
    # Without it, TimeService's NTP sync clobbers persist.sys.saved_time and the
    # NEXT boot has no trigger to fire: root silently disappears on alternate
    # boots while the app still reports kernel_write_ok.
    svc = (STAGE4 / "app" / "src" / "io" / "github" / "voidnullvalue" /
           "snusnuroot" / "persistence" / "PersistenceService.java")
    if not svc.exists():
        problems.append("PersistenceService.java not found under stage4-persistent/app")
    else:
        src = svc.read_text(encoding="utf-8", errors="ignore")
        if "WATCHDOG_PATH" not in src:
            problems.append("app source has no WATCHDOG_PATH -- NTP will clobber "
                            "saved_time and root will vanish on the next boot")
        elif "setsid /system/bin/sh " not in src:
            problems.append("app source never spawns the watchdog with setsid -- a "
                            "non-detached child dies with the channel and re-arming stops")
        elif "__SNU_CARRIER_MISS_" not in src:
            problems.append("app source does not retry the carrier in-boot -- measured "
                            "on this device, a boot whose first attempt returned ENODATA "
                            "succeeded on the next attempt, so single-shot loses ~1 boot in 3")
        elif "__SNU_BUILD_MISMATCH__" not in src:
            problems.append("app source has no build/digest gate on the carrier launch -- "
                            "an OTA can change selinux_enforcing's address while /data "
                            "keeps the old carrier")
        else:
            notes.append("app: watchdog from root-owned path, carrier retried in-boot, "
                         "build+digest gate present")

        # Executing a script out of the actor's 0777 scratch directory is a
        # privilege-escalation path: any local app could replace it and run code
        # as uid 1000, which re-arms root.
        if 'STATE_DIR + "/watchdog.sh' in src or "watchdog.sh\" + " in src.lower():
            problems.append("app writes/executes the watchdog from the writable state dir; "
                            "it must run the root-owned WATCHDOG_PATH instead")

    # ---- 10b. the watchdog source lives in the repo, root-installed --------
    # (CRLF is already checked for every stage4 *.sh in section 4.)
    wd = STAGE4 / "watchdog.sh"
    if not wd.exists():
        problems.append("stage4-persistent/watchdog.sh missing -- the installer "
                        "installs this file as the root-owned watchdog")
    else:
        wsrc = wd.read_text(encoding="utf-8", errors="ignore")
        if "/data/cache/snusnu/disable" not in wsrc:
            problems.append("watchdog.sh has no disable sentinel -- --remove would "
                            "leave it re-arming the trigger forever")
        if "watchdog.pid" not in wsrc:
            problems.append("watchdog.sh has no pidfile -- duplicate guards could run")
        if "/proc/sys/kernel/random/boot_id" not in wsrc:
            problems.append("watchdog.sh does not record the boot id -- the pidfile "
                            "survives reboot, so a recycled PID would make the guard "
                            "exit and never re-arm")
        if "/data/cache/snusnu/state/watchdog.sh" in wsrc:
            problems.append("watchdog.sh points at the writable state dir")

    # ---- 11. the waiter must outlast the carrier retries -------------------
    # The actor may spend 5 attempts x ~42 s before it reaches Permissive, so a
    # waiter that gives up sooner abandons a boot that is still making progress.
    if w.exists():
        wsrc = w.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r"seq 1 (\d+)\); do", wsrc)
        if not m:
            notes.append("CHECK  waiter Permissive-wait count not found")
        elif int(m.group(1)) < 240:
            problems.append("waiter.sh waits only %s s for Permissive; the carrier retry "
                            "loop can need ~210 s" % m.group(1))

    # ---- 12. the installer must clear the package's stopped state ----------
    # A freshly installed package is stopped and receives no BOOT_COMPLETED, so
    # the actor never runs. Observed on device after uninstall+reinstall: no
    # watchdog, no status writes, no root, with every other check passing.
    if inst.exists():
        t = inst.read_text(encoding="utf-8", errors="ignore")
        if "stopped=false" not in t or "BootstrapActivity" not in t:
            problems.append("install-persistence.sh does not clear the package stopped "
                            "state -- a freshly installed package receives no "
                            "BOOT_COMPLETED and would silently never run")

    print("preflight for a root cycle")
    print("  repo: %s" % REPO)
    print()
    for n in notes:
        print("  ok    %s" % n)
    print()
    if problems:
        print("BLOCKERS (%d) -- do not spend a root cycle until these are fixed:" % len(problems))
        for p in problems:
            print("  FAIL  %s" % p)
        return 1
    print("RESULT: clean -- safe to spend a root cycle")
    return 0


if __name__ == "__main__":
    sys.exit(main())
