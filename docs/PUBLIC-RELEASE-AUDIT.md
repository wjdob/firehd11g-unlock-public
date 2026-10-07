# Public-release audit: 2026-10-06

> **Scope note.** This document records the release audit of the *private* research
> repository this tree was extracted from, so parts of it describe tooling and state
> that are not in this public baseline, `tools/hooks/`, `tools/sync-handoff-bundle.py`,
> `tools/check-bundle-drift.py` and the `stage2a-unlock/` bundle all live upstream.
> It is included because the *results* are what matter: it is the record of what was
> checked for disclosure and found clean, and of the one thing that was not.
> The data-hygiene guidance a reader needs is in [../dumps/README.md](../dumps/README.md)
> and [../NOTICE](../NOTICE).


Recorded before flipping `wjdob/firehd11g-unlock` from private to public. The point
of writing it down is that the *negative* results took real work and should not be
re-derived on a hunch.

## Verdict

**No secrets and no unredistributable content are on the published branch.**
Everything sensitive lives in **local-only** refs that `git push origin master` does
not publish, and the two device/personal identifiers that *were* in tracked files have
been redacted from HEAD.

**Two things are deliberately outside this verdict, and both are stated rather than
fixed:**

1. the device serial and Windows username **remain in git history** (they were pushed
   before this audit). Redacting HEAD does not remove them, see "Residual" below.
2. the local-only checkpoint refs still **hold** a throwaway private key and
   third-party MediaTek tooling; they are guarded by a pre-push hook rather than
   purged.

## What the remote actually holds

| check | result |
|---|---|
| `signing.pfx` (private key) reachable from `origin/master` | **No** |
| `stage2-unlock/mediatekTools/*.zip` reachable from `origin/master` | **No** |
| `stage2a-unlock<date>.zip` reachable from `origin/master` | **No** |
| Largest object reachable from `origin/master` | 2.59 MB (`stage1-root/.../magisk`) |
| GitHub-reported repository size | ~2.3 MB |
| Working tree at HEAD | 151 tracked files, 10.8 MB |

## Device and user data: what was checked and found absent

| class | finding |
|---|---|
| Partition dumps (`mmcblk*`, `gpt-*`) ever committed | **none**: only `dumps/README.md`, `dumps/SHA256SUMS.txt`, `dumps/dump-small.sh` |
| `userdata` / `metadata` / IDME contents | **never committed**; `dumps/` is gitignored |
| MAC addresses | none in tracked files |
| Email addresses | none in tracked files |
| Credentials/tokens/secrets | none. The `token` hit in `diagnostics/fastboot-gate-probe.txt` is the `getvar token` *command name*; the `secret` hits under `diagnostics/sepolicy/` are Android SELinux class names |
| `.der` files under `stage2-unlock/` | X.509 **certificates** (`30 82 04 2d`) and RSA **public** keys (`30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01`); public material, no private keys |
| Device serial | **REDACTED** in HEAD; replaced with `<SERIAL>` (see below) |
| Windows username / absolute paths | **REDACTED** in HEAD; `C:\Users\<user>`, `/c/Users/<user>`, `<user>` |

### Redaction applied to HEAD (2026-10-06)

25 tracked files, 211 replacements:

* the device serial → `<SERIAL>` (48 occurrences)
* `/c/Users/<user>`, `C:\Users\<user>` path forms (160 occurrences)
* the bare username → `<user>`

Two script edits needed care rather than a blind substitution:

* `stage1-root/run-root.ps1` hardcoded `ADB=` followed by a personal absolute path.
  Replaced with `ADB=${ADB:-$HOME/adb/adb.exe}`, which removes the personal path **and**
  keeps working for the original author, since `$HOME` resolves to the same directory.
* `stage1-root/port/tools/adb-portable.sh` lists candidate adb paths. A naive
  `<user>` substitution there **breaks the script**, because `<` is a shell redirection
  operator; the first attempt did exactly that and failed `sh -n` with
  `syntax error near unexpected token '<'`. It now uses `"$HOME/adb/adb.exe"`.

Verified after redaction: `sh -n` clean on all 20 shell scripts, PowerShell parser
clean on all 4 `.ps1`, all `.py` parse, and both boot-chain verifiers still PASS.

One deliberate exception worth stating: the GitHub owner name in the remote URL is
**not** a match for the username being redacted(the two differ by one character) so
the remote URL was left untouched. It was checked explicitly for corruption, because a
careless substitution would have broken the published URL.

### Residual: the identifiers remain in git HISTORY

**Redacting HEAD is not the same as removing the data.** The serial and the username
are still reachable in the commits already pushed to `master`:

```sh
git log -p -S '<the serial>' origin/master     # still finds them
```

Removing them from history needs a rewrite (`git filter-repo`) followed by a
**force-push**, which rewrites every commit hash and invalidates existing clones and
forks. That was **not** done, by choice: the identifiers are the author's own, and the
cost of rewriting published history is real. Recorded here so the decision is explicit
rather than accidental.

## What is local-only and must not be published

`refs/agents/<session>/checkpoints/turn/<n>`, 35 agent-session checkpoint refs.
They are the only thing keeping these objects alive:

* `stage3-recovery/host/winusb-fastboot/signing.pfx`; a throwaway self-signed
  code-signing **private key** (ref `refs/agents/820c8688-.../turn/10`)
* `stage2-unlock/mediatekTools/`, ~195 MB of third-party MediaTek tooling
  (`SP_Flash_Tool_v5.2316_Win.zip`, `MTK Auth Bypass Tool_V6.0.0.1.zip`,
  `MediatekBootloaderUnlocker.zip`, …). Not ours to redistribute
* `stage2a-unlock<date>.zip`, generated bundle exports (30.8 MB + 13.3 MB)

Local `.git` measures ~223 MB because of these; the published history is ~2.3 MB.

## Mitigation chosen

The owner elected to **keep** the checkpoint refs rather than purge them, so the
guard is procedural rather than destructive: `tools/hooks/pre-push` refuses any push
carrying refs outside `refs/heads/` and `refs/tags/`.

Verified against a throwaway local remote:

| command | result |
|---|---|
| `git push --dry-run --mirror <remote>` | **blocked**, exit 1, lists all 35 refs |
| `git push --dry-run <remote> master` | allowed, exit 0 |
| `sh tools/hooks/test-guard.sh` | 7 passed, 0 failed |

**Standing rule:** publish with `git push origin master`. Never `--mirror`.

## If this ever changes

If the checkpoint refs must be removed later, the sequence is:

```sh
git for-each-ref --format='%(refname)' refs/agents/ | while read r; do git update-ref -d "$r"; done
git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

That is irreversible and discards four sessions of checkpoint history; it reclaims
roughly 220 MB and removes the private key from the local object store.

## Residual risk after going public

* **A rewritten history cannot un-publish a blob.** Nothing sensitive is on the
  remote today, so this is not yet an incident, but it means the decision to keep
  the checkpoint refs must be paired with discipline about how pushes are made. The
  hook exists for exactly that reason; do not bypass it with `--no-verify` out of
  convenience.
* **The `signing.pfx` in local history is a throwaway with password `temp`.** If it
  is ever disclosed, the only exposure is that a certificate matching its public half
  could be trusted on a machine where it was imported. Remove that certificate from
  `LocalMachine\Root` / `TrustedPublisher` when the fastboot driver is no longer
  needed (see `stage3-recovery/host/winusb-fastboot/README.md`).

## Bundle payload finding (2026-10-06, after the redaction pass)

The redaction above covers **tracked text**. A separate pass over the *binary* payloads
in the shareable bundle found one more disclosure that git ignore rules do not cover,
because the bundle is the artefact that gets zipped and shared rather than committed.

Scanning every `.bin`/`.img` in `stage2a-unlock/` for serial, MAC and PSN patterns:

| payload | device-unique data |
|---|---|
| **`dumps/trona-1735/mmcblk0boot1.bin`** | **WiFi MAC, Bluetooth MAC, serial, PSN, FSN** |
| `mmcblk0boot0.bin`, `mmcblk0p4`–`p7`, `gpt-*.bin`, `ota-extract/images/*` | none |

`mmcblk0boot1` is the IDME database. It is now **excluded from the bundle** by
`tools/sync-handoff-bundle.py`, which carries the rationale inline so it is not
re-added. The local copy under `dumps/` is kept; it is evidence for the unlock-code
analysis and stays gitignored. `dumps/README.md` now warns about this.

Two related fixes in the same pass:

* `MANIFEST.txt` carried the builder's absolute repo path in its `Source:` line. It now
  reads "repository working tree", since that file ships inside the bundle.
* both `sh -n` and the PowerShell parser were run over every script after redaction.
  That caught a real break: substituting a `<user>` placeholder into
  `adb-portable.sh` is a **syntax error**, because `<` is a shell redirection operator.
  It now uses `"$HOME/adb/adb.exe"`.

Post-fix verification: bundle contains **0** occurrences of the serial, either MAC, the
PSN/FSN, or the username; `verify-manifest.py` 49 ok / 0 unlisted; drift check PASS.

## Re-audit for the 2026-10-08 exploit-research material

The same sweep was re-run after the MT8183 exploit-research session added
`exploits/` (anchor, register, boot-chain map, evidence under `exploits/notes/` and
tooling under `exploits/tools/`).

What was found and fixed: **the reference unit's serial appeared in 11 places across
seven new evidence files** (the live-surface summary and six raw captures, all
getprop/device-tree output). Every occurrence was replaced with the existing
`<SERIAL>` placeholder. The two new hygiene tools that build their patterns from
device strings were rewritten to assemble those patterns from fragments, the same way
`tools/publish/publish-public.py` does, so that a clean sweep always means a real leak
rather than the tool flagging itself.

Verification after the fix:

* `exploits/tools/id-sweep.py` over the working tree: **clean**.
* `exploits/tools/id-sweep.py` over the handoff bundle (`stage2a-unlock/`): **clean**.
* publisher `identifier sweep`: **clean** on the 198-file export; binary integrity
  reported every binary byte-identical to source; `check-bundle-drift.py` PASS and
  `verify-manifest.py` 124 ok / 0 unlisted.

Two structural points worth recording, because they are what make the new material
safe to publish rather than merely believed safe:

1. The public repository is a **history-free export**: `git archive HEAD` of the private
   tree, a fresh `git init`, one commit. Local-only `refs/agents/*` checkpoints, which
   carry a throwaway signing key and third-party MediaTek tooling, cannot reach it,
   and the publish step force-pushes the `main` branch only, never `--mirror`.
2. Redaction is applied at the source, not at export time, so the private tree and the
   public tree agree and the handoff bundle (which is zipped and shared separately) is
   clean for the same reason.
