# MT8183 preloader tool (trona)

A single-file tool for talking to the Fire HD 10 (2021) preloader over its USB serial port
and, if the unit allows it, reflashing `recovery` and `misc`. The point of the tool is not
to assume the DA path works; it is to **prove which stage fails** on this unit.

## What the PS7319 preloader actually does (recovered from the image)

| fact | evidence |
|---|---|
| DA destination is `0x40200000` | literal at file `0x5746`, loaded into `r0` before the receive call |
| the preloader receives the body into that address | `0x5748` loads `r1 = len` and calls through a function pointer with `r0 = 0x40200000` |
| it answers with a checksum, then a status | XOR over the body halfwords, sent at `0x5808`; status at `0x58F8` |
| the DA is verified only when `SEC_CFG` bit 2 is set | `0x5816` calls `is_secure_soc()`; secure goes to `0x5834` (verifier), non-secure to `0x5820` ("DA validation disabled on non-secure chip") |
| `0xD7` SEND_DA, `0xD5` JUMP_DA | command dispatch |
| `READY` / `METAMETA` / `ADVEMETA` / `METAFORB` strings | META boot-mode switch, not a flash transport |

The consequence is a clean diagnostic split:

* **No checksum** after the body means the preloader never finished receiving it. That is a
  transfer or timing problem, and it says nothing about the fuse.
* **Checksum present, body status non-zero** means the preloader received the DA and refused
  it. That is the secure verifier, and no amount of retrying changes it.

Earlier attempts on this unit produced the first symptom (nothing after the body), which is
why the tool starts with a size and pacing probe instead of the 16 KB payload.

## Usage

```
python stage6-lineage/mtk-tool/mtk8183.py selftest          # mock device, no hardware
python stage6-lineage/mtk-tool/mtk8183.py ports
python stage6-lineage/mtk-tool/mtk8183.py handshake --wait 60
python stage6-lineage/mtk-tool/mtk8183.py da-probe --size 16
python stage6-lineage/mtk-tool/mtk8183.py da-probe --size 512 --chunk 64 --gap 0.01
python stage6-lineage/mtk-tool/mtk8183.py da-probe --size 16168 --chunk 512 --gap 0.005
python stage6-lineage/mtk-tool/mtk8183.py da --image dumps/amonet/v11/amonet/bin/pl-payload.bin
python stage6-lineage/mtk-tool/mtk8183.py read  --lba 20544 --count 2048 --out misc.img
python stage6-lineage/mtk-tool/mtk8183.py write --lba 20544 --count 2048 --image misc-clean.img --yes
```

`--wait N` polls for the port, so it can be started before a looping tablet reaches the
preloader window.

## Probe ladder

Each rung answers one question, cheapest first:

| probe | question it answers |
|---|---|
| `handshake` | is this the preloader's binary service, and does it complete the four-byte handshake |
| `da-probe --size 16` | does the preloader acknowledge a *small* body at all |
| `--chunk 64 --gap 0.01` | does pacing change the outcome (small internal buffer) |
| `--size 16168 --chunk 512` | does the real payload size survive a paced transfer |
| `da --image ...` | does the jump produce the `b1b2b3b4` hello |

Only a jump with the hello unlocks `read` and `write`. `write` additionally requires
`--yes`, checks that the image length matches `--count`, and refuses to proceed unless the
DA was accepted and the hello arrived.

## Recovery writes this tool exists to perform

From [../bench-reflash.md](../bench-reflash.md):

| target | LBA | blocks | image |
|---|---|---|---|
| `misc` (clear the BCB) | 20544 | 2048 | 1 MiB of zeros |
| `recovery` (restore stock) | 325696 | 83,904 | `recovery.img` from the backup |

## Limits worth knowing before a live run

* The DA payload shipped by the release (`pl-payload.bin`) was built against the PS7331
  preloader. If the jump crashes, the block commands never run even though the DA was
  accepted; a PS7319 payload would have to be built against this preloader's own function
  addresses. The tool reports the hello separately so that case is visible.
* `READY` and `METAMETA` are a boot-mode switch. The tool detects the banner but does not
  use META as a write path, because no META command that writes flash has been identified.
* Windows serial handles can survive a mid-transfer reset. The tool closes on every path,
  but if a run ends with `Access is denied` on the next open, re-enumerate the device.


## First live result (2026-10-25): the verifier is active

A 16-byte zero body, sent to `0x40200000` on a reconnected unit:

```
port COM4
  header accepted
  body sent: 16 bytes in 0.000s
  checksum 0000
  body status 7024
  DA refused by the preloader (verifier)
result: stage=body-status ok=False
```

Read that carefully, because it separates two things that were previously tangled:

* **The transfer works.** The checksum arrived, and it is `0000` because sixteen zero bytes
  XOR to zero. The body was received in full.
* **The preloader refused it.** Status `0x7024` is the download module's refusal code (the
  same immediate appears in the preloader at file `0x19314` and in the handler at `0x5930`).
  A non-secure part skips the verifier entirely at `0x5820` and answers `0x0000`.

So `SEC_CFG` bit 2 is set on this unit. The earlier "no checksum" runs were a transfer
problem, which is why the probe ladder exists; with the transfer fixed the refusal is
explicit. Combined with the LK refusing the unsigned recovery image, both fuse gates are now
measured rather than inferred.

### What this rules out

* **SP Flash Tool.** It downloads a DA through this exact path. `MTK_AllInOne_DA.bin` is
  MediaTek-signed, while the preloader verifies against its own key (it carries an
  `LK DA pubk` string and a verifier at `0x255A4`), so the DA fails authentication before
  any partition operation begins.
* **Any unsigned DA**, including the release's own payload.

### The supplied scatter file

`MT6771_Android_scatter.txt` is **not generic**. It is `platform: MT6771`,
`project: k71v1_64_bsp`, storage EMMC, 42 partitions. This unit's GPT has 21 partitions, and
the two lists disagree on 24 names: the scatter has `preloader`, `pgpt`, `seccfg`, `lk2`,
`logo`, `proinfo`, `md1img` and others that do not exist here, while trona has `kb`,
`dkb`, `keys` and `misc` that the scatter lacks. A scatter encodes a platform's exact
layout, so this one describes a different device and must not be used.

## Status

The tool is complete and self-tested against a mock that follows the recovered protocol.
It has **not** yet been run against the tablet with the new probe ladder, because the unit
was powered off after the failed recovery swap. The first real run should be
`handshake --wait` followed by `da-probe --size 16`; those two are read-only.