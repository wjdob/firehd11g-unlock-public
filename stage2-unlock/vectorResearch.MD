> **Editorial preface, added 2026-10-06, not part of the original document.**
> The text below is external research correspondence reproduced **verbatim**. It opens
> mid-thread, and its leads have since been followed up, so this preface records where
> each one actually landed. Read the summary, not the whole document, unless you are
> tracing the reasoning.
>
> **What it argued.** That the strongest remaining direction was the preloader's
> handling of image headers *before* authentication: the LK signatures in two historical
> Trona firmware packages exclude the leading 512-byte container header, and the LK
> verification key differs from the unlock-token key. It explicitly declined to claim a
> complete unlock, and explicitly declined to conclude that *every* software bypass
> requires forging an Amazon signature.
>
> **Where each lead landed.**
>
> - **§3, container-header handling, CLOSED, and it was a real finding.** Verified
>   cryptographically against the installed bootloaders: the 0x200-byte header **is**
>   outside the signature (now proven rather than inferred), it supplies the **length**
>   of the pre-authentication copy, and that copy happens **before** any signature check.
>   That is a genuine pre-auth write primitive of the Koboreru / CVE-2023-20695 class.
>   It is unusable in practice: the primitive is bounded to a region overlapping LK's
>   own destination, and exploiting it needs boot-critical writes this project forbids.
>   See [README.md](README.md) §"Container-header audit".
> - **Its closing caveat was the right call.** It refused to generalise from "no usable
>   bypass" to "no bypass exists", and that distinction is preserved in
>   [README.md](README.md)'s claim-status table, which still records *"every possible
>   software bypass has been excluded"* as **not established**.
> - **The `atf_dram` follow-up it prompted** is in
>   [vectorResearch2.MD](vectorResearch2.MD), where the same outcome pattern applies.
>
> **Net:** this document correctly identified the best remaining lead, that lead was
> pursued to a verified conclusion, and the conclusion is negative for unlocking. The
> value is that the reasoning is on the record.

With the full notes, I can narrow this considerably. **The strongest remaining direction is the preloader’s handling of image headers and other data before authentication.** I investigated that against two historical Trona firmware packages hosted by Amazon and found a concrete detail worth adding to your analysis: **their LK signatures exclude the leading 512-byte container header, and their LK image verification key is different from the unlock-token key.**

I have **not found a confirmed bootloader unlock for your current Trona build**, so I cannot honestly assign medium or high confidence to a complete working solution. I can now distinguish several well-supported research targets from the generic techniques your work has already excluded.

Your findings support abandoning the ordinary `seccfg` unlocker, the unavailable BootROM entry recipes, and direct modification of an authenticated LK. They do **not** establish that every software bypass requires forging an Amazon signature. That broader conclusion depends on the correctness of the loaders, parsers, policy checks, and trusted-memory configuration around the cryptography.

Below, I distinguish observations I reproduced in historical firmware from findings reported in your post. I have not inspected your installed-device dumps.

## 1. New evidence: historical signed Trona LK images are available

I retrieved the relevant archive members from these two Amazon-hosted packages:

| Amazon package | Internal device identification | LK size | Relevant file offsets in accompanying preloader |
|---|---|---:|---|
| [Fire OS 7.3.1.9; PS7319/1726](https://fireos-tablet-src.s3.amazonaws.com/vm4jfkR0UZpAcbUDC8if6XSnyp/update-kindle-Fire_HD_11-PS7319_user_1726_0020367982212.bin) | `pre-device=trona`; build identifies `Amazon/trona/trona` | 604,912 bytes | Image-verification modulus: `0x37b98`; unlock modulus: `0x37c98` |
| [Fire OS 7.3.2.1; PS7321/2324](https://fireos-tablet-updates.s3.amazonaws.com/T4sFrgJ4OjzESNVBzBG9GH2gnG/update-kindle-Fire_HD10-PS7321_user_2324_0021274104964.bin) | `pre-device=trona`; build identifies `Amazon/trona/trona` | 604,912 bytes | Image-verification modulus: `0x37bb0`; unlock modulus: `0x37cb0` |

Both contain `images/lk.img`; their updater scripts explicitly check for Trona and install that member to the LK partition. I inspected the internal metadata rather than relying on the marketing names in the download filenames.

### What I verified cryptographically

For **both** historical LK images:

- The last `0x100` bytes form a valid RSA-PSS signature using SHA-256 and MGF1-SHA-256.
- Verification succeeds over **`LK[0x200:-0x100]`**.
- The public modulus that verifies that signature is the **image-verification modulus** in the table.
- The separate modulus immediately following it matches the unlock public key embedded in LK at `0x4bab8`.

Therefore, for these two releases:

> **The image-verification key and unlock-token key are distinct, and the leading `0x200` bytes are outside this LK signature.**

The first release reproduces your reported `0x37c98` location for the unlock modulus. The image-verification modulus is **256 bytes earlier**, at `0x37b98`. That is a particularly useful location to cross-check against your preloader’s `AMZN_PL_VERIFY` call path.

This establishes the signature/key relationship in those files. Your current preloader’s runtime selection of the key still needs to be checked against its actual callers.

For comparison with your dumps, the extracted LK SHA-256 values are:

```text
PS7319/1726:
ca027c283fad9c469380ef094746ae0134cceded354d3d160a2d1ce365782fb6

PS7321/2324:
47e42285fe6b49e7d0afc798a29bf4f6005485b8f1930c7be4c9d5af57b1a34d
```

The LKs contain different code and build strings, but both have `_LK_VER:` followed by the same raw bytes, `01 06`. **That tag alone will not distinguish meaningful historical code changes.**

These results make historical LK comparison a concrete research option. They do not establish that either image is vulnerable or that your current preloader would accept it. In particular, the keys must match your current trust policy, and compatibility remains a separate question.

## 2. How I would rank the remaining work

This table describes the strength of the evidence for investigating each path, rather than an estimated probability of unlocking the tablet.

| Priority | Research target | Evidence supporting it | What remains unproven |
|---|---|---|---|
| **1** | LK container-header handling and other preloader parsing before authentication | Confirmed signature boundary in two historical Trona images; your mapped LK loader | Whether any relevant field is used without adequate validation |
| **2** | Differential analysis of historical signed Trona LK | Two distinct, signed, model-identified LK images are publicly obtainable | A useful historical vulnerability and acceptance by your current preloader |
| **3** | Preloader USB processing before DA authentication | Your device exposes that interface; MediaTek lists relevant MT8183 preloader vulnerabilities | Whether your build contains any affected implementation |
| **4** | Boot-time consumption of IDME flags | Your post maps the consumers and a restricted fastboot writer | Whether the consumers independently require a verified unlock |
| **Conditional** | SRAMROM permission configuration | CVE-2021-0904 explicitly covers MT8183 and Android 9-era software | Exact Trona applicability and a path from additional access to boot control |
| **Conditional** | An accepted signed DA1 followed by Carbonara | Published V5/V6 mechanism | Availability of a DA1 trusted by your production device |

The first three are the most relevant to a functional bootloader bypass. The flag investigation could instead produce a useful repair or boot-policy result while the bootloader remains cryptographically locked.

## 3. Highest-priority vector: what happens to the LK header before verification?

The new signature result gives you a narrowly defined question:

> **What does the preloader do with the leading 512-byte LK container header before it authenticates the signed LK payload?**

A header outside a payload signature is not itself a vulnerability. Its effects may be constrained by fixed destinations, independently derived lengths, other checks, or authenticated copies of the relevant information. The task is to establish those constraints.

Starting from your loader at preloader `0x2c60`, I would trace:

- **Length:** Where does the loader obtain the amount to read, allocate, copy, and hash? Are those quantities identical or independently bounded?
- **Destination:** Does a header field influence where bytes land, or does the loader enforce a fixed destination and permitted region?
- **Entry point:** Is execution derived from a fixed convention or from metadata outside the signed region?
- **Signature and version discovery:** What bounds the `_LK_VER:` search and the calculation of the signature location?
- **Ordering:** Do the checks occur before every consequential copy or allocation?
- **Failure handling:** Can an unsuccessful verification leave modified state that a subsequent operation uses?

Those questions can be answered through disassembly and an offline model of the parser. They do not require changing a boot partition.

### Where Koboreru fits after this additional research

[Koboreru](https://github.com/R0rt1z2/amonet-koboreru) is a useful published example of this general weakness: preloader image-header processing permits a consequential copy before authentication. Its documented implementation exploits TEE loading and specific overlap-check behavior. The project describes a firmware-dependent vulnerability, with Amazon fixes around 2022. It is not a demonstrated Trona port. [GitHub](https://github.com/R0rt1z2/amonet-koboreru?utm_source=chatgpt.com)

Its source also explicitly explains that the original signed LK is verified **before** the TEE entry point runs. The payload subsequently replaces the already-verified in-memory LK. That is why a correct parent-stage signature check does not, on its own, exclude every later preloader bypass. [GitHub](https://github.com/R0rt1z2/amonet-koboreru/blob/main/main.c?utm_source=chatgpt.com)

I checked both historical Trona preloaders above: **neither contains `check_part_overlapped` or `check_part_overlapped done`.** That lowers the priority of a direct Koboreru port for these particular images. It does not prove that equivalent unsafe parsing is absent.

My recommendation is to use its analysis as a comparison for **validation order and memory-range enforcement**, while auditing your actual LK and TEE loaders independently.

### Two additional primary examples worth comparing selectively

Meta’s researchers published two relevant preloader findings:

| Published finding | Useful comparison question |
|---|---|
| **CVE-2023-20695:** certificate-image loading checked one size but copied a larger total including the header | Does each bound cover the complete operation actually performed? |
| **CVE-2023-20696:** different parsing passes authenticated one certificate interpretation but consumed another | Are the fields used for the security decision exactly the fields authenticated? |

The first affected a preloader certificate buffer; the second allowed a secure-boot bypass through ASN.1 parsing inconsistency. Their advisories provide enough technical detail to compare implementations. [GitHub](https://github.com/metaredteam/external-disclosures/security/advisories/GHSA-v45w-cq6c-vcx8?utm_source=chatgpt.com)

**I would not label either a Trona vulnerability.** MediaTek’s corresponding affected-chip lists do not name MT8183. Moreover, your mapped Amazon LK signature path is different from the two-certificate flow described in the ASN.1 advisory. Only investigate that exact flaw further if another reachable Trona verification path uses the corresponding parser. [Security Bulletin](https://www.mediatek.com/product-security-bulletin/May-2023?utm_source=chatgpt.com)

## 4. Historical signed LK: your rollback finding becomes useful if there is a weaker implementation

Your statement that the examined preloader does not enforce a minimum LK version may be one of your most useful findings. The accompanying dismissal that an older signed LK is unavailable should be revised in light of the packages above.

The productive question is:

> **Does a historical Trona LK retain a weaker, reachable implementation that your current preloader would still authenticate?**

I would compare the two historical LKs with your actual installed LK in these areas:

- Boot and recovery image parsing before authentication.
- Fastboot download-buffer handling and commands reachable while locked.
- IDME parsing and security-policy consumers.
- Temporary-unlock certificate and code processing.
- Error paths and fallback modes that alter verification policy.

This is a focused differential analysis. A code change matters if it identifies a previously weaker check in a path available under your device’s locked state.

The order of evidence matters:

1. **Identify the candidate precisely** by hash and build string.
2. **Check its signature against the current preloader’s relevant trusted modulus and exact verification format.**
3. **Establish which other compatibility and version checks apply.**
4. **Find a concrete weakness in the candidate implementation.**

A historical image being properly signed answers only one of those questions.

Both complete OTA scripts I inspected also contain a build-date downgrade restriction. That belongs to the recovery updater and is separate from your reported preloader-to-LK version behavior. Consequently, “the preloader may accept this LK” and “the stock updater will install this historical OTA” are different propositions.

One further qualification: your `trona-1735` naming may indicate an early baseline, but a directory name does not establish a firmware version. **Compare your current LK hash and embedded build string first.** If you already have substantially the earliest implementation, historical downgrade research may offer little additional code to examine.

## 5. Preloader USB remains a legitimate audit target despite DA authentication

Your command-dispatch analysis convincingly eliminates several specific tools and recipes. It does not establish that the remaining USB implementation is free of memory-safety or authentication-state errors.

In particular, **a DA signature check protects the transition into the DA only if the processing leading up to that decision is correct**.

MediaTek’s March 2022 bulletin explicitly lists MT8183 for:

- **CVE-2022-20055, -20056, -20058, and -20059:** preloader USB out-of-bounds writes.
- **CVE-2022-20060:** a preloader USB permission bypass involving improper image authentication. [Security Bulletin](https://www.mediatek.com/product-security-bulletin/March-2022?utm_source=chatgpt.com)

Its April bulletin lists MT8183 for **CVE-2022-20069** and **CVE-2022-20073**, involving integer overflow and underflow in preloader USB handling. These bulletins identify Android 10–12 software, so chip inclusion does not establish applicability to your Fire OS build. [Security Bulletin](https://www.mediatek.com/product-security-bulletin/April-2022?utm_source=chatgpt.com)

Your function map gives this work a useful starting point:

| Your mapped area | Focused offline question |
|---|---|
| Command loop at `0x5658–0x5c06` | Which parsing and USB-control operations occur before authorization? |
| DA receive/authentication path around `0x5800` | Are all received lengths, destinations, and intermediate buffers constrained before use? |
| Jump path around `0x592e` | Is successful authentication bound to the exact image and entry point subsequently used? |
| Range validation at `0x258e4 → 0x25874` | Does validation cover the complete transfer interval, including arithmetic, alignment, and end boundaries? |

The distinction between checking a starting address and checking the entire operation is particularly relevant. Your finding that a whitelist exists is valuable; the next question is whether every caller uses it correctly.

**Confidence:** strong evidence that this is a relevant component to audit; insufficient evidence to identify one of these CVEs in your binary.

## 6. IDME: separate the writer’s permissions from the reader’s behavior

Your `oem flags` result establishes that a locked-device fastboot command cannot set `dev_flags` or `fos_flags`.

It does not, by itself, establish that LK ignores those fields when another mechanism changes them.

Since you report Android-root access to IDME, the next question is at the **boot-time consumers** around LK `0x2c150–0x2c3d0`:

> **Does a cryptographically verified unlock condition control each flag’s effect, or does that condition exist only in the fastboot setter?**

Specifically, check whether:

- An unlock check dominates each security-relevant consumer.
- IDME fields have another integrity check.
- Their values are normalized, overridden, or regenerated before use.
- A command-line change is followed by separate enforcement elsewhere.
- The kernel on this build honors the resulting boot parameter.

If a consumer acts unconditionally, that could support a persistent policy change while keeping the original signed boot components. **It would not automatically make a modified LK or arbitrary boot image acceptable.** Its value could be in repair, verity behavior, or a more durable root arrangement.

### The IDME parser is a separate question

The presence of IDME error messages does not demonstrate that arbitrary malformed databases are handled safely.

Your entry format contains lengths, counts, alignment, and variable-sized values. An offline review can examine:

- Bounds against the actual database extent.
- Length and alignment arithmetic.
- Copies into fixed-size destination buffers.
- Duplicate-field and missing-field behavior.
- Differences between the preloader and LK implementations.

I would keep this below the more concrete header and USB leads until a specific defect appears. It is an unclosed parser audit, not evidence of an exploitable flaw.

Also, your map places **temporary unlock in LK**, while the preloader’s LK-signature waiver appears to consult permanent authorization. Unless the preloader has an equivalent temporary-unlock path, a temporary-unlock result in stock LK would not authorize a modified LK on storage. That distinction is worth preserving when evaluating any future candidate.

## 7. Two conditional leads, with their prerequisites made explicit

### SRAMROM: a close chip match, but the register annotation needs correction

MediaTek’s **CVE-2021-0904** advisory explicitly names MT8183 and Android 8.1–11. It describes a permission bypass in SRAMROM configuration requiring System privileges. That makes it a more relevant firmware-comparison lead than many newer, unrelated secure-monitor vulnerabilities. [Security Bulletin](https://www.mediatek.com/product-security-bulletin/December-2021?utm_source=chatgpt.com)

However, I found no primary public technical write-up that establishes its affected configuration in Trona or turns it into a Trona unlock.

There is also a concrete annotation issue in your post: primary MT6771/MT8183 reverse-engineering code identifies **`0x1001a080` as the USB download request register**, subsequently labeled **`USBDL_FLAG/BOOT_MISC0`**. It does not identify that address as an SRAMROM security-control register. [GitHub](https://github.com/cyrozap/mediatek-lte-baseband-re/blob/master/SoC/common/usbdl.py?utm_source=chatgpt.com)

That source’s reset flow also uses separate control registers outside your reported four-byte whitelist. A mode-request register does not establish that a device’s ROM will honor the request when download entry is disabled.

Accordingly, I would pursue two separate offline questions:

- Correctly identify `0x1001a080` and its reset semantics in your binaries.
- Determine whether your trusted firmware’s **actual SRAM permission initialization** matches the vulnerable configuration or its fix.

I would not connect that whitelist entry to CVE-2021-0904 without further evidence.

### Carbonara: relevant to V5, but it starts after a trusted DA1 is accepted

[Carbonara’s authors](https://penumbra.itssho.my/Mediatek/Exploits/Carbonara) describe a DA1 vulnerability affecting both V5 and V6. Their documentation explicitly requires a signed DA1 on fused devices. It does not bypass the initial requirement to load a DA trusted by the device. [penumbra.itssho.my](https://penumbra.itssho.my/Mediatek/Exploits/Carbonara?utm_source=chatgpt.com)

This leaves a conditional question:

> **Is there a legitimate DA1 that your Amazon-provisioned preloader accepts, and does that DA1 contain the relevant vulnerable implementation?**

Until such a DA is identified, I would park the route. A matching MediaTek hardware code, a signed DA from another vendor, or a generic authentication file does not answer the trust question.

Your absence of `seccfg` rules out the bundled unlock command. It does not make every possible use of a Download Agent irrelevant; DA execution and Amazon’s persistent unlock-token mechanism are separate capabilities.

## 8. The Sunstone comparison needs a narrower conclusion

The public [Sunstone unlock script](https://github.com/R0rt1z2/amonet/blob/36ae24e86338f79baa3037c81873bebe133af937/unlock.sh) first requires Android root, then copies and executes a separate `bin/unlock` program with that privilege. Its implementation was not present in the public branch I inspected.

Consequently, the separately published unsigned-DA loader does **not** establish that a factory-state Sunstone has its secure fuse clear. It establishes that the loader expects an environment in which that payload can execute.

There is a directly documented example of why chronology matters: [sprig](https://github.com/R0rt1z2/sprig) gains execution in a privileged boot component, changes the preloader’s security checks in memory, and returns to an insecure USB handshake. Its author expressly distinguishes that later interface from the original preloader interface. This is a counterexample to the factory-state inference, not evidence that sprig or the same primitive works on Trona. [GitHub](https://github.com/R0rt1z2/sprig?utm_source=chatgpt.com)

The useful Sunstone research question is therefore **what its initial root-side program accomplishes**. Porting the later unsigned-DA transport does not reproduce that prerequisite.

Two smaller terminology corrections also matter when sorting potential vectors:

- **CVE-2020-0069 concerns the MediaTek CMDQ driver and `mtk-su`**, rather than Kamakiri’s BootROM vulnerability. Correcting the attribution does not restore Kamakiri’s missing BootROM entry prerequisite. [Quarkslab's blog](https://blog.quarkslab.com/cve-2020-0069-autopsy-of-the-most-stable-mediatek-rootkit.html?utm_source=chatgpt.com)
- **Heapbait/`heapb8` targets V6 DA2**, rather than BootROM. Its published protocol and stage are the reasons to deprioritize it for your V5 target. [R0rt1z2](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/?utm_source=chatgpt.com)

Finally, I would narrow two risk statements in the post. A disconnect/dead-loop routine describes a terminal state for that execution; it does not inherently establish permanent damage. A repeatedly rejected on-disk LK can make that failure recur after every reset. Likewise, IDME error paths do not establish that arbitrary IDME edits are low risk. Your existing no-write rules remain appropriate for this investigation.

## What I would validate next

I would spend the next research session on these three concrete questions, in order:

1. **Does your installed preloader use the same two distinct RSA moduli and the same LK signed region as the historical images?** Compare hashes and call sites, especially the modulus immediately before your reported unlock modulus.
2. **Which leading-header fields affect LK loading, and what constrains them before copying or verification?** This is the strongest newly grounded implementation audit.
3. **Does LK independently gate the boot-time `dev_flags` and `fos_flags` consumers?** This is a small, bounded question that could yield a useful repair result even without a full unlock.

After those, I would compare the reachable preloader USB implementation against the vendor-listed flaw classes and use the historical LK corpus to identify meaningful code changes.

**The evidence now supports a more precise conclusion than “only Amazon’s private key can help”: the intended authorization mechanism is cryptographic, the generic public recipes you examined are blocked, and several specific implementation questions remain open.** The historical Trona images and their verified signature boundaries give you a concrete way to investigate those questions entirely offline.