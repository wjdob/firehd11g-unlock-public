> **Editorial preface, added 2026-10-06, not part of the original document.**
> The text below is external research correspondence reproduced **verbatim**, and it has
> no title because it is a reply in an ongoing thread. Its central lead has since been
> pursued to a conclusion, so read this preface first.
>
> **What it argued.** The strongest new lead was the `atf_dram` sub-image, because it is
> loaded *after* LK has already been authenticated: its **copy length** comes from the
> unsigned outer container header, while its **authenticated length** comes from a
> separate inner header. The destination sits below LK in RAM. Hence a specific
> question, can a later, validly authenticated component's oversized outer transfer
> change the **already-verified** LK before execution?
>
> **Where it landed; a real defect, and still not an unlock.**
>
> - The structural claim was **confirmed**. `tee.img` is three separately wrapped
>   components (`atf`, `atf_dram`, `tee`); copy and verify genuinely read different
>   fields, and **no equality check exists between them**. Re-verified
>   cryptographically against this project's own images, and against the installed
>   `tee1`/`tee2` dumps, which match the OTA image byte-for-byte. See
>   [README.md](README.md) §"ATF_DRAM" and
>   [verify-tee-signature.py](verify-tee-signature.py).
> - **The geometry only closes under conditions this project forbids.** Enlarging
>   `atf_dram`'s outer length past `0x1a00000` moves the `tee` container beyond its
>   partition into `metadata`, and the bytes that land on LK are not attacker-chosen by
>   default. It needs boot-critical writes with a single 4-byte error being
>   unrecoverable.
> - **And the decisive blocker, found later:** the `atf`/`atf_dram`/`tee` bodies are
>   **encrypted**: 2.8 MB at exactly 8.000 bits/byte, and decrypt with efuse-derived
>   keys via the hardware crypto engine, reachable only over BROM, which is closed on
>   this unit. So what an oversized tail decrypts to, and whether ATF re-validates LK
>   after handoff, are **unverifiable offline**. This vector is a documented dead end,
>   not an open lead. See [README.md](README.md), "Open questions closed" §C.
> - **§5 also corrected this project's own errors**, which is why it is kept: an earlier
>   draft had claimed the overlap guard "tests the destination, never the length" and that
>   every nested header uses the `0xffffffff` sentinel. Both were wrong, and both
>   corrections were adopted.
>
> **Net:** a genuine structural defect in the container format, correctly identified,
> pursued to the limit of what static analysis can reach, and blocked by encryption
> rather than by misunderstanding. It is worth reading as a worked example of the
> method, advance the lead, then check whether it is *usable*.

The strongest new lead is the atf_dram sub-image loaded after LK has already been authenticated. In the firmware I examined, that later load gets its copy length from the unsigned outer container, while its authenticated length comes from a separate inner header. Its destination is below LK in RAM.

That combination gives you a specific unresolved question: can a later, validly authenticated component’s oversized outer transfer change the already-verified LK before execution?

I have high confidence in the supporting code observations in the historical firmware, and medium confidence in this as a candidate for your device. It is not a demonstrated unlock.

Your PICACHU tracing still closes that particular saved-context target. The new lead concerns a different component, a different destination, and a different authentication path.

Evidence scope

I read the updated README.md and independently examined the Trona PS7319/1726 preloader, LK, and TEE images extracted from Amazon’s historical OTA package.

The attachment contains your analysis, not your installed binaries. Consequently, the observations below need comparison against your installed images. Matching function offsets are encouraging, but they do not establish binary identity. All code offsets below are file offsets in PS7319/1726, unless explicitly described as RAM addresses.

My priorities would be:

Priority Research direction Assessment

1 Later ATF_DRAM copy versus its inner authenticated extent Strongest candidate: confirmed length separation and relevant boot order in the historical image
2 get_img_size continuation scanning: 32-bit accumulated size versus 64-bit flash position Concrete omission from the LK length argument; still needs a useful write effect and feasible source layout
3 Ownership and lifetime of the cached TEE reservation state Real, exercised path, but substantially constrained by a signed reservation-size check


All of this work was offline. These findings do not justify relaxing your existing no-write rules.

1. Highest priority: examine the later ATF_DRAM load

The TEE partition contains three separately wrapped components

The historical tee.img is not one outer header followed by one payload. It contains:

Outer-header offset in tee.img Component Stock outer payload length Destination

0x00000 atf 0x13c00 Caller supplies RAM address 0x00100800
0x13e00 atf_dram 0xda00 Caller supplies RAM address 0x54600000
0x21a00 tee 0x2b6000 Selected through the TEE reservation helper


The third header also provides an immediate correction to the stock-header survey:

tee outer header +0x28 = 0x08c00000
tee outer header +0x2c = 0

It does exercise the reservation branch at 0x26064. The sentinel values in the first ATF header do not describe every nested header.

LK is authenticated before these loads

The preloader sequence is:

Operation File offset

Load LK 0x19d2e
Authenticate LK 0x19d62
Save LK’s entry address 0x19d72
Enter the chained ATF/TEE loader 0x19dc2 → 0x195e4
Load ATF_DRAM 0x1968e → 0x200f4
Authenticate ATF_DRAM 0x196ce → 0x26034
Load and authenticate TEE 0x196fc, 0x19716


ATF_DRAM’s default destination comes from the literal at file offset 0x1974c:

ATF_DRAM destination: 0x54600000
LK destination:       0x56000000
Distance:             0x01a00000 = 26 MiB

This changes the geometry of the problem. The copy under investigation begins below an image that has already passed authentication. You no longer need the LK copy itself to reach a useful object above its own window.

The copy and authentication use different lengths

This is the most consequential finding.

The shared loader at 0x200f4 uses the unsigned outer header’s hdr[4] as the transfer count. For ATF/TEE, the verification path then does the following:

Function Relevant behavior

0x26034 Replaces the caller’s size argument with the cached TEE reservation-size value
0x2bc08 Checks the inner header’s reservation field at +0x23c, then enters the cryptographic verifier
0x2b9cc Obtains the authenticated extent from the inner header
0x2ba92–0x2ba9c Computes that extent as inner [0x08] + [0x18]


Thus, the relevant contracts are:

\[
\text{copy extent}=\text{outer container’s declared payload size}
\]

\[
\text{authenticated extent}=\text{inner header size}+\text{inner body size}
\]

These values agree in the stock files:

Component Inner header size Inner body size Authenticated total

atf 0x240 0x139c0 0x13c00
atf_dram 0x240 0xd7c0 0xda00
tee 0x240 0x2b5dc0 0x2b6000


I found no check enforcing that equality in the examined loader, chained-loader, or authentication functions.

I also independently verified all three stock signatures using the public modulus at preloader 0x388f0: RSA-2048-PSS, SHA-256, MGF1-SHA-256, salt length 32. The signature occupies inner [0x13c:0x23c], which is zeroed for hashing. The verification succeeds over the inner-header-derived extent.

That establishes the signature boundary with actual bytes, rather than inferring it from function names.

Why this could matter for unlocking

Your enlarged-LK argument says that extending the LK copy also moves the expected LK tag and signature, causing rejection. That reasoning does not establish the same result for ATF_DRAM.

Here, the hypothesis is:

> A later outer transfer has effects beyond its authenticated inner component, potentially including changes to LK that was authenticated earlier.



The inner ATF_DRAM signature could remain valid while bytes beyond its authenticated extent have already been copied elsewhere. Successful authentication would then say nothing about those additional effects.

Post-verification processing does not immediately close this gap. The decryption path uses the inner body length and shifts that body down to the original image base. For stock ATF_DRAM, that is 0xd7c0 bytes. It does not inherently clear an excess tail from a larger outer copy.

The broader boot-order idea has precedent: Koboreru’s implementation explicitly relies on the preloader authenticating stock LK before the TEE stage, then replacing LK in memory afterward. That is useful corroboration for examining this ordering, but it is not evidence that Koboreru’s specific entry technique transfers to MT8183. 

The remaining conditions are concrete

I would concentrate your next offline pass on these four questions.

1. Does the installed build bound the complete ATF_DRAM transfer before it can reach LK?

In the examined shared loader, the explicit overlap check protects g_dram_buf around 0x44800000. An ordinary, non-wrapping interval starting at 0x54600000 and extending through LK does not intersect that protected region.

I did not find a separate ATF_DRAM reservation-capacity comparison or LK-overlap rejection in the listed functions. Hardware permissions still need checking. In particular, the boot flow invokes the EMI configuration helper at 0x177f0 before loading LK; its programmed permissions are a precise remaining target.

2. Can the following authentic TEE still be found?

This is a significant constraint, not a detail to defer.

The chained loader uses the recomputed outer sizes to locate the next component. If \(A\) is the first ATF payload span and \(D\) is the ATF_DRAM payload span, it seeks the following TEE header at:

\[
A+D+0x400
\]

The calculation occurs at 0x196ba–0x196fc. Increasing the ATF_DRAM outer span therefore changes where TEE must be found. A larger copy alone does not establish a bootable sequence.

3. Which source bytes would actually reach LK?

Work out the source-to-destination mapping using the real partition layout, including the consumed outer headers. An oversized transfer is not automatically a write of chosen values.

Also, the README’s statement that recovery/cache are unwritable “while locked” needs a narrower basis. Locked fastboot policy and Android root’s access to raw block devices are separate mechanisms. Neither should be inferred from the other; this is a capability question to establish independently, without a write experiment.

4. Does the affected LK survive through handoff and execute?

I found no direct LK re-verification in the examined preloader path after the chained loads. The final path retrieves the saved LK address at 0x1a00c and passes it through 0x19800 → 0x26324 into the ATF handoff structure.

I have not completed the ATF-side boot-path audit. A later check, reload, protection fault, or cache interaction could still invalidate the hypothesis.

This is the candidate I would pursue first alongside your USB audit. It supplies a reachable later copy, a useful relative destination, and an independently authenticated length.

If it eventually works, its immediate result would be an execution-path bypass. It would not manufacture an Amazon-valid IDME unlock token; persistent behavior would require the bypass to remain reproducible across boots.

2. Reopen the LK size argument specifically for continuation scanning

There is another substantive gap in the updated length analysis.

In this preloader, get_img_size at 0x2b260 is a multi-image scanner, not merely a rounding operation applied to one header.

Its output really does become LK’s verification size

The dataflow is:

1. The shared loader writes the raw copy count through its size-output pointer at 0x20274–0x20278.
2. It passes that same pointer to get_img_size at 0x202e2.
3. get_img_size zeroes and recomputes the output.
4. The main boot flow reads that result at 0x19d60 and passes it to LK authentication at 0x19d62.

The recomputed result is therefore not just bookkeeping for locating another image.

The scanner uses different integer widths

After finding the initial named image, the function:

- Adds its aligned payload length to the returned size.
- Advances the flash position by the payload span plus the outer header.
- Examines subsequent headers.
- Accepts a continuation according to the high byte of the parsed field at outer +0x3c.
- Adds each continuation’s header and aligned payload span to the result.

The accumulated verification size uses 32-bit arithmetic. The flash cursor advances with 64-bit arithmetic.

An abstract model is:

\[
V=\left(A_0+\sum_{i=1}^{k}(512+A_i)\right)\bmod 2^{32}
\]

Here, \(V\) is the returned verification extent and \(A_i\) are aligned payload lengths.

The precise offline question is:

> Can an accepted continuation sequence make the returned extent identify the original authentic LK, despite a larger initial copy?



That case is not addressed by reasoning about a single rounded hdr[4].

There is a useful distinction here: the scanner reads headers at computed flash positions. Advancing its cursor across large declared spans does not require copying every intervening payload into RAM.

Nevertheless, this remains behind ATF_DRAM in priority. You still need accessible header positions, correct error propagation, preservation of the authentic LK bytes, and a useful consequence of the initial copy. It does not reopen the PICACHU target whose contents are overwritten before use.

Changing alignment alone looks unproductive

The extended-header parser permits an alignment unit up to 0x1000.

For a positive unit and ordinary arithmetic, rounding cannot turn a larger copy into a smaller authenticated extent. The examined arithmetic-overflow and zero-unit cases yield a zero aligned extent, rather than the positive size needed for the authentic LK.

So the lead is continuation accumulation, not simply trying different alignment values.

3. The reservation helper is real, but its signed constraint matters

The README’s conclusion that the destination is not header-controlled is too strong.

In 0x200f4, a zero mode and non-sentinel outer parameter reach 0x26064. The returned address becomes the actual copy destination and is written back to the caller at 0x2026e. The branch itself contains no TEE-only component-name restriction.

However, this is constrained allocation, not an arbitrary-address primitive.

The helper splits the parameter into a rounded reservation size and a low-18-bit remainder, reserves an aligned region, and caches the result. Once initialized, later invocations reuse the cached state rather than recomputing it from their new parameter. That state also feeds verification policy and later memory-protection setup.

This makes the identity of the first component to initialize it worth tracing.

There is also a substantial limiting check:

- The inner TEE header contains reservation size 0x08c00000 at +0x23c.
- That field lies within the authenticated extent.
- 0x2bc08 compares it with the cached reservation size.
- Stock ATF and ATF_DRAM instead contain the accepted wildcard 0xffffffff.

Consequently, a simple “change the reservation size and bypass verification” theory is not supported. I would include this state-lifetime audit within the chained-image review, while keeping ATF_DRAM’s outer/inner length separation as the main candidate.

4. Corrections worth making before drawing another closure conclusion

Several details in the updated notes should be corrected because they affect subsequent reasoning.

Current statement What the historical binary or arithmetic supports

The pre-copy overlap guard checks the destination, “never the length” It loads the length at 0x201da and computes destination + length at 0x201e2. It protects a particular interval; it is not a general capacity check.
The ordinary LK verification-size output includes its leading 0x200 header The returned stock extent is 0x938f0. The file size is 0x93af0; the signed data length is 0x937f0. The initial 0x200 advances the flash cursor.
Every shipped nested header uses the address sentinel The historical third, tee, header contains 0x08c00000, with mode zero.
g_dram_buf is 2.5–40 MB below LK 0x56000000 − 0x44800000 is 280 MiB.
The LK-window end to framebuffer gap is about 11.8 MB 0x624e0000 − 0x56900000 is 187.875 MiB.
0x89c00000 demonstrates a 32-bit wrap That address itself is below \(2^{32}\); the stated wrap needs a separate derivation.


The source-to-RAM table should also account for the outer header being consumed rather than copied: a source offset measured from the beginning of the container includes that 0x200 displacement.

These corrections do not overturn your PICACHU write-before-use result.

I also checked the earlier IDME-flags question. In the historical LK, the relevant consumers call 0x2c0e4, which checks the locked-production predicate through 0xdcde. The restriction exists at consumption time as well as in the command handler. That closes the direct-flags idea for this build without requiring a live flag write.

Finally, I would keep the vulnerability labels precise. CVE-2023-20695 concerns a specific cert2 size-check/copy mismatch producing a 0x200 overflow. It is an analogous failure class, but it does not identify or establish the Trona behavior described here. 

Reproducibility and the next focused question

These are the exact historical inputs used for the offline observations:

PS7319_1726_preloader.img, 248,540 bytes
SHA-256:
62fc05e197289cebcdd235417e2b7b452dfa93671a140ee5b5afe86477ec3ce7

PS7319_1726_lk.img, 604,912 bytes
SHA-256:
ca027c283fad9c469380ef094746ae0134cceded354d3d160a2d1ce365782fb6

PS7319_1726_tee.img, 2,980,864 bytes
SHA-256:
c34e2aea1ccc81eb24fa3ea5953dbefaf9958389f1dfb6a3f2008bcad5416a80

The next disassembly question I would put at the top of your notes is:

> On the installed build, what prevents the complete outer ATF_DRAM transfer from modifying already-authenticated LK, while authentication and decryption remain limited to the original inner ATF_DRAM image?



The relevant path is 0x195e4 → 0x200f4 → 0x26034 → 0x2bc08 → 0x2b9cc, followed by the next-component calculation and final handoff. An enforced transfer bound or later LK check could close it. In their absence, the remaining work becomes a concrete source-layout and memory-lifetime analysis, without needing to challenge RSA-PSS or obtain Amazon’s private key.

I would keep the overall investigation open. Your audit supports several useful negative results, but I found three concrete reasons to narrow its conclusion:

1. The USB reader does not impose a cumulative limit that makes the 70 MiB gap unreachable.
2. There is an additional read call through a cached vtable, so the four-pattern scan is not a complete call-site inventory.
3. SEND_DA has a separate length-subtraction issue that the READ32/WRITE32 checks do not address.

There is also an important obstacle that strengthens the negative assessment of the oversized USB transfer: the rejection path clears the entire supplied receive range before entering a non-returning panic path. I have not found a useful target consumed before that clearing.

My assessment remains: no demonstrated unlock, but the evidence does not establish that all software avenues are closed. The ATF_DRAM candidate from my previous response remains the highest-priority lead.

Scope of this cross-check

I independently traced these paths in the same historical PS7319/1726 preloader extracted from Amazon’s OTA package:

SHA-256:
62fc05e197289cebcdd235417e2b7b452dfa93671a140ee5b5afe86477ec3ce7

The offset-level findings below are my own offline binary analysis. They still need comparison with your installed image; the matching version family and offsets do not substitute for a hash or function-byte comparison. No device writes or crafted test images were involved.

1. The 70 MiB separation is not a transfer bound

Your observation about the fixed destination is correct:

DA destination:      0x40200000
g_dram_buf:          0x44800000
Separation:          0x04600000 = 70 MiB

What does not follow is that the transfer can only reach unused DRAM.

The underlying reader retains the full host length

The callback invoked at 0x5754 resolves to the USB reader at 0x17cb4. It maintains:

Register Meaning

r6 Advancing destination
r5 Remaining 32-bit byte count
r7 Timeout argument


Its loop copies a chunk, subtracts that chunk from the remaining count, advances the destination, and repeats:

0x17cfa  compare available bytes with remaining count
0x17d00  cap the current chunk to the remaining count
0x17d04  drain that chunk
0x17d08  remaining -= chunk
0x17d0a  destination += chunk
0x17d0c  repeat while remaining != 0

The eventual destination write is a CPU byte store at 0x4c62, reached through 0x287b4 → 0x4c40.

The small receive buffer and its 0x200-scale checks limit buffer occupancy and individual chunks. They do not limit the aggregate number of bytes streamed into the destination.

SEND_DA disables this reader’s timeout

The handler supplies r2 = 0 at 0x5744. The reader treats zero as disabling its elapsed-time check. Its polling path also refreshes the watchdog through 0x211e4 → 0x289ac.

Consequently, I found neither an aggregate DA-window limit nor a fixed overall receive deadline in this path.

That establishes a narrower, useful result:

> The inspected software permits a declared transfer extent that reaches g_dram_buf, without address wrap.



Actual memory permissions, DRAM accessibility, and runtime behavior remain to be established. The subsequent checksum loop also has its own timing considerations. This is not a claim that such a transfer has been demonstrated on your device.

g_dram_buf is already live at USB entry

This is not merely a buffer that will be initialized much later:

- Platform initialization calls 0x5c34 at 0x21a86, establishing g_dram_buf.
- USB command entry occurs afterward at 0x19a22.
- SEND_DA itself calls 0x21164 at 0x573e, storing DA-related metadata at g_dram_buf + 0x81978 through +0x81988.

Therefore, the reach argument cannot be closed by saying that the first known working allocation is 70 MiB away.

The literal survey is also insufficient to establish a live-memory map. For example, the 0x42200000 occurrence at file 0xb354 is used as a register value in a masked read/modify/write operation, rather than as an owned RAM-object address.

2. The real obstacle is target lifetime and cleanup

This is where the USB path becomes substantially less promising.

The obvious control and authentication targets are below the write

The independently resolved runtime locations include:

Object Runtime address

DA acceptance flag 0x00115761
Active USB transport pointer 0x00115764
g_dram_buf pointer variable 0x00115768
Receive-ring structure 0x00116d40
RSA modulus working buffer 0x001177c4
Modulus-initialized byte 0x001178c4


Those objects are in SRAM, below the DA destination. The active stack and code are also below it.

Your direct-trampoline conclusion therefore stands: an ordinary, non-wrapping forward copy from 0x40200000 cannot overwrite the slot at 0x401ffff4.

The distinction is between reaching some live DRAM state and reaching a useful control or authentication target. I established the former in the software’s address model, but have not established the latter.

An oversized receive is followed by a full-range clear

The secure-device completion path performs:

1. The receive.
2. A checksum over the supplied length.
3. Secure-chip and key-context handling.
4. The 0x120000 size check.
5. Rejection of an oversized length.
6. A clear of the original destination using the original host length.
7. Panic.

The clearing sequence is explicit:

0x590a  r1 = 0
0x590c  r2 = original host length
0x590e  r0 = original DA destination
0x5910  call clear routine

The failure call at 0x5920 reaches 0x216c0 → 0x21670, which ultimately ends in the self-branch at 0x216b4. There is no normal return from that path into the later acceptance-flag assignment.

This changes the useful research question to:

> Which reachable object is consumed during the receive, during the checksum/key setup, or before the rejection clear destroys the supplied values?



I did not find a useful consumer in the normal completion-to-rejection path. In particular, I did not find the reachable DA metadata being used there to redirect execution or change the acceptance decision.

That is a meaningful negative result. The defensible closure is currently “no useful consumed target identified”, rather than “the copy cannot reach working memory.”

3. The four-site scan misses a concrete fifth read

There is another call through the same read interface in the handshake code. It caches the transport table first:

0x55ac  ldr.w sb, [r7, #8]     ; cache transport table

Then it invokes the read member later:

0x55c8  movs r1, #1            ; fixed length
0x55ca  ldr.w r3, [sb, #4]     ; read callback
0x55ce  mov r0, r5
0x55d0  mov r2, r1
0x55d2  blx r3

This read is fixed at one byte. It is not another overflow finding.

Its significance is that it does not match the adjacent two-load idiom used by the scan. It is a concrete counterexample to the claim that the pattern inventory proves every read call has been found.

I would describe the scan’s result as an inventory of occurrences of that encoding. A complete USB input audit additionally requires following the callback target through cached pointers and wrappers, plus separately accounting for the lower driver and control-request processing.

This does not mean those other paths are vulnerable. It means the completeness claim requires a broader method than the one reported.

4. There is a separate SEND_DA subtraction issue

First, the CVE distinction matters: CVE-2022-20073 is classified by MediaTek as integer underflow in preloader USB, whereas CVE-2022-20069 concerns integer overflow. MT8183 appears in the published affected-chipset lists. The multiplication and address-containment checks in the memory commands do not, by themselves, close subtraction involving DA lengths. 

I found an actual subtraction to examine in this binary.

The missing relation check

At 0x5876, the handler computes:

body_length = total_length - sig_len

I did not find a preceding check establishing:

total_length >= sig_len

The wrapper at 0x255a4 requires the signature length to equal 0x100. That enforces the expected RSA signature size, but it does not establish that the total received length is at least that size.

The wrapped value reaches hashing

The resulting body length is passed through:

0x58a6 → 0x255a4 → 0x2b108

At 0x2b16a–0x2b170, it is forwarded to the hash path. The later helper at 0x2c4fc chunks the input and maintains a 64-bit source cursor.

The observed consequences of the missing relation check are therefore potentially:

- A greatly enlarged hardware-hash input extent.
- A signature pointer below the ordinary DA base.
- A hardware error or hang.

I have not established an authentication bypass or an out-of-bounds write from this condition. If hashing completes, the ordinary RSA/PSS validation still follows. This may ultimately be only a malformed-input failure.

It also should not yet be labelled as the exact implementation of CVE-2022-20073: the vendor’s published description identifies an out-of-bounds write, and I have not demonstrated that consequence here or matched the relevant patch.

Nevertheless, it is a separate, concrete arithmetic path that the reported READ32/WRITE32 review does not cover.

A smaller correction to the multiplication proof

The reported comparison:

count < (count * 4 modulo 2^32)

is not independently a complete multiplication-overflow detector. Some overflowing products still exceed the original count.

However, the combination of that comparison with containment in a tiny allowlisted window can still exclude overflowing counts. An overflowing multiplication requires a very large count, while the combined comparison and window size force it to be small.

So I would preserve the likely negative result for those memory commands, while changing “two independent overflow guards” to “the combined arithmetic and containment checks exclude the examined cases.”

5. What this changes in the research ranking

The USB audit does not resolve the ATF_DRAM issue from my previous response. That path concerns:

- LK being authenticated first.
- A later ATF_DRAM copy starting below LK.
- An outer transfer count separate from the authenticated inner extent.
- Whether that later copy can affect LK before handoff.

None of those conditions depends on SEND_DA, the USB memory-command allowlist, or the DA acceptance flag.

I would retain this ranking:

Direction Current assessment Specific question that would advance or close it

ATF_DRAM outer-copy versus inner-authenticated extent Highest priority; medium confidence as a bypass candidate Does the installed build prevent the complete transfer from affecting already-authenticated LK, and does the subsequent component layout remain coherent?
Oversized SEND_DA transfer Copy-before-bound confirmed; transport reach not limited by the stated distance; no useful target established Is any reachable state consumed before the full-range clear or during the transfer?
DA total-length/signature-length subtraction Missing relation check observed; oversized hash input possible; no unlock impact established Does the complete hash/error path turn this into anything beyond rejection or a hang?
Direct overwrite of the below-base trampoline Closed for an ordinary forward copy No change from your result
Inspected PMIC operations and memory-command allowlists Your local negative results remain useful Preserve their precise scope rather than treating them as a whole-stack proof


I would also adjust the final “hardware only” wording. Carbonara’s documented prerequisite is an accepted signed DA1 on a fused device; that is a loader-acceptance prerequisite, not by itself a requirement for a hardware attack. CVE-2021-0904 is described as insecure SRAMROM permission configuration requiring system privileges, rather than as a fault-injection technique. Neither source proves applicability to this Amazon build. 

For the next pass, I would spend the effort on the ATF_DRAM path. The USB cross-check supplies useful corrections and one additional input-validation issue, but it has not supplied a convincing control-flow target. The later ATF_DRAM load still has the more direct relationship to your goal: it may affect the image whose authentication has already succeeded.