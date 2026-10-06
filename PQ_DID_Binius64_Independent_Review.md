# PQ-DID: independent review of the Binius64 G0 handover

Date: 29 September 2026  
Review type: retained-source inspection and mathematical analysis; no native execution

## Decision

**Retain the pause on private authentication using the inspected Binius64 revision. G0's principal reasons are supported by the supplied source.** The two immediate problems are distinct: a private-witness-dependent terminal opening target is transmitted in plaintext, and the original witness codeword is opened without the randomisable support required by the Blueprint. Correcting only the terminal send would leave the second problem intact.

This conclusion applies to the pinned implementation and its proposed use. It is not an impossibility result for PQ-DID, for Binius generally, or for a corrected construction. It does not demonstrate recovery of a particular KYC credential or holder secret. No replacement construction has been validated by this review.

The functioning ML-DSA baseline, durable KYC lifecycle and recorded measurements remain useful, separate results. They do not supply the missing private authentication proof. The original project scope and 31 October target are unchanged; this review provides no basis for promising complete private authentication by that date.

## 1. Evidence and verification

The reviewed archive is `binius64-g0-handover-v1.tar.xz`:

- Size: **1,065,684 bytes**.
- SHA-256: `17a0ac8fd32038e6530254e4cd27610c8a76e76aba53f446986e435845262f8e`.
- All **112 archive members** had safe relative paths and were regular files; no duplicate member names were found.
- All **110 listed payload checksums**, lengths and file-list entries matched the extracted bytes. The two inventory/checksum files are outside their own payload list.
- All **46 source-map entries** matched their retained hashes. All **42 entries with Git blob identities** matched both their computed Git blob hashes and the supplied recursive tree's path, size and blob identity.
- The retained commit metadata associates commit `441fbf51ff0bcb0bcd28f3f1b73f4954029e8577` with tree `544452a781fee0f9b262d4ecfdcc47326fb6974f`.
- The retained Blueprint PDF matched SHA-256 `0dfdfd2fb8066842e0c0914901930b6b4f276284983838ad40ff0f2e8f0d9803`. Its printed pages 42–44, including the masking equations, were also inspected visually.

These checks establish consistency of the supplied handover. They are not independent authentication of the upstream repository or a reproducible-build check. The archive contains selected source snapshots, not a complete checkout and dependency closure. The native NTT internals and the full IntMul auxiliary-oracle implementation were not available for a complete trace.

No source patch, build, application test, benchmark, prover execution or proof verification was performed. The user's WSL repository and its resource/proof ledgers were not modified. Only manuscript Sections II–VIII and agreed clarifications remain authoritative; this is a backend review, not a fresh verification of the manuscript's security theorems.

## 2. Findings checked against the source

Source paths below are paths in the pinned upstream repository. The handover's `source-map.json` maps them to retained files.

| Finding | Independently inspected evidence | Assessment |
| --- | --- | --- |
| Ordinary inner messages receive one-time pads | `crates/spartan-prover/src/wrapper/zk_wrapped_prover_channel.rs`, `send_one` | Present. It adds a precommitted key before forwarding the value. This does not cover all messages. |
| Terminal opening target bypasses that encryption | Same file, `prove_oracle_relation`; `crates/spartan-verifier/src/wrapper/zk_wrapped_channel.rs`, `verify_oracle_relation` | Confirmed. The prover forwards `claim` directly. The verifier reads it as a public/inout value and checks equality to its internally computed claim. |
| Inner packed witness has no fresh blinding support | `crates/prover/src/prove.rs`, `IOPProver::prove` and `pack_witness` | Confirmed for this path. Non-public words are packed deterministically and padded with zeros. The wrapper delegates the buffer unchanged. |
| The companion mask does not randomise that original row | `crates/iop-prover/src/fri/encode.rs`, `encode_masked`; `crates/math/src/reed_solomon.rs`, `encode_batch` | Confirmed at the retained implementation/API boundary. The unchanged message and an independent mask are concatenated and encoded as independent interleaved vectors. |
| Original query values are sent to the verifier | `crates/iop-prover/src/fri/query.rs`, `BrakedownOracleProver::open_queries`; `crates/iop-prover/src/merkle_channel.rs`, `send_openings` | Confirmed. The query path opens the original committed buffer; the Merkle channel serialises every scalar in each selected leaf. For this ZK encoding, the leaf contains both original-row and mask-row symbols. |
| Public statement observation is present | `crates/prover/src/prove.rs`, `observe_words`; `crates/prover/src/zk_config.rs`, prover/replay setup; corresponding verifier callers | Present in the inspected path. The privacy findings should not be reported as an absence of public-input transcript binding. This is not a complete adversarial test of context binding. |
| Native affine masking differs from Blueprint notation | BaseFold prover and verifier channels | Confirmed. Native code uses `(1−γ)π + γω`; the Blueprint describes `π + αω`. A conditional algebraic correspondence exists, but a complete transcript/security transfer is still needed. |

### Plaintext terminal target

The ring-switching reduction produces an opening relation of the form

\[
s=\langle\pi,T\rangle,
\]

where `π` is the packed hidden witness and `T` is determined by public challenges. The wrapper's ordinary `send_one` encrypts a field value, but `prove_oracle_relation` calls the underlying channel's `send_one(claim)` directly. The verifier explicitly places the received value in its public segment.

The outer proof therefore certifies consistency of the revealed value; it does not hide it. Later BaseFold masking cannot remove this earlier observation from the verifier's view. This differs from the terminal-target masking prescribed in Blueprint §§7.1 and 7.3.

A witness-dependent observable alone is not a proof that every relation instance leaks a recoverable secret: the distribution must be considered for the actual public statement and witnesses. G0 appropriately avoids that stronger claim. Nevertheless, this source path does not implement the generic hiding transformation being invoked to justify its use.

### Original codeword openings

The mask row addresses a different part of the protocol. Sending a pair

\[
\bigl(E(\pi)[j],E(\omega)[j]\bigr)
\]

does not encrypt the first element. Both elements are available to the verifier. The Blueprint explicitly separates hiding original query symbols through randomisable support from hiding folded messages through a companion codeword.

The retained `encode_masked` routine supplies the companion mask. It does not insert fresh randomness into `π`. The inner packing path supplies no such randomness either. Outer IronSpartan code does have a separate blinding routine; its existence does not randomise the inner packed witness.

Original positions are obtained by shifting the global index by the oracle's lift. There are at most `q` distinct original positions for `q` sampled indices, after collisions and lifting. Later FRI folding arity must not be used to multiply this count. Folded openings and terminal data remain additional, correlated parts of the complete view.

## 3. A mathematical check independent of the report's wording

The following argument explains why the query issue matters without claiming an executed attack.

Suppose a fixed public statement admits two known valid witnesses with distinct packed messages `π₀` and `π₁`. Suppose the advertised encoder is a length-`N`, dimension-`k` Reed–Solomon encoder, and an interactive verifier samples a fresh uniform original position `j`. These are explicit assumptions for this argument, not measured native parameters.

The two distinct encoded messages differ at at least `N−k+1` positions: the nonzero difference polynomial has degree below `k` and at most `k−1` roots. A verifier that sees the original-row symbol can identify which candidate witness was used at every differing position. Guessing otherwise gives success probability at least

\[
\frac12+\frac{N-k+1}{2N}.
\]

The separately revealed independent mask row does not reduce this distinguishing information. A change of polynomial basis does not change this minimum-distance argument, provided the advertised Reed–Solomon encoding contract holds.

**Limits:** this is a conditional witness-distinguishing argument in the stated interactive model. It is not a numerical attack estimate for the native Fiat–Shamir transcript, an executed example, or proof that a selected PQ-DID statement has those two witnesses. The missing native transform internals and the actual challenge distribution were not independently validated here. It strengthens the reason to reject a generic zero-knowledge claim for this path; it does not justify claims of full secret recovery.

## 4. What a repair must establish

### Query-support condition

For fixed public coefficients, write a proposed oracle as

\[
\Pi=Jw+Ur,\qquad r\mathrel{\leftarrow}\mathbb F^d,
\]

with uniform independent randomness. Let `E` include the actual encoder and its permutations, and let `Q` be the distinct queried positions. The observed linear part is

\[
Y_Q=E_QJw+E_QUr.
\]

For valid witnesses `w,w′`, these observations have the same distribution precisely when

\[
E_QJ(w-w')\in\operatorname{im}(E_QU).
\]

This follows directly from uniformity on a linear image and equality of its affine cosets. Full row rank of `E_QU` is sufficient for uniform query symbols, but not necessary for every restricted relation. Counting `q+1` or `q+2` random coordinates does not by itself establish the condition.

The implementation must also preserve the original relation. Semantic opening operands must annihilate the blinding subspace. Existing zero padding cannot simply be replaced by randomness while keeping a ring-switching identity that evaluates those coordinates. Additional revealed linear quantities must be analysed together with shared randomness. Adaptive queries require a sequential simulation argument; a fixed-matrix calculation cannot condition away their dependence on earlier observations.

This calculation does not prove hiding of Merkle roots, authentication paths, nonlinear outer-proof messages or the full transcript. Those require the appropriate commitment and joint simulation arguments. The Blueprint's statement that one extra random coordinate covers commitment hiding is not, alone, an instantiated theorem for these concrete hashes and query budgets.

### Terminal binding condition

G0 correctly rejects merely replacing the plaintext send with ordinary OTP encryption. If an inner commitment uses `kᵢ` while the outer circuit uses an independently unconstrained `kₒ`, checks of the form

\[
c=s_{\rm outer}+k_o=\langle\Pi,T\rangle+k_i
\]

only imply

\[
s_{\rm outer}-\langle\Pi,T\rangle=k_i-k_o.
\]

They do not enforce equality of the intended claims. Opening the keys in plaintext would defeat the purpose. This is a missing local binding condition, not a demonstrated full forgery.

### One concrete alternative worth evaluating

**Research option only — neither implemented nor established secure:** avoid copying a terminal OTP key across two commitments. Instead, give the outer committed witness `z` a designated private coordinate `z_s`. Have the outer constraints enforce that `z_s` equals the inner verifier's computed terminal claim. Then discharge the single joint relation

\[
\langle\Pi,T\rangle-\langle z,e_s\rangle=0,
\]

where `e_s` selects that exact committed coordinate. The public target is zero; neither individual target is disclosed.

The local binding implication is straightforward: if the outer relation and this joint committed-oracle relation both hold for the same extracted objects, then `s_outer = z_s = ⟨Π,T⟩`. It avoids the specific duplicated-key equality problem. It does **not** solve query hiding, prove extraction, or validate the outer proof.

Making this a protocol would require a commitment opening mechanism that handles a cross-oracle linear relation without separately publishing its two targets. The present per-oracle interface does not provide that guarantee. Commitment order, oracle identity, batching challenges, dimensional lifting, the additional observation of `z`, and the complete masking/simulator argument would all have to be specified. A later stage must not silently reintroduce either individual opening value.

This is a concrete algebraic design target for specialist review, not an instruction to patch the current wrapper or adopt a new profile. It also illustrates why equality of two copied keys is a requirement of that particular OTP repair, not the only possible form of a corrected construction.

## 5. Remaining qualifications

- **Exceptional challenges:** away from `γ ∈ {0,1}`, the native affine combination can be rescaled using `α=γ/(1−γ)`. At zero it leaves the original row; at one it leaves only the mask row. Under one ideal uniform draw in `GF(2^128)`, the union probability is `2/2^128`. This local calculation is not an overall security level or a proof of equivalence of the complete transcripts.
- **Outer blinding:** the source includes `q+1` dummy wires and two dummy multiplication constraints. This review confirms that code exists; it does not certify its complete joint distribution, rank properties or finite security bound.
- **Additional relations:** the retained prover and verifier callers explicitly report an IntMul pushforward relation. Its full implementation was not included. The Blueprint's four-oracle/single-inner-opening description cannot automatically be treated as a complete inventory for the native route.
- **Concrete security:** CSPRNG-derived masks, hashes, Fiat–Shamir, extractor/simulator composition, quantum adversaries, finite parameters and the project's adaptive sampler-tail term remain separate obligations. A passing native regression suite would not discharge them.
- **Resources:** a corrected construction needs a new complete resource model. This review did not validate memory, proof size or latency for Binius authentication. More RAM or GPU capacity would not remedy the identified privacy gaps.
- **Standards and lifecycle:** local W3C mappings and genuine ML-DSA baseline results are separate from standards-level interoperability and complete private authentication. No previously unavailable private-proof benchmark becomes available through this review.

## 6. Recommended next action

Do not resume Binius private-authentication implementation from a terminal-send patch or a random-padding guess. Do not spend the remaining proof attempt to test whether a known-incomplete privacy construction happens to verify.

Use this review as the independent assessment of G0. The next substantive deliverable, if this route is funded, should be **one integrated construction result**: an exact oracle embedding and hidden terminal-opening protocol, its relation-preservation and binding argument, its native-encoder query-support argument, and an applicable joint privacy/extraction theorem with explicit remaining assumptions. The joint-zero-target option above is one candidate for its terminal-binding part. It is not yet that integrated result.

That work is best reviewed with the proof-system authors or a cryptographer experienced in these polynomial commitments. No contact or message has been sent. Additional source needed for such a review should be requested specifically—for example the exact NTT/permutation implementation and IntMul auxiliary-oracle path—rather than restarting a broad backend search or another generic review.

Only after that result supports an implementation should Codex receive one consolidated implementation-and-validation package, including a justified resource model. Correctness regressions should then cover the true compiled relation, malformed openings, commitment substitutions, statement/context binding and the exceptional challenges. Statistical-looking output or passing examples must not be reported as a zero-knowledge proof.

Until then, retain the existing baseline and datasets, keep private verification fail-closed, and describe complete PQ-DAA authentication as unimplemented. This preserves the original research goal without relabelling partial work as its completion.

## Source index

The assessment uses the uploaded handover, especially:

1. `README.md`, `file-list.json`, `SHA256SUMS`, `source-map.json`, `missing-evidence.json` and the retained commit/tree metadata.
2. `repo/docs/oct31_binius64_g0.md` and `repo/docs/oct31_binius64_replacement_decision.md`.
3. The retained Blueprint `repo/docs/data/oct31_binius64_replacement_decision_1/sources/spec.pdf`, particularly §§2.3 and 7.1–7.3; printed pages 42–44 for the two masking mechanisms and terminal-target prescription.
4. The prover, verifier, wrapper, encoder, Reed–Solomon and Merkle/query source files identified in the findings table; ring-switching source in the G0 source directory.
5. Outer blinding definitions in `crates/spartan-frontend/src/constraint_system.rs` and implementation in `crates/spartan-prover/src/lib.rs`.

No conclusion about a later upstream revision is made. No missing theorem is replaced by a test result, and no unperformed native experiment is presented as evidence.
