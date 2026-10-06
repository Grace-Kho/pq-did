# OCT31-BINIUS64-REPLACEMENT-DECISION-1

**Decision: NO-GO for the examined revision as a private-authentication replacement.**
The word-level backend is a credible engineering direction, but its implemented
ZK path does not yet match the supplied Blueprint at two privacy-critical boundaries.
Do not adopt it, provision it or admit private witnesses/proofs on this evidence.
This is a decision about this revision, not impossibility of Binius64 or PQ-DID.
The original complete scheme, KYC testbed and benchmarking scope and **31 October**
target remain unchanged; a commitment to full completion by that date is unsupported.

The [conditional implementation proposal](data/oct31_binius64_replacement_decision_1/implementation-proposal.md)
is one integrated plan, with exact blocking gates and a consolidated prospective
budget. It is **not currently ready for private-proof execution**. The concrete user
decision is whether to authorise repair of this named candidate within that plan,
including its explicit experimental security boundary, or decline it. No replacement
is selected automatically and no general backend survey is proposed.

## Identity and source findings

Pinned current source: [`binius-zk/binius64`,
`441fbf51ff0bcb0bcd28f3f1b73f4954029e8577`](https://github.com/binius-zk/binius64/tree/441fbf51ff0bcb0bcd28f3f1b73f4954029e8577),
27 September 2026, root tree `544452a781fee0f9b262d4ecfdcc47326fb6974f`.
The [Blueprint](https://www.binius.xyz/spec.pdf) is dated 15 August 2026,
SHA-256 `0dfdfd2fb8066842e0c0914901930b6b4f276284983838ad40ff0f2e8f0d9803`.
Website source resolves to `37270884e8b7d6cab9e9297c70d7d9901c56f709`, also 15 August.
The PDF was retained and read, not rebuilt; byte-for-byte correspondence to a build
of that website commit is unverified. It is the matching conceptual specification,
not an exact conformance certificate for September code. [Source identities and
acquisition records](data/oct31_binius64_replacement_decision_1/source-index.json)
pin individual downloaded Rust files to the recursive Git tree's blob IDs as well
as SHA-256. No downloaded code was executed.

Rust toolchain is **1.98.1**, edition 2024, workspace 0.1.0. `Cargo.lock` is absent;
workspace versions are semver requirements, not resolved transitive pins.
The [dependency requirements](data/oct31_binius64_replacement_decision_1/dependency-requirements.json)
record exact declared values and required local crates. Prover/verifier, frontend,
field/math, transcript/hash, IOP/IP and Spartan components are required. Examples,
recursion and M4 are not the selected path. Dependencies reachable from the broad
circuits crate must still be resolved even if unrelated examples are not built.
There is no verified acquisition/build lock or compatibility result today.

### Actual ZK path and inconsistencies

All paths below are relative to the pinned repository; retained copies are indexed
above. `crates/prover/src/zk_config.rs::ZKProver::{setup,prove}` and
`crates/verifier/src/zk_config.rs::ZKVerifier::{setup,verify}` select the wrapper,
not the ordinary transparent `Prover/Verifier`. Setup symbolically runs the inner
verifier, compiles its arithmetic into IronSpartan, pads the outer system, and uses
one combined BaseFold compiler. The prover precommits OTP keys, runs the inner
word constraints through `ZKWrappedProverChannel`, replays the verifier to populate
the outer witness, proves IronSpartan, then opens the combined oracles.
`ZKVerifier` also checks the public wiring evaluation natively; this is legitimate
only for its actually public inputs and cannot justify moving PQ-DID secret checks.

| Layer | Source behaviour and specification comparison |
| --- | --- |
| Inner messages | `spartan-prover/src/wrapper/zk_wrapped_prover_channel.rs::send_one` consumes fresh keys and sends `m+k`; outer replay constrains decryption. Comments saying OTP wiring is future work are stale relative to these functions. |
| Terminal private claim **B64-ZK-001** | The same file's `prove_oracle_relation` calls `inner_channel.send_one(claim)` directly and records plaintext. `prover/src/prove.rs` passes the private witness ring-switch `sumcheck_claim` to it. This bypasses OTP `send_one`. Blueprint §7.3 explicitly requires an additional random support coordinate and masked terminal claim. An outer proof checking this clear value does not hide it. |
| Inner oracle **B64-ZK-002** | `prover/src/prove.rs::pack_witness` packs pairs into GHASH elements and zero-pads. The inner path supplies no RNG or query-count support allocation; `oracle_specs(true)` flags masking but does not establish support. `basefold/channel.rs::send_oracle` passes this buffer to `encode_masked`, stores an equal-length independent mask, and commits the interleaved rows. No correspondence argument establishes the Blueprint's **q+2** randomisable coordinates for the inner oracle. Query-opening hiding cannot be inferred from the folding mask. This source gap must be resolved across the encoder/opening implementation before any private admission. |
| Outer IronSpartan | `BlindingInfo::for_fri_queries` adds q+1 random wires and two dummy multiplication constraints; `pack_and_blind_witness` samples dummy operands and products. Degree-2 Libra/MLE-check masking is committed separately. The equality-weighted check, not bare characteristic-two Libra sumcheck, is the relevant Blueprint Theorem 6.3. |
| PCS | `iop-prover/src/basefold/channel.rs` retains message, independent mask, codeword and Merkle commitment for each oracle. It sends mask inner products before sampling gamma, batches claims and opens one combined FRI. Source uses `(1-gamma)pi+gamma*omega`; Blueprint §7.2 writes `pi+gamma*omega`. Away from gamma=1 these relate by scaling and gamma/(1-gamma), but exceptional events, all claim/transcript distributions and extractor behaviour need an explicit correspondence argument; identical protocols must not be claimed. |
| Hashes/parameters | `StdHashSuite` is SHA-256; challenges are GHASH GF(2^128). Both standalone security constants are **96**; `ZKVerifier` uses the Binius verifier's 96 setting. A proposed “128” label is not the current implementation and would not establish overall quantum security. |

`ARCHITECTURE.md`'s “Binius64: No” ZK table omits the explicit composed ZK API.
Neither that stale table nor the newer API name settles privacy. The clear terminal
claim and missing demonstrated inner support are substantive, not documentation-only
issues. No attack, leakage experiment, proof or test was executed in this package.

### OtterSec public-input correction

[OtterSec](https://osec.io/blog/zkvms-unfaithful-claims/) identifies the omitted
public-input absorption and links
[`86a515f0632d2acdf547ed82780dfe7f9f39358f`](https://github.com/binius-zk/binius64/commit/86a515f0632d2acdf547ed82780dfe7f9f39358f).
Its four-file patch adds observation on prover and verifier paths. GitHub's retained
comparison reports **diverged**, with that fix one commit off the common ancestor;
it must not be described as an ancestor of the selected revision. The *substantive
correction* is present in current source: inner prover observes `witness.inout()`
before witness commitment/challenges; transparent verifier `verify_statement` and
ZK verifier observe the same words before delegating. Constants remain tied to the
trusted circuit, so the application must additionally bind the descriptor/PID.

The fix commit itself adds **no regression test**. Inspected current
`prover/tests/prove_verify.rs` has ZK SHA-256 roundtrip/serialisation, public-segment
512/513-word regressions and wrong/missing signature-message rejection. These are
source-level coverage observations, **not tests run here**, and not an identified
adversarial replacement-public-input regression for the OtterSec attack. Add that
specific ordinary/ZK-path regression at future admission; do not describe the
existing positive tests as its proof. The 16 old EXP2 cases concern Aurora, not Binius.

## Full relation and security applicability

[The implementation proposal](data/oct31_binius64_replacement_decision_1/implementation-proposal.md)
maps all checks of `relations.auth = PubOK AND auth_private AND Ppub` into one
experimental descriptor, preserving bounded ML-DSA-65, same credential/holder/
attributes/rid, SHA3-384, exact SHAKE128/256, disclosure/policy, Merkle and lifecycle
context. SHA3-384 and Keccak-f1600 gadgets exist; a bounded SHAKE sponge, ML-DSA
verifier, samplers, canonical codec and full composition are still missing.
The existing fixed SHA3 gadget masks unused tail bits, so the adapter must separately
reject noncanonical trailing input bits rather than quietly accept aliases.

| Claim/result | Applicable conditions and status |
| --- | --- |
| Word relation/knowledge | Blueprint §§3–5 specifies word constraints, LIOP reductions, binary-field BaseFold and BCS/Fiat–Shamir. Correct native primitive equations do not prove the new ML-DSA/codec lowering. Two-way relation correspondence and malformed/exhaustion cases require implementation validation. |
| IronSpartan HVZK | Blueprint Theorem 6.3/Appendix D is an equality-weighted MLE-check simulator with O(1)/|K| statistical exception, not a bare-sumcheck masking theorem. Full dummy-row, committed-segment and query joint distributions must match. No precise finite bound is extracted from unspecified constants. |
| Binary PCS privacy | [Diamond 2025/1015](https://eprint.iacr.org/2025/1015) proposes characteristic-two ZK polynomial commitment compatible with BaseFold. Blueprint §§7.2–7.3 requires rank-sufficient random support, one-time claim masks and hiding commitments. The inspected inner path does not establish those hypotheses. |
| Compositional ZK | [CFW 2026/391](https://eprint.iacr.org/2026/391) gives composable HVZK IORs and round-by-round knowledge soundness; [VEIL 2026/683](https://eprint.iacr.org/2026/683) gives a related lightweight wrapper. Their public abstracts were checked; full PDFs were unavailable through the browser. Neither is a verified theorem instantiation for this exact code. Blueprint simulator sketches and citations alone do not settle the joint transcript, Merkle or adaptive historical game. |
| Fiat–Shamir / PQ goal | A classical ROM construction is not a QROM adaptive knowledge/extraction theorem. Need an applicable transformation with precise oracle access, round-by-round/extractor premises, commitment conditions and losses for this composition. Whether an existing result suffices remains unresolved; a new argument is required if these premises cannot be established. |
| Concrete/finite security | Pin rate, query count, field, full round degrees, hash/Merkle domains, CSPRNG assumption and all failure terms at the actual workload. SHA-256's quantum collision bound is not automatically a proof-system attack or a 128-bit PQ guarantee. GHASH field size, “96”/“128”, hash-based design and passing tests cannot supply overall bit security. |

Blueprint's random masks are ideal independent uniforms. The source derives an
internal `StdRng` from a `CryptoRng`; a real implementation therefore needs an
explicit cryptographic-PRG/entropy assumption, fresh independent proof seeds and
failure handling. It does not inherit the manuscript's raw independent-tape model
unchanged. Keep adaptive Delta_tail, component advantages at reduction budgets,
commitment simulation, quantum extraction, concrete hashes, production custody,
erasure and side channels open. The active construction and BC-1 remain unchanged.

## Resource decision and delivery consequence

Fresh read-only host observation: WSL MemTotal **8,126,111,744 B**, available
**4,153,139,200 B**, swap 2 GiB; the physical host's 16 GB is user-reported and is not
available WSL working memory. AVX2, PCLMULQDQ, AES and SHA are present; AVX-512 is
absent. Existing 2 GiB headroom leaves about **1.87 GiB** beyond the reserve at that
instant, while the native worker's present hard cap is only 1 GiB. No build, native
runtime or whole-authentication memory has been measured for this backend.

The retained fixture needs 146 private-path Keccak permutations before any separately
justified public-prefix optimisation. Source has 24 rounds ×25 word χ products per
permutation: **87,600 word χ operations** for that shape, derived from the actual
lane loops, not historical Boolean gates divided by 64. This excludes XOR/shift
wiring, byte conversion, all ML-DSA arithmetic/sampling and the privacy wrapper.
It is not a complete constraint count or a memory-admission result. See the proposal's
whole-buffer formula and contingent envelope. No sufficient new memory ceiling can
be justified until the full count and live-buffer schedule exist; a bigger lower
bound is not a sufficient allocation.

October therefore still lacks an admitted private construction, a completed relation
lowering and measured complete private proofs. Reference/lifecycle work and the
preserved baseline remain useful. The examined Aurora route stays closed; its failure
is not evidence against all PQ-DID constructions. **Stages 2–3 remain open.**
This assessment is **not complete private authentication**.

## Preservation and accounting

Opening ledger: **2,586.937826 s implementation**, **974/1,050 invocations**,
**10/13 builds**, work events **77,593,603**. Analysis/isolation/proof balances are
separate and unchanged. Source inspection, documentary calculations and completion
are charged under the retained implementation accounting convention. No invocation,
build, circuit, proof, installation or activation ran. The 21 full-relation checks
remain unrun; v1 and all 276 measurements are reused unchanged.

The GitHub comparison unexpectedly returned 958,752 bytes of patch metadata despite
`per_page=1`, overshooting the internal source-size estimate. Retained source total
is 2,588,275 bytes. It stayed within the 1 MiB per-file and enclosing evidence caps;
no retained data was deleted/reclassified. Further acquisition stopped and only
completion work uses the existing reserve. This estimate/admission issue is preserved
in `source-budget-observation.json`; no historical stop is rewritten as successful.

Final audit, full inventory, report readback, cleanup and exact remaining balances
are recorded in the appended closure below and the package JSON records. Only this
source-decision package can close. Ordinary private verification stays fail-closed,
isolation stopped/unactivated, CPU proving paused, proof ledger **two used, one unused**.


Preservation completed: the full audit exited **0**, with **10,901**
disjoint original/supplementary content comparisons, **10,936** historical
identity-inclusive paths, no missing or unauthorised content, and completed inventory
and reporting. Outer guard **4.539334s**, worker
**4.203199s**, cgroup-v2 memory.peak
**47,255,552 bytes** under256MiB (worker,
descendants and charged cache/kernel); sampled process-tree RSS separately
**63,913,984 bytes**. No cgroup resource event occurred.
Scoped lint/format and documentary source/v1 checks passed; no native code ran.
[Final inventory, report readback, cleanup and exact resource balances](data/oct31_binius64_replacement_decision_1/validation-closure.json)
complete this source-decision package only. Metadata acquisition used bounded reads,
per-request timeouts and256MiB process address-space limits; it has no cgroup peak
measurement and must not be conflated with the measured audit worker.
