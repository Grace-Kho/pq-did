# Binius64 joint-opening construction decision

**S3-BINIUS-JOINT-OPENING-CONSTRUCTION-1 — NO-GO for a native correction
prototype on the presently established correspondence.** The proposed joint
equation has a valid local binding argument. It avoids revealing the terminal
scalar at that interface, provided a genuinely joint opening verifies it against
the same committed outer witness. The existing per-oracle opening interface does
not implement that protocol. More decisively, the native encoder admits a
source-derived counterexample to hiding by arbitrary trailing random support:
its original codeword symbol at index zero equals message coordinate zero.
Adding random trailing coordinates does not hide this symbol.

This is a construction result, not an executed attack, a proof that every
PQ-DID instance leaks a secret, or an impossibility result for Binius64/PQ-DID.
The smallest outstanding construction obligation is stated precisely below as
**JOINT-OPENING-LEMMA-1**. A technical question suitable for specialist review is
included in this report. No source overlay, profile adoption or implementation
package is admitted. G1–G3, proving and isolation remain paused; ordinary private
verification remains fail-closed. This is **not complete private authentication**.

The complete privacy-preserving PQ-DID scheme, KYC testbed and benchmarking remain
the project scope. 31 October remains the target, without evidence supporting a
commitment to full completion by then. Only manuscript Sections II–VIII and
SPEC-001–004 are authoritative. Stages 2–3, adaptive `Delta_tail`, component
advantages at reduction budgets, production security and full proof
knowledge/privacy remain open. The proof ledger stays two used, one unused.

## Inputs and source correspondence

The user-supplied [independent review](../PQ_DID_Binius64_Independent_Review.md)
is 17,773 bytes, SHA-256
`75e3d51861e2eead35bceec593909f1fcc23a604ee343e4c68859d7e3cecc97d`.
Its joint-opening option is a proposal, not an established theorem. The
[G0 report](oct31_binius64_g0.md),
[replacement decision](oct31_binius64_replacement_decision.md) and verified
[handover](private_proof_handover.md) remain unchanged.

| Input | Retained identity / use |
| --- | --- |
| Binius64 source | Commit `441fbf51ff0bcb0bcd28f3f1b73f4954029e8577`, tree `544452a781fee0f9b262d4ecfdcc47326fb6974f`; upstream paths below refer only to this pin |
| Blueprint | Retained 15 August 2026 PDF, SHA-256 `0dfdfd2fb8066842e0c0914901930b6b4f276284983838ad40ff0f2e8f0d9803`; sections 2.3, 5, 6.3–6.5, 7 and Appendix D |
| Original handover | Unchanged v1 archive, SHA-256 `17a0ac8fd32038e6530254e4cd27610c8a76e76aba53f446986e435845262f8e`; source index and missing-evidence list retained |
| Additional source | Ten specifically needed NTT/basis/permutation and IntMul files, acquired once at the same commit; lengths and Git blob IDs checked against the retained tree, with SHA-256 in [source-acquisition.json](data/s3_binius_joint_opening_construction_1/source-acquisition.json) |
| Reference relation | [Complete relation mapping](oct31_auth_relation_integration.md), `src/pqdid/relations.py` and its canonical statement/witness, binding, disclosure/policy and revocation modules; no relation implementation or encoding changed |
| Current baseline | `KYC-BASELINE-ISSUER2-MANAGER2-WALLET-PAGED-1`; comparison point v1, all 276 original measurements and later separate datasets remain immutable; 21 full-relation checks remain unrun |

Acquisition is source inspection, not execution of upstream code. It used 3.013
seconds. Its process-lifetime RSS diagnostic exceeded 256 MiB despite an installed
256 MiB address-space limit; the measurement qualification and stop are retained
under Resources below. No additional source acquisition followed. The exact
source list is the acquisition record, not a claim to possess a complete checkout.

The actual trace is:

| Pinned function/path | Established source finding |
| --- | --- |
| `prover/src/prove.rs::IOPProver::prove`, `pack_witness` | Packs `witness.non_public()` deterministically: two 64-bit words per GHASH128 element, low word first, then zeros. `observe_words(witness.inout())` binds public input separately. |
| `spartan-prover/src/wrapper/zk_wrapped_prover_channel.rs::send_one` / `prove_oracle_relation` | Ordinary field messages use committed OTP keys. Terminal claims instead go directly to `inner_channel.send_one(claim)`. |
| `spartan-verifier/src/wrapper/{builder_channel,zk_wrapped_channel}.rs::verify_oracle_relation` | Symbolic and replay paths allocate that terminal scalar as public/inout and assert equality to the computed claim. Transparent operands must be public functions of constants/challenges. |
| `iop-prover/src/basefold/channel.rs`, `iop/src/basefold/channel.rs` | Batch relations **within each oracle**, disclose mask claims, use affine `(1-gamma) pi + gamma omega`, and start batched sumcheck from the vector of known individual targets. Later transmit per-oracle folded evaluations. |
| `iop-prover/src/fri/encode.rs::encode_masked` | Samples an independent companion oracle, concatenates unchanged message and mask, then encodes them as distinct rows. Does not randomise the original message. |
| `math/src/reed_solomon.rs::encode_batch` | Bit reversal of the message/batch axes, repetition for rate expansion, then additive NTT with specified early/late layers skipped. Encoder domain equality is checked. |
| New `math/src/ntt/{mod,domain_context,neighbors_last,reference,subspace_polys}.rs` and `bit_reverse.rs` | Novel polynomial basis, Gao–Mateer linear-subspace domain and exact transform/permutation convention; zero-index property derived below. |
| `iop-prover/src/fri/query.rs::BrakedownOracleProver::open_queries` | Opens original leaf at `global_index >> log_lift`. Each ZK leaf exposes both original and companion symbols. Later folded cosets are separate observations. |
| New `prover/src/protocols/intmul/{prove,witness}.rs`, `verifier/src/protocols/intmul/{common,verify}.rs` | Phase 5 invokes committed transparent-table logup; one auxiliary pushforward has two terminal relations, against equality and the power-table MLE. The table has `2^16` entries, with twelve limb columns. |

## 1. A precisely specified joint terminal relation

Work over the native field `F = GF(2^128)` with its GHASH representation; subtraction
equals addition but the minus sign retains the intended relation. Let `O_I` be the
already committed inner packed-witness oracle `Pi`. Let `O_Z` be **the same**
outer-private-segment oracle `z` later used by IronSpartan, not a second commitment
to an equal-looking copy. The compiled outer layout allocates one private wire
`s_a` per terminal call, with canonical scalar position `j_a < n_private`.
Its selector is `e_ja[k]=1` exactly at that position, zero elsewhere. The position
is derived from the constraint-system layout and fixed terminal-call order;
neither prover nor proof parser may supply a free index.

Replace the current public allocation by an outer constraint

`z[j_a] = Claim_a(decrypt(ciphertexts, precommitted_keys), public_challenges)`.

Preserve every existing inner verifier assertion, public-input check and canonical
statement/context binding. Queue a *joint* public-target relation

`R_a: sum_i <O_i,T_ai> - <O_Z,e_ja> = 0`.

For the primary terminal call this is exactly `<Pi,T> - <z,e_s> = 0`.
The IntMul pushforward requires its own two calls/selectors; it must not be
silently folded into a supposed single-inner-oracle theorem. Fixed public-target
relations from the outer proof also belong to the joint system, with their
specified public right-hand sides.

**Identity and order required by this proposal:**

1. Fix the relation/profile identifier, field/encoder dimensions, ordered oracle
   specifications, outer layout (including each selector), canonical public
   statement and message domains. Preserve the existing statement observation.
   A future descriptor must bind these values explicitly; no new format is adopted
   here and an arbitrary caller-supplied context cannot replace trusted context.
2. Precommit independent OTP keys as currently required. Commit each inner oracle
   at its existing protocol point, and run the encrypted inner transcript in its
   fixed order. Commit the outer private witness and Libra mask before the new
   joint-opening batch challenge. The private terminal value depends on earlier
   challenges, so committing `z` after those challenges is intentional.
3. Run the outer algebraic reductions, retaining their prescribed order. Then
   bind the ordered joint-relation descriptors, public targets, commitment roots,
   exact handle-to-oracle mapping and preceding transcript before sampling a fresh
   domain-separated batching challenge. A handle cannot be relabelled, omitted,
   duplicated or substituted. In the native queue, outer precommit comes first,
   then all inner oracles, then outer private and outer mask. An implementation
   must check exact queue consumption, including the conditional IntMul oracle.
4. For `m` fixed relations, use one common coefficient `lambda^a` on **every term**
   of relation `a`, not different random weights on its two oracle terms. Set
   `U_i=sum_a lambda^a T_ai` (including the negative selectors on `O_Z`) and
   `B=sum_a lambda^a b_a`. Prove only `sum_i <O_i,U_i>=B`. Here the hidden terminal
   relations contribute public zero; individual terminal targets are never sent.

Under the additional premise that the outer argument and commitment-opening
argument extract the **same** committed objects, acceptance of all these exact
equations gives `<Pi,T>=z[j_a]=Claim_a`. Conversely an honest reference witness
and correct inner transcript satisfy them. This is a direct substitution
argument, not a proof that the current commitment compiler supplies that premise.
It preserves the original relation; merely asserting equality of two *unbound*
scalars would not.

For fixed false relation residuals committed before independent uniform `lambda`,
the aggregate residual is a nonzero polynomial of degree at most `m-1`. Its zero
probability is at most `(m-1)/|F|` (capped at one). This is only the classical,
fixed-residual batching lemma. Adaptive Fiat–Shamir choices, extraction and other
protocol errors are not covered by adding this number to a security statement.

**The present downstream path is not usable unchanged.** It expects known targets
per oracle (`sum_primes`) and reveals the terminal target through the wrapper.
Calling it separately for the two terms would disclose the two forbidden values.
A proposed joint variant must start from the *single aggregate* `B`, use correct
zero-lifting for heterogeneous dimensions, and never send a per-term target or
an unmasked selector opening on `z`. Zero-lifting an operand and repeating a
smaller codeword for FRI are different maps; their existing equality-indicator
factors must remain in the final check.

One algebraic opening design would send only
`Sigma=sum_i <Omega_i,U_i>`, commit every companion `Omega_i` first, then sample
`gamma` and open the aggregate on `V_i=(1-gamma)O_i+gamma Omega_i` with public
target `(1-gamma)B+gamma Sigma`. This equation is correct by linearity. It is a
**proposed protocol change**, not evidence that the pinned per-oracle sumcheck
and FRI implementation is zero-knowledge for it. Per-oracle folded values, later
sumcheck messages, final codeword and query leaves remain part of the view and
must pass the joint argument below.

## 2. Actual embedding, support and a native-basis counterexample

Write an oracle's candidate embedding as `O_i=J_i w_i+S_i r_i`, with `r_i`
uniform and independent in an explicitly specified field-vector space. Here
`J_i` includes packing, permutations and padding; `S_i` is a *map*, not merely
a count of coordinates. It must be chosen before the relevant random challenges.
For the current inner oracle `S_I=0`. Outer precommit/private segments append
random dummy wires; the extra dummy multiplication triples `(a,b,a*b)` have a
nonlinear distribution and cannot be counted as three independent uniform
support coordinates. The outer Libra oracle has its own coefficient-to-proxy map.

For each ordinary semantic linear operand `t_i`, relation preservation by such
support requires `t_i^T S_i=0`, or a new, explicitly proved decoded embedding
whose transported operand has that property. In particular, current zero padding
in the inner ring-switch polynomial is not automatically an unconstrained tail.
The original reduction must still refer to exactly the original packed words.
The selector `e_ja` is not zero on its selected private coordinate: randomising
that coordinate without changing the outer claim equation is invalid.

Let `E_i` be the actual native linear encoder, including bit reversal, batch
permutation, expansion, NTT and oracle-specific lift. At a fixed set `Q_i` of
distinct original query positions, the view is

`E_i,Q J_i w_i + E_i,Q S_i r_i`.

For two valid witnesses at the same public statement this has the same distribution
exactly when `E_i,Q J_i(w_i-w'_i)` lies in `image(E_i,Q S_i)`. The proof is equality
of affine cosets of a uniform linear image. Full row rank is sufficient for
uniformity but not necessary for a restricted relation. This is an exact algebraic
statement; it does not imply a commitment simulator.

### Zero-index derivation for the retained encoder

The newly retained code makes the earlier generic monomial example concrete for
the native layout:

- Bit reversal fixes scalar index zero. In the concatenated `(message || mask)`
  input, it moves the batch bit to the low axis; it does not add the two rows.
- Rate expansion repeats the transformed buffer; the first element stays unchanged.
- `GaoMateerOnTheFly::twiddle(layer,0)=0`; the pre-expanded form also has zero as
  its first entry. This is evaluation on a **linear** subspace containing zero,
  not a shifted nonzero coset.
- The reference butterfly is `u += v*twiddle; v += u`. Along the zero output path
  `u` stays unchanged at every executed layer. The optimised `neighbors_last`
  implementation explicitly implements that zero-block rule (including its
  fused zero-block path). Skipped early/late layers do not change this conclusion.
- Consequently the original row satisfies `E(m)[0]=m[0]`. The original ZK leaf
  at index zero contains `m[0]` and the separate companion value `omega[0]`.

Thus, for any trailing-coordinate support that leaves `m[0]` unrandomised,
`E_{\{0\}} S=0` and its rank is zero, however many such coordinates are added.
If admissible messages differ in `m[0]`, their views at this position differ.
The packed **non-public** inner witness can contain such a first word pair;
no assertion is made that every fixed PQ-DID statement admits that variation.
If it is fixed by a particular public instance, this row alone is not a leakage
example for that instance, but the claimed general full-rank implication is still
false. Outer appended dummy-wire support has the same zero-row limitation.

This is a source-derived algebraic counterexample to “enough trailing random
coordinates imply hiding”; no NTT, circuit, native test or attack was run. If a
future query sampler permits zero, it must handle that event. For independent
uniform draws over an original codeword of length `N`, the chance of hitting zero
in `q` draws is `1-(1-1/N)^q`; native Fiat–Shamir/adaptive-query probabilities are
not established here. Excluding zero alone neither proves the other rows have
full rank nor justifies changing the verifier's sampling distribution.

A principled new embedding could reserve a polynomial subspace whose evaluations
have the required interpolation rank, and transport **all** semantic operands
through a left inverse of its data map. This is not the same as filling the
existing tail. It requires a native basis/permutation map, efficient transported
operands, all oracle dimensions and a joint-view proof before choosing coordinates
or changing dimensions. We do not propose a guessed support or implement it.

### Oracle coverage, including IntMul

| Oracle | Existing shape and randomness | Required unresolved correspondence |
| --- | --- | --- |
| Inner trace | Power-of-two packed non-public words, zeros after real data; no original-row blinding | A relation-preserving embedding with actual query-image rank, not an arbitrary larger zero tail |
| IntMul pushforward, when IntMul is present | Phase-5 logup for twelve 16-bit limb columns over a `2^16` power table; two opening operands (`eq_z` and transparent table MLE) | Both claims must become joint relations. Their operands/support, commitment point and all public-dependent weights must be traced through the still-missing logup helpers; table transparency does not make the witness-dependent pushforward public |
| Outer precommit | OTP keys plus unconstrained random dummy wires | Keys, ciphertexts, query values and other mask claims must be jointly simulatable; tail size alone fails the universal rank assertion |
| Outer private | Decrypted messages/intermediates, proposed terminal wires, dummy wires and nonlinear dummy triples | Selector positions, outer matrices, dummy distribution and all disclosed products/segment claims; no independent-coordinate count for `(a,b,a*b)` |
| Outer Libra | Multilinear proxy for masking coefficients, with its evaluation relation | Image/rank conditional on the disclosed mask evaluation and other correlated messages; existence of a random oracle vector is insufficient |
| Every companion row | Equal-length independent field vector generated using the native RNG/PRG path | Correct ideal-random premise and a computational PRG replacement argument; same randomness must be used consistently in claims, folds and openings |

At most `q` distinct original positions per oracle result from `q` global positions
after lifting/collision collapse. Later folded coset openings and terminal data
must be counted separately, not used to multiply that original-position count.
Oracle dimensions are heterogeneous. The Blueprint's four-oracle description
does not cover the IntMul auxiliary path merely by naming it “batched”.

The ten newly acquired files resolve the NTT path and the IntMul caller/limb
semantics. Full `crates/iop-prover/src/logup_star.rs`, `crates/iop/src/logup_star.rs`
and their `crates/{ip-prover,ip}/src/logup_star/` helper bodies are **not retained** in
this package. Their actual paths and blob identities can be located in the
already retained recursive tree and this package’s `missing-source-index.json`;
no substitute implementation or assumed
pushforward blinding is used. A complete dependency checkout/build remains absent.

## 3. Joint view and the exact outstanding lemma

There is a useful, limited coupling calculation. Fix public operands `U_i`, public
aggregate `B`, a nonzero `gamma`, and two original-oracle vectors differing by
`Delta_i` with `sum_i <Delta_i,U_i>=0`. Shift the uniform companion masks by

`Omega'_i = Omega_i - ((1-gamma)/gamma) Delta_i`.

Then every `V_i` is unchanged and aggregate `Sigma` is unchanged. The shift is a
bijection on uniform companion masks. Any deterministic folding transcript of
those same `V_i` is consequently identical **in this conditional algebraic model**.
This explains why a genuinely joint mask claim is appropriate: separate
`sigma_i` are not generally unchanged when only the *sum* of the relation
residuals vanishes.

It does not settle the complete protocol. Original query leaves also expose
`E_i O_i` and `E_i Omega_i` separately. To keep those equal, support randomness
must permit the coupled original difference to have `E_i,Q Delta_i=0` while all
semantic relations remain correct. With shared randomness or additional revealed
linear forms, stack all their rows into one observation map; separate rank proofs
do not prove the stacked condition. Outer ciphertexts and nonlinear dummy products
place additional constraints on a coupling. Commitments to unopened leaves change
under this shift and require a commitment/ideal-oracle simulation argument.

The complete view to be simulated contains the canonical public statement and
context; ordered commitment roots; encrypted inner messages and all public
challenges; joint relation descriptors; outer constraint-check rounds and revealed
products/segment contributions; Libra claims; aggregate or per-oracle companion
claims; BaseFold rounds and per-oracle folded evaluations; intermediate commitment
roots; the final reduced codeword; original and folded query leaves; authentication
paths; parsing lengths and rejection behaviour. Hiding one scalar, or showing
each item has a witness-independent marginal, is insufficient.

**JOINT-OPENING-LEMMA-1 (missing, not claimed):** for the actual encoder/permutations,
all actual oracle shapes, a public statement and any two valid hidden witnesses,
provide embeddings `J_i,S_i` and transported semantic operands such that (a) the
original bounded relation is preserved, with support annihilation; (b) for every
admissible transcript prefix, the *conditional joint observation* difference lies
in the image of the still-available randomness map, with explicitly bounded bad
events; and (c) the corresponding sequential simulator can produce consistent
commitments, joint openings, folded data and authenticated queries without either
terminal target. It must use the same committed outer coordinate as the constraint
argument. Specify how nonlinear outer masks/OTP constraints are sampled and how
the extractor obtains these same objects. The rank premise must use the **actual**
query observations, not just count `q+1` random coordinates.

Parts (a)–(b) already fail for the unchanged inner packing or naive tail-fill at
the native zero row. No amount of implementation testing can supply (c). An
embedding satisfying (a)–(b), followed by an applicable commitment/compiler theorem
or a new proof of (c), is the smallest coherent reopening condition. It is not a
request for another backend survey.

Adaptive queries require an online conditional-distribution argument: positions
can depend on previous roots/messages. Choosing a fixed `Q` after seeing a witness
and applying an unconditional rank calculation does not establish that argument.
Fiat–Shamir adds challenge programmability and extraction requirements beyond
this interactive algebra. Neither has been demonstrated for the modification.

## 4. Exceptional challenges and applicable security results

The native affine mask is `(1-gamma)pi+gamma omega`; the Blueprint writes
`pi+alpha omega`. When `gamma != 1`, multiplying by `(1-gamma)^-1` gives
`alpha=gamma/(1-gamma)`, with the same rescaling required for targets, folded
evaluations and verifier equations. Uniform `gamma` conditioned away from 1 does
**not** give uniform `alpha` on the whole field (in characteristic two it excludes
1). This is conditional algebra, not byte-for-byte transcript correspondence.
At `gamma=0` companion masking vanishes; at `gamma=1` the virtual relation loses
the original row. Both events need explicit treatment in a security proof.
For one independent uniform field challenge their union is exactly `2/|F|`;
that is not an overall bit-security claim or permission to add an error term to
an unproved privacy/extraction reduction. No rejection sampling or transcript
change is implemented here. Other challenge degeneracies and rank failures need
their own arguments and finite bounds.

| Result / primary source | What it supports | Premise missing for this proposal |
| --- | --- | --- |
| Finite-field linear-image/coset lemma, proved above | Exact fixed-view equality criterion; conditional coupling for aggregate masking | Actual embeddings and stacked/adaptive conditional rank; nonlinear/commitment parts |
| Polynomial root bound | Fixed-error classical batching and one affine-mask check | Errors fixed before an independent challenge; complete reduction/query budgets, Fiat–Shamir transfer |
| Retained Blueprint Theorem 6.3, Protocol 6.2 and Appendix D | HVZK of the equality-weighted MLE check **given its public claim and reduced value**; handles characteristic two | Simulator for the reduced value, outer revealed products, commitments and modified joint openings. The stated `O(1)/|K|` has no supplied finite constant to reuse numerically |
| Blueprint §§6.4–6.5 | Intended dummy-constraint and IronSpartan composition | Joint distribution of actual dummy triples, segment targets and added terminal coordinates; theorem applicability to modified outer matrices |
| Blueprint §§7.1–7.3, citing Ben-Or et al., Frigo–shelat and VEIL | Intended encrypted-message composition and ZK BaseFold strategy | The Blueprint uses a terminal OTP coordinate, not the proposed cross-oracle zero-target opening; §7.2 defers the full Merkle simulator. Citation alone supplies neither the changed interface nor its premises |
| Native NTT documentation, referring to LCH additive NTT and Diamond–Posen | Basis/domain and code-linearity semantics used in the zero-row derivation | Code linearity is not ZK or hiding; library support for a field/domain does not prove rank or commitment privacy |
| BaseFold/BCS/Fiat–Shamir results recorded in the replacement/security assessment | Candidate compiler and extraction framework under their stated models | An explicit application to this adaptive, joint, heterogeneous-oracle composition and simulator access, then the required quantum knowledge/privacy transfer |

The [pinned native implementation](https://github.com/binius-zk/binius64/tree/441fbf51ff0bcb0bcd28f3f1b73f4954029e8577)
and [Blueprint](https://www.binius.xyz/spec.pdf) are the primary sources used here;
the retained PDF identity governs the latter. We do not claim that the papers
cited by the Blueprint prove the proposed modification. No new literature campaign
or numerical security estimate was run. Classical/ideal-oracle algebra and HVZK
statements do not establish the required quantum knowledge extraction, quantum
privacy, concrete-hash replacement, finite parameters or adaptive-tail bounds.

## 5. Specialist question and inactive correction map

**Question to resolve before authorising implementation:** For the above pinned
GHASH/additive-NTT encoder, can one give a public embedding/decoding pair and
randomisable subspaces for the inner trace, IntMul pushforward, outer precommit,
outer private and Libra oracles that satisfy JOINT-OPENING-LEMMA-1 for a joint
zero-target opening, including the native affine mask? Supply either an explicit
sequential simulator/extractor correspondence to a named theorem with matched
hypotheses, or a counterexample. In particular, explain how the zero-index
observation is hidden, how the two IntMul operands annihilate support, and how
the same outer private selector is constrained without revealing its value
through a later per-oracle target/evaluation.

Inputs for that question are this report, the independent review, the unchanged
handover archive and this package's ten-file acquisition/index. The new local
binding and coupling lemmas are derived conclusions; source findings are the
trace/table and zero-row derivation; JOINT-OPENING-LEMMA-1 and full security
composition remain unresolved assumptions. No specialist has been contacted.

If the lemma is supplied, the concrete correction map is limited to these
interfaces, but **inactive**:

- All three wrapper paths (symbolic builder, prover replay and verifier) must use
  the same private terminal-wire event and deterministic layout, replacing the
  public terminal send/allocation. Encrypted-message counts and transcript events
  must agree; caller coverage includes the IntMul logup path.
- Oracle specifications/packing and all transported semantic operands must
  implement the proved embedding. `encode_masked` alone cannot repair original
  query privacy. Preserve public-input observation and every bounded ML-DSA,
  holder binding, certified disclosure/policy and same-identifier revocation check.
- Both BaseFold channels and sumcheck/opening APIs must verify a joint public
  aggregate, including exact oracle identities, selectors, lifting and challenge
  order, without a vector of secret component targets. The commitment/query path
  must implement the proven hiding transformation.
- Native validation would need complete transcript/caller comparisons, altered
  selector/oracle/commitment/order rejection, all oracle shapes, malformed lengths,
  exceptional challenges, support/rank and adversarial-witness checks. These are
  inactive future checks, not invocations authorised or executed here. They could
  test correspondence, never substitute for the missing lemma.

A credible complete resource estimate cannot be produced before the support maps,
oracle dimensions, query budget and joint sumcheck algorithm are fixed. They
determine original/companion codewords, embedding buffers, outer constraints,
commitment trees and concurrent folding storage. No new resource envelope,
build or proof allowance is requested on the basis of an unknown construction.
The concrete user decision is to seek the stated construction result (or select
a separately justified construction), not to approve a speculative native patch.

## Resources and preservation

The earlier missing-review admission and its 10-second charge are retained. The
analysis allowance opened at 80.91750274339225 seconds before that charge and
70.91750274339225 on this continuation. This is the existing analysis workflow;
implementation remains 810.6179695621813 seconds and KYC remains
443.3903556420428 seconds, including its protected reserve. Invocations stay
1,140/1,146 and builds 10/13. There are no functional tests, circuit evaluations,
builds, proofs, benchmarks or activations in this package.

Source acquisition was capped prospectively by a 12-second alarm, bounded reads,
one process, two-CPU affinity, 1 MiB files and a 256 MiB `RLIMIT_AS`. The immutable
record reports lifetime `ru_maxrss=279,449,600` bytes, **11,014,144 bytes above**
256 MiB. It does not include a pre-exec baseline or a cgroup trace. The value may
include launch/pre-exec high-water state, but that possibility is not evidence
that the excess was harmless. We cannot certify resident-memory compliance for
that acquisition. It completed once, with verified source bytes; no retry or
further acquisition followed. This observation remains open in
[source-memory-observation.json](data/s3_binius_joint_opening_construction_1/source-memory-observation.json).
Preservation success must not relabel this observation as a successful memory
measurement. Subsequent guarded work is completion/static checking only.

The conservative local source/documentation/bookkeeping allocation is 35 seconds
in addition to the earlier 10 seconds and measured acquisition. Actual guarded
static/preparation/audit/readback time is added separately. At most 2 MiB new
evidence is admitted within existing shared headroom (7,743,389 bytes at opening),
retaining the shared 2 MiB completion reserve. The cumulative ceiling stays
40 MiB. Every new source/report remains under the ordinary 1 MiB per-file cap;
the handover's two exact archive exceptions are unchanged. No artifacts are built.

The established full preservation workflow, historical baselines and disjoint
comparison partitions are reused. Only this new report/evidence root and explicit
append-only status/traceability/issues updates are registered; the user-supplied
review receives an exact full-file identity check. Current finalisation outcomes
will be appended below, with final inventory/readback and resource closure in
`docs/data/s3_binius_joint_opening_construction_1/`. The source/math decision is
separate from resource compliance and from successful completion of preservation.


### Preservation completion checkpoint

The single full audit passed, exit **0**: **10,901**
disjoint historical content comparisons and **10,936** identity-inclusive paths,
with no changed/missing protected content or inventory discrepancy. Audit guard
time was **4.635 seconds**; cgroup-v2 `memory.peak` was
**47,558,656 bytes**, including descendants and charged
cache/kernel, below 256 MiB. This certifies the audit worker, not the unresolved
source-acquisition lifetime-RSS observation. The first static run's E501 failure
and exact formatting correction are retained; the affected repeat passed. No
functional case was run. Final report seal, inventory/readback and exact closing
analysis balance are in this package's `manifest.json`, `validation-closure.json`
and `resource-closure.json`. Historical baselines and previous failure records
were not regenerated or changed. This completes a construction decision and
preservation checkpoint, not a native privacy repair or proof-security claim.
