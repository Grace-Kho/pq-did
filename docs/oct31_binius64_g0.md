# Binius64 G0 construction-repair decision

**Decision: NO-GO at the construction gate.** This completes the authorised G0
decision, not the integration milestone. No justified prover/verifier source
overlay is delivered: the required committed-mask binding and joint-view hiding
argument have not been established. Implementing an unbound terminal pad or
randomising unspecified padding would not be a supported correction. G1–G3 stay
inactive. This is not an impossibility result for Binius64 or PQ-DID.

The original complete privacy-preserving PQ-DID scheme, KYC testbed and benchmarking
remain the goal. 31 October remains the target; current evidence does not support
a commitment to complete private authentication by then. Only manuscript Sections
II–VIII and SPEC-001–004 govern the scheme. The prior Aurora closure, comparison
point v1, all 276 measurements and 21 unrun complete-relation checks are preserved.

## Identity and scope

The revision remains `441fbf51ff0bcb0bcd28f3f1b73f4954029e8577`, tree
`544452a781fee0f9b262d4ecfdcc47326fb6974f`. The retained Blueprint is dated
15 August 2026, SHA-256
`0dfdfd2fb8066842e0c0914901930b6b4f276284983838ad40ff0f2e8f0d9803`.
Use the retained PDF, not a changing website, for this decision. The earlier
[decision](oct31_binius64_replacement_decision.md) and its pinned source evidence
are immutable. Eight missing source files (90,955 bytes) were obtained read-only,
verified against the retained recursive Git tree's blob IDs and lengths, and
SHA-256 recorded in [acquisition records](data/oct31_binius64_g0_1/source-acquisition.json)
and [continuation](data/oct31_binius64_g0_1/source-acquisition-2.json).
No checkout, dependency, production file, circuit, profile or cryptographic input
was changed. New experimental Python files implement only documentation and
preservation checks, not a Binius implementation or privacy simulator.

## B64-ZK-001: the actual public value

The trace below is source inspection, not native execution. All source paths refer
to the pinned repository; the acquisition files and prior source index retain the
exact bytes. [Pinned prover entry](https://github.com/binius-zk/binius64/blob/441fbf51ff0bcb0bcd28f3f1b73f4954029e8577/crates/prover/src/prove.rs)
and [wrapper](https://github.com/binius-zk/binius64/blob/441fbf51ff0bcb0bcd28f3f1b73f4954029e8577/crates/spartan-prover/src/wrapper/zk_wrapped_prover_channel.rs)
are the relevant callers.

| Step | Actual operation | Privacy consequence |
| --- | --- | --- |
| Witness construction | `IOPProver::prove` packs `witness.non_public()` using `pack_witness`. Two words form one GHASH element, `w0 + 2^64*w1` at the bit-representation level, followed by zeros. | This buffer has no fresh randomness or reserved support. The expression describes packing, not integer arithmetic in the binary field. |
| Statement | `observe_words(witness.inout())`; public evaluation and wiring checks remain on the native path. | The public-input correction is retained; it does not hide private openings. No public statement check is removed. |
| Reduction | `ring_switch::prove` sends the 128 partial bit-column evaluations through the wrapped channel, transposes the tensor and forms `s` using the public row-batching challenge. It returns `T = rs_eq_ind` and `s = <pi,T>`. | Wrapped ordinary field messages have OTPs. Nevertheless `s` is a linear functional of the packed hidden witness for the sampled, known operand T. |
| Terminal send | `ZKWrappedProverChannel::prove_oracle_relation` directly calls `inner_channel.send_one(claim)`, records it and queues the unchanged opening. | This deliberately bypasses the wrapper's OTP `send_one`. |
| Serialisation | `MerkleProverChannel::send_one` forwards the field element to the prover transcript. | The serialised element is clear; hashing transcript bytes is not encryption. |
| Verifier | `ZKWrappedVerifierChannel::verify_oracle_relation` reads that element, allocates a public/inout value and attests `claim == decrypted_claim`. `IronSpartanBuilderChannel` constructs the same equality. | The outer proof binds the value to the reduction; it does not conceal it. |
| Commitment discharge | BaseFold receives this same `s`, later receives `sigma=<omega,T>`, samples gamma and checks the affine-combined claim. | Later randomness cannot remove a value already in the complete view. |

Sources newly resolved here include
[ring-switch prover](https://github.com/binius-zk/binius64/blob/441fbf51ff0bcb0bcd28f3f1b73f4954029e8577/crates/prover/src/ring_switch.rs),
[ring-switch verifier](https://github.com/binius-zk/binius64/blob/441fbf51ff0bcb0bcd28f3f1b73f4954029e8577/crates/verifier/src/ring_switch.rs),
[verifier wrapper](https://github.com/binius-zk/binius64/blob/441fbf51ff0bcb0bcd28f3f1b73f4954029e8577/crates/spartan-verifier/src/wrapper/zk_wrapped_channel.rs)
and [symbolic builder](https://github.com/binius-zk/binius64/blob/441fbf51ff0bcb0bcd28f3f1b73f4954029e8577/crates/spartan-verifier/src/wrapper/builder_channel.rs).

The full randomness inventory includes precommitted OTP keys, challenges, the
independent BaseFold companion rows, randomised outer witness support/dummy
products and Libra masks. None is added to this terminal scalar before it is sent.
The verifier knows T: its evaluator is explicitly required to depend only on
known constants or challenges. Public information includes the statement,
ciphertexts, sampled challenges, public wiring/evaluation claims, this scalar,
commitment roots, sigma values, folding messages, terminal coefficients and query
openings. One must simulate their **joint** distribution, not each marginal.

This establishes an unmasked witness-dependent observable in the generic native
path. For two admissible hidden assignments whose difference d has `<d,T> != 0`,
the corresponding conditional scalar values differ. It does not demonstrate
recovery of a PQ-DID secret, quantify a concrete attack, establish that every
fixed statement has two witnesses, or execute a forgery. Such stronger claims are
unnecessary: the claimed generic wrapper correspondence is not established.

## B64-ZK-002: implementation gap and exact rank obligation

The newly inspected
[encoder](https://github.com/binius-zk/binius64/blob/441fbf51ff0bcb0bcd28f3f1b73f4954029e8577/crates/iop-prover/src/fri/encode.rs)
settles the earlier uncertainty. `encode_masked` samples an independent equal-length
omega, concatenates **unchanged pi and omega**, and encodes them as separate rows.
It does not fill randomisable coordinates of pi. Its immutable message view,
length checks, allocation and concatenation all agree on that behaviour. Thus
the inner packed-witness omission is an implementation gap, not just missing prose.

[ReedSolomonCode::encode_batch](https://github.com/binius-zk/binius64/blob/441fbf51ff0bcb0bcd28f3f1b73f4954029e8577/crates/math/src/reed_solomon.rs)
interprets the message in a non-standard polynomial basis, applies bit reversal,
repetition and the additive NTT on a Gao–Mateer subspace. It is not permissible to
reason as though arbitrary message coordinates were consecutive monomial
coefficients or evaluations of a systematic Reed–Solomon code.

The [query prover](https://github.com/binius-zk/binius64/blob/441fbf51ff0bcb0bcd28f3f1b73f4954029e8577/crates/iop-prover/src/fri/query.rs)
opens each original commitment at `global_index >> log_lift`. For a ZK oracle the
original leaf contains both `Enc(pi)[j]` and `Enc(omega)[j]`. They are transmitted
separately under the authentication path; the first is not encrypted by the second.
If there are q sampled positions there are at most q distinct original positions
per oracle after lifting/collision collapse. **Do not multiply this by a later
FRI folding arity.** Later folded-oracle cosets and the terminal codeword are
additional correlated observations and belong in the joint analysis.

For a fixed public statement write a proposed packed oracle as

`Pi = J*w + U*r`, with independent uniform `r in F^k`, `F = GF(2^128)`.

J must implement exactly the existing data packing and index map; U describes
genuinely unconstrained randomisable coordinates. Let E be the *actual* encoder
including its permutations and Q a set of distinct queried positions. Then

`Y_Q = E_Q J*w + E_Q U*r`.

The exact linear-algebra condition for equal distributions between two valid
witnesses w and w' at fixed public coefficients is

`E_Q J*(w-w') in image(E_Q U)`.

Full row rank `rank(E_Q U)=|Q|` is sufficient for uniform query symbols but not
necessary for all possible restricted relations. This follows because a uniform
linear image is uniform on its image subspace; its translations agree precisely
when their difference lies in that image. It is a structural argument, not a
finite-test claim. For additional revealed linear quantities, stack their rows
and their common random variables into the same equation. Separate full-rank
matrices do not prove the stacked condition. Adaptive selection requires a
sequential conditional-distribution/simulation argument, not conditioning away
the dependence on previous transcript messages.

Necessary support requirements before choosing any dimension are:

1. A public, fixed embedding J and support U for each actual committed oracle,
   respecting little-endian packing, segment ordering, zero-extension semantics
   and all public-input and ring-switch identities.
2. Original semantic query operands vanish on random support. Padding currently
   used as zero-extension is not automatically unconstrained: the ring-switch
   equality operand has no explicit support-annihilation rule. Randomising it
   changes the polynomial that the existing reductions refer to.
3. Prove the above rank/image condition for the encoder and the actual query
   union, including any extra claim-key observation. Derive a bad-query bound if
   some admissible positions are exceptional. A count of q+1 or q+2 columns alone
   proves neither their rank nor this bound.
4. For commitment hiding, establish conditional entropy of unopened leaves and a
   simulator for authenticated openings in the chosen commitment/hash model.
   One spare dimension alone is not a hiding theorem for a Merkle commitment.

For example, even a standard monomial code with random support only in positive
powers cannot hide the constant coefficient at evaluation point zero: all those
random columns evaluate to zero there. This is a symbolic counterexample to the
**cardinality-only inference**, not an executed counterexample for this native
NTT layout. We do not claim the native layout has that exact bad event without
deriving its basis/permutation mapping.

Blueprint §§2.3, 7.2 and 7.3 prescribe vanishing operands, random support and a
terminal claim key. They do not supply an implementation-specific support/rank
proof for the inspected layout. Its §7.2 expressly defers the complete Merkle
simulator. The present pin additionally queues an IntMul pushforward relation
when integer multiplication constraints are present (`prove.rs` and `verify.rs`
record this). Accordingly, the Blueprint's four-oracle, single-inner-opening
description cannot be assumed to cover every native constraint system. The full
IntMul auxiliary-oracle privacy trace remains unresolved; it is not silently
covered by this packed-witness diagnosis.

## Why the obvious terminal patch is insufficient

A necessary proposed local interface would extend the committed oracle with a
claim-key coordinate e, set the compiled operand to `T' = T + e*` (T vanishes on
that coordinate), and reveal `c = s + k`. Then `<Pi,T'> = c` binds the ciphertext
to the oracle's k. Outer constraints must simultaneously prove that the **same**
k decrypts c to the value computed by the encrypted inner verifier. This is not
achieved by replacing the wrapper call with its ordinary OTP send: those keys
live in the separately committed outer precommit segment, not in the inner oracle.

If the outer circuit uses a fresh unconstrained `k_outer`, while the PCS uses
`k_pi`, its checks only enforce

`c = s_inner + k_outer = <pi,T> + k_pi`.

Without equality of these keys, this permits
`s_inner - <pi,T> = k_pi - k_outer`. This is a precise missing local binding
condition, not a complete protocol forgery. A correct solution must enforce the
cross-commitment equality without exposing either key. The current per-oracle
opening interface exposes each target separately; adding a clear opening of the
key would undo the privacy repair. A jointly masked cross-oracle equality or an
equivalent committed-witness representation needs its own correspondence proof.

The exact unresolved construction result is therefore an embedding and compiled
opening protocol for **all actual oracle shapes** that simultaneously establishes:

- extraction of the unchanged inner witness/relation, including public binding;
- equality of the terminal pad in the inner commitment and the outer constraints;
- support-annihilation and joint query/claim hiding in the actual RS basis;
- simulation of encrypted reduction messages, outer proof, sigma values,
  affine-masked folds, terminal data and authenticated query openings together.

This is a new implementation-specific argument/application, not a claim that a
new general cryptographic primitive is required. No cited result has been shown
to instantiate it here. An implementation or passing examples cannot supply that
missing premise. G0 therefore stops before adding coordinates, dimensions or an
unjustified overlay.

## Affine gamma and exceptional challenges

Both native BaseFold channels use
`pi'=(1-gamma)*pi+gamma*omega`, `s'=(1-gamma)*s+gamma*sigma`.
The Blueprint uses `pi+alpha*omega` and `s+alpha*sigma`. For gamma not in {0,1},
division by `1-gamma` and `alpha=gamma/(1-gamma)` gives an algebraic correspondence.
In characteristic two, subtraction and addition coincide. The map is a bijection
on `F \ {0,1}`; it is not a statement that the unconditioned transcripts are
identical, or that all sumcheck messages can be left unchanged under rescaling.

At gamma=0 the folding view uses pi alone; at gamma=1 it uses omega alone and
does not test the original claim through that combination. For one ideal uniform
field draw the union has probability exactly `2/2^128`. This number describes
only those two exceptional challenge values. It is not an overall privacy,
knowledge or concrete quantum-security bound. The same gamma is shared across
oracles in this source; do not multiply by oracle count for that same draw.

For fixed committed rows and already fixed s,sigma, an invalid affine relation
gives a nonzero degree-at-most-one polynomial in gamma and hence at most one root
unless both component equalities already hold. This local soundness observation
does not establish extraction or the joint simulator. A valid transfer must map
all messages, challenges, query adaptivity and simulator/extractor access, then
justify Fiat–Shamir in the required model. Rejection-sampling gamma or replacing
the affine rule would change the protocol; neither is done here.

Native masks use CSPRNG-derived field elements (`StdRng` and `par_rand`); replacing
ideal independent uniforms by that implementation needs the explicit PRG/entropy
assumption already recorded. Outer dummy multiplication rows have statistical,
not automatic perfect, hiding. Equality-weighted Libra Theorem 6.3 addresses its
specified MLE-check, not the absent inner support/key linkage. No unspecified
asymptotic constant has been converted to a finite security claim. QROM,
commitment simulation, extraction/privacy composition, concrete hashes,
finite parameters, adaptive Delta_tail and production security remain open.

## Validation performed and native gate left unrun

This is a source/mathematical NO-GO, not a tested correction. There are **zero new
functional cases, zero native builds and zero proofs**. Completed Python/native
evidence from other packages is reused, not reinterpreted as Binius evidence.
Documentation/static checks verify the pinned source identities, source-reference
provenance, previous seals, manuscript identity, unchanged benchmark identities,
resource records and preservation. They do not test masking.

The following precise gate would be required for a future justified overlay; all
items are **unrun**, not implicitly authorised by this report:

| Gate | Required native observation after the construction argument exists |
| --- | --- |
| Oracle layout | Real builder/prover/verifier agree on packing, support, key coordinates, domain dimensions and oracle order, with and without IntMul. |
| Relation preservation | Unchanged bounded reference accepts/rejects identically; zero-extension, public segment and hidden assignments cannot be substituted. |
| Cross-commitment binding | Alter only the inner key, outer key, ciphertext or oracle identifier; each inconsistent assignment fails the genuine outer/PCS checks. |
| Support and encoder | Verify the proved basis/permutation map and rank certificate on bounded independent fixtures; invalid support/rank configurations reject. These examples do not prove all-query rank. |
| Complete opening | Genuine paired-row queries, lifted indices, folded cosets and terminal data agree with the construction, with no clear private target. |
| Exceptional coefficients | Deterministic test-only coins exercise gamma=0,1 and ordinary values with the specified failure/security treatment; no ordinary-interface bypass. |
| Public context | Wrong instance/key/context/relation identifier and changed public input are rejected by the actual caller path. |
| Joint distribution | Use the proved simulator to specify expected bounded distributions/linear images; do not invent acceptance from a histogram or mocked PCS. |

There is also an independent **resource-admission stop**. The authoritative opening
is 2,401.2883560892915 implementation seconds, 974/1,050 invocations and 10/13
builds. Shared evidence headroom is 1,737,206 bytes, below the inherited 2,097,152-byte
completion reservation required before ordinary jobs. Cumulative evidence
headroom is 3,758,749 bytes. No ordinary implementation/test job was admitted and
no reserve was reset or borrowed. The bounded read-only source diagnosis and
completion work consume the remaining completion space; this report does not
classify a functional experiment as a documentation check. Any later execution
would need that nested reservation reconciled prospectively as well as the
construction gate. Increasing storage alone does not fix the mathematical gap.

## Preservation and completion

The isolated workflow reuses the corrected auditor and the immediately preceding
package's full seal/inventory chain. Only this new report, this package's exact
evidence/tooling roots and append-only status/traceability/issues are admitted.
Historical baselines are not regenerated. The required full audit, final inventory,
report readback and guard shutdown are recorded in this package's completion
evidence; the final result is appended below after execution.

**Next decision:** keep G1–G3 inactive. A supported continuation on this candidate
requires the exact committed-key/support/joint-simulation result above, supplied
as a reviewed construction argument against the actual oracle shapes. A patch
that only encrypts the terminal send or adds random padding is insufficient.
No alternative backend is selected. Stages 2–3 stay open; this is not complete
private authentication. Private verification stays fail-closed, isolation stays
stopped/unactivated and CPU proving stays paused. Proof ledger: two used, one unused.


### Completed preservation checkpoint

Scoped lint/format and identity checks passed. One complete audit exited **0**,
with 10,901 disjoint historical content comparisons and
10,936 identity-inclusive historical paths. The
audit inventory covered 11,434 entries with no missing,
unexpected or overlapping partitions. Guard time was **4.867 s**
(worker 4.527 s); peak cgroup-v2 `memory.peak` was
**47,054,848 bytes (44.875 MiB)**
under 256 MiB, including descendants and charged file-cache/kernel memory. No
resource breach occurred. Sampled aggregate worker-tree RSS was
63,827,968 bytes, a distinct metric. No temporary storage or
new build artifacts were used. Eight source blobs, 95 prior package seals,
362 comparison-dataset files and 21 source/binary files were checked.

The first lint command was refused before launch because the completion option
followed argparse's remainder position. Its diagnostic is retained; placing the
same flag before positional arguments admitted the unchanged completion-only
worker. No functional invocation, guard-policy relaxation or hidden retry occurred.
The successful static job and full audit are retained separately.

Final inventory/readback, exact completion time/storage and shutdown confirmation
are in `validation-closure.json` and `resource-closure.json` in this package's
evidence directory. Those closure records are authoritative after the final
readback; the audit's in-flight time reservation is not final consumption.
Accounting uses measured command durations plus explicitly conservative manual
source-review/documentation/bookkeeping charges, as in the inherited workflow.
Invocation ledger remains **974/1,050**; builds **10/13**. No masking fixture or
native correspondence result is claimed.

Final readback initially rejected a literal-text phrase split across a newline,
after successful inventory and seal checks. That failed job, original manifest
and inventory are preserved in `readback-correction.json`; only this report
appendix and exactly named repeat-readback outputs were added. No audit or native
test was repeated. Required explicit boundary: not complete private authentication.
