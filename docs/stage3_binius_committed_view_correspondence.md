# S3-BINIUS-COMMITTED-VIEW-CORRESPONDENCE-1

## Decision and authority

**Outcome: unresolved construction lemma; this bounded attempt is closed without
admitting a native prototype.** The ordered hidden-opening relation below is
well-defined algebraically. Neither of the two attempted commitment simulators
establishes its privacy for the actual wrapper prefix. The missing result is
**CV-ONLINE-SAME-OBJECT-1**: online simulation of the committed view, coupled to
extraction of the same inner and outer objects. Section 7 gives the precise
question, including the point at which each attempted argument stops.

This is a proposed construction, not an adopted profile or a security theorem.
Only manuscript Sections II–VIII and agreed clarifications are authoritative.
The external `PQ_DID_Binius64_Joint_Opening_Construction_Review.md` supplies
proposed mathematics assessed here. Its identity is recorded in
[opening.json](data/s3_binius_committed_view_correspondence_1/opening.json).
No source, profile, dependency, baseline or historical result is changed.
The complete PQ-DID/KYC/benchmarking scope and 31 October target remain; current
evidence does not support committing to full private-authentication completion
by that date. Stages 2–3 remain open.

The pinned commit is `441fbf51ff0bcb0bcd28f3f1b73f4954029e8577`, with tree
`544452a781fee0f9b262d4ecfdcc47326fb6974f`.
[The retained source map](data/s3_binius_committed_view_correspondence_1/retained-source-map.json)
records exact local paths and expected historical hashes, rather than copying or
acquiring sources. The retained Blueprint is the recorded 15 August 2026 version,
SHA-256 `0dfdfd2fb8066842e0c0914901930b6b4f276284983838ad40ff0f2e8f0d9803`.
The [embedding report](stage3_binius_embedding_correspondence.md), EC-01–EC-25 and
its correct completed `continuation-1/validation-closure.json` remain completed
Python-model evidence. Native comparisons remain unrun. The earlier accidental
external upload of an Aurora closure is not evidence against that completed
embedding package and is not repaired by regenerating its records.

## 1. Source correspondence and the actual view

Paths in this table are upstream names; the source map gives their retained local
files and identities. Findings are source inspection, not newly executed cases.

| Native path/function | Established correspondence and limitation |
| --- | --- |
| `prover/src/prove.rs`, `IOPProver::prove` | Observes public in/out words, commits the packed private trace, runs IntMul when the public constraint system requires it, and later queues the trace ring-switch opening. `send_public_claim(wiring_eval)` is an additional unencrypted value represented as public by this protocol; its public-function property remains a required premise. |
| `prover/src/protocols/intmul/prove.rs`; `iop-prover/src/logup_star.rs::prove_transparent` | Current IntMul uses one transparent power table with 16 logical variables and twelve limb columns. After looker-batching challenge eta, it commits the witness-dependent pushforward Y before later reduction challenges. It opens the **same oracle handle twice**, first against an equality operand, then the power-table operand. |
| `iop/src/logup_star.rs::verify_transparent`; `ip/src/logup_star/verify.rs::verify_reduction_transparent` | Verifier receives the same Y handle and requests both relations. The equality point is the returned `pushforward_eval_point`; the transparent reduction takes the **last `table.n_vars` coordinates** of `node_point`. Generic committed-table prefix conventions must not replace this suffix. |
| `spartan-prover/src/wrapper/zk_wrapped_prover_channel.rs` | Constructor commits the precommit segment first. `send_one` uses precommitted one-time-pad keys; `send_public_claim` bypasses that encryption. `prove_oracle_relation` directly sends its claim and queues the relation. `finish` constructs the replayed outer witness, proves it, then finishes the underlying channel. Stale comments about future key allocation do not override these operations. |
| `spartan-verifier/src/wrapper/zk_wrapped_channel.rs::verify_oracle_relation` | Reads a plaintext claim, allocates an in/out value and constrains equality with the inner computed claim. The private slots proposed below are **not implemented** here. |
| `spartan-prover/src/lib.rs::Prover::prove` | Commits outer private and Libra-mask oracles before mulcheck. Sends outer multiplication evaluations, a mask evaluation and precommit wiring evaluation; computes the private wiring target from the batched sum and public/precommit parts. Queues precommit, private and Libra relations. Dummy triples, decryption keys and masks have correlations; they are not interchangeable independent uniform witnesses. |
| `iop-prover/src/basefold/channel.rs::prove_batch_zk_basefold` | Existing batching is per oracle. Sends per-oracle companion claims, samples gamma, blends, runs per-oracle sumchecks and sends reduced evaluations before combining. The proposed single aggregate claim and genuinely joint relation need a different interface. |
| `iop-prover/src/fri/query.rs`; `iop-prover/src/merkle_channel.rs` | Original queries use `global_index >> log_lift`, paired original/companion leaves and separate folded cosets. Commitments write deterministic roots. Openings reveal leaves, authentication material and an optimal layer; `send_committed_vector` reveals a final folded buffer. This does **not** establish disclosure of every complete original blended vector. |
| `hash/src/lib.rs` | Default digest/compression/hash suite uses SHA-256. The trait names do not establish independent ideal leaf, node and transcript oracles, programmable concrete hashes, or a QROM composition theorem. |

The actual prefix/view to simulate includes roots, public statement observations,
inner ciphertexts, public claims, challenges, outer multiplication/wiring/mask
messages, opening/folding messages, the final combined codeword and authenticated
original/companion/coset openings. The current implementation's per-oracle claims
and reduced evaluations must also be accounted for when describing its view;
they cannot silently survive a proposal whose privacy argument assumes only an
aggregate target is revealed. Prover-local arrays are not automatically messages.

The proposed replacement keeps the full reference authentication predicate:
bounded ML-DSA-65 with exact certified message, expected key/instance/context,
holder-secret binding, disclosure/policy, and non-revocation for the same certified
identifier. Canonical parsing, range/overflow checks, malformed-input rejection
and sampler exhaustion remain inside their existing relation boundaries. No
hidden predicate is converted into public preprocessing. This package implements
none of those predicates in a new backend.

## 2. Exact ordered proposed construction

### Objects, embedding and fixed slots

Use the retained native GF(2^128) scalar convention and the component's verified
bit order. For oracle i let a_i be its logical vector and D_i its fixed decoder.
The proposed physical vector P_i has random even coordinates and logical odd
coordinates: P_i[2j]=rho_i[j], P_i[2j+1]=a_i[j], with strict logical zero padding.
Thus D_i P_i=a_i. Randomisable support is the even-coordinate subspace, not
arbitrary padding. The native encoder/basis/permutation correspondence is the
completed Python-model result; it is not a native privacy theorem. Logical field
vectors in the outer proof must not be mistakenly repacked as trace u64 words.

| Ordered identity | Logical object | Commitment point and binding |
| --- | --- | --- |
| O0 | K: outer precommit segment, including the existing key/dummy layout | Wrapper construction, before encrypted inner messages; the same decoded K participates in decryption and outer wiring. |
| O1 | Pi: canonical packed inner trace | After public in/out observation and before inner reductions; the same Pi serves the authentication trace and ring-switch operand. |
| O2, if IntMul exists | Y: the single transparent-table pushforward, sum of eta-weighted looker pushforwards | After eta, before logup reduction challenges; both transparent openings use this one identity. |
| OZ | z: outer private witness, including private terminal-claim slots | After the inner transcript, before outer mulcheck; the same z is used by outer constraints and joint selectors. |
| OL | L: Libra multiplication-check mask | Immediately after OZ, before outer mulcheck; retains its degree-two outer-mask role. |

Each root must bind the applicable original encoded P_i and companion Omega_i
with the same field/domain/dimension and paired-leaf convention. Omega_i denotes
the separate companion mask, not the logical Libra mask L. Independent uniform
companion coefficients are an **ideal premise** below; native RNG expansion and
its relation to all other randomness require their own justification.

Freeze terminal call slots in the compiled outer layout, never in caller-supplied
proof metadata. With IntMul, calls are j=0: Y equality, j=1: Y power-table,
j=2: trace ring-switch. Without IntMul only the trace call remains, at j=0.
Write s_j=`layout.private_terminal[j]`. These are exact symbolic layout selectors;
numeric offsets depend on the compiled instance, which this package does not
generate. The layout identifier must bind that mapping. Equality operands use
the explicit transparent returned point, without reversal by a generic helper.

The outer constraints enforce z[s_j]=c_j, where c_j is the inner verifier's
computed terminal claim using its decrypted messages and recorded challenges.
They do not allocate c_j as a public in/out value or send it individually. Queue
the following **two-object relation** for each call:

    <P_i, D_i^T t_j> + <PZ, DZ^T e_sj> = 0.

Subtraction equals addition in this field. The selector has physical position
2s_j+1. Both IntMul rows use O2 and different slots in the **same OZ**; the trace
row uses O1 and that same OZ. This identity follows directly from transposing the
decoder. It does not by itself supply a secure opening protocol.

Retain the outer precommit/private/Libra relations with their public targets
b_pre, b_priv and b_libra. Their computation from outer messages, public inputs
and challenges stays constrained. Do not hide only the trace target while
exporting either IntMul target. Do not remove outer public messages from the
simulator's view merely because their claims are not terminal slots.

### Ordered challenges and batching

The full proposed transcript order is:

1. Bind public statement, relation/layout identifiers and canonical context;
   commit O0, then observe inner public inputs and commit O1 as above.
2. Execute the existing encrypted inner protocol. If needed, sample eta,
   commit O2, then run its reduction. Record terminal operands and private slots
   in call order. Existing challenge dependencies and public claims remain.
3. Construct and commit OZ and OL. Run the outer protocol, including its
   multiplication messages/challenges and wiring batching challenge mu. These
   determine outer opening operands and public targets.
4. Bind all ordered roots, oracle handles, dimensions, field/domain identifiers,
   fixed selectors, public operands/targets and the complete preceding
   transcript. Sample a **fresh global** lambda_J. It is neither eta nor mu nor
   a replacement name for the existing per-oracle batching implementation.
5. Order rows as terminal calls followed by outer precommit, private and Libra.
   For row j write sum_i <P_i,u_ji>=b_j. Form
   U_i=sum_j lambda_J^j u_ji and B=sum_j lambda_J^j b_j. Each term of a row uses
   exactly the same coefficient. Terminal rows have b_j=0.
6. Send only Sigma=sum_i <Omega_i,U_i>, **before** sampling gamma. Set
   V_i=(1-gamma)P_i+gamma Omega_i and S=(1-gamma)B+gamma Sigma.
7. Prove the genuinely joint relation sum_i <V_i,U_i>=S, with subsequent
   sumcheck/folding challenges theta. Do not first reveal individual original
   targets, companion claims or per-oracle reduced evaluations under an argument
   that assumed only the aggregate. Every later message needs joint simulation.

This specifies semantic descriptors, not an approved wire-format change.
Same handles must propagate through every fold and authenticated opening; merely
including equal names in two host structures is not cryptographic binding.

Different dimensions need an explicit common-domain map. Semantic zero extension
is one precise algebraic description: extend both operands with the high-bit
zero-selector Z. Their product at a non-Boolean sumcheck point is
Z(high)^2 V(low)U(low), **not** Z(high)V(low)U(low). The existing native FRI
lift/repeat and query shifts are different maps. An implementation must prove
the transport between them, preserve ordering and include degree changes; this
report does not substitute a naive zero-extension into native BaseFold. That
transport is an additional premise of CV-ONLINE-SAME-OBJECT-1.

At gamma=0 the uniform-blend simulation fails; at gamma=1 the original-relation
coefficient vanishes. Under a uniform field challenge each named value has
probability 1/|F| in the stated ideal game, not an overall security guarantee.
This proposal does not adopt resampling or silently remove exceptional events.
For gamma not 0 or 1, alpha=gamma/(1-gamma) converts the affine blend into a
scaled P+alpha Omega. It changes the conditional challenge domain/distribution;
all operands, targets and folds need consistent scaling. A theorem for additive
blending does not transfer merely by renaming gamma.

## 3. What the online algebraic argument actually proves

Concatenate the oracle vectors and write A(X)=sum_i <X_i,U_i>. Condition on a
public prefix for which A and B are fixed, A(P)=B, and Omega is uniform and
independent of P **after conditioning on that prefix**. Independence must include
every outer message and commitment information accessible in the game.

If A is nonzero, Sigma=A(Omega) is uniform. Conditional on Sigma=s, Omega is
uniform on A(Omega)=s. For any gamma!=0 the affine map
Omega -> (1-gamma)P+gamma Omega is a bijection onto

    {V : A(V)=(1-gamma)B+gamma s}.

The distribution depends on P only through B. This supports an online procedure
that sends uniform s before gamma and then samples this coset. Gamma may depend
on s and independent public coins if the stipulated conditional distribution is
preserved. When A=0, consistency requires B=0 and s=0; the simulator must handle
that case rather than invert a nonexistent coefficient. For an inconsistent
row this is not a valid-witness privacy argument.

These are elementary finite-dimensional linear-algebra facts, not assertions
about the actual committed prefix. Even computationally hiding roots cannot
simply be erased from a statistical conditioning argument. If the transcript
already exposes additional Omega-dependent forms, the conditional coset is
smaller. Ciphertexts with committed keys and a correlated outer proof require
a joint argument before importing the independence premise.

## 4. Two attempted commitment simulators and their stopping points

### SIM-A: commit concrete dummy objects, then adapt

Attempt: choose arbitrary dummy P0 and Omega0, run the real deterministic Merkle
committer at every required early point, and later use the coset simulator to
make the outer claims and hidden terminal relations consistent.

The roots now bind concrete vectors. A later coset sample generally is not the
blend of those vectors, and the outer witness may not satisfy the fixed public
statement and decrypted transcript. Changing vectors while retaining the roots
would require breaking binding or an equivocation mechanism absent from this
interface. Alternatively the simulator must sample a complete constraint-valid
dummy tuple without the witness, with the right conditional distribution. No
such sampler follows from the aggregate lemma. This is a failure of this
simulation strategy, **not a proof that zero knowledge is impossible**.

### SIM-B: early ideal roots and lazy programmed openings

Attempt in an explicitly idealised programmable-hash game:

1. At each commitment point, supply a root and consistent already exposed tree
   anchors without fixing an entire witness vector. Simulate encrypted inner and
   outer messages using a hypothetical joint outer-prefix simulator S_outer.
2. Once operands are fixed, send Sigma, receive gamma and sample V in the
   aggregate coset. Generate sumcheck/fold messages from the corresponding
   conditional distribution.
3. At each query choose original/companion leaves from the conditional embedding
   fibre, respecting all earlier leaves, folded values and constraints. Extend
   consistent authentication paths/optimal layers to the early roots, programming
   only fresh ideal hash inputs. Repeated positions must return identical data.

This describes how roots *would* precede challenges, but steps 1 and 3 remain
unproved. S_outer must preserve key/ciphertext, dummy-triple, Libra and terminal
slot correlations, and must work for adaptive challenges. The aggregate lemma
does not produce S_outer. Programming must handle adversarial earlier hash
queries, shared tree nodes, exposed optimal layers, later codeword revelation and
all transcript uses of the same hash suite. “Choose a random root” is not a
complete simulator for an already queried deterministic hash function.

Concrete SHA-256 is not programmable. A classical random-oracle proof would need
an explicit hybrid and a bounded bad event for programming an input already
queried or otherwise fixed. A QROM adversary makes classical query-table freshness
insufficient. Neither replacement argument is established by the retained code.

### CV-RANK-1: a more precise necessary entropy calculation

The following refinement is newly derived here; it is conditional algebra, not
an implementation result. In a linear-observation ideal game, write
P=J a+S_r r, where a is fixed logical data and r is uniform in F^m. Suppose all
conditioned linear observations of r are exactly M r=d, with a nonempty fibre.
Then r is uniform on that affine fibre. For an additional original-leaf
observation L P, the residual rank is

    d_L = rank([M; L S_r]) - rank(M).

Its conditional distribution has |F|^d_L equiprobable values; the largest point
probability is |F|^(-d_L). A single field symbol has d_L at most one. Wider leaves
require their actual row block. For two logical candidates, equal observation
distributions additionally require the logical offset difference H J(a-a') to
lie in image(H S_r). A rank count alone is not this image condition.

Now condition also on the **whole** V and nonzero gamma. For each original leaf,

    E(Omega)(x) = (E(V)(x) - (1-gamma) E(P)(x))/gamma.

The paired original/companion leaf has the same residual entropy as the original
leaf, not twice as much. This rules out counting a pair as two independent field
symbols of fresh entropy in a root-programming argument. It makes no bit-security
claim about SHA-256. If the only previous restrictions are q distinct scalar
evaluation rows, and the random part is the degree<m polynomial established by
the embedding model, a fresh distinct row has rank increment one when q<m and
zero when q=m. Actual cosets, repeated/lifted indices and outer linear claims
must be stacked into M. Nonlinear outer constraints need not define an affine
fibre at all, so this calculation cannot be applied to them without a new step.

Under the *additional* ideal-game premise that an unqueried leaf input retains
this min-entropy conditional on the adversary's entire state, a classical
guessing union bound could charge Q guesses by Q/|F|^d_L. At d_L=0 it is useless.
This is not a bound for the actual protocol: root observations, internal nodes,
adaptive outer messages, different hash roles and quantum queries remain outside
the premise. In particular, m>q alone neither verifies M nor proves freshness.
The result identifies exactly what a proposed lazy-opening simulator must prove,
instead of assuming “enough random coordinates”.

## 5. Entropy saturation and the weaker native view

The review's counterexample is correct **for its stronger view**. Let the random
polynomial part have degree<m. Given m distinct original codeword evaluations,
the whole V, a nonexceptional gamma and two known candidate logical tuples with
the same public aggregate target, subtract each candidate's known logical
contribution. Interpolation uniquely gives that candidate's random polynomial,
hence P and Omega=(V-(1-gamma)P)/gamma. The observer can compute each complete
paired codeword and deterministic commitment root. Distinct candidates are
distinguished except for commitment collisions or identical committed objects.
Candidate existence and the specified disclosed view are explicit hypotheses.

This refutes extending a root-free uniform-symbol lemma to this stronger view
at q=m. It is neither an executed attack nor a demonstrated native distinguisher.
The native final folded/combined vector is a linear image C(V_0,...,V_k), with
additional reduced evaluations and authenticated leaves; it is not automatically
the tuple of complete original V_i. Failure of privacy for a stronger view does
not imply failure for its projection. Conversely, that projection is not thereby
safe: its rows, outer messages and query observations must enter the joint
conditional-distribution argument. No rank for the complete actual view has
been established. No mask dimension or privacy parameter changes are adopted.

## 6. Same-object extraction and security applicability

Extraction is separate from simulation. A needed joint-opening extractor must
produce low-degree original and companion objects consistent with the ordered
roots and query answers. The outer extractor must return **the same OZ**, decoded
with the fixed layout, that supplies all terminal slots. The inner trace and Y
must be the same O1 and O2 used by their relation checks. Padding, domains and
canonical decoding are part of this statement, not post-extraction advice.
Merkle collision resistance alone supplies neither knowledge nor low-degree
proximity extraction.

For fixed residual row errors epsilon_j determined before lambda_J, a nonzero
polynomial sum_j epsilon_j lambda_J^j has at most r-1 roots for r rows. For fixed
original/companion residuals before gamma, their affine combination has at most
one root unless identically zero. These facts explain why the commitment and
challenge order matters. They do not establish that the native extracted objects
are fixed at the required times, nor supply an overall soundness bound.

Invoking separate outer and opening extractors can yield witnesses from different
forks. Rewinding an outer challenge can change z and its root; rewinding lambda_J
or gamma after all roots must retain a compatible prefix. The required theorem
must compose extractors at those forks, or provide extractable commitments and
an applicable composition argument that identifies one common OZ. Honest-run
host equality of oracle handles does not prove this against malicious provers.

| Result/claim | Status for this proposal |
| --- | --- |
| Decoder transpose, affine-coset distribution, CV-RANK-1, fixed-polynomial root facts | Derived elementary implications under the stated hypotheses; no new execution and no complete protocol theorem. |
| Blueprint section 6.3 / Appendix D masking and equality-weighted checks | Relevant idealised ingredients. Their public-claim, distribution and protocol premises must match; unspecified constants in asymptotic losses do not yield precise security numbers here. |
| Blueprint wrapper sections 7.1–7.3 | The proposed private terminal slots and joint zero relations differ from the retained terminal-opening path. Section 7.2's commitment-simulation obligation is not discharged by library support. A matching joint outer-prefix simulator has not been shown. |
| BaseFold / classical IOP-to-argument and Fiat–Shamir routes in the retained assessment | Conditional candidates only. Need matching lift, oracle, commitment, query and extractor hypotheses plus an actual reduction for this modified protocol. No theorem application establishing this composition was completed. |
| Other previously recorded abstract-level compiler/VEIL references | No additional theorem text acquired; do not upgrade the earlier evidence level or claim their premises were checked here. |
| Classical zero knowledge and knowledge soundness for the modified complete view | Unresolved, even before the requested quantum goal. |
| Fiat–Shamir adaptive security, QROM extraction/simulation | Unresolved. Classical rewinding and classical programmable-root sketches do not transfer automatically. |
| Concrete SHA-256, RNG replacement, finite parameters and adaptive Delta_tail | Separate open obligations. A field size or hash output size is not an overall security level. |

The privacy proof would also need adaptive-query conditioning and probabilities
for exceptional challenges, commitment/programming failures and every reduction
at its actual query budget. This work does not sum unproved error terms into a
privacy or extraction claim. It does not establish full Aurora correctness,
Binius64 correctness, W3C interoperability or complete private PQ-DID security.

## 7. Precise unresolved result and stopping decision

**CV-ONLINE-SAME-OBJECT-1.** For the ordered five-oracle instance above (four
without IntMul), with fixed public relation/layout and the native field encoder,
give an efficient online simulator taking only the public statement that:

- emits each commitment at its prescribed time, before dependent challenges;
- simulates the correlated encrypted/outer prefix and aggregate joint opening;
- answers adaptive original/companion, coset, final-vector and authentication
  disclosures consistently, with a quantified hash-oracle programming event;
- proves the conditional image/rank or other distribution property after that
  **whole** prefix, including wider leaves and the real lift/permutation;
- composes with an extractor yielding one common OZ and the same O1/O2 objects
  for every hidden terminal relation and the outer constraints.

The deliverable needed from a specialist is a proof with an explicit oracle model,
challenge order, simulator/extractor access, query budget and exceptional-event
bounds, **or an actual-view counterexample with the specific required commitment
or protocol change**. CV-RANK-1 gives a local condition to check, not permission
to assume the missing prefix lemma. If only a classical/ideal-oracle result is
obtainable, its later quantum/concrete-hash requirements must be stated separately.

What was attempted is concrete: SIM-A fails at adaptation of already binding
roots; SIM-B depends on an unconstructed correlated prefix simulator and an
unproved fresh-programming/conditional-entropy argument. No source finding
supplies either. The saturation calculation explains one boundary where the
stronger-view extension is false, but does not settle the actual native view.
Separate extraction analysis additionally identifies the shared-root/fork
compatibility requirement. These are the substantive results of this attempt.

The bounded attempt ends here. No speculative overlay, new mask dimension,
native implementation, general backend review or subsequent package is launched.
Reopening implementation requires the specific construction correspondence above,
not additional unchanged encoder tests. Ordinary private verification remains
fail-closed; private proving and isolation remain paused. Production-security,
adaptive-tail and complete knowledge/privacy obligations stay open, including
the historical unresolved acquisition-memory observation. Proof ledger: two used,
one unused.

## 8. Evidence, accounting and preservation checkpoint

The opening ledger is 686.8259277794259 implementation seconds, of which
243.43557213738308 are outside KYC. This package prospectively allocates at most
180 of those seconds, with 30 reserved for completion. KYC's
443.3903556420428 seconds (including its protected 300 seconds) and the separate
11.510943178986167 analysis seconds are unchanged. Accounting follows the
established convention: 90 conservative operator seconds for source inspection,
mathematical work, authoring and direct bookkeeping, plus measured guarded checks
once. The operator charge is not a measured CPU or wall-time statistic.

The new 1 MiB evidence envelope fits the 6,121,639-byte opening shared headroom
while preserving 2 MiB for shared completion. Opening cumulative evidence is
35,372,722 of 41,943,040 bytes. No artifact allocation, acquisition, installation,
functional invocation, build or proof is used. The unchanged ledgers are
1,165/1,168 invocations and 10/13 builds; unused embedding corrective slots are
not repurposed. Comparison point v1, its 276 observations, later KYC measurements,
all historical failures and the closed Aurora experiments remain protected.

The package reuses the existing resource guard and corrected preservation auditor.
The four planned non-functional commands are `run.py quality`, `prepare`,
`full-audit` and `readback` in the package evidence directory. They retain a
256 MiB cgroup-v2 aggregate `memory.peak` scope, swap zero, plus sampled process
tree RSS, one worker, two CPUs, four controlled children, existing file/output/
temporary/storage checks and bounded command reservations. The external monitor
also has its existing address-space cap. These are documentation/static and
preservation checks, not new mathematical or cryptographic experiments.

The final resource and validation closures record actual checkpoint outcomes.
The new report and only three named historical documentation appendices are
permitted; their historical prefixes remain hash-protected. The completed
embedding report, sources, manifests and closures retain strict full-file seals.
No baseline, source seal, expected historical entry or permitted content scope is
regenerated to make this checkpoint pass.


### Completed comparison audit and finalisation

The single complete preservation audit passed, exit **0**, in **5.025703 seconds**.
It completed **10,901** disjoint historical content comparisons and **10,936**
identity-inclusive paths; no content discrepancy, missing protected entry or
partition overlap was reported. The audit-time inventory contained **12,472**
paths. Documentation/link checks and report generation/readback within the audit
passed. The enclosing guard passed: cgroup-v2 `memory.peak` **48,558,080 bytes**,
sampled tree RSS **63,836,160 bytes**, swap peak zero, no memory-limit/OOM event,
under the unchanged **268,435,456-byte** ceiling. The cgroup metric covers the
worker and descendants, including charged anonymous, file-cache and kernel memory;
the external monitor is outside that cgroup. The two metrics have different
accounting scopes and must not be added or treated as interchangeable.

Static/lint/format and sealed-input checks passed in **0.327315 seconds**; inventory
preparation passed in **0.810629 seconds**. This is zero functional validation
invocations. The final inventory, sealed-report readback and termination evidence
are completed by the package's `validation-closure.json`; exact final resource
usage and remaining balances are in `resource-closure.json`. Neither earlier
comparison-only results nor this paragraph alone substitutes for that closure.

The construction result is an unresolved lemma, not a supported implementation
release. The completed embedding results and unresolved acquisition-memory
observation are preserved. No implementation/proof follows this package.
