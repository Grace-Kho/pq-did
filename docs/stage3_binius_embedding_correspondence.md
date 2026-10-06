# S3-BINIUS-EMBEDDING-CORRESPONDENCE-1: prepared component package

**Decision: the addendum justifies an isolated component-only correspondence
experiment. The native/private-protocol route remains unadmitted.** Its bit-order,
decoder and rank identities agree with the retained source contracts. Its restricted
joint-view lemma is valid under the independence and visibility conditions below;
it is not a security theorem for the complete protocol. No implementation, test,
native build, source acquisition or proof was run during this preparation.

The proposal is one bounded package, not another backend review. The executable
scope presently supportable is a layout/operand adapter, independent polynomial
reference, source-faithful encoder model and exact synthetic checks. Native encoder
comparisons remain explicitly **unrun**: the retained dependency requirements are
not a resolved lock/checkout or a demonstrated toolchain. No Aurora build allowance
is silently transferred. The final approval request is limited accordingly.

## Authority, retained evidence and opening balance

The input is the user-supplied
[construction addendum](../PQ_DID_Binius64_Native_Embedding_Analysis.md), recorded
by exact length/SHA-256 in
[review-identity.json](data/s3_binius_embedding_correspondence_1/review-identity.json).
It is a proposal, not approval to change the construction. The pin is
`441fbf51ff0bcb0bcd28f3f1b73f4954029e8577`, tree
`544452a781fee0f9b262d4ecfdcc47326fb6974f`.

The [joint-opening decision](stage3_binius_joint_opening_construction.md), G0,
the two prior reviews, all source snapshots, baseline datasets and historical
failures remain unchanged. In particular, the old acquisition's lifetime RSS
279,449,600-byte observation is still unresolved; source checksums do not settle
its memory compliance. No new acquisition was attempted here.

Only manuscript Sections II–VIII and SPEC-001–004 remain authoritative. This is
not complete private authentication. Production, BC-1, signed/canonical encodings,
the KYC baseline, comparison point v1 and all 276 measurements are preserved.
The 21 full-relation checks remain unrun. Stages 2–3 stay open, Binius/proving and
isolation stay paused, private verification stays fail-closed, and the proof ledger
remains two used/one unused. Full scope and the 31 October target are unchanged;
this component supplies no evidence supporting a complete-delivery commitment.

The live predecessor is
`docs/data/s3_binius_joint_opening_construction_1/resource-closure.json`:

| Resource | Opening balance; no reset |
| --- | --- |
| Analysis | 26.2521356981853 seconds; this preparation uses this allowance only |
| Overall implementation | 810.6179695621813 seconds |
| KYC allocation | 443.3903556420428 seconds, including protected 300-second completion reserve |
| General implementation outside KYC | 367.2276139201385 seconds; proposed component must use this portion |
| Invocations / builds | 1,140/1,146; 10/13. No execution scope follows from unused capacity |
| Cumulative evidence | 34,160,588 / 41,943,040 bytes |
| Shared evidence headroom | 7,333,773 bytes, including unchanged 2,097,152-byte completion reserve |
| Artifacts | 58,966,547 / 134,217,728 bytes |

## Source and mathematical assessment

The source anchors below are paths at the unchanged pin. The retained additional
ten files total 174,970 bytes. Their seals and the original encoder/channel
snapshots are reused, not regenerated.

| Claim in the addendum | Source correspondence and limitation |
| --- | --- |
| Raw index `j` uses novel-basis coefficient `rev_d(j)` | `math/src/ntt/subspace_polys.rs:39–68` specifies codeword-domain constants, reversed truncated factors and the lane identity. `reed_solomon.rs::encode_batch` actually bit-reverses, repeats and invokes the NTT with early/late skips. `bit_reverse.rs::reverse_bits` and scalar reference path agree. |
| `rev_(ell+1)(2j)=rev_ell(j)`; odd indices add `2^ell` | Exact bit identity: the new low bit becomes the highest reversed bit. No appeal to a numerical experiment is needed. |
| `F_P=R+W_ell G` | Each native novel-basis polynomial has degree equal to its index. The high bit factors out `W_ell`, giving the displayed identity with random even/data odd coordinates. This uses the constants for the **physical codeword domain**, not an arbitrary previously cached logical domain. |
| Companion lanes remain distinct | Source lane formula is `out[(x<<b)|lane]=E(lane_msg)[x]`, with input base `rev_b(lane)<<log_dim`. In its notation `b` is **log batch size**, so there are `2^b` lanes. For the two-lane case `b=1`, `P || Omega` yields `[E(P)[x],E(Omega)[x]]`; it is not a second even/odd embedding. |
| New selector is low variable `y0` | The raw physical address is `2j+1`; its multilinear selector is `y0`. BaseFold `channel.rs:344–347` reverses sumcheck binding-order challenges before using variable-index order. The adapter must label/convert that order, not use the first sampled challenge as `y0`. |
| Existing native tests express the same identities | `tensor_row_matches_reed_solomon_encoding` and `interleaved_lanes_are_independent_codewords` occur in `subspace_polys.rs`. Their definitions are source evidence only; they were not executed here and are not imported as passing results. |

Let `k=2^d`, `m=2^ell>=k`. Put fresh uniform independent `rho_j` in `P[2j]`
and logical `a_j` (zero for `j>=k`) in `P[2j+1]`. Decoding selects the first
`k` odd coordinates. Therefore `DJ=I`, `DS=0`, and for **every** physical vector
`<P,D^T t>=<DP,t>`. The succinct operand is

`U(y)=y0 * t(y1,...,yd) * product_(j=d+1..ell)(1-yj)`.

All products and indices have their stated inclusive ranges; the high product
is empty when `ell=d`. For `ell>d`, `G_bar_a` uses the *ell-bit* raw index map.
It must not be replaced by the original length-k encoded polynomial merely
because the added logical values are zero. This distinction affects expected
codewords, while decoder/operand transport preserves the logical opening.

The normalised novel polynomials `X_0,...,X_(m-1)` have distinct degrees and
nonzero leading coefficients. Thus `R` is uniform on all polynomials of degree
below `m`. Evaluation on any `s<=m` distinct field points is surjective by
interpolation; each fibre has equal size. Adding the fixed `W_ell G` translates
a uniform image. This proves uniform original symbols for these query sets,
including zero (`F_P(0)=rho_0`). It resolves the prior **tail-support** obstruction
for this different embedding, not the implementation gap in the unchanged pin.

Adaptive original queries can depend on earlier answers, the restricted folded
view and independent public randomness. Induction on distinct queries uses the
conditional uniform fibre; repeats return their cached value. Queries influenced
by commitments, hash queries or other witness-correlated data require a different
argument. The number to bound is actual distinct original field evaluations per
oracle after lift and leaf extraction. For the existing two-lane leaf each lane
exposes one position; later folded cosets are separate observations. A future
layout/FRI change must recompute this bound, not inherit an old `q` by name.

## Precise status of the restricted joint-view lemma

The following hypotheses are essential, not optional implementation details:

1. Dimensions, fields, encoders, public operands `t_i` and aggregate target `B`
   are fixed. Logical tuples satisfy `sum_i<a_i,t_i>=B`. Comparing witnesses uses
   the same public data. More generally one may condition on a public prefix only
   after establishing the same independence properties **conditional on it**.
2. Embedding vectors `rho_i` are uniform, fresh and mutually independent, independent
   of logical messages and operands. Companion vectors `Omega_i` are uniform and
   independent of every `P_i`. Outer OTPs, dummy triples or correlated PRG outputs
   do not automatically meet this premise.
3. `gamma` is fixed nonzero, or independently sampled and then conditioned on
   that value. Every oracle uses that same affine coefficient and the correctly
   transported operand. This is not a simulation of choosing gamma after a
   previously committed/disclosed mask claim.
4. The exposed mask claim is **only the aggregate** `Sigma`; the view includes
   whole `V_i`, paired original/companion query values and functions of `V_i`
   and independent public randomness. There are at most `m_i` distinct original
   positions per oracle. No commitment roots, authentication paths or additional
   mask-dependent messages are present.

Under these conditions, `Omega_i -> V_i=(1-gamma)P_i+gamma Omega_i` is a
bijection for every fixed `P_i`. Hence `V_i` are uniform and independent of `P_i`.
The identity

`Sigma=(sum_i<V_i,U_i>-(1-gamma)B)/gamma`

then proves that the aggregate reveals no further information given this view.
The paired answer follows by linearity of the same encoder. The rank argument
supplies conditional original answers, including adaptively selected ones in
this restricted view. This establishes the addendum's **distributional algebraic
lemma**, not a complete online protocol simulator or extraction theorem.

There is a concrete reason not to substitute native per-oracle claims. For
`gamma != 0,1`, whole `V_i` plus individual `sigma_i` determines

`<a_i,t_i>=(<V_i,U_i>-gamma*sigma_i)/(1-gamma)`.

Tuples can have equal aggregate `B` but different individual targets. Their
individual-claim views then differ. This is a counterexample to extending this
particular lemma to arbitrary individual mask claims, not a statement that an
actual native transcript reveals whole `V_i` or an executed attack.

At gamma zero the simulator formula fails and the original vector is unmasked.
At gamma one this privacy calculation still works, but the blend contains no
original-relation binding. No rejection sampling rule, exception probability
budget, Fiat–Shamir argument or overall security level is adopted here.

## One implementation deliverable, with explicit ownership

Proposed isolated root: `experiments/binius_embedding_correspondence_1/`.
Evidence/results: `docs/data/s3_binius_embedding_correspondence_1/execution/`;
the present preparation records remain immutable. No production/pinned file is
edited, no private key/witness is used, and nothing connects to the normal proof
acceptance interface.

| Proposed file | Contract and completion check |
| --- | --- |
| `layout.py` | Immutable versioned `EmbeddingSpec(oracle_id,k,m,rate,field_encoding,point_order)`; guards before allocation; `embed`, `decode`, `transport_operand`, `eval_transported_operand`; exact dimensions/field elements/expected ID. No caller metadata overrides trusted expected spec. |
| `field_model.py` | Bounded GF(2^128) arithmetic with an explicitly derived bridge to the pinned GHASH scalar representation. A u128 label alone is not a representation proof. Fail admission if the bridge cannot be derived from the approved files. |
| `polynomial_reference.py` | Independent field arithmetic path and direct subspace-polynomial products/interpolation; derives `W_j` from the codeword-domain basis. No call to candidate embedding, NTT, bit-reversal or expected-output helpers. |
| `encoder_model.py` | Source-faithful scalar permutation/repeat/butterfly model using the retained convention. Label all its executions **Python model**, never actual native encoder execution. |
| `cases.py`, `run.py` | One invocation per fixed row in the matrix; guard record, inputs/expected/actual, allocated dimensions, time/memory/bytes and stop outcome. Routine affected corrections retain the original failed case and charge a targeted rerun. |
| `native/README.md` | Required actual target/callers and admission gate; N-01–N-04 explicitly unrun. No mock library, compiler invocation or implicit dependency installation. |
| Result report and execution ledger | Individual results, source provenance, component-only resource measurements and the full-protocol gap map; no authentication performance projection. |

The component selects **strict physical padding**: honest odd positions past `k`
are zero; its admission API rejects nonzero odd padding. The decoder's algebraic
identity remains true for arbitrary vectors, but strict admission is a separate
check. If this policy is ever adopted in a proof, those private zero checks must
be constrained inside the relation; a host-only check is insufficient. This does
not adopt a different credential language or allow arbitrary physical encodings
in production.

External vectors have exact lengths and canonical field encodings, no Boolean-as-
integer coercion or silent reduction of malformed words. The random-vector input
is separate from the logical vector and companion mask. Synthetic deterministic
fixtures exercise identities only; they do not provide evidence of entropy,
freshness or production RNG security. An injected entropy failure must release
no physical message.

Only these missing source files are proposed for acquisition: the four field/
portable-representation files and eleven logup helper files enumerated by exact
path, blob ID and length in
[proposed-source-allowlist.json](data/s3_binius_embedding_correspondence_1/proposed-source-allowlist.json)
(15 files, 176,779 bytes). Fetch at the unchanged commit, verify size and Git blob
before use, retain SHA-256. No full archive, lock resolution, downloaded script,
dependency or toolchain installation. Additional required sources are a stop,
not an implicit wildcard permission. The earlier memory observation requires
prospective acquisition measurement in a 256 MiB cgroup established **before**
starting the interpreter; do not reuse lifetime RSS as a worker-scope measurement.

Inspect logup to enumerate actual committed objects and both terminal operands;
do not assume table transparency makes the pushforward public. Native scalar
representation and multiplicative-generator constants must be justified before
claiming the 16-variable table-operand check corresponds to the pinned contract.

## Fixed checks and expected-value provenance

The complete 25-row matrix is in
[execution-plan.json](data/s3_binius_embedding_correspondence_1/execution-plan.json).
Every row is one fixed fixture, not a hidden parameter sweep; whole-vector
comparison within one fixture is its output check. Any extra parameter tuple,
probe, repeat or failed attempt consumes another invocation. At most three
targeted corrective reruns are proposed, for 28 invocations total.

| IDs | Meaningful coverage |
| --- | --- |
| EC-01–06 | `(k,m,r)=(1,1,2),(2,2,2),(2,2,4),(4,4,2),(2,4,2),(4,8,4)`. All codeword positions including zero and both companion lanes; compare the model to independent `R+W_ell G`. |
| EC-07 | Arbitrary admitted physical vector, decoder and transported dot-product identity |
| EC-08–13 | Wrong parity, wrong point-order label, non-power-of-two dimension, missing randomness, wrong expected oracle ID, nonzero odd padding; rejection before release/allocation where applicable |
| EC-14–16 | Full-vector/succinct operand agreement with and without padding; logical terminal selector `s=1` at physical coordinate 3 |
| EC-17–18 | Both IntMul operands with the actual 16 logical variables; a point with one non-Boolean coordinate permits independent two-address expansion without materialising the 65,536-entry oracle |
| EC-19–21 | Exact small evaluation rank including zero, repeated-position caching/distinct accounting, and rejection when distinct original query count exceeds `m` |
| EC-22–25 | Fixed nondegenerate aggregate-mask identity; expected individual-mask counterexample; gamma-zero rejection; gamma-one privacy identity explicitly labelled as lacking original-relation binding |

The public power-table operand uses the pinned multiplicative generator and
`product_j(1+y_j*(g^(2^j)-1))`; the independent expectation expands the two
selected Boolean addresses instead of calling that candidate factorisation.
The equality operand similarly uses independent address weights. These are
operand checks, not a complete IntMul execution or auxiliary-oracle proof.

The wrong-order case checks the explicit order tag/conversion boundary; an API
cannot magically recognise arbitrarily permuted unlabelled field values. The
oracle-ID case checks local descriptor consistency, not cryptographic binding.
Finite rank checks corroborate implementation of an already stated symbolic
lemma, not proof of zero knowledge or universal native correctness.

Success requires all admitted fixed checks, preserved failures/corrections,
independent expected values, exact scope and one complete preservation checkpoint.
A native pass must never be inferred from model success. Missing native
prerequisites, mathematical disagreement and resource stops are concrete outcomes,
not reasons to substitute easier tests or increase limits automatically.

## Native admission and separated security obligations

No Binius build is requested now. Recorded requirements specify Rust 1.98.1,
edition 2024, no retained Cargo.lock and no verified transitive dependency closure.
The prepared native gate requires a full pinned checkout matching the retained
files; locked dependencies/checksums/features; available compiler/CPU support;
reviewed build scripts; a resource-admitted build and named actual
`ReedSolomonCode::encode_batch`/`NeighborsLastSingleThread`/`Ghash128b` callers.
None follows from the three unused build slots. N-01–N-04 are a concrete small
native comparison set in the plan, **unrun, unreserved and outside the requested
execution scope**. Native build/installation admission would require a concrete
separate approval if these prerequisites become available; it is not a fallback
action within this component package.

| Obligation | Effect of the addendum / remaining condition |
| --- | --- |
| Embedding and original-query rank | Explicit source-consistent proposal and symbolic rank argument; executable correspondence unrun |
| Terminal joint opening | Must constrain the terminal wire in the same outer committed object, transport selector to `2s+1`, bind identities and batch distinct equations soundly. Current per-oracle claim API remains unsuitable |
| Commitment and online simulation | Need roots, paths, hash queries, mask-claim-before-gamma order and correlated outer transcript simulated jointly. Neither the rank lemma nor Section 5 supplies this |
| Outer masks and IntMul | OTP/precommit correlations, nonlinear dummy triples, Libra disclosures and all logup objects/claims must fit the actual dependency graph. Helper inspection supplies a gap map, not a simulator |
| Extraction / soundness | Same-object extraction, malicious auxiliary values, heterogeneous lifting, batching order and exceptional challenges require an applicable theorem or new argument |
| Quantum / concrete security | QROM knowledge/privacy, concrete hash replacement, finite parameters, adaptive tail and component advantages remain unresolved; no overall bit-security number |

`B64-JOINT-001` is narrowed, not closed: a candidate embedding/rank argument now
exists, while joint protocol simulation/extraction remains open. `B64-ZK-001/002`
remain findings about the unchanged implementation. The Aurora closure and
`AURORA-BRIDGE-001` are not altered. No commitment or terminal-protocol patch is
part of this request.

## One consolidated prospective approval request

Request authorisation for the above isolated adapter/reference component and
the exact 15-file source inspection, with routine in-scope corrections and the
following allocation. **All execution remains inactive until approved.**

| Item | Proposed allocation/amendment |
| --- | --- |
| Implementation time | Reallocate **200 seconds** from the existing 367.2276139201385 seconds outside KYC. No cumulative increase. KYC and its 300-second reserve remain untouched. Nominal overall balance after full use: 610.6179695621813 seconds |
| Phase caps | 30 admission/source; 70 adapter/reference/gap map; 50 fixed validation; 20 routine corrections; 30 preservation/reporting/cleanup. Total 200; final 30 is protected inside the cap |
| Invocations | Allocate existing six unused slots plus **22 additional**, ceiling **1,146 → 1,168**. Maximum 28 new invocations: 25 fixed cases plus three targeted reruns, individually charged |
| Builds / proofs | **Zero**; existing ledgers unchanged. Native comparisons are explicitly unrun |
| Memory / concurrency | Existing 256 MiB tool/audit worker ceiling, zero swap, one worker, two CPUs, existing process and headroom controls. No 1 GiB/large-instance proposal activated |
| Evidence | Allocate at most **1 MiB** within current shared headroom; cumulative 40 MiB and shared 2 MiB completion reserve unchanged. Ordinary files remain at most 1 MiB |
| Artifacts / temporary | At most 8 MiB of temporary component data within existing aggregate 128 MiB artifact/8 MiB temporary limits. No binary build artifacts or per-file exception requested |
| Command bounds | Existing 60-second command/55-second child maxima remain; each counted case at most one second, source acquisition at most 15 seconds/256 KiB aggregate. Stop case admission unless its bound and the 30-second completion reserve fit |

The largest comparison has 16 physical field elements and 128 paired encoded
elements (2,048 payload bytes). Even with Python objects, separate oracle/model
buffers and small rank matrices, a conservative **8 MiB component working-data
reservation** is ample as an estimate; interpreter and guard overhead must be
measured and remain inside 256 MiB. This is not a measured peak or a full-auth
resource model. No full IntMul oracle is allocated. The addendum's 65,536-element
example gives 2 MiB per physical/companion message and `4r` MiB paired encoded
payload, excluding other buffers; that example is a calculation only and is
outside the proposed cases. All work uses existing aggregate work-event accounting;
there is no new work-event ceiling or transfer from analysis/isolation/proof budgets.

After this preparation, use its final resource record for exact evidence headroom.
There is no storage-ceiling increase in this request. The one numerical increase
needed is the 22 invocation slots; the other changes are explicit task-scope and
within-balance allocations. If sources cannot establish the scalar bridge, or
any hard limit or substantive construction mismatch occurs, preserve the outcome
and finish the admitted report rather than broadening the package.

Future entry points to implement are `run.py preflight`, `run.py case EC-XX` in
the recorded order, and `run.py finalise`, all under the retained cgroup/accounting
guard. They are **planned interfaces, not presently existing commands**. File
ownership is serial in the isolated root; no parallel worker allocation is needed.
Baseline reruns, private witnesses, prover calls and lifecycle activation are
excluded. The proposal does not promise native correspondence or complete PQ-DID
authentication if only the reference path is executed.

## Preparation preservation

This preparation reuses the completed source evidence. No acquisition, function
test, build or proof ran. Eight conservative operator seconds cover local reading,
proposal and finalisation bookkeeping; measured static/preparation/audit/readback
time is charged separately to the 26.252-second opening analysis balance. The
existing ten-second analysis completion reserve and all implementation/KYC balances
remain protected. Only this report/evidence root and append-only status/issues/
traceability changes are permitted. The addendum receives a full-file seal without
changing its contents. The prior acquisition qualification and lint failure remain
historical evidence. Final audit/readback and exact accounting are appended below
and recorded in this package's closure files.


### Preservation completion checkpoint

The single full preservation audit passed with exit **0**: **10,901**
disjoint historical content comparisons and **10,936** identity-inclusive
paths; no protected changes, missing files or inventory discrepancy. Guarded wall
time was **4.742 seconds** and cgroup-v2 `memory.peak` was
**48,177,152 bytes**, covering the worker and descendants plus charged
cache/kernel memory, below the unchanged 256 MiB ceiling. Static lint/format and
preparation also passed on their first runs. The report seal and final inventory/
readback are completed through the existing workflow; their definitive outcome and
exact closing balances are in `docs/data/s3_binius_embedding_correspondence_1/`
`validation-closure.json` and `resource-closure.json`.

This completes preparation and preservation only. All EC/N cases remain unrun;
the component implementation/allowance request remains inactive. Implementation,
KYC, invocation, build and proof balances are unchanged. Historical resource
qualifications remain open; this audit does not certify the earlier acquisition.


## Authorised execution — stopped at the representation gate

The subsequent user approval activated this component only: 200 existing
implementation seconds outside KYC, 28 invocation slots (ceiling 1,146 to 1,168),
15 exact pinned source files and 1 MiB evidence. All historical preparation files,
including their then-inactive plan and seals, remain unchanged. The prospective
approval and EC-08 clarification are in `execution/approval.json`. EC-08 means a
**declared** parity/layout mismatch; it cannot detect every arbitrary parity-swapped
raw vector, and it establishes no cryptographic binding.

**Outcome: blocked before component implementation or case admission.** This is
an evidence-dependency stop, not a counterexample to the embedding/rank argument.
No Python encoder model was executed, no EC case ran and no native comparison ran.
The intended outputs remain **Python-model results**, if later executed, never
native results. The command guard now refuses EC admission while the recorded
representation blocker exists. No placeholder arithmetic or substitute generator
was introduced to obtain a result.

### Verified acquisition and precise missing premise

The sealed report, plan, allowlist and final preparation closure were verified
before mutation. The allowlist matches all 15 exact entries of the retained tree
`544452a781fee0f9b262d4ecfdcc47326fb6974f`, at unchanged commit
`441fbf51ff0bcb0bcd28f3f1b73f4954029e8577`. All **176,779 bytes** were acquired;
each response length and Git `blob <length>\0` SHA-1 matched before retention/use.
Per-file SHA-256, URL, length and Git blob are in
[the acquisition record](data/s3_binius_embedding_correspondence_1/execution/source-acquisition.json).
Only these files were fetched; no archive, dependency, script execution or build.

Acquisition took **4.706 guarded seconds** (15-second ceiling). The cgroup existed
before the interpreter: `MemoryMax=268435456`, zero swap, two CPUs, one worker.
Its measured cgroup `memory.peak` was **25,866,240 bytes**; external sampled tree
RSS was **45,178,880 bytes**. These are different scopes, both below the ceiling.
The earlier acquisition-memory observation remains unresolved and unchanged.

The inspected portable arithmetic explicitly uses modulus
`X^128+X^7+X^2+X+1`, reduction constant `0x87`, low-bit polynomial coefficients,
and warns that this is not GCM wire bit-endianness. `Ghash128b::new` and `From<u128>`
retain a raw `M128` value. The retained source tests describe the expected unit,
shift and reduction behaviour; they were not run. Packed source names the
strategies, but no compiled architecture mapping has been validated.

The scalar declaration invokes `binary_field!` with
`0x494ef99794d5244f9152df59d87a9186` and `1 << 121`. The call-site comment identifies
the latter as a trace-one candidate. The **macro definition is absent** from both
the approved 15 files and the retained source snapshots. It supplies the field
trait implementations, so inspecting the argument list alone does not verify
which values become `MULTIPLICATIVE_GENERATOR` and `TRACE_ONE_ELEMENT`. The former
is consumed by the actual 16-variable IntMul power-table operand (EC-18), the
latter by native Gao–Mateer domain generation (EC-01–06). These are exact input
identities, not merely an isomorphism class of GF(2^128).

`B64-EMBED-REP-001` records the missing pinned source:

- Path: `crates/field/src/binary_field.rs`.
- Size: **24,075 bytes**.
- Git blob: `d073d856abf2d1a2ad58b9a0dbe6b7a49460f1df`.
- Metadata provenance: retained tree only; **content not acquired or verified**.

The precise next evidence needed is that macro's expansion contract: assignment
of its arguments to the scalar associated constants and the relevant field
operations. It may settle this premise or expose further explicitly identified
references. No additional acquisition is automatic. This is the plan's explicit
stop when representation evidence would require an unlisted source, rather than
an inference that the library uses a different constant. The independent model,
layout adapter and all functional checks were left unimplemented/unrun after
this gate; the isolated root contains only its stop README.

### Acquired logup source correspondence and remaining construction obligation

Source inspection also identifies the real objects to which any future embedding
must apply. `ip-prover/logup_star/witness.rs::combined_lookers` constructs
`Y_t = sum_i gamma^i (I_i)_* eq_{r_i}`. Its introductory comment says each table
has its own gamma, but the function signature and shared `powers(gamma)` series
use one gamma across tables, with distinct denominator challenges. We record the
implementation behaviour, not that inconsistent comment. These pushforwards depend
on hidden index columns even when the table is public.

`iop-prover/logup_star.rs` samples that looker-batching challenge, constructs each
Y, commits the Y oracles and only then runs the reduction. This gamma has a
different role from the later BaseFold affine blend. `iop/logup_star.rs` receives
one masked Y oracle per table in the same order. Its transparent path binds both
`<Y, eq_z>` and `<Y,T>` to the same oracle; index claims remain the caller's
responsibility. `ip/logup_star/output.rs` and the pushforward reduction distinguish
table-point **prefixes** from index-point **suffixes**, as a consequence of opposite
padding conventions. Transporting both operands through the decoder, preserving
those dimensions/orderings, and binding the terminal wire to the *same* outer
committed witness remain required. No logup implementation or privacy repair was
performed by this source inspection.

The addendum's rank argument and restricted aggregate-view algebra remain
conditional source/mathematical results. An online simulator for commitments,
authentication paths, correlated outer masks, claim-before-challenge order and
adaptive observations is still missing. Same-object extraction, sound aggregation
and exceptional-challenge treatment are separate. No quantum/concrete finite
security conclusion, native correctness or private authentication follows from
this acquisition. B64-ZK-001/002 and B64-JOINT-001 remain open.

### Individual outcomes and accounting boundary

Every fixed case was withheld at the same representation-admission gate; none
consumed an invocation. No expected outcome was changed and no corrective rerun
was used. The EC-08 clarification was recorded without adding a case.

| Case | Fixed purpose | Outcome |
| --- | --- | --- |
| EC-01 | k1-m1-r2 | Unrun — B64-EMBED-REP-001 |
| EC-02 | k2-m2-r2 | Unrun — B64-EMBED-REP-001 |
| EC-03 | k2-m2-r4 | Unrun — B64-EMBED-REP-001 |
| EC-04 | k4-m4-r2 | Unrun — B64-EMBED-REP-001 |
| EC-05 | k2-m4-r2 | Unrun — B64-EMBED-REP-001 |
| EC-06 | k4-m8-r4 | Unrun — B64-EMBED-REP-001 |
| EC-07 | decoder | Unrun — B64-EMBED-REP-001 |
| EC-08 | parity | Unrun — B64-EMBED-REP-001 |
| EC-09 | order | Unrun — B64-EMBED-REP-001 |
| EC-10 | dimension | Unrun — B64-EMBED-REP-001 |
| EC-11 | randomness | Unrun — B64-EMBED-REP-001 |
| EC-12 | oracle-id | Unrun — B64-EMBED-REP-001 |
| EC-13 | odd-padding | Unrun — B64-EMBED-REP-001 |
| EC-14 | operand-equal | Unrun — B64-EMBED-REP-001 |
| EC-15 | operand-padded | Unrun — B64-EMBED-REP-001 |
| EC-16 | terminal-selector | Unrun — B64-EMBED-REP-001 |
| EC-17 | intmul-equality | Unrun — B64-EMBED-REP-001 |
| EC-18 | intmul-table | Unrun — B64-EMBED-REP-001 |
| EC-19 | rank | Unrun — B64-EMBED-REP-001 |
| EC-20 | repeated-query | Unrun — B64-EMBED-REP-001 |
| EC-21 | query-budget | Unrun — B64-EMBED-REP-001 |
| EC-22 | aggregate | Unrun — B64-EMBED-REP-001 |
| EC-23 | individual-control | Unrun — B64-EMBED-REP-001 |
| EC-24 | gamma-zero | Unrun — B64-EMBED-REP-001 |
| EC-25 | gamma-one | Unrun — B64-EMBED-REP-001 |

N-01–N-04 remain unrun and outside this execution approval. Invocations are
**1,140/1,168**, with all 28 allocated slots unused; builds remain **10/13** and
proofs **two used/one unused**. Measured component generation/evaluation time,
model memory, rank checks and expected/actual field outputs are **unavailable**;
the resource measurements above describe acquisition, not encoder performance.

The retained accounting convention charges 50 conservative operator/bookkeeping
seconds (8 admission, 36 source/tooling and correspondence, 6 completion), plus
measured guarded commands. No analysis/KYC allowance is consumed. The 200-second
allocation and 30-second completion reserve are not reset; actual closing figures
and each phase's charge appear in `execution/resource-closure.json`. Evidence
includes source bodies, tooling, logs, report appends and finalisation; the 1 MiB
package and shared 2 MiB completion reserve stay enforced. Final preservation,
inventory and readback are recorded below. This closes this attempt with a
blocker; it does not complete the component validation or activate a next package.


### Execution preservation and retained tooling corrections

Full preservation passed, exit **0**, in **4.534 guarded seconds**:
**10,901 disjoint historical content comparisons**, **10,936 identity-inclusive
paths, and no missing/changed protected file or inventory discrepancy. Cgroup-v2
`memory.peak` was **48,721,920 bytes**, including descendants and charged
cache/kernel memory, below 256 MiB. The final inventory/report seal/readback and
precise closing ledger are in `execution/validation-closure.json` and
`execution/resource-closure.json`.

Three tooling failures are retained, separately from the unrun EC cases:

1. `quality`: E501 in a diagnostic string; splitting the literal preserved its
   exact runtime value and AST. The affected `quality-2` passed.
2. `prepare`: the new helper wrote its newly collected snapshot twice; the
   established auditor refused the second write. The original partial
   `checked-inputs.json` is preserved. The correction writes once to
   `checked-inputs-v2.json` after including the isolated README; no original
   expected entries, hashes or baselines changed.
3. `quality-3`: stopped before starting a worker because the reused resume helper
   recognised the initial lint stop but not the retained preparation stop. The
   correction admits only the exact three recorded failure phases and verifies
   their retained hashes/reasons; unknown stops or resource failures still stop.
   `quality-4` passed, then `prepare-2` passed. No functional invocation was used
   for these static/preservation checks. Every failed guard/log/stop record remains.

The single full audit then passed. Finalisation preserves the approved 1 MiB
package-output cap and 2 MiB shared completion reserve. No actual resource breach
occurred in this attempt. No component result, native correspondence or security
claim is inferred from preservation success. The outstanding construction still
needs same-object terminal joint opening, commitment/online simulation and
extraction correspondence; supplying the missing macro source alone would address
only this component's representation-admission evidence.


## Approved scalar-source continuation: Python component results

This continuation supersedes the earlier **unrun** component status; it preserves
that attempt, its three tooling failures and all original seals. The prospective
one-file amendment is recorded in
[data/s3_binius_embedding_correspondence_1/continuation-1/amendment.json](data/s3_binius_embedding_correspondence_1/continuation-1/amendment.json).
The original proposal, execution plan, allowlist and prior closure were checked
against their retained identities before use. No historical seal was regenerated.

### Source admission and exact implementation boundary

At unchanged commit `441fbf51ff0bcb0bcd28f3f1b73f4954029e8577`, the new
`crates/field/src/binary_field.rs` matches the retained tree entry, length
**24,075 bytes**, Git blob `d073d856abf2d1a2ad58b9a0dbe6b7a49460f1df`, and
SHA-256 `4907b827c90b585f110186524cdb5442e37e6b5f0ded79544a1c5f343c189390`.
The 15 previously acquired files were hash-verified and reused, not downloaded.
The source set is **16 files / 200,854 bytes**, below the 256 KiB acquisition cap.
The single added retrieval took **0.467952 guarded seconds**, within 15 seconds.
Full source provenance is in `continuation-1/source-acquisition.json`; the first
15 identities remain in `execution/source-acquisition.json`.

The macro connects its generator argument to `MULTIPLICATIVE_GENERATOR` at line
206 and its trace argument to `TRACE_ONE_ELEMENT` at line 314. Together with the
retained GHASH and portable arithmetic sources, this establishes the scalar
contract: raw bit i represents the coefficient of X^i in
GF(2)[X]/(X^128+X^7+X^2+X+1), with unit 1, generator
`0x494ef99794d5244f9152df59d87a9186` and trace-one value `1 << 121`.
This is the portable polynomial convention, not the GCM wire bit order.
`B64-EMBED-REP-001` is resolved for this source-supported scalar-model admission.
It does not establish compiled SIMD/native correspondence.

The isolated implementation is under `experiments/binius_embedding_correspondence_1/`:
`field_model.py` (bounded scalar arithmetic), `layout.py` (typed layout and
logical/physical mapping), `encoder_model.py` (source-directed bit reversal and
additive-NTT encoder), `polynomial_reference.py` (independent arithmetic/polynomial
oracle), `relations.py` (restricted algebraic helpers), and `cases.py` (the fixed
25 cases). The old root README remains historical; `native/README.md` records
unrun native gates N-01–N-04. No Rust source, production module, active profile or
cryptographic parameter changed.

### Correspondence and limits of the independent checks

The candidate field multiplies with fixed 128-step shift/reduce operations. The
independent oracle uses a full carryless product and polynomial long division,
with extended-Euclidean inversion. It does not call the candidate field or
encoder. Its Gao basis uses Frobenius powers and odd binomial coefficients,
independently of the candidate's repeated x²+x descent. Its normalised subspace
polynomials use explicit products over spans, rather than the candidate's
butterfly schedule. All six small encoder fixtures compare every output position.

The physical witness has random even coordinates and logical odd coordinates;
unused odd coordinates must be zero. The source-directed concatenation,
bit-reversal, rate duplication and `skip_late_rounds=1` schedule yield the
specified two-lane polynomial evaluations. The reference independently evaluates
R + W_ell G and the companion lane. Operand transport and selector checks retain
logical lane order; IntMul's two operand families retain their 16-variable shape.
Those IntMul fixtures use sparse/non-Boolean point structure so independent
expansion remains bounded; they are not exhaustive 16-variable evaluations.

The descriptor rejects incompatible version, point ordering, oracle identity,
dimensions and parity. These are **local checks**, not commitment binding. EC-08
uses the approved explicit layout declaration mismatch: no claim is made that an
arbitrary exchanged even/odd vector is intrinsically recognisable as malformed.
Injected short randomness is rejected; this is not an entropy assurance test.

For the restricted joint-view identity, gamma != 0 permits computing one aggregate
mask claim from V and public B; the two-witness coupling preserves the aggregate.
EC-23 deliberately shows why disclosing individual mask claims can expose the
individual targets. It is a model negative control, not an executed native attack.
Gamma=0 is outside the restricted helper, and gamma=1's privacy identity does not
establish binding to the original witness. Four distinct points give a full-rank
small masking matrix, including zero; repeated queries are cached and the budget
counts distinct points. Finite fixtures do not prove rank for all parameters or
an adaptive online simulation theorem. Uniform independent masks, the admitted
support/basis, public operands, conditioning and query-budget hypotheses remain
requirements of the restricted argument.

### Individual outcomes and measured component resources

All 25 fixed cases passed at their first invocation; there were no case failures,
no corrective case reruns and no extra functional probes. Native comparisons
N-01–N-04 are **unrun**. Exact expected/actual values, source identities, per-case
work and resource records are retained in `continuation-1/EC-*.outcome.json` and
[case-summary.json](data/s3_binius_embedding_correspondence_1/continuation-1/case-summary.json).
Times below measure the Python component body, not native/proof performance.

| Case | Observation | Outcome | Component seconds |
| --- | --- | --- | ---: |
| EC-01 | Encoder k=1,m=1,rate=2; all encoded positions equal independent polynomial reference | Pass | 0.002950 |
| EC-02 | Encoder k=2,m=2,rate=2; complete output equality | Pass | 0.003980 |
| EC-03 | Encoder k=2,m=2,rate=4; complete output equality | Pass | 0.007641 |
| EC-04 | Encoder k=4,m=4,rate=2; complete output equality | Pass | 0.008936 |
| EC-05 | Encoder k=2,m=4,rate=2; padded logical input; complete output equality | Pass | 0.009145 |
| EC-06 | Encoder k=4,m=8,rate=4; padded logical input; complete output equality | Pass | 0.096291 |
| EC-07 | Decoder and transported inner product on admitted physical data | Pass | 0.000131 |
| EC-08 | Explicit parity/layout declaration mismatch rejected (not arbitrary vector detection) | Pass | 0.000021 |
| EC-09 | Incorrect point-order declaration rejected | Pass | 0.000017 |
| EC-10 | Non-power-of-two dimension rejected before allocation | Pass | 0.000021 |
| EC-11 | Short injected randomness rejected without releasing an embedded vector | Pass | 0.000024 |
| EC-12 | Incorrect local oracle identifier rejected; no cryptographic identity claim | Pass | 0.000023 |
| EC-13 | Non-zero odd-coordinate padding rejected | Pass | 0.000025 |
| EC-14 | Operand transport, m=k | Pass | 0.000202 |
| EC-15 | Operand transport, m>k | Pass | 0.000335 |
| EC-16 | Terminal selector s=1 maps to physical coordinate 3 | Pass | 0.000017 |
| EC-17 | IntMul equality operand, 16-variable shape, independent expansion | Pass | 0.000797 |
| EC-18 | IntMul power-table operand, 16-variable shape, independent expansion | Pass | 0.001115 |
| EC-19 | Four-point masking matrix rank 4, including evaluation point zero | Pass | 0.001279 |
| EC-20 | Repeated original query reuses its cached answer | Pass | 0.000015 |
| EC-21 | Distinct-query bound rejected before the next query callback | Pass | 0.000016 |
| EC-22 | Two-oracle aggregate claim and alternate-witness coupling identity | Pass | 0.003611 |
| EC-23 | Individual mask-claim negative control recovers individual targets | Pass | 0.003625 |
| EC-24 | Gamma zero rejected by restricted helper | Pass | 0.000013 |
| EC-25 | Gamma one preserves restricted privacy identity but does not bind original witness | Pass | 0.002176 |

Total guarded case time was **3.214082 s**; summed component-body time was
**0.142404 s**. Maximum case cgroup-v2 `memory.peak` was **19,529,728 bytes**,
including descendants and charged cache/kernel memory, under the 256 MiB ceiling.
Sampled process-tree RSS and process `ru_maxrss` are separate metrics in the
records and must not be substituted for cgroup usage. The largest encoder fixture
has 16 physical coefficients and 128 encoded field words (2,048 payload bytes).
There were **4,348,928** explicitly defined arithmetic work events across the
cases, below 2^32; these are not gates or complete-authentication cost estimates.
The historical acquisition-memory observation remains unresolved; these current
cgroup measurements do not retroactively resolve it.

### Corrections, accounting and remaining construction gate

The initial `quality` and affected `quality-2` static/lint/format checks passed.
Before final preservation, a narrow accounting correction changed exclusion of
all README basenames to exclusion of only the exact previously charged historical
root README. The new native-status README is now charged normally. The prior
helper and correction hashes are retained in `accounting-correction.json` and
`run-before-readme-accounting.txt`. This correction changed no model/case input;
all 25 results are reused. Static and preservation commands are recorded separately
from the functional invocation ledger, now **1,165/1,168** with three unused
component corrective slots. Builds remain **10/13**; proofs **two used/one unused**.

Accounting retains the original **61.68825586186722 s** package charge and adds
45 conservative operator/bookkeeping seconds plus measured guarded continuation
work, within the same 200-second allocation. The legacy guard configuration field
`prior_analysis_charged_seconds` carries that prior package implementation charge;
it is not a charge to the analysis budget. Phase redistribution is prospective,
with 30 seconds retained for completion. KYC's allocation and protected reserve,
analysis allowance, original evidence and shared completion reserve are unchanged.
Final exact balances, storage and all commands are in
`continuation-1/resource-closure.json`; preservation and readback are in
`continuation-1/validation-closure.json`. Final completion is contingent on the
whole preservation workflow, recorded below.

The completed checks establish **Python-model component correspondence only**.
The remaining construction obligation is a same-committed-object terminal joint
opening that hides both individual targets, composed with commitments, query
openings and the full verifier view. Commitment/online simulation, extraction,
exceptional-challenge soundness, QROM/finite-parameter security, adaptive tails and
complete authentication are separate unresolved obligations. No native build or
private prototype is admitted by this result. Binius implementation/proving and
isolation remain paused; ordinary private verification stays fail-closed.
Stages 2–3, original full scope and the 31 October target remain unchanged, with
no supported commitment to full completion by that date. No next package starts.


### Continuation preservation and completion record

The full comparison audit and outer resource guard passed, exit **0**, in
**4.741370 seconds**, with cgroup-v2 `memory.peak`
**49,397,760 bytes**, below the unchanged 256 MiB
ceiling. Coverage was **10,901** disjoint original/supplementary content
comparisons and **10,936** identity-inclusive paths. Content, report prefixes,
seals, documentation and inventory checks passed; no unexpected/missing protected
files or overlapping partitions were reported.

A preceding launcher failed before the comparison auditor was entered because
its preparation omitted the required `scope_sha256`. This is retained as
`continuation-1/full-audit.json`, its log/service record, `STOP.json`, and the
byte-identical failed-result snapshot `audit-failure.json`. The routine correction
restored that required scope-hash check, retained the old helpers and preparation,
and used new `quality-3`, `prepare-2` and `full-audit-2` records. Both corrected
static/preparation phases passed. There were **two launcher attempts, one failed
before comparisons, and one complete comparison audit**; nothing was refunded or
retroactively labelled successful. No case was rerun and no resource ceiling was
increased. The failed result remains separate from the successful aggregate result.

Five additional conservative correction/bookkeeping seconds are charged, making
**50** operator seconds plus all guarded continuation times, on top of the
unchanged prior **61.68825586186722 seconds**. This replaces the provisional
45-second operator figure above prospectively. Final inventory, report seals and
readback are recorded in `continuation-1/validation-closure.json`; exact consumed
and remaining balances, including all failures, are in
`continuation-1/resource-closure.json`. Those closure records determine final
completion, rather than the comparison-only evidence.

EC-01–EC-25 are passed **Python-model results**; native comparisons remain unrun.
The component resolves scalar admission and supplies independent small-instance
embedding evidence. It does not discharge terminal same-object joint opening,
commitment/online simulation, extraction or quantum/finite-parameter security.
Stages 2–3 stay open, production verification fail-closed, Binius/proving/isolation
paused, and the proof ledger two used/one unused. No subsequent package is started.
