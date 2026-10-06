# OCT31-COMPACT-AUTH-REPRESENTATION-1 — result and admission decision

**NO-GO: the complete selected representation does not meet resource admission.**
The exact experimental affine encoding is implemented and its bounded fixtures
pass, including actual native checking. This is **not complete private authentication**.
No full matrix, witness assignment, codeword or proof was allocated. The oversized
route stopped at the early whole-workload assessment.

The obstruction is precise: this representation retains every original AND row.
Six required forward-NTT cores already force at least43,401,216 such rows, before
entry conversions, inverse transforms, sampling, hashing and other checks. The
retained corrected Aurora family then requires at least48 GiB per codeword and
192 GiB for the four codewords simultaneously retained by the native submission
path. These are conditional payload lower bounds, not measured peak memory or
universal lower bounds for all authentication representations.

Only manuscript Sections II–VIII and agreed SPEC-001–004 define the scheme. The
manuscript, active BC-1, signed encodings, parameters, dependencies, production code,
comparison point v1 and all276 measurements remain unchanged. The selected
experiment is **AFFINE-GF192-1**, not an adopted profile or proof interface.
[The pre-execution contract](data/oct31_compact_auth_representation_1/contract.md),
[approval](data/oct31_compact_auth_representation_1/approval.json) and
[opening ledger](data/oct31_compact_auth_representation_1/opening.json) record the
scope and continuing budgets. The previous integration evidence remains intact.

## Exact representation and correspondence

Implementation is isolated in `experiments/compact_auth_representation_1/`:
`affine.py` contains the compiler/checker; `cases.py` the independent fixture
comparisons; `native_cases.py` the retained-loader bridge; `admission.py` the
whole-workload model; the remaining files provide the existing guarded execution
and preservation workflow.

| Item | Exact representation and enforced condition |
| --- | --- |
| Field | Existing GF(2^192), polynomial x^192+x^7+x^2+x+1; native field payload24B. No field change. |
| Free private witness | Existing5,329 bytes /42,632 bits; each free bit has b(b+1)=0. No input becomes public. |
| Constants/primary | Column0 is constant1; empty form is0. Column1 is verifier-fixed acceptance1. |
| XOR/NOT | Sorted unique support of coefficient1 terms; XOR uses symmetric difference, NOT toggles column0. No independent XOR/NOT witness variables unless spilled. |
| Original AND | Always one fresh auxiliary and A*B=C, even when substituted operands are equal or constant. No AND is dropped. |
| Spill | A support larger than64 becomes an exact linear equation A*1=y and a singleton retained form. At most128 temporary terms; never truncation. |
| Completion | Original output=primary and primary=constant1. Header identity, producer order, opcode, footer counts, dimensions and full row digest checked. |
| Bounds | Independent wire-form, term-entry, column, source-gate and row caps; capacity failure poisons completion. Retains source-wire forms, not a last-use frontier. |
| Assignment checking | Locally trusted completed descriptor; canonical field values, exact dimensions and row digest; full-field multiplication for adversarial assignments. A supplied descriptor is not network verification evidence. |

**Completeness direction.** Given an accepting source-graph witness, assign each
AND auxiliary its Boolean product and each spill its affine value. Source-order
induction satisfies every equation and the terminal acceptance equations.
**Soundness direction.** Since this is a field, b(b+1)=0 forces0 or1. Characteristic2
makes every coefficient0/1 affine expression over Boolean atoms Boolean. The
multiplication and linear-link equations uniquely fix each new auxiliary, so all
original source wires reconstruct identically and the terminal rows force source
acceptance. Duplicate terms cancel canonically; arbitrary field auxiliaries cannot
replace missing equations. These are structural arguments, supported by finite
fixtures, not a universal machine-checked compiler proof.

The lift to the reference authentication relation reuses the complete source map
from the preceding integration. No arithmetic, sampler or hash gadget is replaced.
Checked signed64 arithmetic, overflow rejection, SPEC-004 quotient/remainder
construction, canonical23-bit residues, exact46-bit public products, norm checks
and malformed-input rules all remain in the graph. In particular, GF192 addition
is **not** used as integer addition or reduction modulo8,380,417. There is no new
integer packing or quotient/remainder advice that could wrap in the backend field.
An invalid source encoding or quotient still fails its original equations/guards.

Public preprocessing remains verifier-recomputed from trusted parameters and full
canonical X; PubOK/Ppub and the public A/t1/tr/zero-leaf computations are unchanged.
One parsed private xH/m/rid/signature/path is retained throughout holder binding,
certification, disclosure and non-revocation. Hidden checks stay inside the graph.
The prior source-level equivalence obligations and21 unrun complete-relation checks
remain open: this algebraic transformation does not retroactively validate them.

The source, row digest and full public-X engineering hashes are not proof
commitments, a completed protocol RID or an adopted PID. A new finite descriptor
would be necessary before integration because row dimensions and sparsity change.
Ordinary private-proof acceptance remains fail-closed.

## Whole-relation coverage and accounting

For a completed source graph let A be original emitted ANDs, X/N its XOR/NOTs and
S the exact linear spills. The compact representation has exactly
`R=42632+A+S+2` rows and `V=42632+A+S+1` variables excluding constant, with
`0<=S<=X+N`. Input Booleanity and both output rows are included once. Nnz and support
sizes are separately accounted; fewer rows need not mean less matrix memory.

[The machine-readable model](data/oct31_compact_auth_representation_1/whole-workload-model.json)
contains the entire workload and provenance. Residual costs below are **unmeasured
nonnegative terms**, not zeros or guessed complete counts.

| Required component | Source-defined workload and current evidence |
| --- | --- |
| Canonical private parsing/disclosure | Same42,632 private bits, exact schema/types/length/padding/rid range; preceding prefix completed this component. |
| Holder binding and certified message | One SHA3-384 and exact canonical context/message framing; prior component evidence reused. |
| Signature syntax/norm | Five×256 response coefficients, strict abs(z)<524092;61-byte hint encoding with6×256 outputs, ordering/count/padding checks. |
| mu | SHAKE256(tr\|\|formatted message,64), framed length dependent on public shape. |
| SampleInBall | SHAKE256(48B,256B), two permutations;248 fixed candidate iterations with private reads/two writes over256 coefficient slots, including rejected-byte consumption and exhaustion. |
| Forward NTTs | Five z plus one challenge transform: each256 entry reductions,1,024 butterflies and output masks; internal eight-stage core counts reused exactly under stated embedding. |
| Matrix/challenge products |7,680 public A×z products/accumulations and1,536 public t1×challenge products/subtractions. |
| Inverse NTTs | Six transforms: each256 entry reductions,1,024 inverse butterflies,256 final factor multiplications. Full combined cost unmeasured. |
| UseHint/w1 |1,536 decompositions, hint operations and high-part range checks,768-byte w1 encoding. |
| Challenge equality | SHAKE256(mu[64]\|\|w1[768],48), seven permutations plus exact equality. Retained full component evidence is not a full-verifier measurement. |
| Non-revocation | Twenty SHA3-384 nodes, private siblings and same certified rid directions, level framing and authenticated-root comparison. |
| Final/public/service checks | Sticky rejection and final conjunction; public parameter/context/state/policy validation remains separate from service freshness and atomic consumption. |

Hash permutation counts follow canonical lengths: for message length m, rate r,
output o, `floor(m/r)+1+max(ceil(o/r)-1,0)`. Before public folding, each Keccak-f
permutation has24×1600=38,400 chi AND operations. These are source-accounting
facts/upper counts before folding, not newly generated hash costs. Do not sum
older overlapping component counts into a claimed full-authentication count.

The precise reusable subset is the eight internal forward stages measured in the
full-forward pilot: each904,192 ANDs, total7,233,536 per core. Current
`mldsa_verify.forward_ntt` calls the same `_from_canonical_producers`, all255
ordinary twiddles, identical lane ordering and1,024 butterflies. The outputs and
scope remain symbolic; the original emitter folds only when both operands are
public. Affine elimination retains every emitted AND. This proves the selected
core subset carries over, without assuming every unmeasured twiddle is identical.
Six source calls give43,401,216 ANDs. The historical **whole** transform's10,679,298
AND count is not substituted: its entry/masking wrapper differs from the current
one. The whole relation also includes all residual rows listed above.

## Admission: all simultaneous storage matters

For padded row domain M, variable domain N and t=max(M,N), the retained family has
`Dconstraint=max(2t+b-1,2M+2b-1)` and power-of-two
`|L|>=8*max(D,Dconstraint)`. Minimum b=1 gives a necessary lower bound; unknown
finite masking/query/folding choices cannot decrease it. Finite soundness/privacy
parameters have not thereby been selected.

| Conditional subset | Padded M/N lower | Minimum codeword length | One codeword | Four coexisting codewords |
| --- | ---: | ---: | ---: | ---: |
| One unchanged internal forward core plus private-input guards |2^23|2^28|6 GiB|24 GiB|
| Six required cores plus guards |2^26|2^31|48 GiB|192 GiB|

Native sizes24B/field,32B/term,72B/constraint were measured by the preceding native
loader and are reused. For the six-core subset, even padded assignment storage
`24N` is1.5 GiB; three Az/Bz/Cz vectors `72M` add4.5 GiB. Constraint/vector payload
is at least `72R+32*nnz` before copies/map nodes/allocator overhead; each retained
AND contributes a nonzero C term. Padding, full graph residuals and spills only add.

The pinned `r1cs_rs_iop/r1cs_rs_iop.tcc` submission code constructs fw and all three
Az/Bz/Cz codewords before submitting them. `iop.tcc` retains submitted oracles;
BCS Merkle construction subsequently consumes those retained vectors. Concurrent
variable-domain arrays, assignment, polynomial/FFT/interpolation buffers, masks,
sparse-matrix copies, commitment trees/salts/openings and retained artifacts are
additional. The192 GiB figure is therefore a **four-vector lower subtotal**, not a
complete peak estimate. Source locations and the original conditional bounds are
recorded in the contract/model. No such vectors were allocated in this package.

The earlier24 GiB result was correct for its stated direct gate-per-row premise:
27,044,356 complete component gates, padded M2^25, b>=1, L>=2^30,24B each. It was
not a full relation measurement. The new6/48 GiB bounds use a different mapping
and different subsets; comparing24 with48 is not a measured regression or saving.

The prior2,000,000-gate stop was the explicit local `Limits(max_gates=2000000)`
in `count_case.py`, running in count mode with zero stored trace bytes. It was not
forced by the2M **materialised** trace ceiling:32M count-only partitions remained
available. The declared smaller probe cap was honoured and is preserved. Raising
that local count to32M would not remove the native memory obstruction. Neither
partitioning nor aggregate2^32 work events grants per-instance memory or proves
private partition composition.

## Bounded implementation and individual outcomes

All29 admitted invocations passed: one early accounting case,24 candidate cases,
and four new native comparisons. No tests were retried, no historical Python or
native suite rerun, and no build was needed. The previous sealed loader binary
was verified before each native comparison. Public synthetic matrix payloads and
exact expected outcomes are retained separately from v1. One initial E501 static
failure and its string-preserving formatting correction remain recorded.

| Case | Result / independent check |
| --- | --- |
| Q-01 | Whole-workload lower bounds reproduced; full resident admission denied. |
| C-01 | Exact independently specified compact row table and assignment passed. |
| C-02 | Same source records agree with uncompressed stream;5 rather than7 rows. |
| C-03 | Non-Boolean free field input rejected. |
| C-04 | Inconsistent AND auxiliary rejected. |
| C-05 | Acceptance0 rejected. |
| C-06 | Noncanonical field value2^192 rejected. |
| C-07 | Undefined/forward producer rejected. |
| C-08 | Wrong statement identity rejected. |
| C-09 | Missing footer cannot complete. |
| C-10 | Wrong footer counts rejected. |
| C-11 |65-input parity spills exactly once; independent expected parity1. |
| C-12 | Modified matrix rejected against trusted complete digest. |
| C-13 | Equal-operand AND still has a fresh constrained auxiliary. |
| C-14 | Tiny wire-form cap produces incomplete result. |
| C-15 | Tiny retained-term cap produces incomplete result. |
| C-16 | Tiny row cap produces incomplete result. |
| C-17 | Unconstrained trailing assignment column rejected. |
| C-18 | Out-of-range constraint column rejected. |
| C-19 | Truncated assignment rejected. |
| C-20 | Noncanonical NOT operand rejected. |
| C-21 | Canonical q-1 times actual twiddle4,808,194 gives3,572,223; exact integer oracle and uncompressed graph agree. |
| C-22 | Input q is rejected with unusable masked output0; no silent modular normalisation. |
| C-23 | Signed64 maximum-1 plus1 accepted, exact integer result. |
| C-24 | Signed64 maximum plus1 rejected as overflow; rejected wrapped output remains unusable. |
| N-01 | Actual native compact matrix satisfied; explicit row/field oracle agrees. |
| N-02 | Actual native input2 violates Booleanity. |
| N-03 | Actual native inconsistent AND auxiliary rejected. |
| N-04 | All true parity inputs changed to0 while claimed spill/output stayed1: native rejects the false spill equation. |

Native paths exercised: default linear combination/add_term, add_constraint,
A/B/C_matrix, create_Az_Bz_Cz_from_variable_assignment, is_satisfied and gf192
operators. No Aurora prover, transcript, IOP, FFT or commitment operation ran.
The loader's previous vector-constructor workaround and pinned sources remain
unchanged. This tests the new rows/assignments through the old binary, not a build.

The prior21 complete checks remain explicitly **not run**: M-01–M-03 full private
sampler cases, J-01–J-16 joint constrained comparisons and Q-02–Q-03 complete
descriptor/frontier checks. The new Q-01 is this package's model case, not a rerun
or renaming of the prior joint-prefix case. Complete native/private relation
admission did not succeed, so no complete-authentication acceptance is asserted.

## Matched measured component costs and limits

| Same source and boundary | Original gates | Original ANDs | Uncompressed rows | Compact rows | Compact spills | Nnz, original → compact |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Tiny relation |3|1|7|5|0|23 →17|
| Fully guarded public-constant modmul |15,158|6,161|15,224|6,367|140|51,888 →135,198|
| Checked signed64 add |335|134|401|200|0|1,272 →606|

For modmul the compact witness has6,366 field-variable slots versus15,223, but
sparsity worsens. The native object-payload formula72R+32nnz is **4,784,760B compact
versus2,756,544B uncompressed**, before allocator/map overhead. This is a calculated
payload from measured counts/sizes, not measured native allocation. Eliminating
rows is therefore not demonstrated memory improvement, even at this kernel.
The compact support table retained15,224 forms/144,732 term entries, max support64;
one-byte convenience assignment storage was6,366B. The whole compiler does not
have a measured full-relation memory bound or last-use implementation.

C-21 paired generation/stream checking took0.181254s; C-22 took0.176569s. Generation
and the two row-check traversals are interleaved and are **not separate timings**.
No trace/matrix was stored for these components. Native fixtures retained only
tiny public matrices. Cgroup phase peaks and complete guard times are recorded in
the resource closure; Python includes the32,870,400B preflight peak, candidate
batch peak23,564,288B, native batch23,875,584B. These are measured process/cached
memory, not projections of complete prover memory. No proof size, throughput,
complete-authentication speedup or RISC Zero forecast is derived.

## Concrete decision and October consequence

Stop the AND-row-preserving full resident route. Under the same four-codeword
rule and minimum masking, even the necessary one-GiB condition requires padded
M and N no larger than2^18: at that boundary the four payloads already use768 MiB,
leaving only256 MiB for all other live structures. For this bit-input encoding
that leaves at most219,510 AND/spill rows after42,632 input guards and two terminal
rows, before budgeting the other semantic checks. The six forward cores alone
have43,401,216 ANDs. This is a necessary condition, emphatically not sufficient
admission or a new parameter setting.

The concrete change required is **an arithmetic-specific representation that no
longer keeps one row for every original AND**, with exact canonical/range/carry,
quotient/remainder and bit-linkage equations and a compatible native masking/domain
construction. Native prime-field quotient equations are a possible engineering
direction, not an established fitting candidate: they cannot be substituted into
this characteristic-two additive-domain profile without a new field/domain and
security correspondence. Hidden hashes, bounded private sampler indexing, hints,
norms and Merkle checks remain even if modular multiplication becomes cheaper.
Increasing the count cap or streaming these same rows is not that change.

No further implementation or proof pilot is recommended on this resident mapping.
A project decision is needed whether to authorise that substantive representation/
backend-field change or stop this backend route for the31 October private-proof
target. Existing evidence does **not** support complete private authentication by
that date. The reference KYC testbed, earlier comparison data and exact candidate
compiler remain reusable; no additional experiment is started here.

TB-06 commitment simulation, private full-schedule correspondence, extraction/
privacy including quantum/restoration and adaptive histories, concrete hashes,
finite parameters, adaptive Delta_tail and production security remain open.
The field size192 does not itself establish192-bit or overall concrete security.
Stages 2–3 and AURORA-BRIDGE-001 remain open; isolation stays stopped/unactivated,
CPU proving paused and ordinary private-proof acceptance fail-closed. Zero proof
attempts and zkVM executions; the proof ledger remains two used/one unused.

## Preservation and resource continuation

Opening balances:3,114.409546 implementation seconds,942/1,050 invocations,10/13
builds,27,379,838 already charged work events. Reallocated maximums108 invocations
and three builds; no ceiling reset. The300-second completion reserve and2MiB
evidence reserve remain inside the existing balances. Analysis80.917503 seconds
and isolation accounting are unchanged.

Opening evidence25,991,650B and artifacts58,966,547B are retained. This continuation
conservatively preserves the remaining5,541,239B of the previous6MiB evidence
allocation, in addition to the unchanged32MiB enclosing ceiling. No fresh output
allowance is invented. The64MiB artifact allocation is likewise reduced by the
previous853,888B charge; the128MiB enclosing ceiling remains unchanged.

Current cases charge213,765 new work events, total27,593,603/2^32; both source
traversals and row checks are charged, including conservative native row passes.
Invocation ledger971/1,050; builds remain10/13. Exact final time, storage, full
preservation audit, inventory and report readback are recorded in the
[closure](data/oct31_compact_auth_representation_1/validation-closure.json).

### Preservation result

The single complete audit exited0 and its outer guard passed: **10,901** disjoint
historical content comparisons (8,759 original+2,142 supplemental), **10,936**
identity-inclusive paths, all retained seals/prefixes and **11,106** inventory
entries, with no missing/unexpected names or partition overlap. Report generation
and audit readback completed. Audit guard **4.400144s**, worker
**4.061071s**; cgroup-v2 peak **46,227,456B**
under256 MiB, including descendants and charged cache/kernel memory. Separate
summed process-tree RSS peak **62,783,488B** may double-count shared pages.
There was no memory-event, swap, timeout, storage or work-event breach. Final
lint/format passed; the earlier lint diagnostic remains retained.

At the audit checkpoint, charged time is112.176080s (100s conservative source/operator
bookkeeping plus measured guarded phases). Final readback, exact-unit shutdown and
completion charges are included in the linked closure. The complete selected
representation remains **not admitted**, independently of successful preservation.
