# OCT31-AUTH-RELATION-INTEGRATION-1 — execution and admission proposal

29 September 2026. **Proposed, not authorised or started.** The preceding
**OCT31-KYC-NATIVE-MILESTONE-1 is closed, complete within its approved scope**, as
`OCT31-KYC-NATIVE-MILESTONE-1/v1`. This is a complete reference lifecycle and public
native-component comparison point, not a complete authentication proof. Its code,
276 benchmark trials, failures, corrected final-binary results and seals remain in
place. The [version manifest](data/oct31_auth_relation_integration_1/comparison-point.json)
references the existing trusted closure and hashes; it neither replaces a baseline
nor reruns a benchmark.

**Decision:** propose one bounded implementation milestone for the complete
same-witness authentication relation, a streaming constraint compiler/checker,
and nontrivial native R1CS loading. Admit a full resident native instance only if
complete counts and a conservative allocation bound fit the existing limits.
The straightforward gate-per-row materialisation is already a conditional
**no-go**: one measured forward NTT alone implies at least a 24 GiB codeword in
the selected corrected Aurora family, versus a 1 GiB worker. Do not allocate it.
A successful small native fixture cannot overturn this result or establish full
relation feasibility. The milestone must return complete measured evidence or an
explicit capacity/security no-go, never relabel an incomplete relation as complete.

The exact missing private-proof conditions are: a simulator for commitments fixed
before challenges and all adaptive openings (TB-06); correspondence of the complete
private EXP2/IOP/query schedule; finite masking/domain/soundness parameters; the
applicable state-restoration or round-by-round knowledge premises and extractor
resources; application history-preserving extraction/online privacy; and a valid
concrete-hash instantiation/composition argument at the enlarged query budgets.
Native correspondence alone supplies none of these missing premises. **Zero proof
attempts are requested.** The intended post-quantum goal remains unchanged.

## Authority, reused evidence and closure

Only manuscript Sections II–VIII and agreed SPEC-001–004 clarifications are scheme
authority. The unchanged manuscript SHA-256 is
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The proposed proof layer is `PQDID-AURORA-AUTH-DRAFT1`, not active BC-1 or an adopted
replacement for the manuscript construction. Preserve `PQ-DID-MITH-1` inside all
existing signed encodings and domain tags. The experimental hint and arithmetic
lowerings remain explicitly noncanonical BC-1.

Reuse the [reference specification](implementation_spec.md),
[construction contract](stage3_aurora_auth_construction_contract.md),
[query contract](stage3_aurora_query_masking_contract.md),
[masking correction](stage3_aurora_masking_correction_contract.md),
[EXP2 contract](stage3_aurora_transcript_correction_contract.md),
[concrete assessment](stage2_concrete_security_assessment.md),
[outer-oracle obligations](stage3_outer_oracle_composition.md),
[full-forward-NTT evidence](stage3_mldsa_full_forward_ntt_pilot.md), and
[final native report](stage3_aurora_masking_native.md). No proof-system survey or
new literature campaign is part of this proposal.

The [completed closure](data/oct31_kyc_native_milestone_1/native-finalisation-1/validation-closure.json)
is sealed by SHA-256
`7a4ab57cb54185bf49fe60f1c5bd4e52dc68d000904c9a8dd879c7b4e7089723`;
its manifest is
`b81bacf5bddb6d371f0ad50120291d039194f2f490718a9179b3a7d6708a3ba7`.
It records all 392 distinct planned cases/trials, including N-01–24 and TR-01–16
on the strengthened binary and C-09. Earlier binary results remain separately
labelled. The 276 measurement results are retained unchanged; no new percentile,
throughput or proof-performance claim is made. Complete preservation included
8,759 original plus 2,142 disjoint supplemental content comparisons. Its final
inventory/readback and resource closure passed. The earlier failed preparation
and rejected admissions remain historical evidence.

Baseline reruns require a recorded change in shared code, fixture, parameters,
clock, instrumentation or measurement conditions. New relation results receive a
new dataset/profile identifier and cannot overwrite or silently pool with v1.

## Complete relation, statement and witness contract

The target is exactly `relations.auth(pp,X,w) = PubOK(pp,X) AND Rprivate(pp,X,w)
AND Ppub(pp,X)`. It is timeless; service freshness/consumption checks are additional.
The detailed [source mapping](data/oct31_auth_relation_integration_1/relation-notes.md)
identifies the existing functions, byte positions and native-loader hazards.

| Boundary | Exact content and binding |
| --- | --- |
| Public statement | `X=(pp, metadata, context, state, D, mD)`, encoded solely by `statements.encode_auth_statement`; parameters include trusted issuer/revocation keys, namespace and schema. All repeated references must agree. |
| Context | Existing suite/audience/session/nonce/policy/issuer-reference/state-reference/expiry record; full canonical X enters EXP2 initialisation. It does not change the issuer's certified message. |
| Private witness | `xH[32] || Esch(m)[1024] || rid[4] || sigma[3309] || path[960]`, exactly 5,329 bytes / 42,632 bits. External byte bits are MSB-first; FIPS packing and arithmetic-word rewiring are explicit. |
| Shared values | The same xH derives Y, the same attributes m feed certification and disclosure, and the same 20-bit rid feeds certification and every Merkle direction. No separately supplied accepted credential, root or signature-verification flag. |
| Proof identifiers | Trusted PID binds field, algorithms, contexts, caps and finite profile; RID binds compiler/semantic shape, complete ordered matrices, sizes, padding and conversions. Full E(X) is bound separately. Internal trace SHA-256 is an engineering fingerprint, not an adopted protocol commitment. |

Select a **statement-specific matrix**, derived independently from exact public X.
This reuses the current constant-public gadgets without pretending they provide a
universal reusable matrix with symbolic public input. Public preprocessing is
verifier-recomputed, or a locally trusted cache keyed by full canonical X, compiler
and parameter identities. An untrusted prover cannot choose matrices or supply
accepted preprocessing. Use one explicit primary field variable fixed by the
verifier to 1, constrained equal to the final private acceptance bit. This also
makes `primary_count+1=2`; it does not move X into private advice. Repeated
presentations with different context/state require distinct statement binding and
potential matrix derivation costs, which must be included in later timings.

Every reference check is assigned below. A resource/shape admission failure is
`INCOMPLETE/CAPACITY`, never a false cryptographic rejection or a smaller claimed
accepted credential set. Protocol u32-length encodings remain unchanged; research
parser limits must be published separately and refuse oversize public instances
before allocation.

| Check | Location and required implementation |
| --- | --- |
| Parameter/schema/instance equality, context/state references, disclosure set and public policy | Reuse typed validators, `PubOK` and `Ppub` in the verifier wrapper. Independently check StateAuth with the existing bounded verifier and trusted revocation key. No supplied acceptance flags. |
| Canonical private m and rid | Reuse `auth_parsing`: field tags/types/lengths, BYTES capacity, BOOLEAN exact 0/1, UINT64 eight-byte range, field/tail zero padding, rid < 2^20. |
| Holder secret and certified body | Constrain existing SHA3-384 holder-binding preimage, `Y`, `B=(Y,Esch(m))`, and exact `build_mcred` framing including metadata and the same rid. These remain hidden checks. |
| Issuer signature preparation | Reuse exact certified-message and FIPS message gadgets: pure ML-DSA `0 || len(ctx) || ctx`, role context `PQ-DID/credential/v1`, tr and mu. Do not sign or add presentation context to Mcred. |
| Public ML-DSA material | Decode trusted pkI; recompute A from rho with 30 separate 1,026-byte SHAKE128 budgets, public t1 transforms and tr. Exhaustion fails closed. No prover-chosen A or t1. |
| Private signature syntax/norm | c-tilde 48B, five response polynomials, six hint rows/55 positions: endpoint/order/index/count/padding checks, strict abs(z)<524092. Preserve malformed active-path rejection and unusable output semantics. |
| Private challenge sampling | Implement fixed-flow SHAKE256 and capped SampleInBall: 256 bytes includes eight sign bytes plus at most 248 sampled indices; rejected indices consume input; all counters/indexed updates/termination/exhaustion constrained. |
| Full polynomial verification | Five z forward NTTs and one challenge forward NTT; 30 matrix/vector products and sums; six challenge/t1 products and subtractions; six inverse NTTs with correct negative twiddles and final 8347681 factor; all norm, reduction, decomposition/UseHint and 768-byte w1 encoding. |
| Challenge equality | Constrain SHAKE256(mu || w1Encode,48) equal to the very same c-tilde, with all validity bits. A host verifier result cannot replace these rows. |
| Selective disclosure/policy | Same m projects to exact mD at D; public policy evaluated on mD. Do not invent a hidden validUntil check or conflate credential policy with session expiry. |
| Non-revocation | Public zero leaf; all twenty level-tagged SHA3-384 hashes with private siblings and certified rid direction bits; final root equals authenticated state root. The root alone does not establish currentness. |
| Final accept | Sticky active invalidity, every subcheck and final output constrained jointly. Free auxiliary values require equations, not test assertions. |

Keep ML-DSA-65 q=8,380,417,n=256,k=6,l=5,d=13,tau=49,omega=55 and all existing
caps. Twiddles are ordinary residues, not Montgomery values. Canonical 23-bit
residues may be retained only with established range and representative invariants;
new inverse/decomposition boundaries need explicit signed/reference conversions.
The 512-byte keygen sampler and 1,024 signing attempts are outside verification;
this milestone neither changes nor introduces them into Rauth.

## Implementation deliverables, interfaces and ownership

All implementation is proposed under `experiments/auth_relation_integration_1/`;
reports/data use the matching new namespace. Production modules, active profile,
prior experimental sources/binaries and frozen v1 dataset stay unchanged. Existing
helpers are imported read-only. Any necessary change to pinned native sources is
outside this proposal and triggers a specific stop, not an opportunistic repair.

| Owner / files | Deliverable and exact interface |
| --- | --- |
| Relation owner: `statement.py`, `private_relation.py`, `mldsa_verify.py`, `merkle.py` | `prepare_public(expected_pp,X)->PreparedPublic`; `compile_private(prepared,sink,limits)->CompletedRelationDescriptor`; complete composition above, explicit staged validity and shared wire map. |
| Compiler owner: `r1cs.py`, `stream.py`, `assignment.py` | Deterministic GF(2^192) rows, variable table, last-use frontier, count/hash sink and bounded assignment sink; `assign_private(descriptor,w,limits)->CompletedAssignment`; `check_stream(descriptor,assignment)->satisfaction`. No completed descriptor after abort. |
| Native/boundary owner: `native/relation_adapter.cpp`, `native/CMakeLists.txt`, `proof_boundary.py` | Checked canonical matrix loader into actual pinned `r1cs_constraint_system<gf192>`; `check_native(descriptor,[1],aux)` with independent expected A*z/B*z/C*z; bounded inactive proof envelope and lifecycle adapter refusing acceptance. |
| Coordinator: `run.py`, `cases.py`, `policy.json`, manifests, report | Individually recorded cases/probes, admission and aggregate counters, independent reference comparisons, resource evidence, preservation and stop decisions. |

The native loader must validate exact dimensions/primary/aux lengths, sorted unique
nonzero coefficients and inclusive columns 0..n. Combine duplicates in the compiler,
reject duplicate/noncanonical loaded terms, define empty sums as zero. Native
`linear_combination::is_valid` has empty-term/final-index defects; Release asserts
are not validators; sparse `map.insert` does not sum duplicates. Do not call that
routine as the sole admission check or repair it silently. Use actual native field
operations, matrix creation and satisfaction, with validated inputs; no mock operator.

Use the conservative characteristic-two translation as the explicit initial
lowering: free input b has `b*(b+1)=0`, AND `a*b=c`, XOR `(a+b)*1=c`, NOT
`(1+a)*1=c`. Map Boolean constants 0/1 separately from native column 0 (constant
one). Derived Booleanity follows by induction; all free auxiliary bits need their
own guards. Integer range/carry/mod-q semantics remain constrained. Linear-gate
elimination, field packing or a new arithmetic strategy is **not** implicitly
approved as a fix for the capacity result; report the exact change and obligations
before expanding this defined lowering.

One logical relation uses global immutable variable IDs and an ordered streaming
row hash. Partition boundaries pass private wires and sticky validity by identity,
not public values specialised to a test vector. Each last-use frontier is bounded;
missing, duplicated, misordered or inconsistent edges abort. A host stream checker
is a full local constraint evaluation only if every row and boundary is visited;
it is not an independently composed proof. Do not add new Booleanity/entry guards
at internal wired boundaries then claim those duplicate counts are intrinsic.

The required deliverable is complete source for Rauth, an independently checked
complete relation descriptor and assignments for the admitted synthetic public
shape, plus nontrivial native correspondence. Complete resident authentication
loading is a **separate capacity-gated result**. If the compiler cannot finish
within its cap, deliver its source and exact incomplete prefix with the milestone
marked incomplete; if complete counts prove resident infeasibility, finish with a
capacity no-go, not a full native authentication success. Public preprocessing,
inverse NTT, sampling and same-rid linkage may not be left as accepted placeholders.

## Complete accounting and allocation gate

Record `m` rows, `n` variables excluding constant, `k` primary, every private/free/
derived/padding variable, nnz(A/B/C), gate types, Booleanity, final equality,
conversion and boundary rows separately. Record per-component half-open row and
variable ranges; their disjoint union must equal the full descriptor. Deterministic
public folding is counted exactly for the actual X. Cache use must preserve the
same expanded logical count and identity. A prefix/projection is labelled incomplete;
never multiply one twiddle's measurement into an exact full transform.

Use a counting/streaming sink **before** matrix, assignment or codeword allocation.
A completed descriptor contains final counts, ordered matrix digest, provenance,
public preprocessing digest, fixed output, topology and maximum frontier. The
independent row checker must consume to the expected final footer; I/O/resource
failure cannot yield satisfaction. Every separately launched partition/probe and
repeat consumes an invocation; replayed/evaluated work consumes aggregate work even
if no trace is stored. No hidden uncounted partition campaign.

The admission record must separately bound:

- input storage (5,329B raw witness plus public X), live symbolic/assignment
  frontier, emitter/index/object overhead and conversion buffers;
- sparse rows: exact term counts and native measured element/container sizes,
  allocation capacity, row-object overhead and copies (not merely serialised bytes);
- native primary/aux vectors, Az/Bz/Cz, interpolation, FFT, masks, simultaneous
  retained oracle/codeword vectors, Merkle nodes/salts/opening data, and source-
  visible copies in `aurora_iop`/`r1cs_rs_iop`;
- stream files, compiler temporary objects, binary outputs and peak combined
  artifact occupancy, separately from logs/manifests/results;
- count generation, witness generation, stream evaluation, native loading and
  any future proof/verification time separately.

Unknown allocation multiplicities or query/masking fixed points mean **not
admitted**. At most 75% of the worker limit may be planned for known live native
allocations; the remaining 25% is an estimate margin, not extra memory. Guarded
actual 1 GiB native / 256 MiB Python limits remain final. Do not allocate a small
fraction then claim the complete instance was admitted.

A source-derived conditional lower bound is already decisive for direct lowering.
The measured forward transform has 27,044,356 gates and 10,679,298 AND gates,
32.392s total generation/counting and 39.296s evaluation across 97 partitions.
One row per gate gives padded M=2^25. For b>=1 the reviewed family requires
`Dconstraint >= 2M+2b-1 > 2^26`, `|L| >= 8*max(D,Dconstraint)` and a power-of-two
domain, hence `|L| >= 2^30`. Three 64-bit limbs per native field element imply
24 GiB for **one** codeword, before other vectors or matrices. This is conditional
on this unchanged conservative lowering, not measured full Rauth/R1CS cost, a
claim about every compact representation, or a revision to RISC Zero forecasts.
Even six forward transforms alone take about 194s generation and 236s evaluation
if the previous measured rates apply; those are projections excluding inverse
transforms, hashes, sampling and all other relation work. Sixteen complete
constraint assignments may not fit the proposed time. That uncertainty is an
explicit stopping condition, not a promise to hide work behind a batched test.

The [execution plan](data/oct31_auth_relation_integration_1/execution-plan.json)
therefore proposes a count-first stop after the defined lowering is assessed.
If it cannot support the native memory bound, **do not build a full private Aurora
instance, split it into separately accepted proofs, move hidden work outside the
relation or automatically switch backends**. A compact/compiler or backend-memory
redesign would require a specific next amendment justified by the completed count,
not another general survey or an unexplained RAM increase.

## Independent validation and stopping semantics

The plan enumerates **96 distinct initial cases/probes** (including four count
admissions) plus at most **32** additional, individually labelled partition jobs
or diagnosed affected corrections: 128 invocations total. Multi-assertion checks
of one fixture remain one case; independent mutations, injected failures, test
polynomials, parameterisations and separate generation probes are separate cases.
Unused slots do not authorise proof attempts or broad regression reruns.

| Group | Cases | Independent basis and required distinction |
| --- | --- | --- |
| P-01–12 | Public X, schema/instance/key/state/context/policy and disclosure boundary | Existing canonical validators and reference PubOK/Ppub; no calling lowering for expectations. |
| W-01–12 | Private canonical parsing, holder binding, bit-order/rid and message context | Existing encoders plus explicit byte layouts; changed trusted selections rejected. |
| M-01–16 | Bounded challenge, norm/hints, forward/inverse/pointwise/decomposition boundaries | Exact host integer arithmetic and bounded verifier; FIPS schedule independently traversed, not shared faulty schedule helper. Test-only sampler streams distinguish exhaustion semantics from finding a real SHAKE preimage. |
| J-01–16 | Joint complete relation positives and cross-component negatives | Existing `relations.auth` and bounded ML-DSA on synthetic real credentials; generated assignment plus every constraint. Host-only agreement cannot mark constrained comparison passed. |
| N-01–16 | Nonzero native matrices, field products, primary/aux/boundary tampering, canonical loader | Independently specified field coefficients and direct row arithmetic; actual pinned native operators. Small matrices are labelled small. |
| B-01–12 | Proof envelope bounds, trusted identifiers, private-data separation and lifecycle fail-closed | No proof creation or accepted synthetic token. Prior lifecycle evidence reused; new adapter must refuse before atomic challenge consumption. |
| G-01–08 | Count/coverage, partial stream, resource accounting and absent completion footer | Synthetic small limits/fixtures; no intentional actual ceiling breach. |
| Q-01–04 | Count-only preflight, complete descriptor, frontier and native admission calculation | Exact counting scope; only completed coverage yields a complete count. Conditional phases skipped with reason on no-go. |

`cases.json` is the exact list. Required joint cases include two valid credentials,
changed context bound to the new statement, valid policy/disclosure variation,
wrong xH, changed certified attributes/signature/rid, swapped credential signature,
swapped non-revocation path from another credential, changed sibling/order/root,
revoked leaf and disclosure mismatch. Same-rid linkage cannot be replaced by two
separately passing host checks. Public invalid cases may reject before constraints;
private negatives must reach the constrained predicate where their syntax permits.
For malformed witness input, record decoder rejection separately from an assigned
false final predicate. Outputs after invalidity remain unusable.

Stop further execution on an integrity/security-boundary/resource failure. A scoped
implementation defect may be diagnosed and corrected only inside the listed new
files, with a recorded affected dependency graph, build/invocation charge and
preserved failed fixture. No automatic retry. An input expectation may not be
changed merely to obtain a pass. If all required joint cases cannot complete,
report partial validation; do not close full-relation validation.

## Proof encoding, verification and lifecycle boundary

Implement a bounded **inactive** envelope validator and descriptor, not an accepted
proof. Retain draft `PQDAUR01`, u16 version/u8 kind/u8 flags, PID/RID/Xtag 64B each,
u32 body length: 208B header. `Fr` retains u16 tag length, u32 number of parts and
u64 part lengths. Outer H is fixed unkeyed sequential BLAKE2b-512; internal
credential/holder/Merkle hashes remain SHA3/SHAKE. Canonical field elements are
24B little-endian coefficients; proposed scalar commitments have 64B roots, 128B
leaf salts and 64B siblings. Packed upstream leaves/pruning are not this encoding.

The eventual fixed descriptor enumerates every round/message/commitment/query,
terminal coefficients, beta and projected opening closure; reject unknown IDs,
counts, duplicate conflicts, noncanonical fields, overruns, trailing bytes and
incomplete paths before expensive work. Check length arithmetic for overflow and
stream under both the declared and configured cap. For complete descriptors the
proposed exact wire formula is
`208+12R+64C+24Mdir+4+sum_openings(152+64*height)`; it is a formula, not a measured
proof size or a fixed secure parameter choice. The provisional 10 MiB proof,
12 MiB presentation, 30s proving/2s verification/45s end-to-end targets are not
established and not new resource authorisations. This milestone keeps ordinary
1 MiB fixture/evidence files; oversized synthetic headers can be rejected without
allocating their claimed payload. A future real proof artifact exception requires
explicit approval if its encoding exceeds existing per-file rules.

Future verification must load a trusted configured PID/RID, reconstruct X from
expected pp and the pending challenge, independently derive the public preprocessing
and relation, enforce PubOK/Ppub, parse complete proof, then use the real admitted
backend verifier. Verification must run without witness access and independently
of the prover process; cross-implementation or independently specified transcript/
opening checks must accompany it. Local `is_satisfied` reads an assignment and is
not a proof verifier. No ordinary API may turn it into authentication acceptance.

Keep request authentication, holder consent, issuer trust, latest-state lookup,
audience/session binding, disclosed DID/version checks, strict final `now < texp`
and atomic single consumption in the existing durable verifier lifecycle. A future
`ProofVerifier.verify(statement,proof)` connects at that existing boundary only
after admission; this package's adapter returns unsupported/failure and leaves the
challenge unconsumed. Freshness is rechecked at commit. Never substitute the
baseline's persistent holder-key signature for private xH knowledge.

## Security admission matrix

| Item | Established | Exact remaining condition / kind of work |
| --- | --- | --- |
| EXP2 and native field/SC/LD/FR | Finite public native correspondence, verified field modulus, corrected unrestricted sumcheck mask/early beta, unit-pad reducer and folded degrees | Complete nontrivial relation and private round schedule: **implementation/refinement**, not full Aurora correctness. |
| Algebraic privacy | Existing joint straight-line classical simulator for the corrected ideal-polynomial-oracle family with bounded projected positions and fresh masks | Full descriptor/query closure `B_RS<=b`, independent masks, terminal/direct messages: **theorem application plus implementation**. Concurrent, restoration and quantum variants are not implied. |
| Commitments, TB-06 | Binding format analysis and identified packed/scalar discrepancy | One witness-free simulator must choose roots before challenges and answer every allowed adaptive value/salt/path opening consistently with algebraic simulation: **missing construction-specific transformation argument and encoding implementation**. A binding hash alone is insufficient. |
| Classical BCS knowledge/privacy, TB-09 | Conditional source theorem and symbolic errors recorded | Exact BCS correspondence, restricted state-restoration soundness/knowledge, encoded IOP and programmable-oracle/query resources: **demonstrated theorem application if premises established; otherwise new bridge**. |
| Quantum knowledge | Informal QROM route recorded | Applicable formal round-by-round knowledge/soundness plus HVZK for this exact IOP/FRI/BCS variant, extractor runtime/state access and finite constants: **unresolved theorem application/argument**. Do not read a numerical guarantee from O-notation. |
| Adaptive application games | OC-REL/EXT/PRIV/BUDGET identified | Preserve terminal statement, acceptance, service history and residual state through extraction; public-only online privacy through later revocation/corruption/repeated presentations: **new application composition argument**. |
| Concrete hashes/parameters | FIPS inner functions and source identities fixed; illustrative workload scenarios recorded | Model all outer BLAKE2b ports/shared encodings, connect instantiation to each game, actual finite `m,n,k,s,a,P,I,q,r,b,D,Df`, enlarged reduction budgets and component advantages: **finite calculation/theorem application plus unresolved hash assumptions/bridge**. No overall bit-security number is established. |
| Operational security | Synthetic reference operations and bounded primitive/lifecycle evidence | Entropy/custody/erasure/side channels, production signing, durable holder storage and adaptive Delta_tail: **separate implementation/security work**, still open. |

For the corrected general reducer, carry `J=3a+5`, `Dlin=2t+b-1`,
`Dtest=max(Dlin,M+2b-1)`, `Dconstraint=max(Dlin,2M+2b-1)`,
`D=2^r*ceil(Dtest/2^r)`, `Df=D/2^r`, and `|L|>=8*max(D,Dconstraint)` with
complete query projection. Do not apply the specialised Figure 5 expression to a
different matrix. BCS's conditional `kappa_sr+3*(Q_H^2+1)*2^-ell` and
`z+p*2^(-ell/4+2)` remain conditional; ell=512 gives a symbolic privacy term
`z+p*2^-126`, not an established 128-bit claim. The CMS informal
`O(Q_H^2*epsilon_rbr+Q_H^3/2^ell)` supplies no finite constants here.

A **classical ideal-polynomial-oracle algebraic experiment** can be explicitly
labelled research evidence after implementation/descriptor checks. A **hashed
private classical-ROM proof pilot** still needs TB-06 and the classical BCS
premises, plus complete relation/resource/wire validation. It is not presently
admitted. A post-quantum application claim additionally needs the quantum/adaptive/
concrete gates above. No relaxed option replaces the intended post-quantum goal,
and none consumes the reserved proof attempt during this milestone.

## Consolidated resource request and executable sequence

Opening implementation balance is **3,297.852425s**, invocations **867/1,050**,
builds **8/13**. These remain unchanged during this preparation. Of 183 unused
invocations, 181 belonged to the closed milestone and two are historical tooling
slots; unused capacity needs this explicit reallocation. Analysis opening is
**107.054637s/300s**. The preparation's measured closure, current storage and
remaining analysis balance are recorded separately in `validation-closure.json`.

Request approval to reallocate **2,550 existing implementation seconds**, including
**300s completion reserve**, **128 invocations** (96 initial + 32 partition/affected
correction slots) and **three existing build slots**. This adds no overall time,
invocations or builds: if all are consumed, 747.852425 implementation seconds,
55 invocation slots (53 reusable milestone + two historical tooling), and two
build slots remain. The analysis/isolation/proof budgets cannot be borrowed.

Propose a new, explicit **2^32 aggregate primitive work-event cap** for this
milestone, covering emitted gates/rows and evaluated gate/row visits, including
failures/repeats. It is a stopping bound, not an estimate that this much work fits
2,550s. Preserve individual trace <=2,000,000 gates, existing count-only ceiling
<=32,000,000 per partition, <=65,536 external input positions and every memory/
storage limit. Each separately emitted/counting partition consumes an invocation;
stop when the 32 additional slots or cumulative allowance cannot cover the next
partition. This is the sole proposed computational-ceiling amendment; no prior
package's aggregate gate allowance is silently reused.

Allocate time as caps, not measured predictions: 240s admission/source/bookkeeping,
600s component/reference validation, 900s full streaming counts/assignments,
165s for three build attempts (55s each), 345s native/boundary/static checks,
and 300s preservation/reporting/cleanup. Their sum is 2,550s. No phase may borrow
completion reserve for tests. Count/evaluation totals are uncertain and may force
a documented stop; the historical component timings do not establish fit.

At the completed milestone, evidence was **24,789,361/33,554,432B** and artifacts
**58,112,659/134,217,728B**. This preparation permits <=2 MiB new evidence and
charges its actual bytes without deletion/reclassification. Request <=**6 MiB**
new integration evidence, including **2 MiB finalisation**: even the full 2 MiB
preparation reservation plus 6 MiB leaves 376,463B below the cumulative cap.
Request <=**64 MiB new artifacts** inside the existing aggregate artifact ceiling;
this leaves 8,996,205B aggregate slack at the recorded opening occupancy. Recheck
actual occupancy at launch. Downloads, scratch, objects, binaries and temporary
matrix/assignment chunks all count as artifacts; metadata/logs remain evidence.
There are no downloads or installations in this proposal.

Retain 32 MiB only for registered artifact files, 1 MiB ordinary source/evidence,
60 KiB command logs, 8 MiB ordinary temporary data, 9 GiB experimental disk stop,
zero swap, 2 CPUs, TasksMax128, native1GiB/Python-tool-audit256MiB and 2GiB aggregate.
One heavy worker at a time; at most two independently owned source tasks may work
in parallel with aggregate accounting. Native/source compiler and relation work
cannot run independently before interfaces/pins are fixed. No new host account,
service activation or global environment mutation. Commands remain bounded by
300s outer/295s child and tighter phase reservations.

Execution order (future driver commands, to be implemented and statically reviewed
before dispatch; not claims that executables already exist):

1. `run.py admit`: verify v1 seals, unchanged dependencies/patches, ledger/storage,
   explicit approval and all reserves; freeze new profile/compiler contract and
   exact public fixture X. Reject a full native allocation on the existing lower
   bound; permit bounded stream/source work only.
2. Implement the listed isolated files. `run.py build B1` builds only the new
   relation adapter against pinned existing dependencies; B2/B3 are available
   solely for diagnosed new-file corrections with retained failures.
3. `run.py case ID`: execute the explicit P/W/M/N/G cases with independent public
   fixtures; each case once, affected corrections separately named. No old N/TR/
   baseline suites are rerun unless changed shared inputs justify them.
4. `run.py case Q-01` then Q-02–04: bounded counting and frontier/descriptor checks.
   Additional partition jobs have explicit IDs and shared counters; no reset at
   boundaries. If incomplete, preserve exact last completed component/row and stop
   further large work. Complete counts determine whether native admission is
   possible; current conservative route is expected to be rejected.
5. J-01–16 run complete stream checks only while their measured/admitted bounds
   leave completion reserve. Native full-relation comparison is additionally
   conditional on complete memory admission. B-01–12 validate the inactive proof
   boundary. Every omitted case is listed with reason; partial coverage cannot be
   reported as full validation.
6. `run.py quality`, `prepare`, `full-audit`, `readback`: reuse the corrected
   preservation workflow with all retained repair artifacts, frozen prior
   prefixes/full seals, exact new-name inventory, final report/resource closure
   and shutdown of only this milestone's transient workers. One final audit;
   failed finalisation is incomplete, not success.

Acceptance requires all four semantic limbs in one relation; independent full
outputs/rejection outcomes; exact complete count/assignment/boundary coverage;
nonzero actual native R1CS correspondence; documented capacity decision; ordinary
proof acceptance still fail-closed; and complete preservation. A negative capacity
result can close the investigation as **NO-GO for resident Aurora integration**,
but cannot close full relation validation if J cases/counts are incomplete.
No private proof, full Aurora proof generation, zkVM run, activation or native
library functional repair is included. Proof ledger remains two used/one unused.

## 31 October decision

There is a usable versioned KYC comparison point now. A complete private
post-quantum authentication proof by 31 October is **not supported by current
implementation, resource or security evidence**. The requested milestone advances
the actual joint relation and yields a concrete complete-count/capacity decision;
it cannot responsibly promise a compact proof at the provisional targets. If the
selected conservative route hits the documented no-go, stop that route explicitly
and use the exact failed capacity/bridge condition to decide whether a narrowly
specified redesign is justified. Do not spend the remaining proof attempt to
conceal missing relation or security premises.

One approval request covers the isolated implementation, explicit existing-budget
reallocation, work-event cap, scoped corrections and stop policy above. No approval
is requested for a proof attempt. Stages 2–3, AURORA-BRIDGE-001, adaptive Delta_tail,
component advantages at reduction budgets, production security and complete proof
knowledge/privacy remain open. Isolation stays safely stopped/unactivated and CPU
proving paused.

## Preparation preservation — completed analysis checks

Proposal lint/format and trusted-v1 identity checks passed; no functional cases,
builds, circuit generations, proofs or zkVM executions ran. The single complete
preservation audit exited 0, with 10,901 disjoint content comparisons (8,759 +
2,142), 10,936 identity-inclusive historical paths, all latest full seals and
protected prefixes, and a 10,770-entry inventory across sixteen non-overlapping
roots. All 1,565 local documentation links passed. No original baseline, expected
hash or retained repair evidence was replaced. Only the explicitly recorded three
status/traceability/issue documents received appendices.

Audit elapsed time was 3.922663s; cgroup-v2 memory.peak was 43,925,504B under
268,435,456B, including worker descendants and charged cache/kernel memory. The
external coordinator is outside that cgroup; separately sampled summed tree RSS
was 60,710,912B, with possible shared-mapping double counting. No memory event,
swap, timeout or diagnostic/storage breach occurred. Final inventory, report-seal
readback, exact analysis charge and storage totals are in the
[preparation closure](data/oct31_auth_relation_integration_1/validation-closure.json).
The 20s conservative local/source/bookkeeping charge includes this finalisation;
measured guarded checks are additional. Analysis opening was 107.054637499s;
implementation remains 3,297.852425286s, invocations 867/1,050, builds 8/13.
The proposed execution remains inactive.
