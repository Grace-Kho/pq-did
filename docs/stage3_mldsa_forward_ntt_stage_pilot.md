# S3-MLDSA-FORWARD-NTT-STAGE-PILOT-1 — four-lane composition

26 September 2026. **All 16 invocations pass** for a dependency-complete fragment
of four butterflies on lanes **0, 64, 128 and 192**, spanning forward lengths 128
and 64. The complete candidate uses **213,448 total/81,838 AND gates**, versus
**621,868/246,058** for the matched reference. Internal canonical reuse preserves
the original external contract. The measured decision, individual results and
preservation/resource closure follow below. This remains an experimental
compiler/profile proposal; active BC-1 and production arithmetic are unchanged.

## Authority, baseline and opening resources

Only manuscript Sections **II–VIII**, agreed SPEC-001–004 and the
[current specification](implementation_spec.md) are authoritative. Reuse the
[butterfly pilot](stage3_mldsa_butterfly_composition_pilot.md),
[arithmetic review](stage3_mldsa_arithmetic_lowering_review.md),
[scalar lowering evidence](stage3_mldsa_modmul_lowering_pilot.md) and
[authentication feasibility plan](stage3_auth_proof_feasibility_plan.md).
The experimental hint lowering and these short-width arithmetic candidates are
not canonical BC-1. No performance claim comes from excluded manuscript sections.

[Preflight](data/s3_mldsa_forward_ntt_stage_pilot_1/preflight-evidence.json) verifies
the previous 49-file seal
`7c4add5ca318d549bc87dbfcd6a691ebceeb9a0f83ebaa65eb497bfd5d01cd6f`,
the 53 assessed source/input identities and manuscript SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
[Reviewed inputs](data/s3_mldsa_forward_ntt_stage_pilot_1/reviewed-inputs.json)
pin exact content revisions; this is not a Git revision or a regenerated baseline.

| Opening ledger | Balance |
| --- | --- |
| Implementation | 224.62266500794794/300 s consumed; **75.37733499205206 s remain** |
| This package | At most 30 s, including validation, audit and established 5 s operator/bookkeeping charge; 10 s evidence/cleanup reserve before pilot |
| Invocations | 263 consumed; explicit ceiling amendment **263→279**, 16 available |
| Analysis | 253.60648515704088 s remain, untouched |
| Isolation | Safely stopped/unactivated; 250.22 s remain; 100 historical invocations, 22 original identity cases pending; untouched |
| Proofs | Two attempts used, one unused; CPU proving paused |

The existing accounting convention charges guarded command wall time plus the
five-second bookkeeping allowance, not conversation time. No budget transfer,
automatic retry or limit increase is permitted. Preserved ceilings: 256 MiB
cgroup-v2 memory.max, zero swap, one worker, two CPUs, four controlled processes,
60 s command/55 s child maxima, 8 MiB temporary disk, 10 MiB cumulative evidence,
1 MiB/file, 60 KiB command diagnostics, existing 9 GiB storage/diagnostic stops
and 2 GiB headroom reserve. Arithmetic also keeps the 128 MiB process-tree RSS
stop and 256 MiB process address-space cap. The unchanged corrected preservation
auditor remains under 256 MiB, including report completion and the outer guard.

Pilot reservation is 13 s (child 12.5 s, inner stop 11 s); generation limit 10 s
and evaluator limit 2 s. Each probe keeps the **2,000,000-gate ceiling** and at
most 8 MiB retained trace data. Count mode's hypothetical serialised size is not
allocated/stored; its existing gate/time limits still apply. Materialised traces
are released sequentially. No 64M-gate/2 GiB proposal is activated.

## Exact schedule and dependencies

The source is [`bounded_mldsa._ntt`](../src/pqdid/bounded_mldsa.py), with the checked
arithmetic relation supplied by
[`scalar_ring.ntt_butterfly`](../src/pqdid/circuits/scalar_ring.py). FIPS 204
Algorithm 41 provenance is already recorded in the preceding reports. The Python
verifier normalises entry coefficients, then iterates lengths 128,64,…,1;
twiddle index m increments at each public start. Here only four nodes execute:

| Node | Length / start / j | Twiddle index and ordinary residue | Old left, old right | Dependencies |
| --- | --- | --- | --- | --- |
| A | 128 / 0 / 0 | m=1, z=4808194 | lanes 0,128 | External inputs x0,x128 |
| B | 128 / 0 / 64 | m=1, z=4808194 | lanes 64,192 | External inputs x64,x192 |
| C | 64 / 0 / 0 | m=2, z=3765607 | lanes 0,64 | A.left, B.left |
| D | 64 / 128 / 128 | m=3, z=3761513 | lanes 128,192 | A.right, B.right |

Public twiddles are `1753^BitRev8(m) mod q`, q=8380417. G1's construction checks
these constants against both the pinned verifier table and that formula; no full
verifier or transform is executed. The independent oracle derives its constants
from the formula and uses an explicitly separate lane schedule.

This fragment is closed under arithmetic dependencies for the selected four
outputs through these two stages. Unlike the previous two-node pilot, it has no
uncomputed frontier producer. Omitted butterflies touch disjoint lanes during
these stages. Their potential failures in a **whole** transform are not assessed:
the fragment proves nothing about other lanes or a global full-transform predicate.
The common incoming rejection bit represents prior faults, not assumed success.

Each node computes checked z*b, reduces p modulo q, then checked a-p and its
remainder, then checked a+p and its remainder, preserving old a and right-before-
left update order. Return ordering is left then right. Final lane ordering is
**C.left, C.right, D.left, D.right**, corresponding to 0,64,128,192.
Forward ordinary residues are not Montgomery or centred representatives.
No inverse NTT operation, reversed/negated twiddle schedule or inverse scaling is
implemented or validated in this package.

## External contract and representations

The isolated [candidate](../experiments/mldsa_forward_ntt_stage_1/candidate.py)
accepts exactly four signed64 NTT Scalars, with existing wire/domain/width checks,
and active/prior-rejection scope controls. Private inputs occupy 258 fixed bits:
four 64-bit words plus two controls. There is no public/private substitution.
The fragment has the same **generic checked butterfly** entry contract as the
previous pilot, not a newly imposed canonical-only input precondition.

For an active clean first-stage node, require signed64 representability of z*b,
a-p and a+p. Any violation rejects the entire fragment. Negative or ≥q words are
not inherently malformed and remain accepted where those original checks pass.
Thus inputs are not silently normalised into acceptance after an original
overflow. This matters at the generic gadget boundary even though the verifier's
normalised entry values already meet stronger bounds.

The measured fragment does not separately implement `_ntt`'s preceding decoded-
coefficient normalisation. Four full signed64 conversions are already performed
inside the candidate's first-stage nodes. A future complete-transform interface
must account for its exact entry normalisation and retain original signed z for
the final norm check. Equivalence of the entire `_ntt` on arbitrary pre-normalised
Python integers is not claimed here.

| Boundary | Representation and checks |
| --- | --- |
| External inputs | Signed64 NTT Scalars; structural checks plus original checked arithmetic acceptance at A/B |
| A/B conversions | Both words per node use unchanged complete SPEC-004 mod64, including quotient/remainder checks and the unsigned magnitude of MIN=-2^63 |
| Every scalar product | Prior experimental canonical guard, exact 23×23→46-bit product and fixed 46-step restoring reduction; same public constants and private bits |
| Every butterfly correction | Original product-overflow predicate, checked raw64 a-p/a+p, signed25 subtraction and correction, 24-bit addition and signed25 q correction |
| A/B outputs → C/D | Unique canonical residue 0..q-1, zero-extended/masked to64 bits; use the actual producer wires, never an external canonicality flag |
| C/D entry | Reuse the producer representation; omit their four redundant complete mod64 calls only; keep product-overflow tests, raw add/sub checks and scalar canonical guards |
| Node outputs | Full64 mask by active AND NOT current rejection, node validity retained for observations |
| Final fragment output | Mask all four lanes again by the final scope predicate; return final validity and canonical64 words; partial output is unusable after rejection |

The private `_from_canonical_producers` routine is used only at C/D, wired by the
fixed fragment constructor from A/B. It is not a general checked raw-input API;
calling it independently on arbitrary scalars would violate its precondition.
There is no caller-controlled “trusted input” flag. This is a construction
invariant in an isolated experiment, not a key-custody or process-security claim.

Baseline, fully guarded experimental composition and reuse candidate share one
external contract. The fully guarded variant calls the previous experimental
butterfly at all four nodes, repeating internal normalisation. The baseline calls
the unchanged production butterfly through its previously validated masked
wrapper. Both boundaries and the final four-lane mask are identical. No production
file or prior candidate is modified.

## Range argument and justified reuse

For public z>0, the prior overflow predicate
`ceil(-2^63/z) ≤ b ≤ floor((2^63-1)/z)` is exactly equivalent to signed64 z*b
representability. The retained complete signed64 comparisons implement it. Raw a±p
checks retain the original acceptance even when a is a noncanonical representative.
For z=0 the public construction branch is trivial; that unused twiddle is not a
new case in this pilot.

After normalisation, 0≤a_bar,b_bar,z<q<2^23, so b_bar*z≤(q-1)^2<2^46.
The reused scalar kernel's exact product and restoring invariant are unchanged:
each prefix remainder r<q gives T=2r+bit≤2q-1<2^24, and T-q∈[-q,q-1] fits signed25.
One conditional subtraction restores 0≤r<q. The butterfly sum lies in
[0,2q-2] within24 bits; its difference lies in [-(q-1),q-1] within signed25.
One q correction suffices, and the selected upper bits are zero before taking23
low bits. Zero-extension restores the required64-bit interface without gates.

Every A/B result is therefore canonical on valid active paths. Invalid/inactive
paths are masked to zero, also canonical. Consequently both words entering C/D
are canonical for **every witness assignment**, independently of validity, while
the rejection bit remains sticky. Applying positive-q mod64 to these words would
return the identical word and true representability. Removing those four calls
cannot change acceptance or a usable output. All other overflow and canonical
checks remain emitted, even where the invariant makes them redundant.

For clean canonical inputs, z*b<2^46, a+p<2q and |a-p|<q also show C/D cannot
introduce an integer-overflow rejection. A prior rejection never clears. This
range induction accounts for both representation reuse and fault propagation;
the scope control does not become secret-dependent Python flow. Loop indices,
node choices, constants and partitioning are public and fixed.

All valid internal and final representatives are the same canonical integers as
the reference, hence byte-for-byte equal when serialised as the required64-bit
words. Congruence alone is not the test criterion. Speculative rejected values
before node masks and internal diagnostic fault wires are not required to match.
The complete exposed fragment always returns zero unusable lanes after rejection.

This is an implementation-equivalence argument, not a universal proof of the
code or compiler conformance. Short-width lowering and invariant-based omission
remain outside frozen BC-1; behavioural agreement does not permit profile adoption.
No change to signature formats, samplers/caps, message/context, original signed-z
norm, certified rid/attributes, holder binding, revocation linkage, disclosure,
freshness or expiry is introduced. Outer-oracle composition and proof knowledge/
privacy obligations remain independent.

## Four probes and twelve complete differential cases

The [runner](../experiments/mldsa_forward_ntt_stage_1/run_pilot.py) performs exactly:

| Probe | Graph and mode | Coverage / counted result |
| --- | --- | --- |
| G1 | One count-only comparison graph with three independent full cores: reference, fully guarded, reuse | Complete four-node counts for each; two harness ANDs separate; no retained trace |
| G2 | Complete reuse candidate, materialised | All A/B/C/D nodes and final output boundary; counts must equal G1 candidate |
| G3 | Reference A/B, materialised | First stage only; internal words and rejection state retained as small observations |
| G4 | Reference C/D and final output boundary, materialised | Takes each case's **observed reference G3 outputs/state**; second stage completes that reference case |

G2 is evaluated for each of the twelve cases, released, then G3 is generated and
evaluated for those same cases, released, then G4 completes them. No two traces
are retained together. The node partition is exactly {A,B} and {C,D}, without
overlap or missing nodes. G3 has no extra stage-final masking or scope check;
G4 contains the one required final boundary. Its carried state is the actual G3
predicate, not a success flag supplied by the oracle. All connecting wires remain
private. XOR/AND/NOT counts must reconstruct the independently counted full
reference core, which checks the counting coverage; differing wire numbers and
partition headers are not represented as identical bytes or a partitioned proof.

These are **twelve full schedule cases**, each with candidate, first-reference and
second-reference observations. There are 36 evaluator calls and 36 independent
trace-observer passes, transparently recorded. A case remains incomplete until
all observations agree; there is no extra input combination or repeated case.
The four circuit generations are separately counted. No native harness, historical
suite, full transform, inverse experiment, proof or zkVM run occurs.

The independent arithmetic oracle uses exact host integers and the preserved
[`floor_pair`](../tests/reference/scalar_oracle.py) Fraction/floor implementation,
with its own explicit lane schedule and public twiddle derivation. It includes
all original signed64 overflow conditions, active control, sticky rejection and
node/final masks. The [independent observer](../tests/reference/signature_oracle.py)
reads all eight node words/flags and all four final lanes. Normal circuit evaluation
also checks final acceptance. Finite cases are not full-transform equivalence.

| Case | Inputs in lane order (0,64,128,192) | Distinct risk |
| --- | --- | --- |
| D1 | (0,0,0,0) | Zero boundary |
| D2 | (0,1,2,3) | Asymmetric lane ordering and all actual twiddle assignments |
| D3 | (q-1,q-1,q-1,q-1) | Upper canonical boundary |
| D4 | (q-1,0,1,q-1) | Addition q correction and negative subtraction correction |
| D5 | (-1,-2,-3,-4) | Signed representatives remain admitted |
| D6 | (q,q+1,2q,2q+1) | Noncanonical positive input conversion without domain narrowing |
| D7 | (MIN,MIN,0,0) | Full signed64 magnitude/normalisation boundary |
| D8 | (0,0,floor(MAX/z1),floor(MAX/z1)) | Original product upper acceptance boundary |
| D9 | (0,0,floor(MAX/z1)+1,1) | A overflows; rejection propagates through every dependent result |
| D10 | (1,MIN,1,1) | A succeeds with nonzero outputs; B's raw subtraction overflows; no partial final result |
| D11 | D9 inputs, inactive/clean | No new rejection, but outputs remain unusable |
| D12 | D2 inputs, active/prior rejection | Existing rejection retained |

MAX=2^63-1, z1=4808194; other cases are active/clean. Shape, wrong-domain/foreign
wire failures and unused public-twiddle refusals are retained in source checks but
not additional executed cases. Negative product thresholds and other twiddles are
not exhaustively sampled. No coverage claim extends beyond the explicit cases
and separate structural range argument.

## Decision criteria and preservation

The first static lint check found one E501 (109-character Markdown link in the
report-generation helper). No circuit or case had run. The exact failure, STOP
record and pre-correction helper/configuration snapshots are retained in
[the correction record](data/s3_mldsa_forward_ntt_stage_pilot_1/lint-correction.json).
After source review, split that line and admit only named formatting/lint follow-up
commands; original failure records are not overwritten. All command time,
including the failed check, is charged. Under the established accounting rules,
static lint/format checks are separate from counted functional tests/probes.
No test/probe retry is authorised or hidden by this correction.

Require complete counts, all sixteen invocations within limits, all intermediate
and final values/flags matching, candidate materialised/count parity and complete
reference partition count coverage. Candidate total/AND reductions must include
entry conversions, retained arithmetic checks, node masks and final boundary.
Capped prefixes, resource failures or incomplete reference partitions cannot pass.
If useful, the next decision concerns a bounded full-forward experiment with an
explicit complete schedule/partition plan, not automatic generation of a full
transform under this package's budget.

Earlier scalar, single-butterfly and two-node counts remain historical evidence.
Report the complete measured three-way comparison and phase increments; do not
add overlapping counts or multiply this fragment into a purported full-transform
result. No complete-authentication proof or RISC Zero forecast is inferred.

The measured reference is exactly `4 × 155402 + 260 = 621868` total gates and
`4 × 61450 + 258 = 246058` AND gates. The fully guarded experimental composition
is `4 × 89189 + 260 = 357016` total and `4 × 33726 + 258 = 135162` AND gates.
The added 260 total/258 AND gates implement the one final four-lane mask/validity
boundary. These are reconciliations with the **measured** G1 fragment, not estimates
of other stages. The reuse candidate then omits four complete internal mod64
calls: 143,568 total/53,324 AND gates, giving 213,448/81,838. No scalar and
butterfly totals are added together, and the earlier two-node result remains
unchanged with its own different boundary and three-input dependency contract.

The original8759-file baseline and all successive historical seals are preserved.
Only this new experiment, report, package evidence and append-only status,
traceability and issues are authorised. The additive seal is not a regenerated
baseline. Final documentation/readback/sealing uses the existing bounded
bookkeeping allowance after the single complete preservation audit.

ARITH-LOWER-001 remains open for full schedule coverage and compiler conformance;
HINT-LOWER-001, AUTH-FEAS-001, OC-REL/EXT/PRIV/BUDGET, adaptive Delta_tail,
component advantages at reduction budgets, production custody/entropy/erasure/
side channels, durable holder storage and complete proof knowledge/privacy remain
open. Stages 2–3 remain open. CPU proving paused; isolation safely stopped and
unactivated; proof ledger two attempts used, one unused.


## Measured outcome and complete cost

Decision: **supports-bounded-full-forward-experiment**. All16 invocations pass without retry: four generation
probes and twelve complete schedule cases. All three G1 cores have complete
counts under identical external inputs, scope state and final-output requirements.

| Complete four-butterfly core | Total gates | AND gates | Emission/counting seconds |
| --- | ---: | ---: | ---: |
| baseline | 621,868 | 246,058 | 0.675696890 |
| fully-guarded | 357,016 | 135,162 | 0.402018118 |
| candidate | 213,448 | 81,838 | 0.246019996 |

Candidate reduction relative to reference: **408,420 total gates
(65.6763%)**, **164,220 AND gates
(66.7404%)**. Internal representation
reuse saves 143,568 total/53,324 AND gates relative to the fully guarded
experimental composition, which has the same external contract. These are measured
fragment differences, not full-transform or proof estimates.

G1 contains the three independent full cores and two separately reported harness
ANDs; there is no equality-to-test-target logic or algebraic sharing between cores.
G2's materialised candidate counts equal its G1 core counts exactly. G3+G4 equals
the complete G1 reference core separately for XOR/AND/NOT: the node partition is
A/B then C/D, with zero overlap/missing nodes and exactly one final output boundary.
Input declarations and separate serialisation headers are not arithmetic gates.
The reconstruction does not assert byte-identical separately numbered traces.

| Core | Included phase | Total gates | AND gates |
| --- | --- | ---: | ---: |
| baseline | original_checked_butterfly | 621,080 | 245,280 |
| baseline | full64_output_masks_and_validity | 528 | 520 |
| baseline | all_four_final_lanes_masked_by_final_scope | 260 | 258 |
| fully-guarded | exact_original_product_overflow_condition | 2,892 | 1,052 |
| fully-guarded | two_complete_signed64_to_canonical_conversions | 287,136 | 106,648 |
| fully-guarded | guarded_scalar_modmul_including_its_output_boundary | 60,632 | 24,644 |
| fully-guarded | checked_raw_subtraction_and_canonical_negative_correction | 2,968 | 1,024 |
| fully-guarded | checked_raw_addition_and_canonical_q_correction | 2,600 | 1,016 |
| fully-guarded | full64_output_masks_and_validity | 528 | 520 |
| fully-guarded | all_four_final_lanes_masked_by_final_scope | 260 | 258 |
| candidate | exact_original_product_overflow_condition | 2,892 | 1,052 |
| candidate | two_complete_signed64_to_canonical_conversions | 143,568 | 53,324 |
| candidate | guarded_scalar_modmul_including_its_output_boundary | 60,632 | 24,644 |
| candidate | checked_raw_subtraction_and_canonical_negative_correction | 2,968 | 1,024 |
| candidate | checked_raw_addition_and_canonical_q_correction | 2,600 | 1,016 |
| candidate | full64_output_masks_and_validity | 528 | 520 |
| candidate | producer_canonical_representation_reused_no_mod64 | 0 | 0 |
| candidate | all_four_final_lanes_masked_by_final_scope | 260 | 258 |

The historical single/two-node measurements are preserved. Four copies of the
historical reference butterfly require an additional four-lane final boundary;
the measured fully guarded experimental core similarly adds that boundary to
four prior candidate butterflies. All three actual twiddle assignments are now
measured. Reuse omits only the four complete internal mod64 calls. No other
arithmetic check or scalar guard is discounted. Host structural validation and
bit rewiring/zero-extension emit no gates. All external conversions remain counted.

## Individual results, timings and memory

| Invocation | Expected and observed outcome | Result |
| --- | --- | --- |
| G1-complete-count-comparison | complete count-comparison | pass |
| G2-complete-candidate | complete candidate | pass |
| D1-zero | node flags=[1, 1, 1, 1]; final=[0, 0, 0, 0]; usable=True | pass |
| D2-asymmetric-lane-order | node flags=[1, 1, 1, 1]; final=[7905700, 2946659, 5441946, 466529]; usable=True | pass |
| D3-canonical-upper | node flags=[1, 1, 1, 1]; final=[4425519, 2718925, 5661490, 3954896]; usable=True | pass |
| D4-both-modular-corrections | node flags=[1, 1, 1, 1]; final=[1046680, 189289, 8187032, 7337829]; usable=True | pass |
| D5-negative-representatives | node flags=[1, 1, 1, 1]; final=[4900236, 8152683, 219544, 3488367]; usable=True | pass |
| D6-positive-noncanonical | node flags=[1, 1, 1, 1]; final=[7527120, 853297, 7527120, 853297]; usable=True | pass |
| D7-signed-minimum-lefts | node flags=[1, 1, 1, 1]; final=[5410580, 603886, 4631251, 1383215]; usable=True | pass |
| D8-product-upper-boundaries | node flags=[1, 1, 1, 1]; final=[3061334, 6882954, 5243726, 1572820]; usable=True | pass |
| D9-first-node-product-overflow | node flags=[0, 0, 0, 0]; final=[0, 0, 0, 0]; usable=False | pass |
| D10-second-node-subtraction-overflow | node flags=[1, 0, 0, 0]; final=[0, 0, 0, 0]; usable=False | pass |
| D11-inactive-invalid | node flags=[1, 1, 1, 1]; final=[0, 0, 0, 0]; usable=False | pass |
| D12-prior-rejection | node flags=[0, 0, 0, 0]; final=[0, 0, 0, 0]; usable=False | pass |
| G3-reference-first-stage | complete reference-first | pass |
| G4-reference-second-stage | complete reference-second | pass |

Every case compares all eight intermediate node words, all four node flags, final
four lanes and final validity against the exact-integer oracle and partitioned
production reference. D10 has an earlier successful node followed by rejection;
no final lane is usable. D11's clean inactive scope stays valid but all outputs
are unusable zeroes; D12 retains prior rejection. Valid words use exactly the same
canonical representative and64-bit serialisation, not just equal residues.

There are36 ordinary evaluator calls and36 independent trace-observer passes:
three observations per one of twelve input/control cases. Each case remains
pending until both reference partitions and the candidate agree; no partial
comparison is a pass. There are no additional input combinations, retries or
hidden parameter products. The fully guarded experimental G1 core has a complete
count but no extra materialised functional run; its implementation/equivalence
argument reuses prior evidence plus this fixed schedule.

| Probe | Total gates, including harness | AND gates | Probe seconds | Retained trace bytes |
| --- | ---: | ---: | ---: | ---: |
| G1-complete-count-comparison | 1,192,334 | 463,060 | 1.324871162 | 0 |
| G2-complete-candidate | 213,448 | 81,838 | 0.263738563 | 3,628,738 |
| G3-reference-first-stage | 310,804 | 122,900 | 0.372731639 | 5,283,790 |
| G4-reference-second-stage | 311,064 | 123,158 | 0.370937576 | 5,288,210 |

G1 is count-only, retains zero bytes, and records a complete streaming fingerprint;
its hypothetical serialised size is not disk use. G2/G3/G4 are each materialised
and evaluated before releasing their trace and starting the next probe. Peak
retained trace data 5,288,210 bytes, below8MiB; no trace
is written to disk. The [machine record](data/s3_mldsa_forward_ntt_stage_pilot_1/pilot-result.json)
contains complete counts, hashes, phase offsets, all observations and timings.

Pilot elapsed 5.491761219s. Python-process high-water RSS
32,874,496 bytes; pilot cgroup peak at final
observation 29,597,696 bytes. Per-component memory
is peak-so-far in a shared process, not isolated memory cost. Times include their
stated emission/counting or observation scope; per-case observation totals do not
include idle time waiting for the next reference partition. No percentile,
throughput or memory-speedup claim follows from this pilot.

## Decision, limitations and preservation closure

No larger representation redesign was needed for these connected internal edges.
The range argument and observed four-node agreement support planning a **bounded
full-forward-NTT experiment**, without claiming full-NTT equivalence. The complete
entry path, all eight stages/twiddles, partition interfaces and global validity
still need explicit coverage. A monolithic full reference trace is not proposed
under the current limits. Next package only: **S3-MLDSA-FULL-FORWARD-NTT-PLAN-1: a bounded source-only plan for complete schedule coverage, exact entry normalisation, invariant-preserving partition boundaries and separately authorised counting/differential resources.** No next package
or execution allowance is active; none was started.

Lint/format and the
[single complete preservation audit](data/s3_mldsa_forward_ntt_stage_pilot_1/result.json)
pass exit0: 10,382 disjoint content paths,
10,410 identity-inclusive paths, exact
inventory, completed report/readback and outer guard. Audit wall
2.535323883s; cgroup-v2 memory.peak
25,112,576 bytes below unchanged256MiB.
Maximum guarded-job cgroup peak 29,597,696 bytes; separate sampled tree RSS
52,207,616 bytes. One retained lint-only failure (E501, report text) was corrected after source
review. No test/probe retry, cap or resource breach occurred.

10 guarded commands consume 9.112603900s, plus established5s bookkeeping:
**14.112603900/30s** charged to this package. Implementation
**238.735268908/300s consumed**, **61.264731092s remain**.
Invocations **279/279**, zero remaining:263 historical +4 generation/count probes
+12 schedule cases. Analysis253.606485157s and isolation250.22s remain unchanged;
isolation100 historical/22 original cases pending. Temporary disk peak
0 bytes, zero retained. Final bounded bookkeeping (256MiB address
space, CPU/alarm5s, two CPUs,1MiB/file) fits the five-second charge and does not
repeat content comparisons. Exact balances and additive seal are in
[closure](data/s3_mldsa_forward_ntt_stage_pilot_1/validation-closure.json) and
[manifest](data/s3_mldsa_forward_ntt_stage_pilot_1/manifest.json).

Production/profile/parameters/dependencies/manuscript/history remain unchanged.
Stages2–3open; CPU proving paused, isolation safely stopped/unactivated. Proof
ledger two attempts used/one unused. Complete proof knowledge/privacy, adaptive
Delta_tail and production-security obligations remain open. No proof, inverse
experiment, zkVM execution, installation or activation occurred.
