# S3-MLDSA-BUTTERFLY-COMPOSITION-PILOT-1 — forward butterfly composition

26 September 2026. **All16 pilot invocations pass; the candidate supports a bounded
forward-transform composition experiment.** The fully guarded signed64 butterfly
uses89,189 total/33,726 AND gates versus155,402/61,450 for the matched reference.
The actual two-node schedule fragment uses178,378/67,452 versus310,804/122,900.
The complete preservation outcome and resource closure follow below. This remains
a proposed compiler/profile change, not active BC-1 or a complete authentication
implementation.

## Authority, preserved inputs and opening ledger

Only manuscript Sections **II–VIII**, agreed SPEC-001–004 and the
[current specification](implementation_spec.md) are authoritative. Reuse the
[arithmetic review](stage3_mldsa_arithmetic_lowering_review.md),
[scalar pilot](stage3_mldsa_modmul_lowering_pilot.md),
[authentication feasibility plan](stage3_auth_proof_feasibility_plan.md) and
[experimental hint evidence](stage3_private_hint_lowering_pilot.md).
The hint candidate and this arithmetic lowering are not canonical BC-1.
VII-A.5/.6 requires the bounded verifier and checked compilation; V-B fixes the
authentication relation. No excluded manuscript section supplies performance claims.

[Preflight](data/s3_mldsa_butterfly_composition_pilot_1/preflight-evidence.json)
verified the preceding49-file seal
`0ecdcdeaa2cefa43e242ae6bc1a8ca91f3b66733d0354a0a35ceaf997710d16f`,
all53 assessed input/source identities, and manuscript SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
[Reviewed source identities](data/s3_mldsa_butterfly_composition_pilot_1/reviewed-inputs.json)
are a content revision, not a Git commit or replacement preservation baseline.
No old scalar/hint evidence, fingerprints, parameters, source or dependencies change.

| Opening ledger | Exact balance and amendment |
| --- | --- |
| Implementation |214.4510645730188/300s consumed; **85.54893542698119s remaining** |
| This package |≤30s, including guarded validation/audit and established5s operator/bookkeeping; ten-second evidence/cleanup reserve before the pilot |
| Test/probe invocations |247 consumed; authorised ceiling247→263; **16 available**, including failures/repeats |
| Analysis |253.60648515704088s remaining, untouched |
| Isolation |Safely stopped/unactivated;250.22s,100 historical invocations,22 original identity cases pending; untouched |
| Proofs |Two attempts used/one unused; CPU proving paused |

The accounting convention is guarded command wall time plus the established
five-second bookkeeping charge, not elapsed conversation time. There is no
allowance transfer or automatic retry. The original corrected preservation engine
uses256MiB cgroup-v2 memory.max with zero swap; memory.peak covers the guarded
worker and descendants, including charged cache/kernel memory. An external monitor
separately samples their aggregate RSS. Arithmetic pilot RSS stop128MiB and
process address-space cap256MiB also remain in force.

One worker, two CPUs, four controlled processes, command60s/child55s maxima,
8MiB temporary disk,10MiB cumulative evidence,1MiB/file,60KiB command output,
9GiB storage stop, existing diagnostic stop and2GiB free headroom are unchanged.
Pilot reservation13s/child12.5s, inner11s, generation10s and evaluator2s are below
the existing maxima. Two physical traces only, each≤2,000,000 gates; at most8MiB
retained trace data, **first trace released before constructing the second**.
Transient serialisation copies remain covered by the memory guard. No trace file
is written. The64M-gate/2GiB proposal remains inactive.

## Actual forward target and reference contract

Source: [`scalar_ring.ntt_butterfly`](../src/pqdid/circuits/scalar_ring.py),
[`bounded_mldsa._ntt`](../src/pqdid/bounded_mldsa.py), and unchanged
[`words`](../src/pqdid/circuits/words.py),
[`division`](../src/pqdid/circuits/division.py) and
[`Scope`](../src/pqdid/circuits/control.py). Primary algorithm provenance is FIPS204
Algorithm41 as recorded in the arithmetic review and bounded-verifier report;
this package derives its executable contract directly from those pinned functions.

Let q=8380417, MIN=-2^63, MAX=2^63-1. For old left a, old right b and public
ordinary-residue twiddle z (exact int,0≤z<q):

1. Compute checked signed64 integer z*b, then p=(z*b) mod q.
2. Compute checked signed64 a-p, then new_right=(a-p) mod q.
3. Compute checked signed64 a+p, then new_left=(a+p) mod q.

The return order is (new_left,new_right), while the update order is product,
right, left, reusing the **old** left in both updates. The reference's Scalar
annotation checks64-bit width, wire ownership and NTT domain; it **does not**
require canonical input residues. Accordingly, this pilot admits all signed64
representatives subject to the original overflow conditions. For a clean active
scope, acceptance is exactly
`MIN≤z*b≤MAX AND MIN≤a-p≤MAX AND MIN≤a+p≤MAX`.
All positive-q div/mod quotient/remainder representability checks pass on these
non-overflowing signed64 values. Rejecting all negative or ≥q inputs would have
narrowed this contract; D4–D7 explicitly exercise that distinction.

The Python verifier normalises inputs before its forward schedule. The public root
is1753 with `zeta[m]=1753^BitRev8(m) mod q`. The first used twiddle is4808194;
the next is3765607. These are **unscaled** residues. No Montgomery coordinates,
centred twiddles, twiddle-factor conversion or hidden inverse scale is involved.

Inverse NTT is outside this implementation/evidence: lengths grow1→128, twiddles
are traversed backwards and negated, sum/difference are reduced **before** the
difference is multiplied, and the final inverse factor is8347681. Forward operand
ordering cannot simply be reused. Even replacing a negative public twiddle by its
positive residue needs a separate acceptance argument for generic signed64 inputs;
modular agreement alone does not preserve checked integer overflow behaviour.

## Experimental construction and complete boundary

New code is confined to
[`candidate.py`](../experiments/mldsa_butterfly_composition_1/candidate.py) and
[`run_pilot.py`](../experiments/mldsa_butterfly_composition_1/run_pilot.py).
`forward(scope,left,right,zeta)` returns two64-bit NTT Scalars and a validity bit.
The matched baseline wraps the unchanged production butterfly. Both wrappers
perform the same public twiddle/type and existing scalar/domain validation.
Public invalid twiddles fail before emission. Wrong width/domain/foreign wire
checks are reused; no extra uncounted malformed cases are executed.

1. For z>0 replace generic checked signed multiplication's overflow predicate with
   the exact bound `ceil(MIN/z)≤b≤floor(MAX/z)`, using two complete signed64
   comparisons and `Scope.require`. The lower public constant is
   `-floor(2^63/z)`. For public z=0 the product always fits. This is public
   construction-time branching, never private witness control flow.
2. Canonicalise **both a and b** using complete unchanged SPEC-004 `mod64` calls,
   with all64 magnitude scan steps,65-bit correction, quotient and remainder
   construction/checks. This includes MIN correctly. These conversions are
   charged even at the second composed node; no trusted-input discount is measured.
3. Call the unchanged experimental scalar
   [`ntt_mul_public_q`](../experiments/mldsa_modmul_lowering_1/candidate.py) on
   canonical b. Include its full64 canonical guard, exact46-bit public/private
   product,46 restoring steps and full64 output mask/scope validity. Its guarded
   canonical-only interface remains unchanged; generic inputs enter through the
   explicit conversion above, after the original product-overflow predicate.
4. Preserve checked **raw a-p** in signed64. For the value, subtract canonical
   a_bar-p in25 bits; add q and select that corrected value exactly when the
   original difference is negative. Keep canonical low23 bits.
5. Preserve checked **raw a+p** in signed64. Add canonical a_bar+p in24 bits,
   zero-extend to25, subtract q and select the subtraction exactly when nonnegative.
   Keep canonical low23 bits. Original right-before-left order is retained.
6. Zero-extend both residues to64 bits; mask **every bit** with
   `active AND NOT rejected`, and return final scope validity. Both matched
   wrappers have the same boundary. No speculative rejected value is usable.

The checked raw add/sub results are used for their validity even though the
canonical output comes from narrower operations. Thus an overflowing a+p rejects
even if its residue is small. A valid b≥q can be normalised, but an overflowing
z*b cannot become accepted through normalisation. There is no unrestricted
private-by-private multiplication or acceptance based solely on a congruence.

`Scope.rejected` is sticky; inactive checks introduce no new rejection. A clean
inactive call can have valid=1 but returns unusable zero words. Once a prior fault
exists, speculative internal values may differ from the reference, but both
complete interfaces have valid=0 and masked zero outputs. Internal diagnostic
fault-wire order is not claimed identical. The comparison preserves acceptance
and usable outputs, not canonical compilation or gate identity.

## Structural range and compositional argument

On an active call without an earlier fault, the public interval test is equivalent
to original signed multiplication representability. Both SPEC-004 conversions
return the unique0..q-1 residues. For canonical b_bar,z<q<2^23,
`b_bar*z≤(q-1)^2<2^46`. The previous scalar proof argument establishes an exact
46-bit product and a remainder r in0..q-1 after each restoring step: from
`T=2r+bit≤2q-1<2^24`, signed25 `T-q` is in[-q,q-1], so one correction is sufficient.
That prior finite validation is reused; no scalar/native suite is rerun.

For butterfly values, `a_bar+p≤2q-2<2^24` and
`-(q-1)≤a_bar-p≤q-1`, so signed25 differences cannot overflow. One subtraction
or addition of q returns exactly0..q-1; the discarded high bits are zero on the
selected arm. Congruence plus this unique representative establishes equality to
the reference's outputs, while the retained raw checks establish equal acceptance.
No lazy or centred output representative crosses the boundary.

Consequently every usable output satisfies the next butterfly's canonical range
invariant. At such an internal edge public z<q gives z*b<2^46; a±p stays safely
signed64. The current implementation **still emits** all conversion/overflow checks.
A future removal requires a separately documented producer invariant and proposed
profile rule. There is no measured trusted-input variant here.

The small composition is a genuine dependency slice of the forward schedule:

| Node | Actual schedule | Inputs | Outputs |
| --- | --- | --- | --- |
|1|len128,start0,j0,m1,z=4808194|initial slots0 and128|updated slots0 and128|
|2|len64,start0,j0,m2,z=3765607|node1 slot0 and **already stage1-updated slot64**|updated slots0 and64|

The third input is explicitly a frontier value. Its producer at len128,j64,
using slots64/192, is **not generated or validated** in this fragment. D11 supplies
4808195, the exact legal frontier from initial slots64=192=1. Initial slots0=q-1,
128=1 complete this synthetic legal slice. Observe both nodes' words and validity;
the final touched state is node2 left(slot0), node2 right(slot64), node1 right(slot128).
D12 induces node1 overflow and requires both node results to be unusable, with
rejection propagated through their shared scope. Other intervening nodes have no
data dependency on these inputs; this is not a complete two-layer block.

This explains the intended refinement and range induction. Finite checks are not
a universal equivalence proof, full NTT compatibility proof or proof-system
knowledge/privacy argument. The proposed short-width lowering is outside frozen
BC-1/SPEC-003/004 rules even where its behaviour agrees; active rules are untouched.

## Matched measurement and sixteen-invocation plan

G1 materialises one paired single-butterfly trace; G2 one paired two-node trace.
Each has a complete independent baseline segment followed by a candidate segment,
identical private positions, public twiddles, admitted signed64 domain, output
representatives, masks and active/sticky-rejection contract. G1 has130 private
bits (two64-bit words plus controls), G2 has194 (three words plus controls).
All constants are public construction data. Public folding remains unchanged;
mixed gates are retained. Count core segments by snapshots in these two probes,
not separate unrecorded generations. One final harness AND combines final validity.

Generation/counting time, gate/AND counts, trace bytes, hashes and process/cgroup
memory observations are recorded in the machine-readable result. The baseline
and candidate share a process, so high-water observations are not isolated memory
costs. Complete G2 counts include both output boundaries and repeated conversions.
No component times or counts are summed into a full-transform estimate.

Independent arithmetic uses exact Python integer multiplication and the preserved
[`floor_pair`](../tests/reference/scalar_oracle.py) Fraction/floor oracle. The
[`independent trace observer`](../tests/reference/signature_oracle.py) reads every
output and node flag; the ordinary evaluator separately reads final acceptance.
Expected validity includes exact signed64 product and a±p bounds, active masking
and sticky rejection. One input/control combination is one differential case.

| ID | Input or operation | Required result |
| --- | --- | --- |
|G1|Paired single z=4808194|Complete matched counts or explicit cap/failure|
|D1|(a,b)=(0,0)|Both outputs0, usable|
|D2|(q-1,q-1)|Upper canonical inputs; left addition requires q correction|
|D3|(0,1)|Negative subtraction requires +q|
|D4|(-1,-1)|Valid signed representatives preserved and normalised|
|D5|(q,q)|Valid noncanonical positive representatives; no silent domain narrowing|
|D6|(MIN,0)|Full signed64 conversion boundary remains valid|
|D7|(0,floor(MAX/4808194))|Largest accepted positive multiplication operand|
|D8|(0,floor(MAX/4808194)+1)|Original product overflow rejects|
|D9|(MAX,1)|Raw addition overflow rejects despite a defined residue|
|D10|D8 input, inactive/clean|No new rejection, zero unusable outputs|
|C1|Public z=-1|Both wrappers reject before emission|
|C2|Public z=q|Both wrappers reject before emission|
|G2|Paired two-node actual schedule fragment|Complete matched counts|
|D11|(q-1,1,4808195)|Legal fragment, intermediate invariants and final words match|
|D12|(0,floor(MAX/4808194)+1,4808195)|First fault propagates, neither node usable|

No parameter Cartesian product, hidden random batch or extra constructor probe.
Constant refusals reuse completed G1 objects. Twiddle0/1, other positive twiddles,
lower negative product threshold and raw subtraction overflow are covered by the
structural argument but **not new executed cases**; wrong-width/domain/foreign
wires likewise remain untested here. The bounded case selection is explicit.

## Security relation, preservation and decision criteria

The same hidden signature, canonical certified message (`build_mcred`), pure-message
framing and `PQ-DID/credential/v1` context remain required. Original signed z must
remain available for the strict final norm check. Holder binding, certified rid
linkage to private revocation, disclosure, PubOK/Ppub, freshness, expiry and atomic
nonce consumption are unaffected. No credential or proof is accepted by this pilot.

Success requires16 completed invocations, matching words **and** rejection/validity,
complete matched counts, and lower total/AND gates in both candidates. Failure or
resource exhaustion stops without retry; no capped prefix can be promoted to a
complete cost. Useful results justify only a separately authorised bounded forward
stage/transform experiment. Inverse composition, full schedule, remaining verifier
operations and full authentication/proof evidence are separate obligations.

The preservation chain starts at the original8759-file baseline and extends via
unchanged historical seals, including the scalar-pilot seal. Only this new
experimental directory/evidence/report and append-only status/traceability/issues
are authorised; no old baseline is regenerated and no directory is excluded to
obtain a pass. Final documentation and seal bookkeeping are explicitly included
within the existing five-second charge, after the single content audit.

ARITH-LOWER-001 stays open for transform composition/conformance; HINT-LOWER-001,
AUTH-FEAS-001, OC-REL/EXT/PRIV/BUDGET, adaptive Delta_tail, component advantages at
reduction budgets, production key custody/entropy/erasure/side channels, durable
holder storage and complete proof knowledge/privacy remain open. Stages2–3open.

## Measured overhead and next bounded scope

The candidate's complete first-node phase increments, derived from the recorded
gate offsets, identify the dominant remaining cost without another probe:

| Included phase | Total gates | AND gates |
| --- | ---: | ---: |
| Exact original product-overflow predicate |723|263|
| Both complete signed64-to-canonical conversions |71,784|26,662|
| Guarded scalar kernel including its output boundary |15,158|6,161|
| Checked raw subtraction and negative correction |742|256|
| Checked raw addition and q correction |650|254|
| Both full64 output masks and final validity |132|130|
| Complete candidate |89,189|33,726|

Conversion dominates this deliberately general interface. A later caller may
establish canonicality once and propagate it, but eliminating repeated conversions
requires an explicit invariant-bearing interface and fair accounting for its entry
guards; it cannot silently weaken the current generic signed64 contract.

Recommend only **S3-MLDSA-FORWARD-NTT-STAGE-PILOT-1**, proposed and inactive:
bound it to an actual forward-schedule chunk of at most eight connected nodes,
with every frontier/entry conversion specified, count-only generation under the
unchanged2M-gate cap, and differential materialised partitions each within8MiB.
Partition coverage and connecting canonical/validity invariants must be explicit;
there is no licence to omit an upstream check. Keep the current fully guarded
interface as the comparison until any distinct invariant-bearing variant is
justified and counted separately. Further invocation/time allowances need separate
authorisation; none is presumed from this recommendation.

The measured paired two-node trace retains8,316,233 bytes, only72,375 below8MiB.
Thus materialising a larger paired trace under this same limit is not a credible
next step; count-only work and small differential partitions serve different
purposes and must be labelled. A cap is still an incomplete prefix. This proposed
chunk does not promise complete128-butterfly stage or256-point transform counts,
and cannot establish full-verifier, proof or RISC Zero performance.


## Measured result and decision

Decision: **supports-bounded-transform-experiment**. Two paired probes, twelve differential cases and two
public-constant refusals pass on their first attempt:16 individually recorded
invocations. No other case or probe ran. Complete matched counts:

| Workload | Fully guarded component | Total gates | AND gates | Generation/counting seconds |
| --- | --- | ---: | ---: | ---: |
| single forward butterfly | baseline | 155,402 | 61,450 | 0.182516059 |
| single forward butterfly | candidate | 89,189 | 33,726 | 0.104929671 |
| two-node schedule fragment | baseline | 310,804 | 122,900 | 0.363280850 |
| two-node schedule fragment | candidate | 178,378 | 67,452 | 0.213800102 |

single forward butterfly: 66,213 fewer total gates (42.6076%), 27,724 fewer AND gates (45.1164%). two-node schedule fragment: 132,426 fewer total gates (42.6076%), 55,448 fewer AND gates (45.1164%).

All signed64 conversions, exact original overflow conditions, scalar guards,
addition/subtraction/corrections, full64 output masks and scope validity are
included, including at the second node. Input bit rewiring and zero-extension
cost no gates. No trusted-input variant, algebraic sharing between cores or
comparison-to-test-target gate is discounted. One final harness AND joins the two
final validity wires, outside the component totals. All counts are complete;
no capped prefix is presented as a complete component.
[Raw record](data/s3_mldsa_butterfly_composition_pilot_1/pilot-result.json) retains
phase offsets, segment hashes, output wires and complete paired fingerprints.
Segment hashes use global paired-trace wire numbers, not canonical BC-1 identities.

The historical guarded scalar saving was67,874 total/28,389 AND gates. After the
complete signed butterfly boundary the measured net saving is
66,213 total/27,724 AND gates, numerically
97.5528%/97.6575% of that
absolute scalar difference. This is an overhead comparison, not attribution of
all butterfly gates to that scalar. The old scalar interface admitted canonical
inputs only; this butterfly admits the full original checked signed64 domain.
The percentage reduction of the **matched butterfly** is the one above, not the
historical scalar percentage. No overlapping component totals are added.

| Invocation | Expected and observed outcome | Result |
| --- | --- | --- |
| G1-single-butterfly | paired trace complete | pass |
| D1-zero | flags=[1]; words=[0, 0]; usable=True | pass |
| D2-canonical-upper-wrap | flags=[1]; words=[3572222, 4808193]; usable=True | pass |
| D3-negative-subtraction | flags=[1]; words=[4808194, 3572223]; usable=True | pass |
| D4-signed-negative-representatives | flags=[1]; words=[3572222, 4808193]; usable=True | pass |
| D5-noncanonical-q-normalisation | flags=[1]; words=[0, 0]; usable=True | pass |
| D6-signed-minimum-left | flags=[1]; words=[3007233, 3007233]; usable=True | pass |
| D7-product-upper-boundary | flags=[1]; words=[4972144, 3408273]; usable=True | pass |
| D8-product-overflow | flags=[0]; words=[0, 0]; usable=False | pass |
| D9-raw-addition-overflow | flags=[0]; words=[0, 0]; usable=False | pass |
| D10-inactive-invalid | flags=[1]; words=[0, 0]; usable=False | pass |
| C1-negative-twiddle | both reject before emission | pass |
| C2-noncanonical-twiddle | both reject before emission | pass |
| G2-two-node-fragment | paired trace complete | pass |
| D11-legal-schedule-composition | flags=[1, 1]; words=[4808193, 3572222, 3954896, 5661490]; usable=True | pass |
| D12-invalidity-propagates-to-next-stage | flags=[0, 0]; words=[0, 0, 0, 0]; usable=False | pass |

Words are ordered first-node(left,right), then second-node(left,right) where
applicable. Both implementations match the independent exact-integer oracle on
all words and node-validity flags. Every usable intermediate/final value is in
0..q-1. Rejected/inactive outputs are zero and unusable. An inactive clean scope
may have valid=1; that does not make its zero output usable. D12 shows the first
node's failure propagating through the same scope to the second node.

Pilot elapsed 1.920946668s; retained trace peak
8,316,233 bytes, first trace released before second
probe; none on disk. Python process high-water RSS
45,006,848 bytes; cgroup peak at final pilot
observation 40,873,984 bytes. Per-component
memory fields are **peak-so-far**, not isolated component costs. Per-component
seconds include emission/counting; paired generation seconds also include
finalisation/hash/bookkeeping. Two generation samples establish no throughput,
percentile, whole-transform, proof-size or RISC Zero prediction.

Finite tests do not prove universal equivalence. This supports only a bounded
forward stage/transform experiment. The omitted frontier producer, full schedule,
other constants, inverse ordering/scaling, signed norm/decomposition and the full
private verifier remain unmeasured. Proposed next package: **S3-MLDSA-FORWARD-NTT-STAGE-PILOT-1: a separately authorised, bounded stage/transform counting and differential experiment with actual schedule, all conversion costs, explicit output invariants and unchanged gate/memory caps.**
No next-package allowance is active and no further work was launched.

## Preservation and final resource accounting

Lint/format and the single
[complete audit](data/s3_mldsa_butterfly_composition_pilot_1/result.json) pass exit0:
10,336 disjoint content paths,
10,363 identity-inclusive paths, exact
inventory, completed report/readback and outer guard. Audit wall
2.427376434s, cgroup-v2 memory.peak
23,633,920 bytes under the unchanged256MiB ceiling.
Across guarded jobs maximum cgroup peak 40,873,984 bytes; separately sampled aggregate
tree RSS 51,171,328 bytes. No resource breach, failure or retry.

8 guarded commands consume 5.171600435s, plus the established5s
operator/bookkeeping charge: **10.171600435/30s** for this package.
Implementation **224.622665008/300s consumed**, **75.377334992s remain**.
Tests/probes **263/263**, zero remaining:247 historical +2 paired generation/count
probes +12 differential +2 constant refusals. Analysis stays253.606485157s;
isolation250.22s,100 historical/22 pending identity cases. Temporary disk observed
peak 0 bytes, zero retained. Final bookkeeping is limited to256MiB
address space, CPU/alarm5s, two CPUs,1MiB/file within the five-second charge;
it is not a repeated protected-content audit.
[Closure](data/s3_mldsa_butterfly_composition_pilot_1/validation-closure.json) and
[seal](data/s3_mldsa_butterfly_composition_pilot_1/manifest.json) retain exact balances.

Production code, BC-1, parameters, dependencies, manuscript and historical evidence
are preserved. Stages2–3open; CPU proving paused; isolation safely stopped and
unactivated. No proofs, zkVM execution, installations or host activation.
Proof ledger two attempts used/one unused; complete proof knowledge/privacy,
adaptive Delta_tail and production-security obligations remain open.
