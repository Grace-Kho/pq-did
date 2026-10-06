# S3-MLDSA-MODMUL-LOWERING-PILOT-1 — isolated scalar comparison

26 September 2026. **The isolated candidate merits a bounded composition experiment.**
All16 named invocations pass. For each of the two public constants, the fully
guarded baseline uses83,032 gates/34,550 ANDs and the candidate15,158 gates/6,161
ANDs:67,874 fewer gates and28,389 fewer ANDs per measured kernel. These are complete
matched component counts, not full-verifier savings. The resource/preservation
closure is appended below. The candidate requires a proposed compiler/profile
change; the active BC-1 arithmetic is preserved.

## Authority, identity and allowance

Only manuscript Sections II–VIII, SPEC-001–004 and the
[current specification](implementation_spec.md) are authoritative. Read with the
[arithmetic review](stage3_mldsa_arithmetic_lowering_review.md),
[bounded verifier report](stage2_bounded_mldsa.md) and
[experimental hint pilot](stage3_private_hint_lowering_pilot.md). This package
neither adopts that hint lowering nor changes signature verification's target.

[Preflight](data/s3_mldsa_modmul_lowering_pilot_1/preflight-evidence.json) verifies
43 preceding sealed files against manifest SHA-256
`7e87b882c125caee67f093d91afbfbf60762eb1ff22c449911059b95f0c3313a`,
53 assessed source/input entries and manuscript SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
Additional [reviewed input identities](data/s3_mldsa_modmul_lowering_pilot_1/reviewed-inputs.json)
cover the production arithmetic, reference oracle and original review. No historical
baseline is regenerated. Source revision is a content inventory, not a Git commit.

The user adds16 invocations: **231→247**,16 available, including all probes,
failures/repeats and parameterised cases. Implementation opens at
**205.62348771607503/300s** consumed, **94.37651228392497s** remaining.
At most30 charged seconds include validation/audit and the established five-second
operator/bookkeeping charge. Guarded command wall time is charged; conversation
and approval latency are not. Analysis253.60648515704088s and isolation250.22s
stay separate and untouched. Safe-stopped/unactivated isolation evidence is reused;
100 historical invocations/22 original actual-identity cases remain pending.
Proof ledger stays **two attempts used, one unused**; CPU proving paused.

Use256MiB cgroup-v2 memory.max, zero swap, worker and descendants including charged
file-cache/kernel memory; external monitor samples aggregate tree RSS separately.
The pilot retains the stricter128MiB arithmetic RSS stop and256MiB process address
space; all other jobs retain256MiB RSS. Sampling can miss transient peaks, and
aggregate RSS can count shared pages repeatedly; it is not cgroup memory. One
worker, two CPUs, four controlled processes,60s command/55s child maxima,
8MiB temporary disk,10MiB cumulative evidence,1MiB/file,60KiB command logs,
existing9GiB storage/diagnostic stops and2GiB headroom remain unchanged.

Admission reserves ten seconds for evidence/cleanup before the pilot, including
its13s outer/12.5s child reservation and11s inner stop within the30s package.
Per-trace generation≤10s, evaluator≤2s (below the5s ceiling), at most two physical
traces, each≤2,000,000 gates/65,536 inputs, aggregate retained traces≤8MiB in memory.
No trace file is written. The64M-gate/2GiB proposal remains inactive. No retry or
limit increase is automatic; any failed case or guard prevents a successful pilot.

## Implementation and exact interface

New source only:

- [candidate.py](../experiments/mldsa_modmul_lowering_1/candidate.py): experimental
  `ntt_mul_public_q` and a fully matched wrapper around unchanged production arithmetic.
- [run_pilot.py](../experiments/mldsa_modmul_lowering_1/run_pilot.py): bounded,
  individually recorded generation/differential/invalid-constant cases.

`ntt_mul_public_q(scope, value: Scalar, factor: int)` returns
`KernelResult(value: Scalar, valid: Bit)`. The scalar has NTT domain and exactly64
LSB-first arithmetic bits, representing a signed64 input. The factor must have
**exact Python type int**,0≤factor<q, q=8380417; bool, symbolic private bits,
negative and noncanonical integers are unsupported. Public factor validation
precedes any emission, followed by original scalar width/wire/domain checks.
No raw private factor, modulus override, quotient advice or alternate sampler enters.

For an active call, require every upper bit23..63 zero and low23<q. The guard
ANDs high-bit complements and the sign of a25-bit zero-extended subtraction
low23-q. Equality with q rejects. `Scope.require` preserves active-path rejection;
invalid private inputs are never silently reduced into an accepted scalar.

Output is the exact canonical product residue, zero-extended to64 bits and masked
by `active AND NOT rejected`. Both wrappers emit the same full64 mask schedule,
even on candidate high zero bits, and the same final `scope.output(())` predicate.
Rejected/inactive values are unusable zeroes. A fault in an inactive call does
not introduce rejection; a prior rejection never clears. Thus `valid=1` on a clean
inactive scope does **not** mean its masked scalar is usable. Validity and output
usability have distinct, explicitly tested semantics.

There is no trusted-canonical-input variant or partial guard omission. Both wrappers
repeat the complete canonical guard in their own gate segments. The baseline then
calls unchanged `scalar_ring.ntt_pointwise_multiply` with public64 factor and
private64 scalar, including signed128 multiplication, signed64 narrowing and the
complete SPEC-004 division/remainder validity. The candidate uses the following
restricted-domain arithmetic. Shared helper source fixes equal boundary semantics;
gates themselves are not shared between baseline and candidate.

## Structural correctness argument and its limits

1. After the guard,0≤x,factor<q<2^23. Emit23 shifted partial products from the
   public23 factor and private low23; add in increasing shift order into a public
   zero46-bit accumulator, using full46-bit ripples and retaining terminal carry
   operations. Every partial sum is non-negative and≤the full product<2^46.
   This remains true for speculative low23 even when the high-word guard fails.
   Thus low46 is the **exact integer product**, not an unchecked wrapped product.
2. Start23-bit remainder r=0. For each product bit45 down to0 form
   T=2r+bit as24 bits and zero-extend to25. Subtract public q with full25-bit
   ripple/carry. Select difference if its sign is zero, otherwise T, using the
   unchanged emitter mux convention; retain the resulting low23.
3. Inductively r is the already consumed prefix modulo q,0≤r<q. Therefore
   T≤2q-1<2^24 and -q≤T-q≤q-1, safely signed25. Its sign test is exact; one
   subtraction suffices and the selected value is again in0..q-1. Discarded
   high bits are zero by that invariant. After46 steps r=factor*x mod q.
4. On canonical inputs the baseline product is<(q-1+1)^2<2^46, so its checked
   integer product and positive-q quotient/remainder fit signed64. Its signed
   floor remainder agrees with the candidate. On noncanonical active inputs the
   **added interface guard** rejects both; independent output masking prevents
   speculative results becoming usable. This does not claim that the unguarded
   generic scalar gadget rejects all such inputs: some negative representatives
   are valid for that generic interface.

All loop bounds, indices and branches depend only on public dimensions or public
constants. Private values control Boolean gates, never Python control flow or array
addresses. The unchanged emitter folds only entirely public operations; every
mixed operation is retained. No private-by-private API, full transform, compiler
rewrite or proof implementation is introduced. The argument explains the intended
refinement; the finite cases below do not prove the code correct for every input.

## Conversion boundary and preserved relation

The measured result is confined to the fully guarded canonical scalar interface.
Input byte-to-bit order is rewiring; guard, operations, full64 output masking and
scope validity count as gates. Zero-extension is wiring. **Signed-to-canonical
normalisation is not measured or silently omitted from a claimed verifier cost.**
The existing verifier canonicalises decoded z/c before NTT, even for out-of-norm
z; signed original z must remain available for its final strict norm check.
A future composed caller must retain that conversion or prove its producer already
outputs a canonical value. Negative inverse twiddles require public q-zeta
normalisation; Montgomery-scaled coordinates are not accepted by mere retagging.
The current Python path uses ordinary residues, not Montgomery scale.

Both selected constants are ordinary residues:4808194 is the actual first used
forward twiddle,8347681 the final inverse factor256^-1 mod q. The latter is measured
as a scalar multiplier; this test does not itself change an NTT/coefficient domain
or constitute an inverse transform. Public-key/matrix-specialisation rules remain
unchanged. All other constants, norm/decomposition exceptional rules, ordered sums,
samplers and full transform composition are outside this kernel.

Same hidden signature, certified message (`build_mcred`), holder binding,
`PQ-DID/credential/v1` context and pure-message prefix remain required. The same
certified rid must feed the private non-revocation path and the same attributes
feed disclosure. PubOK/Ppub, freshness, expiry and atomic nonce consumption stay
as specified. No credential is accepted through this experiment and no ordinary
proof-verification path is changed. SPEC-003/004 and active BC-1 fingerprints remain
frozen;23/46/25-bit lowering needs a separately reviewed compiler/profile identity.

## Fair counting design and individual invocation plan

The latest user request explicitly permits case selection and asks for actual
public constants and unsupported-constant rejection. Within16 invocations, select
two constants and replace the review's proposed width/domain/minimum-word cases
with the named constant/control cases below. Those omitted cases are untested,
not counted as passes. No extra case or repeated historical suite is hidden.

**G1 and G2 each generate one comparison trace**, one for4808194 and one for8347681.
Each trace contains a complete baseline segment then a complete candidate segment,
with independent scopes but identical66 private positions: signed64 x, active bit,
prior-rejection bit. Their outputs/validity wires are observed independently.
There is one final AND combining acceptance bits for the ordinary evaluator. That
harness gate is reported separately, not charged to either kernel. There are two
physical trace generations and four measured core segments; per-segment counts
come from snapshots during those two probes, not additional uncounted probes.

Both segments have the same public factor, private visibility, canonical guard,
64-bit output mask and sticky validity contract. Segment generation time includes
its guard and finalisation. Record segment gate ranges/SHA-256 and entire paired
trace fingerprints; a gate-segment hash with global wire numbers is not a standalone
circuit fingerprint. No equality-to-test-target gate is included. Full paired counts
must equal both segment totals plus the one reported harness gate. No algebraic
sharing between segments or trusted-input discount is used.

| Counted ID | Factor | Input or construction case | Expected outcome |
| --- | ---: | --- | --- |
| G-4808194 |4808194| Generate/count one complete paired trace | Complete or explicitly incomplete |
| G-8347681 |8347681| Generate/count one complete paired trace | Complete or explicitly incomplete |
| D1-zero |4808194| x=0, active/clean | Canonical product0 |
| D2-unit |4808194| x=1, active/clean | Public factor |
| D3-upper |4808194| x=q-1, active/clean | Canonical remainder of maximal input product |
| D4-wrap |4808194| x=2, active/clean | Product crosses q; exact remainder |
| D5-inverse-unit |8347681| x=1, active/clean | Public inverse factor |
| D6-inverse-upper |8347681| x=q-1, active/clean | Canonical upper-input product |
| D7-noncanonical-q |4808194| x=q, active/clean | Reject despite fitting23 bits; zero unusable output |
| D8-negative |4808194| x=-1, active/clean | Reject high/sign bits; no normalisation into acceptance |
| D9-inactive-invalid |8347681| x=q, inactive/clean | No new rejection; zero unusable output |
| D10-sticky-rejection |8347681| x=1, active/prior rejection | Rejection retained; zero unusable output |
| C1-negative-factor |unsupported| factor=-1 | Both interfaces refuse before emission |
| C2-factor-q |unsupported| factor=q | Both refuse before emission |
| C3-boolean-factor |unsupported| factor=True | Exact type rejection; no integer coercion |
| C4-private-factor |unsupported| factor=symbolic private Bit | No private/public substitution |

Every differential input/factor/control combination is one case; reference,
candidate, independent oracle and evaluator observations belong to that same case.
Each constant refusal is individually recorded for both interfaces. They reuse
completed probe objects and must reject at public argument validation before any
emission; no third emitter or hidden generation is created. Other integers,
wrong-width/domain/foreign-wire cases and full transforms are not silently batched.

The independent arithmetic oracle is
[`floor_pair`](../tests/reference/scalar_oracle.py), exact Fraction/floor of host
integer product; it does not call the restoring circuit algorithm or cryptography.
Its independent trace interpreter observes both64-bit words and validity flags.
The ordinary evaluator checks the same complete paired trace's acceptance bit.
Expected canonical validity and control state are determined from the interface
contract. All valid words and all invalid/control outcomes must agree; partial
output equality cannot discharge rejection. No native ABI harness is repeated.

## Decision criteria, preserved evidence and limitations

A successful candidate requires all16 admitted invocations to complete under the
guards, complete matched counts for both constants, and fewer total/AND gates in
each candidate core **including** all boundary checks. No useful improvement is a
valid negative outcome; a mismatch/resource failure is retained and stops the
package. Capped prefixes cannot be labelled complete counts or automatically rerun.
Generation/evaluation timing and process/cgroup peaks have their measured scopes;
shared-process high-water observations do not isolate each core's memory cost.

The old25847 scalar counts and original hint-prefix measurements are preserved and
incomparable as a replacement baseline for these constants/guards. No component
result is turned into complete-verifier savings, proof-size estimates or RISC Zero
forecasts. There is no complete authentication circuit or proof in this package.

ARITH-LOWER-001 remains open for composition and profile conformance. A useful
result warrants only a separately bounded forward/inverse butterfly composition
pilot, including signed entry conversion and canonical bounds. HINT-LOWER-001,
AUTH-FEAS-001, OC-REL/EXT/PRIV/BUDGET, adaptive Delta_tail, component advantages at
reduction budgets, production custody/entropy/erasure/side channels, durable holder
storage and complete proof knowledge/privacy remain open. Stages 2–3 remain open.


## Measured result and decision

Decision: **merits-bounded-composition**. Both paired traces and every one of the fourteen named
validation cases completed on the first attempt. No additional test or probe ran.
Each paired trace contains complete, independent baseline and candidate cores;
the single final conjunction gate is separately reported as harness overhead.

| Public factor | Fully guarded core | Total gates | AND gates | Generation/counting seconds |
| --- | --- | ---: | ---: | ---: |
| 4808194 | baseline | 83,032 | 34,550 | 0.096204210 |
| 4808194 | candidate | 15,158 | 6,161 | 0.018203477 |
| 8347681 | baseline | 83,032 | 34,550 | 0.096546457 |
| 8347681 | candidate | 15,158 | 6,161 | 0.018610550 |

All canonical guards, scalar operations, full64 output masks and final scope
validity are included. Input rewiring/zero-extension require no gates. There are
zero equality-to-test-target gates. Gate-segment SHA-256 values, wire offsets,
phase counts and complete paired-trace fingerprints are in the
[run record](data/s3_mldsa_modmul_lowering_pilot_1/pilot-result.json).
Segment hashes refer to that paired trace, not standalone BC-1 circuit identities.
No trusted-canonical variant was measured. All counts above are complete.

| Invocation | Expected and observed outcome | Result |
| --- | --- | --- |
| G-4808194 | paired trace complete | pass |
| G-8347681 | paired trace complete | pass |
| D1-zero | valid=True; word=0; usable=True | pass |
| D2-unit | valid=True; word=4808194; usable=True | pass |
| D3-upper | valid=True; word=3572223; usable=True | pass |
| D4-wrap | valid=True; word=1235971; usable=True | pass |
| D5-inverse-unit | valid=True; word=8347681; usable=True | pass |
| D6-inverse-upper | valid=True; word=32736; usable=True | pass |
| D7-noncanonical-q | valid=False; word=0; usable=False | pass |
| D8-negative | valid=False; word=0; usable=False | pass |
| D9-inactive-invalid | valid=True; word=0; usable=False | pass |
| D10-sticky-rejection | valid=False; word=0; usable=False | pass |
| C1-negative-factor | both reject before emission | pass |
| C2-factor-q | both reject before emission | pass |
| C3-boolean-factor | both reject before emission | pass |
| C4-private-factor | both reject before emission | pass |

For each differential case, the reference and candidate output words and validity
match the independent exact arithmetic/control oracle. The normal evaluator also
agrees with the combined acceptance predicate. An inactive invalid input is not
accepted as a usable scalar: its scope stays fault-free but both output words are
zero and unusable. Existing rejection remains sticky.

Pilot elapsed 0.544392857 s. Aggregate retained trace bytes:
3,338,738; all released at process exit, none on disk.
Pilot Python-process high-water RSS: 26,406,912
bytes; pilot cgroup peak at final observation:
22,020,096 bytes. Per-component records are
**peak-so-far observations**, not isolated component memory costs. Both cores share
a generation/evaluation process; no memory or timing speedup claim follows.

The measurements justify this decision only for the two tested public constants
and this fully guarded scalar interface. Finite cases are not a universal
implementation equivalence proof. They do not generalise to private multiplication,
a complete transform/verifier, proof size or RISC Zero performance.
Recommended next package only: **S3-MLDSA-BUTTERFLY-COMPOSITION-PILOT-1: separately bounded forward/inverse butterfly composition with exact entry conversions, guards and matched counts.** Not started or authorised here.
All compiler/profile conformance, full authentication and proof knowledge/privacy
obligations remain open.

## Complete preservation and resource closure

Lint/format and the single
[complete preservation audit](data/s3_mldsa_modmul_lowering_pilot_1/result.json)
pass, exit 0: 10,290 disjoint content paths,
10,316 identity-inclusive paths, exact name
inventory, complete report readback and outer guard. Audit 2.465593635s,
cgroup-v2 memory.peak 23,232,512 bytes under256MiB.
Maximum guarded-job cgroup peak 23,232,512 bytes; separately sampled tree RSS
40,980,480 bytes. No resource breaches, failed checks or retries.

8 guarded commands consumed 3.827576857s. With the established five-second
operator/bookkeeping charge, package charge is **8.827576857/30s**.
Cumulative implementation charge **214.451064573/300s**;
**85.548935427s remain**. Tests/probes **247/247**, zero remaining:
231 historical +2 paired generation/count probes +10 differential +4 constant cases.
Analysis stays253.606485157s; isolation250.22s,100 historical/22 pending identity cases.
Temporary disk observed peak 0 bytes, zero retained. Final bounded
bookkeeping uses256MiB address space, CPU/alarm5s,two CPUs,1MiB/file inside the
five-second charge; no repeated content audit.
[Closure](data/s3_mldsa_modmul_lowering_pilot_1/validation-closure.json) and
[seal](data/s3_mldsa_modmul_lowering_pilot_1/manifest.json) retain exact balances.

Production code/parameters/profile/dependencies/manuscript/history are unchanged.
Stages 2–3 remain open; CPU proving paused, isolation safely stopped/unactivated.
No proofs, zkVM executions, installations or activation; proof ledger two used/one unused.
