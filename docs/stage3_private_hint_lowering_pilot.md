# S3-PRIVATE-HINT-LOWERING-PILOT-1

26 September 2026. Isolated complete private hint-decoder experiment. The measured
decision and validation closure are appended below only after the required audit
and its outer guard complete. No active compiler or proof profile is changed.

## Authority, isolation and starting allowances

Only manuscript **Sections II–VIII** and SPEC-001–004 are authoritative. The
[preflight](data/s3_private_hint_lowering_pilot_1/preflight-evidence.json) verifies
the manuscript SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`, all 53 assessed
source/input entries and the prior 63-file planning seal
`956aae0c92e6720d47000232746f4d60f9f9d49e0b2c2218ed15858bd34773c4`.
Source identity is content-addressed; this workspace has no Git revision.

Read with the [feasibility plan](stage3_auth_proof_feasibility_plan.md),
[original hint audit](stage3_feasibility_review.md), its
[raw capped result](data/stage3_hint_prefix_audit.json),
[current specification](implementation_spec.md),
[private signature components](stage3_signature_inputs.md) and the frozen
[decoder](../src/pqdid/circuits/signature.py),
[emitter](../src/pqdid/circuits/emitter.py) and
[active-path rules](../src/pqdid/circuits/control.py). No original count or
fingerprint is regenerated or overwritten.

The user amends the invocation ceiling **223→231** without resetting 222 consumed.
Nine are available. This package explicitly counts **one generation probe plus
eight differential cases**, including any attempted failures. Generation is not a
free hidden ninth operation; native and Boolean observations of one named case
belong to that case. There is no random campaign, parameterised sub-batch or retry.

Implementation starts at **195.8630371170584/300 s** charged,
**104.13696288294159 s remaining**. The package cap is **30 charged seconds**,
including guarded jobs and the established five-second operator/bookkeeping charge.
The experimental command has a 14 s outer/13.5 s child deadline, with a 12 s inner
pilot stop and an 8 s generation stop. Admission reserves ten further seconds for
evidence/cleanup. Other command reservations are 2–5 s, below unchanged 60/55 s
maxima, and are admitted only if their full reservation fits the remaining 30 s.
The full audit is reserved at 5 s; closure is included in the five-second bookkeeping
charge. Unused time is not charged as though it was consumed.

Memory remains **256 MiB cgroup-v2 memory.max**, zero swap, with an independent
256 MiB aggregate sampled tree-RSS stop; one worker, two CPUs, four controlled
processes. Kernel memory.peak covers the worker and descendants, including charged
cache/kernel memory; the external monitor is outside that cgroup. Shared pages can
be counted repeatedly in RSS, and sampling may miss peaks. Preserve 8 MiB temporary
disk, 10 MiB cumulative evidence output, 1 MiB/file, 60 KiB command diagnostics,
existing diagnostic/9 GiB storage stops and 2 GiB headroom. The candidate is capped
at **2,000,000 gates** and an **8 MiB in-memory trace**; no trace is written to disk.
The previous 64M-gate/2 GiB proposal remains inactive.

Analysis stays **261.8157406691462 s**; isolation stays **250.22 s**, safely
stopped/unactivated with 100 historical invocations and 22 original identity cases
pending. Historical closure/failed activation evidence is reused, not retested.
Proof ledger stays **two used, one unused**, CPU proving paused.

## Candidate construction and required profile change

The [candidate](../experiments/private_hint_lowering_1/candidate.py) is named
`experimental-private-hints-v1`. It is a **proposed compiler/profile change**,
not an optimisation permitted by BC-1. It narrows proven bounded values, shares
expressions and replaces the literal source-order private-index scans. BC-1
R-034–036 requires signed64 integer cells, full scans, masked source loops and no
CSE/reassociation. Those production rules and their implementation are preserved.
The existing emitter still uses XOR/AND/NOT, the prescribed OR expansion and
all-public-only folding. Sharing is explicit in this experimental circuit's source.

Use the original **42,632 private positions** and hint bytes **4308:4369**
(bits34464:34952) from `alpha-42-old-002c`. Only the 488 hint bits are read by either
standalone decoder. Every hint/index/endpoint byte is private; no decoded advice,
holder/credential disclosure or fixture value enters construction. Public constants
are K=6, N=256, omega=55, the raw layout and the standalone active scope. The
experimental public description gives the trace its own identity. The generator
receives symbolic wires only; the same single completed circuit serves all cases.

For raw coefficient bytes `y[0..54]` and endpoints `end[0..5]`:

1. Enforce `0 <= end[0] <= ... <= end[5] <= 55`. Eight-bit unsigned comparison
   carries the result of the most significant differing bit; there is no narrowing
   of an unchecked signed value. All inputs are bytes and all indices in the
   emitted schedule are public constants.
2. For each row and each public slot j, derive
   `inside[row,j] = (start[row] <= j < end[row])`, where start is zero or the
   preceding endpoint. Share the comparisons `j < end[row]`.
3. Enforce `y[j-1] < y[j]` only when **both** adjacent slots belong to that row.
   This rejects repeated or descending positions inside a row. It correctly allows
   the same coefficient in different rows and accepts empty rows.
4. Construct all 256 equality selectors for each private coefficient byte with a
   binary prefix tree. Each leaf is exactly `y[j] == position`. All eight bits are
   consumed; positions 0 and 255 are valid. Shared prefixes are deliberately new
   lowering, not extra public information or a new witness.
5. Require every unused slot `j >= end[5]` to be zero, using the same equality
   selector for zero. No masked padding or malformed-input check is omitted.
6. For every row and position, OR all 55
   `inside[row,j] AND (y[j] == position)` terms. All loops have fixed public bounds;
   no private value selects host control flow or a Python array access.
7. Submit the combined validity condition to existing `Scope.require`. Preserve
   its sticky rejection and active-path mask. Mask outputs with
   `scope.active AND NOT scope.rejected`, then zero-extend each constrained Boolean
   value to a **64-bit word**. Return the validity bit and finish with the existing
   scope output predicate. Masking/finalisation count as core gates; zero-extension
   is rewiring and introduces no arithmetic, advice or comparison gates.

Output is six polynomials of 256 signed64-compatible values. Each valid value is
exactly 0 or 1 by Boolean construction; no separate 64-bit range proof is needed.
All malformed outcomes remain **unusable**. Candidate rejected outputs are zero;
the original decoder can have partial values at rejection, but neither interface
allows those values to be used as a valid decode. Consumers must retain the sticky
validity condition. This pilot does not change any consumer.

## Structural equivalence and limits of evidence

For valid endpoints, the six intervals partition exactly `[0,end[5])`. Thus the
native decoder's advancing private index visits exactly the slots selected by
`inside`. Within each interval, the native first-element exception and subsequent
strict-order tests are exactly the candidate's adjacent-pair predicates. The
monotone bounds imply at most 55 consumed positions and ensure every native read
is within the 55 coefficient bytes. Byte values are already in `[0,255]`, so each
native write addresses one of 256 cells. A prefix-decoder induction shows that,
for any eight-bit input, exactly one leaf is one and it names that byte. Therefore
the OR-of-membership construction marks precisely the cells the native loop writes.
The final zero test covers precisely the native unused suffix. These facts give
the same valid language and reconstructed values for the fixed 61-byte domain.

If any bound/order/padding rule fails on an active path, at least one candidate
condition is false; `Scope.require` sets rejection and it cannot be cleared.
Checks for adjacent values outside a row cannot reject it. Extra work after a
rejection is total bounded Boolean computation; it cannot rescue an invalid decode.
With an inactive scope, no new rejection is added and outputs are the zero
initialiser. An incoming rejection remains sticky. This last composition argument
uses the unchanged Scope implementation; this pilot's measured circuit starts
active and not rejected, matching the original standalone count. **No new
inactive/upstream-rejected-scope test or full signature integration is claimed.**

This is a source-level structural argument, not a machine-checked universal
equivalence proof. Eight finite differential inputs cover distinct failure risks,
not every 488-bit encoding. The exact-length public API guard is inspected but no
separate wrong-length invocation is hidden in the test matrix. Compiler conformance,
alternate embedding/range invariants and complete cryptographic verification remain
separate obligations. Accepting a syntactically valid hint sequence proves nothing
about whether the enclosing signature or credential is valid.

## Measurements and fair comparison method

The [runner](../experiments/private_hint_lowering_1/run_pilot.py) writes each invocation
as started **before** performing it, then records pass/failure. One fixed circuit
is materialised, counted and fingerprinted once; generation failure cannot produce
a usable circuit. Counters use the existing emitter's opcode definitions and
public-only folding; disjoint cumulative phases attribute validation, selection,
bitmap/output work. The overall total includes returned validity and final output
operations after the last intermediate phase.

Each differential case compares native `_decode_hints` acceptance with the existing
Boolean evaluator. A separate previously validated trace observer reads every
64-bit output and the validity bit without adding gates. All 1,536 valid outputs
must agree exactly, not merely an output hash. Rejected outputs must be zero and
marked invalid; they are never compared as legitimate native partial results.
Record generation time, each case's evaluation/observation time, wire/trace bytes,
generation-time process high-water RSS and cgroup peak; outer resource records
cover the complete worker and descendants. All test inputs are synthetic.

| Invocation | Purpose |
| --- | --- |
| 1 | Single complete generation/count probe, no private fixture passed to construction |
| 2 | Original valid historical hint bytes |
| 3 | All-zero hints, six empty rows, all-zero padding |
| 4 | Decreasing row endpoints |
| 5 | Endpoint 56, beyond omega=55 |
| 6 | Equal adjacent coefficient positions in one row |
| 7 | Descending coefficient positions in one row |
| 8 | Nonzero unused suffix |
| 9 | Total55, coefficient255, empty middle rows and coefficient255 repeated across rows |

The original audit has **32,000,000 gates / 13,532,448 ANDs** at the cap, after
284 complete masked slots and part of the 285th. It lacks final padding/validity
and a complete fingerprint. Its 60.232 s was count-only with its historical
resource profile. This package does not repeat it: that alone exceeds the present
30 s package allowance. The candidate includes all six rows, padding and final
validity. Parameters, private positions and required usable signed64 outputs match;
lowering, trace storage and timed work differ. Retain that distinction when comparing.
Do not call the two rows matched complete decoders or a measured timing speedup.
No overlapping prefixes are added. No RISC Zero forecast or active proof-size
formula is revised from the result.

## Validation, preservation and stops

Sequential guarded command IDs are `preflight`, `imports`, `source-format`,
`quality`, `format`, `pilot`, `prepare`, `full-audit`. Their exact commands,
reservations and measurements are in the
[run ledger](data/s3_private_hint_lowering_pilot_1/run-ledger.json) and
[configuration](data/s3_private_hint_lowering_pilot_1/config.json).
The entry point is `.venv/bin/python -I -B
docs/data/s3_private_hint_lowering_pilot_1/run_checks.py CASE_ID`.
No completed command or failed case is automatically retried. A generation cap,
semantic mismatch, missing result or resource failure is not a pass. If required
evidence cannot fit, report incomplete and stop rather than borrowing time.

The unchanged corrected preservation auditor checks all 8,759 original entries
plus the historical additive chain, digest identities, nonoverlapping content
partitions, exact name inventory and entire historical prefixes of the three
append-only reports. The new experimental subtree receives an **additional exact
name inventory**, not an exclusion. Freeze all new source/configuration and result
inputs before the single full audit. Report readback and outer guard completion
are required. The final write-once seal/closure records only new evidence and
measured report suffixes; it does not regenerate the baseline or repeat content
comparisons outside the guard.

Only the new experimental files/evidence/report and appended status/traceability/
issue dispositions may change. No production sources, active parameters, dependency
locks, manuscript or historical evidence change. Complete proof knowledge/privacy,
adaptive Delta_tail, component reduction budgets, production custody/entropy/
erasure/side channels, durable holder storage and KYC interoperability remain open.
Stages 2–3 remain open, isolation safely stopped/unactivated and CPU proving paused.


## Measured result and decision

**A justified component candidate for further integration into a separately
reviewed lowering.** One generation probe and all eight differential cases pass,
first run. No original baseline rerun, no extra construction or hidden batch.

| Case | Reference valid | Candidate valid | Decoded values compared | Seconds | Outcome |
| --- | --- | --- | --- | --- | --- |
| original-valid | True | True | 1536 | 0.127852 | pass |
| all-zero-valid | True | True | 1536 | 0.127097 | pass |
| decreasing-endpoints | False | False | 0 | 0.127275 | pass |
| endpoint-over-55 | False | False | 0 | 0.124813 | pass |
| duplicate-within-row | False | False | 0 | 0.128333 | pass |
| descending-within-row | False | False | 0 | 0.124965 | pass |
| nonzero-unused-padding | False | False | 0 | 0.124417 | pass |
| capacity55-position255-cross-row-repeat | True | True | 1536 | 0.133484 | pass |

The generation probe completed in 0.451735641 s; emitter timer
0.451584485 s. Complete count:
**383,420 gates / 203,142 ANDs**, with
179,223 XOR and 1,055 NOT gates,
426,054 wires, 6,518,229 in-memory trace bytes.
There are zero test-comparison gates and zero extra gates for signed64 output
zero-extension. Output masking and final sticky validity ARE included.
Fingerprint: `4b26216c3a0d760848a03b08823392a4d9d5b7688c61de31443dbb47bb39ac9a`.
Generation-time Python-process high-water RSS:
42,758,144 bytes; cgroup peak at that point:
40,382,464 bytes. These are different scopes.
The final guard records the entire worker/descendant peak, including validation.

The preserved baseline is an **incomplete 32,000,000-gate / 13,532,448-AND prefix**.
Its final padding/validity is unreached. The complete candidate uses
13,329,306 fewer ANDs than that
prefix. For continuation of that exact original recipe, full baseline cost is at
least its recorded prefix; this is a useful conservative component cost gap.
It is **not a measured percentage reduction between two complete decoders**, a
canonical BC-1 optimisation or a measured whole-authentication reduction.
No matched timing/memory speedup is claimed: the old baseline counted only and
used a different resource envelope; this pilot also materialised and evaluated.

The candidate removes a demonstrated large private-index cost, so it could
materially reduce this component in a new whole-circuit design. Other measured
fragments remain: response/norm 537,603 ANDs and message preparation 413,709 ANDs
are separate results, not a sum or a complete residual. Bounded polynomial/NTT/
modular arithmetic and private depth-20 hashing remain major integration/cost
uncertainties. Full authentication and proof communication are still unmeasured.
Even this complete component exceeds the previously calculated 21,344-AND limit
for the frozen 10 MiB raw-view target, if embedded without further changes while
retaining that formula. No revised proof format is selected; no full-proof byte
projection or revised R0 forecast is made. A new compiler AND proof representation
still require a construction/security decision.

Recommend only **S3-MLDSA-ARITHMETIC-LOWERING-REVIEW-1**, a separately authorised
source/range-equivalence design for the next polynomial-arithmetic bottleneck.
Do not automatically generate another circuit or proof. Full integration needs
range/representation and active/inactive/composed-circuit validation beyond this
nine-invocation pilot; no invocation allowance remains for it in this ledger.

## Complete validation and preservation closure

Lint and formatting pass. The single
[complete preservation audit](data/s3_private_hint_lowering_pilot_1/result.json)
passes content, exact inventory, report readback and outer guard, exit 0:
10,205 disjoint content paths,
10,229 identity-inclusive paths,
2.423156706 s and
23,277,568-byte cgroup-v2 peak.
Maximum guarded-job cgroup peak 40,382,464 bytes; separately sampled tree RSS
51,757,056 bytes. Both remain below 256 MiB; swap zero, no resource events.

8 guarded commands total 4.760450599 s. With five seconds of established
operator/bookkeeping charge, **9.760450599/30 s** is consumed by this package.
Implementation cumulative **205.623487716/300 s**, **94.376512284 s remain**.
Invocations **231/231**, zero remaining: 222 prior + one generation + eight cases.
Analysis remains 261.815740669 s; isolation 250.22 s,100 historical invocations and
22 pending identity cases. No resets, borrowed allowances, failures or repeats.
Temporary disk peak 0 bytes, zero retained; the in-memory trace is
released on process exit. Five-second final bookkeeping uses 256 MiB address space,
five-second CPU/alarm and two CPUs within the existing charge, no repeated scan.
[Closure](data/s3_private_hint_lowering_pilot_1/validation-closure.json) and
[seal](data/s3_private_hint_lowering_pilot_1/manifest.json) retain exact balances.

Existing code/BC-1/configuration/dependencies/manuscript/evidence are preserved.
Only three historical reports gain append-only dispositions. Stages 2–3 open;
isolation safely stopped/unactivated; CPU proving paused, two attempts used and
one unused. No installations, activation, proof attempts or zkVM executions.
