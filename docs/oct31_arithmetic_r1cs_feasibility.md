# OCT31-ARITHMETIC-R1CS-FEASIBILITY-1 — 29 September 2026

**Decision: NO-GO before arithmetic-gadget implementation.** Direct integer
constraints can remove the forward-transform AND-row obstruction of the previous
candidate, but an unchanged required hash already exceeds resident admission.
The selected odd-prime field also lacks the reviewed native masking construction.
Neither arithmetic optimisation nor passing constraint evaluations resolves those
two independent obstacles. This is not complete private authentication.

The affine-elimination candidate is closed as unsuccessful for resource admission.
Its code, 29 outcomes, density regression, limits and complete preservation closure
remain unchanged. The v1 comparison point and all 276 measurements are retained.
Only manuscript Sections II–VIII and SPEC-001–004 are authoritative. No dependency,
production code, active BC-1 profile, parameter, original vector or manuscript was
changed. The previous lower bounds are historical evidence, not estimates for
this new field.

## Selected representation and exact semantics

The [pre-execution contract](data/oct31_arithmetic_r1cs_feasibility_1/contract.md)
specifies **INT-R1CS-FR254-1** in the existing pinned libff `alt_bn128_Fr` prime
field. This uses the scalar modulus, not the curve base field or curve assumptions.
The field is 254 bits with 2-adicity 28. It is a proposed experimental profile;
there was no native field instantiation, compiler build or active profile change.

The contract gives explicit bit/range/packing equations, signed64 and wide checked
arithmetic, quotient/remainder bounds, canonical mod-q multiplication, forward and
inverse representation boundaries, validity and inactive-output treatment. For
example, a public-constant product is `c*x=q*k+r`, with canonical x/r and a bounded
nonnegative k. Its integer difference is strictly below p; range and complement
constraints prevent a modular-field solution from representing an invalid
integer. The fully guarded kernel's specified 123 rows include input and output
canonicality and quotient bits, before additional boundary/control links. This
is an exact **formula for a proposed kernel**, not a measured implementation or
whole-transform estimate. All auxiliary values require constraints.

Signed64 entry normalisation is retained. Canonical arithmetic replaces checked
operations only where caller ranges prove overflow impossible. Strict norm,
hint/index/padding validity, the 256-byte/248-candidate SampleInBall cap,
exhaustion, and SPEC-004 quotient/remainder behaviour remain mandatory. Byte
encodings, messages, role contexts, certified fields, the same holder secret and
the same certified identifier feeding non-revocation remain unchanged.

The completeness/soundness argument is limited precisely: the specified kernels
have unique range-bounded integer interpretations, and preserve reference
operations when wired as specified. A complete prime-field compiler and its
composition have **not** been implemented or validated. No claim of complete
relation equivalence is inferred from the equations alone.

## Complete workload separation

| Required work | What arithmetic changes | Remaining work and evidence |
| --- | --- | --- |
| Parse 42,632 private bits; signature/hint formats | Packing may link existing bits to integer columns | Canonical layout, malformed rejection, ordered hints and all bit checks remain; no complete prime-field count |
| Holder binding | Nothing in SHA3-384 | Private framed xH hash remains inside the same relation; retained hash evidence reused |
| Disclosure/policy | Integer comparisons may use range constraints where equivalent | Same private attributes, disclosed bytes and policy; existing public policy/trust boundary retained |
| ML-DSA mu hash | Nothing in SHAKE256 | `tr || formatted_message`, output64; private message, exact context/framing, positive residual cost |
| Challenge sampling | No shortening of stream/scan | SHAKE256(48B,256B), then248 candidate iterations, exact sequential cell updates and exhaustion; full sampler remains unrun |
| Five z transforms and one c transform | Replace integer butterflies/reductions, not one row per original arithmetic AND | Six forward transforms, each1,024 butterflies; exact signed64 conversion, ordinary twiddles and final representatives |
| A*z and c*t1 | Public coefficient products and modular accumulation/subtraction | 7,680 A*z terms and1,536 c*t1 terms; input/output guards and density still require complete accounting |
| Six inverse transforms | Signed/integer product, sum/difference and reductions | Each1,024 inverse butterflies plus256 factor products; not covered by forward-only evidence |
| Norm, decomposition, UseHint, w1 | Norm integer comparisons; initial decomposition/hints remain exact Boolean definitions | 1,280 strict norms,1,536 hint/decomposition outputs,768-byte w1; range/byte links included symbolically |
| Final challenge | **Unchanged hash dominates the early lower bound** | SHAKE256(mu64||w1[768],48), seven permutations, same private signature comparison |
| Non-revocation | No replacement of private SHA3 path by arithmetic advice | Twenty level-framed nodes, private siblings, derived zero leaf, direction from the same certified rid, final authenticated-root equality |
| Public admission/lifecycle | No hidden checks delegated | Independently bound public key expansion/state/context, policy, freshness and atomic consumption retain their existing contracts |

Every row is required; unknown rows, variables and terms remain nonnegative
residuals, never zero-cost components. The source covers the whole predicate;
complete constraint/witness counts are unavailable because early admission fails.
There is no sum of overlapping component counts and no full-authentication timing
or proof-size projection.

## Field-correct hash bound and simultaneous storage

The retained [M-16 result](data/oct31_auth_relation_integration_run_1/cases/AR1-0054.json)
completed the final SHAKE/equality component with 1,365,895 Boolean gates,
including269,187 ANDs. Its mu was public and w1 private; it is not a joint-auth
measurement. The actual joint caller keeps mu private. This package does not
rerun that component or specialise joint mu to its old test value.

The source's seven Keccak-f permutations have24 rounds each and25*64 chi
products per round: **268,800 required chi products**. The retained measurement
corroborates this subset. Under this candidate each chi product receives `x*y=z`
over the **new field**. XOR is `(2*x)*y=x+y-z`, requiring an additional product
for two unknown bits; NOT may remain affine `1-x`. Therefore GF192's free affine
XOR accounting is not transplanted. Dropping all XOR, input and comparison costs
gives an optimistic lower bound; it is not a complete hash count. No cross-round
or algebraic hash-specific optimisation is part of this candidate.

Retaining the existing masking/degree/rate envelope conditionally requires:

`M,N >= 2^19; b>=1; Dconstraint >= 2^20+1; |L| >= 2^24`.

The actual b and other degree terms remain symbolic. Setting b=1 for this lower
bound neither reduces a protocol setting nor claims a sufficient security bound.
The following are **calculated payload bounds**, not measured native memory:

| Storage item, already forced by the final-hash subset | Lower bound |
| --- | ---: |
| One codeword at >=32 bytes/element | 536,870,912 B /512 MiB |
| Four simultaneously retained codewords | 2,147,483,648 B /2 GiB |
| Padded assignment | 16,777,216 B /16 MiB |
| Three Az/Bz/Cz vectors | 50,331,648 B /48 MiB |
| Unpadded chi auxiliaries alone | 8,601,600 B |
| Three matrix coefficients per chi row, excluding indices/containers | 25,804,800 B |

The last four rows are distinct representations with lifetimes to account for,
not an assertion that all their peaks necessarily overlap. The four-codeword
subtotal **does** overlap in the retained `submit_witness_oracles`: fw is
constructed, then the three ABCz codewords, before any of the four submissions.
It exceeds the1 GiB worker cap and consumes all2 GiB aggregate capacity before
any positive overhead. FFT/interpolation, mask coefficients, sparse matrix copies,
container allocations, salts/Merkle trees and other oracles only add requirements.
No private witness, complete matrix, codeword or large instance was allocated.

Spilling does not give admission: one512 MiB codeword exceeds the complete128 MiB
artifact cap, and streaming does not establish the resident prover's working set.
No resource limit was raised. A full upper bound below the limits would have been
necessary for admission even if this lower bound had fitted.

## Independent construction and security obstruction

The pinned field has multiplicative subgroups through2^28. It cannot supply the
binary additive subspaces used by the corrected proof path. The retained native
`encoded_aurora_parameters` explicitly rejects `paper_masking=true` unless the
domain is additive, non-holographic and ZK. This was established by source
inspection, not an executed native rejection test. Disabling paper masking or
choosing weaker b/rate/repetition/security values is not an authorised solution.

Thus the storage calculation optimistically grants a compatible multiplicative
masking port with the existing degree envelope; that port and its simulation
argument do not yet exist in the validated stack. Field size alone does not
settle finite soundness, query budgets, commitment transformation, adaptive
Delta_tail, quantum extraction or complete-view privacy. Degree-two kernel
equivalence proves none of those claims. AURORA-BRIDGE-001 remains open.

The candidate cannot be admitted merely as a classical proof experiment either:
the implementation/resource barrier remains, and no proof attempt is authorised.
Ordinary private-proof verification remains fail-closed.

## Execution, individual outcomes and correction

The source/seal preflight passed. The only new counted work was a deterministic
feasibility calculation using retained evidence and native source identities:

| Invocation | Outcome |
| --- | --- |
| ARF1-0001 /Q-01 | Calculation wrote its model; final case reporting failed because the new cases directory had not been created. Retained as **incomplete**, not a passing invocation. |
| ARF1-0002 /Q-01-R1 | One justified targeted rerun after creating the designated directory prospectively; passed with identical calculated output and expected values. |

The [correction record](data/oct31_arithmetic_r1cs_feasibility_1/reporting-correction.json)
and patch preserve the first diagnostic and model hashes. The original missing
case record was not backfilled. The guard's conservative50,000,000-event charge
for incomplete work is retained; actual newly emitted gates/rows/terms and
constraint evaluations were zero. This conservative charge is not reported as
generated work. No build, native test, arithmetic gadget, new hash circuit,
historical test suite, benchmark, proof or zkVM execution ran. Affected lint and
format checks passed after the scoped reporting correction.

A later static-check launch also failed before invoking ruff: the coordinator's
`--completion` option was placed after its positional arguments and was parsed
as the child command. Its log and absent worker receipt remain a failed launch.
The exact retained systemd unit reports exit1, no control group/MainPID,
MemoryMax268,435,456B, zero swap and MemoryPeak10,891,264B. Correct placement
before the positional arguments fixes the command, without a guard redesign.
Only the affected static checks are repeated; these are not cryptographic cases.

All21 outstanding relation checks remain explicitly **unrun**:
M-01–M-03 (full private sampler), J-01–J-16 (joint valid/rejection comparisons),
Q-02–Q-03 (complete relation/backend measurements). The admission decision precedes
their execution. No synthetic acceptance or component pass substitutes for them.

## Accounting and preservation

Opening balances were2,995.1980095516446 implementation seconds,971/1,050
invocations,10/13 builds,27,593,603/2^32 work events,26,326,576 evidence bytes
and58,966,547 artifact bytes. Shared evidence allocation remaining was5,206,313B,
inside the32 MiB cumulative ceiling. The300-second and2 MiB completion reserves
remain inside these limits. Analysis balance80.91750274339225s and isolation
allowances are untouched. The original conservative operator bookkeeping convention
is retained separately from measured guarded command durations.

The corrected preservation auditor is reused unchanged at its256 MiB ceiling,
with exact new roots and append-only status/traceability/issues. All previous
baselines, expected hashes, failed runs and repair artifacts remain in scope.
The former affine report and experimental code are immutable inputs here.
Final audit, inventory, readback, shutdown and remaining balances are appended
below and recorded in the package closure; preparation alone is not completion.

## Decisive next step

**Stop the arithmetic-only resident Aurora route for the31 October target.** Even
perfectly free polynomial arithmetic would leave the required final hash too large
under this representation and envelope, with all other private hashes, sampling
and Merkle checks still to pay for. The supported next construction decision must
jointly address SHA3/SHAKE arithmetisation and a compatible privacy/masking domain,
with complete simultaneous-buffer admission. Another NTT/modmul optimisation does
not address this obstruction. A resource-only amendment would require more than
2 GiB just for the four final-hash codewords plus positive overhead and would
still leave masking and full-workload costs unresolved; no such amendment is
requested or applied by this package.

The result is specific to INT-R1CS-FR254-1 and the retained resident backend,
not a demonstrated attack or impossibility of every arithmetic representation.
Existing evidence does not support complete private authentication by31 October.
Stages 2–3, production security, complete proof knowledge/privacy and all cited
security obligations remain open. Isolation stays stopped/unactivated and CPU
proving paused. The proof ledger remains two used, one unused.


Preservation completed: the single full audit exited0 with 10,901 disjoint
content comparisons and 10,936 historical identity-inclusive paths.
It took 4.844211s including the guard (4.444965s worker),
with cgroup-v2 memory.peak 46997504B under256 MiB;
sampled summed process RSS was 63,692,800B and is a distinct metric.
All retained failure records remain present. Final inventory, report readback,
exact-unit shutdown and the authoritative remaining balances are recorded in
[validation-closure.json](data/oct31_arithmetic_r1cs_feasibility_1/validation-closure.json).
No resource admission for the complete representation follows from preservation.
