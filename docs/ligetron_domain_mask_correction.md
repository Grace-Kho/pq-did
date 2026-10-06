# LIGETRON-DOMAIN-MASK-CORRECTION-1

Component implementation and 32 fixed checks passed. Full preservation completion
is authoritative only in [validation closure](data/ligetron_domain_mask_correction_1/validation-closure.json).
Complete private-proof admission remains **NOT ADMITTED**. No GPU, VM, complete
prover/verifier, hidden-message ML-DSA or proof execution occurred.

## Identities and scope

Base commit `4b1cdef1bfdf4497fb3e38170db4541fba3f6c12`, tree
`95984ef209bf37a53624d27a36905e41886dacfc`. The completed randomness overlay,
its 35 passing cases and pinned dependencies remain unchanged. Its overlay hash is
`043ee96fbae51b9416b3435be7e7ad27cfc076ddb7790e14f14be6ea09c0dc3c`.
The source/algebra archive is 80,432 bytes, SHA-256
`bf9f36211c19cd5d113b25f8fd4e79d5a471c882b45f3ce033b765d2c3ecbe9b`.
Its safe paths/checksums and twelve source memberships reuse the retained tree;
additional six source/header/template files have length/blob/SHA-256 records in
[source acquisition](data/ligetron_domain_mask_correction_1/source-acquisition.json).
No dependency installation, upgrade or replacement revision occurred.

New patch SHA-256 `31f1515e498182664f51e92d91925416c0063d5b117494948e4a52dc6fcc5723`.
[Reviewed overlay](data/ligetron_domain_mask_correction_1/reviewed-overlay.patch).
CPU binary SHA-256 `9d21ea26044ab0959379ec5bcdd8d8cd5d47794fd45518381b7b532f19d6a3fb`, 600632 bytes.
[Build commands](data/ligetron_domain_mask_correction_1/build-2-commands.json).
Build 1 consumed a slot but stopped before compiler launch because its designated
parent directory was absent; build 2 succeeded after creating that directory.
No third package build is authorised. Serial build warnings are retained.

## Exact component contract and mathematical correspondence

Experimental component dimensions: k=8192, ell=7936, n=32768, q=192 queries,
256 private padding coordinates; BN254 unchanged. No production profile adopts
these dimensions. The interpolation sets are H_k and H_2k; code points are 7 H_n.
The algebra requires exact root orders and 7^n != 1, making the code set disjoint
from the interpolation subgroup. The former inverse-root identity remains a
negative control; changing generators alone never separated the subgroups.

The transform model first interpolates, scales coefficient j by 7^j and evaluates
on H_n. Decoding inversely transforms H_n, scales by 7^-j and only then folds
coefficients modulo X^k-1. GPU engine/shader overlays implement the same proposed
ordering, but have not been compiled or executed. Ordinary values, public
coefficient rows, batches and all three mask encodings share this code domain.
The source template and generated packed shader were updated together; deployed
shader selection and actual device correspondence remain unverified.

The code-test mask now has k independent field draws. Its injective linear
encoding is uniform over the code conditional on the stated ideal-draw premise.
For fixed rows and weights the affine response is uniform. The former zero-tail
mask allowed cancellation of aggregated padding from the disclosed response and
row samples. D-06 and M-05 preserve those distinct local negative controls;
neither is a GPU/application attack. Full-tail M-06 checks the changed statistic,
not a finite-model proof of complete-view privacy.

For a row with ell fixed message evaluations, the difference of two valid
interpolants is Z_message(X)R(X), deg R < k-ell. On at most 192 distinct code
points, the observation map is a nonzero diagonal times a Vandermonde matrix and
has full row rank because k-ell=256. This local fact does not condition on Merkle
roots or establish adaptive committed-transcript simulation.

The native public-coefficient rows interpolate k zero-padded values, not an
ell-point polynomial. Therefore the linear response degree can reach 2k-2.
**We do not silently claim the paper's degree < k+ell-1.** This component uses
D_L=D_Q=2k-1 as exclusive bounds and adds matching verifier coefficient checks.
The changed degree/observation parameters still require full protocol analysis.

Linear masks: sample D_L coefficients with the highest 2k-th coefficient zero,
evaluate on H_2k, then subtract the mean of the first ell even evaluations.
Since the constant polynomial has nonzero sum ell, this is a surjective linear
projection onto the sum-zero subspace. Every target has the same number of
preimages; conditional uniform draws therefore give a uniform constrained mask.
It preserves the required sum, without the old additional per-message zeros.

Quadratic masks: fix the first ell even H_2k evaluations to zero; independently
sample every other coordinate except the last odd coordinate. Solve that pivot
using sum_i v_i omega_2k^i=0. This is precisely the highest inverse-transform
coefficient equation, with a nonzero pivot. It gives a bijection from independent
coordinates to the degree<D_Q vanishing subspace. The original zeros survive.
Mask draw counts at the proposed dimensions are 8192, 16383 and 8447 respectively;
full-sized mask execution/resource performance was not measured.

Sampling and masking loops have public shapes. The inherited 256-candidate field
sampler cap is unchanged and separate from every ML-DSA cap. Exhaustion aborts
before returning the mask bundle. Variable-time GMP remains reference-only.
All three stages reuse the same private seed/draw order; batching uses k-ell
rather than query count. Independent field draws and secure private expansion
remain conditional assumptions, not empirical conclusions.

The experimental profile tag binds k/ell/n/q/delta/degree to Stage1. Stage2 now
includes the complete Stage1 digest. Both entry points reject other dimensions.
This binding edit is source-checked; no full entry point was executed. It does
not certify canonical proof parsing, application/layout binding or a compiler.

## Inspected protocol arguments and remaining admission conditions

The online 47-page [extended Ligero paper](https://eprint.iacr.org/2022/1608.pdf)
was inspected on 3 October 2026: §§4.6.1–4.6.3, B.3–B.5, Lemma 4.15 and §5.
Affine code blinding and constrained polynomial masks support the local contracts;
the lemma's strict padding premise alone does not certify our modified degree map
or the complete native view. Commitment and noninteractive transformations are
separate. The inspected text's paragraph/figure oracle notation and its simulator
must be mapped explicitly, not treated as interchangeable with native messages.

The 44-page [Frigo–shelat paper](https://eprint.iacr.org/2024/2010.pdf), Theorem 4
(printed pp.8–9), concerns BCS-compiled ZKIPCP under its stated parameters. Its
classical/quantum adaptive knowledge claims do not automatically apply here;
unspecified asymptotic constants supply no concrete quantum security level.
Optional PDF acquisition returned HTTP 403; online inspection was expressly
permitted and succeeded. No local PDF hash or independently pinned revision date
is available. [Reference identity record](data/ligetron_domain_mask_correction_1/references.json).

LIG-PARAM-MASK-001 remains open for the complete ordinary/batched joint view,
modified degree accounting and entropy after commitment observations.
LIG-PUBLIC-EXPANSION-001 remains open for known-key challenge expansion and
adaptive bounded-sampler losses. LIG-COMMIT-FS-001 remains open for complete
commitment simulation and circuit/program/layout/profile compiler correspondence.
LIG-KNOWLEDGE-PQ-001 remains open for same-assignment extraction, quantum privacy,
Fiat–Shamir and finite-parameter losses. Merkle authentication is not hiding.
No substitute wrapper, new theorem or overall security claim is introduced.

## Validation and limits

The 32-case matrix and direct host-integer polynomial/Vandermonde expectations
were sealed before candidate execution. AES expectations use the existing OpenSSL
CLI and share that primitive; byte order, rejection and draw consumption are
independently specified. The CPU implementation uses radix-2 transforms while the
oracle uses direct polynomial evaluation/inverse-Vandermonde sums.

Actual native code exercised: pinned bn254 field/root functions and bounded
sampler, mpz_random_engine, patched witness_manager::process_masks,
process_reset_linear_row, commit_release_witness and shared mask helpers.
CPU models cover ordinary/batched transform algebra and decoding; these are not
executed batch/GPU callbacks. Small algebra/mask cases use k=8,n=32,ell=4;
D-01 verifies proposed default root/domain conditions and P-08 checks default
profile admission. Default-sized masks, full relation and GPU/VM execution remain
unrun. N-07/N-08 mask validators are harness contract checks; only the proposed
source verifier degree checks are on the full verifier path.

All 32 fixed cases passed once, zero corrective reruns. Eleven historical slots
remain reserved; four new correction slots are unused. The prior 35 randomness
cases, 302 historical baseline observations and four smoke observations were not
rerun or altered. [Individual outcomes](data/ligetron_domain_mask_correction_1/outcomes.json).

| Case | Outcome | Seconds |
| --- | --- | ---: |
| D-01 | pass | 0.003965 |
| D-02 | pass | 0.002173 |
| D-03 | pass | 0.001465 |
| D-04 | pass | 0.001509 |
| D-05 | pass | 0.001269 |
| D-06 | pass | 0.001274 |
| M-01 | pass | 0.001454 |
| M-02 | pass | 0.002268 |
| M-03 | pass | 0.001175 |
| M-04 | pass | 0.001194 |
| M-05 | pass | 0.001574 |
| M-06 | pass | 0.001758 |
| P-01 | pass | 0.002134 |
| P-02 | pass | 0.001153 |
| P-03 | pass | 0.001195 |
| P-04 | pass | 0.001379 |
| P-05 | pass | 0.002021 |
| P-06 | pass | 0.001691 |
| P-07 | pass | 0.001656 |
| P-08 | pass | 0.001240 |
| N-01 | pass | 0.001630 |
| N-02 | pass | 0.001085 |
| N-03 | pass | 0.001206 |
| N-04 | pass | 0.001468 |
| N-05 | pass | 0.001428 |
| N-06 | pass | 0.001118 |
| N-07 | pass | 0.001043 |
| N-08 | pass | 0.001092 |
| R-01 | pass | 0.002128 |
| R-02 | pass | 0.002216 |
| R-03 | pass | 0.002620 |
| R-04 | pass | 0.001287 |

## Failures, resources and completion

Retained failures: sandbox denied the user bus before job admission; the identical
guarded acquisition was approved through normal escalation. Source acquisition
succeeded before the optional PDF HTTP403. Initial lint diagnostics were corrected.
Preflight caught an incomplete multiline Stage2 argument edit before compilation;
its correction and before/after hashes are retained. Build 1's missing-directory
failure is charged. Build 2 and the 32 cases passed; no failure was rewritten.

Allocation: 360 existing seconds outside KYC including 60 completion reserve;
36 new slots (ceiling1265), two existing build slots (ceiling13), 1MiB evidence,
8MiB artifacts. KYC allocation 383.7084432235879 seconds and its 300-second reserve
are unchanged. Shared evidence completion reserve remains 2MiB. The 200-second
conservative operator charge is booked once, separately from measured guarded
jobs; it covers source/math inspection, edits, diagnosis, web reading and reporting.
Before completion jobs, measured guard consumption was 10.397739 seconds.
No time, slot or storage reset occurred. Final exact values and memory/storage
are in [resource closure](data/ligetron_domain_mask_correction_1/resource-closure.json).
The unresolved historical acquisition-memory observation remains unresolved.

One final preservation workflow verifies original comparisons, prior package
seals, appended historical documentation prefixes, final inventory and readback.
Only its successful closure establishes preservation. Component results do not
close Stages2–3, security obligations or complete private authentication.
Only manuscript Sections II–VIII and agreed clarifications remain authoritative.
Production code, manuscript, dependencies, comparison points and datasets remain
unchanged. Binius correspondence stays closed/unresolved. Private verification
is fail-closed; proving/isolation paused; proof ledger two used/one unused.
No subsequent package is started.

Preservation preparation initially reported the two sealed root-level Ligetron
archives missing because its inherited partitioner visits directory descendants
only. Both existing hashes are retained. Explicit file partitions now verify
those two names/hashes alongside all original directory/content comparisons;
preparation.json and its failed job remain unchanged. The corrected result is
preparation-corrected.json. No historical baseline was regenerated.

The first audit launcher aborted at its scope/preparation hash precondition,
before historical comparisons: it selected the original failed preparation.
The diagnostic remains intact. Corrected completion selects the versioned
preparation-corrected-v3.json and uses the same exact root-file partitions in
the inner auditor. Audit launches and completed comparison runs are reported
separately; no functional rerun or baseline/hash relaxation occurred.
