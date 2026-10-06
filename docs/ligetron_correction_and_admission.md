# LIGETRON-CORRECTION-AND-ADMISSION-1

CPU-only component implementation and validation complete; final preservation is
recorded in [validation closure](data/ligetron_correction_admission_1/validation-closure.json).
**Private-proof admission: NOT ADMITTED.** This is not a complete Ligetron repair,
VM verification, private authentication or a production-security claim.

## Source and patch identities

Public commit `4b1cdef1bfdf4497fb3e38170db4541fba3f6c12`; root tree `95984ef209bf37a53624d27a36905e41886dacfc`.
Independent HTTPS GitHub commit/tree records match all 19 supplied source blobs.
The additional `src/bn254.cpp` matches blob `6064d558b6eb7967d320b1bed58ba62e3fca1fcb`
and SHA-256 `eb5cec3bdfc266439b4c7dfd5b8c096b9285e61b1a886194f91fbd5ad21e0c79`.
These are origin/API and object-membership checks, not signature authentication
of an upstream release. The original handover and all original snapshot bytes
remain immutable. [Source records](data/ligetron_correction_admission_1/source-provenance.json)
and [additional-source record](data/ligetron_correction_admission_1/additional-source.json).

Handover SHA-256 `e116904d8f39c017b1a0807b4b1d891afc79bb50a98eff2279e6e45a48747fb8`;
original proposed patch `4d417cb21836fdd5ed0ed98b3d850d95d3e02d649365bf422fecdeeab374c567`.
The [reviewed overlay](data/ligetron_correction_admission_1/reviewed-overlay.patch)
has SHA-256 `043ee96fbae51b9416b3435be7e7ad27cfc076ddb7790e14f14be6ea09c0dc3c`.
It changes only the five approved source paths plus the shared
`include/zkp/pqdid_rng_exp1.hpp`. The immutable base and experimental overlay are
separate under `experiments/ligetron_correction_admission_1`.

## Actual correction and executed boundary

The prover's 32-byte encoding seed now uses checked `RAND_priv_bytes` without
weaker fallback. The query generator emits SHA256(label || seed || BE64(counter))
from block zero, resets its cache/counter on reseeding, implements exact discard,
and throws after the final uint64 counter block. Its label excludes NUL.
The stage-label helpers intentionally retain the upstream char-array trailing NUL.

Field sampling accepts a fresh 254-bit candidate only when it is below the pinned
BN254 modulus, preserving the caller output on exception. The approved 256-draw
cap is experimental backend policy; no ML-DSA sampler/attempt cap changed.
Code/linear/quadratic challenge engines use the existing distinct IVs 1/2/3.
Those counter intervals must not overlap (fewer than 2^120 AES blocks per stream).
The three encoding stages intentionally replay one private seed and stream.

The helper is shared by the patched prover/verifier call sites, the context
initialiser and the native harness. Native execution covered the actual query
engine, `bn254_gmp::generate_random`, active `mpz_random_engine`, shared helpers and
`portable_sample`. It linked the pinned BN254 source. It did not exercise other
BN254 operations, a whole VM, WebGPU, proof serialisation or the complete
prover/verifier entry points. ENT-02 checks the helper's failure boundary; the
prover's before-stage-1 call ordering is source evidence, not an executed receipt
failure path. The linker entropy wrapper exists only in the synthetic harness.
The declared platform is amd64/little-endian; transcript portability is unproved.

## Dependencies and build

GCC 15.2.0-16ubuntu1; exact Ubuntu development archives:
`libssl-dev_3.5.5-1ubuntu3.6_amd64.deb` and
`libboost1.90-dev_1.90.0-6ubuntu1_amd64.deb`. Both sizes and SHA-256 match the approved
pins. Only the required header closure was extracted locally (3,171,302 bytes).
The retained GMP 6.3.0 headers/static C and C++ libraries match the payload of the
historically sealed development archive. OpenSSL header/runtime version and
amd64 ELF symbol/path checks pass; each counted native case also checked runtime
OpenSSL and GMP versions. No installation, package hooks or environment changes.

[Exact build commands](data/ligetron_correction_admission_1/build-1-commands.json)
compile `native/cases.cpp` and `overlay/src/bn254.cpp` with C++20, explicit local
include/library paths and the test-only RAND linker wrapper. One build attempt
passed; the second was unused. OpenMP pragmas emitted retained warnings because
this component build is serial; no permissive option suppressed errors.
Binary SHA-256 `7f28431909d2d570d6e722abb6364f6e4b7797175d64c1ee825776557ba2fa63`, 441176 bytes.

## Independent expectations and individual results

[Expectations](data/ligetron_correction_admission_1/expectations.json) were sealed
before candidate execution. Python hashlib specifies query/transcript bytes.
The AES reference uses the installed OpenSSL CLI: it shares the cryptographic
primitive, while independently specifying bytes, endian import, rejection and
consumption. Query selection expectations independently implement the pinned
Boost byte-to-range law and Fisher-Yates schedule. No expected output calls the
candidate executable. Finite checks do not prove entropy quality or independence.

All 35 fixed invocations passed once; no native correction or rerun. The 20
original headings are expanded into separately counted seeds, endpoints, discard
counts and stream roles. [Detailed outcomes](data/ligetron_correction_admission_1/outcomes.json).

| Case | Outcome | Seconds |
| --- | --- | ---: |
| ENT-01 | pass | 0.005003 |
| ENT-02 | pass | 0.002426 |
| ENT-03-A | pass | 0.001998 |
| ENT-03-B | pass | 0.002029 |
| Q-01-A | pass | 0.001855 |
| Q-01-B | pass | 0.002062 |
| Q-02 | pass | 0.001844 |
| Q-03-partial | pass | 0.001814 |
| Q-03-full | pass | 0.001720 |
| Q-03-zero | pass | 0.001752 |
| Q-04-0 | pass | 0.001857 |
| Q-04-1 | pass | 0.003176 |
| Q-04-31 | pass | 0.001866 |
| Q-04-32 | pass | 0.001806 |
| Q-04-33 | pass | 0.001780 |
| Q-04-64 | pass | 0.001768 |
| Q-04-65 | pass | 0.001716 |
| Q-05 | pass | 0.001852 |
| Q-06 | pass | 0.001810 |
| F-01-zero | pass | 0.001333 |
| F-01-max | pass | 0.001137 |
| F-02 | pass | 0.001118 |
| F-03 | pass | 0.001136 |
| F-04 | pass | 0.001254 |
| F-05 | pass | 0.001141 |
| D-01-0 | pass | 0.002385 |
| D-01-1 | pass | 0.002363 |
| D-01-2 | pass | 0.002052 |
| D-02-0 | pass | 0.001906 |
| D-02-1 | pass | 0.002118 |
| D-02-2 | pass | 0.002076 |
| D-03 | pass | 0.002257 |
| D-04 | pass | 0.002106 |
| I-01 | pass | 0.002063 |
| I-02 | pass | 0.001757 |

Q-06 reproduces only the old first-block seed omission, not a forgery. D-04 checks
the last aligned candidate before the 16-KiB cache boundary and the first after
refill. All candidate results are public synthetic CPU-component results.

## Retained failures and corrections

The first dependency readback failed because the historical member index contains
names/sizes rather than per-member SHA-256. The correction compares actual files
with their exact payloads in the retained, checksum-verified archive. Downloads
and extraction were not repeated. The failed record remains intact.
The first scoped lint pass failed on long lines and closure-variable binding;
formatting/default-binding corrections passed. Final callback lint also required
explicit captures; its synchronous behaviour and all native inputs are unchanged,
so no functional rerun was needed. A direct launch rejected misplaced
`--build` before compiler admission; corrected argument placement used the first
build slot. No failure was reclassified as a success and none consumed a hidden
native invocation. All direct bookkeeping is included in the conservative charge.

## Security admission conditions

- PARAM/MASK: k=8192, ell=8000, t=192, n=32768 gives k=ell+t and does not meet the
  cited strict k>ell+t premise. No parameter was changed. Row padding and batch
  padding use different source paths; sample_size cannot silently serve as both
  a changed padding count and an unchanged query count. `process_masks` and all
  mask/batch callbacks need a complete domain, degree, observation and entropy
  correspondence. GPU transform definitions were not acquired in this CPU closure.
- PUBLIC-EXPANSION: separate IVs prevent identical counter streams, but a
  secret-key PRG theorem does not establish ideal public challenges under a known
  AES key. The applicable public-seed expansion argument remains missing. Under
  ideal independent candidates only, capped rejection is uniform conditional on
  success and contributes at most N*((2^254-q)/2^254)^256 over N draws. N and
  computational/adaptive/quantum replacement losses remain uninstantiated.
- COMMIT/FS: establish complete-view hiding/simulation for the committed rows,
  masks, roots and openings. Merkle binding is insufficient. Program/layout,
  public/private positions, parameters and complete prior-prefix binding must
  match the selected compiler theorem. The new labels alone do not implement an
  authenticated profile manifest or prove adaptive statement binding.
- KNOWLEDGE/PQ: extraction of one full application assignment and the applicable
  Fiat-Shamir, quantum-privacy and finite-parameter statements remain separate.
  Generic theorem statements do not certify this experimental implementation.
- RELATION/RESOURCES: a future ML-DSA port must preserve exact signed encodings,
  standard hashes/padding, bounded exhaustion, private control/memory constraints,
  holder binding, disclosure/policy, the same certified identifier's revocation
  path and session context. No complete relation/resource measurement was made.

**Decision:** validated component corrections with security admission open. No
hidden-message ML-DSA proof pilot is admitted. Any missing simulator, masking,
commitment or extractor construction stops that security route; it does not
trigger another repair or wrapper package. No overall security level is assigned.

## Accounting and preservation

The 30-second authorised preparation debit is charged once, separately from this
execution package. The 600-second amendment is outside KYC. A 180-second
conservative operator charge covers implementation, source inspection, diagnosis,
bookkeeping and reporting outside guarded jobs; it is not measured wall time.
Measured guarded jobs include failed attempts and finalisation. The exact closure
records final balances, storage, memory and one complete preservation result.

[Resource closure](data/ligetron_correction_admission_1/resource-closure.json),
[validation closure](data/ligetron_correction_admission_1/validation-closure.json)
and [ledger](data/ligetron_correction_admission_1/ledger.json).

The genuine ML-DSA KYC baseline, 302 historical observations, four separate smoke
observations, all prior failures, comparison points, production code and active
parameters remain unchanged. Only manuscript Sections II–VIII and agreed
clarifications are authoritative. Stages 2–3 and complete private authentication
remain open; Binius correspondence stays closed with its unresolved result.
Private verification is fail-closed; proving and isolation remain paused.
Proof ledger: two used, one unused. No subsequent package is launched.


### Final preservation result

The single complete audit passed, exit 0, in **7.187452 seconds**
(including guarded launch/completion). Audit-worker cgroup-v2 memory.peak was
**59,756,544 bytes**, below 256 MiB. It completed **10,901**
disjoint historical content comparisons and **10,936**
identity-inclusive paths. Audit-time inventory: **13,091**;
no missing/unexpected paths or partition overlap. The final inventory, complete
report seal/readback, termination and exact remaining balances are recorded in
the package validation/resource closures. No proof-security obligation is closed.
