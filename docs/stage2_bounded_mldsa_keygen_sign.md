# S2-BOUNDED-MLDSA-KEYGEN-SIGN-1 — bounded reference core

25 September 2026. **Reference key generation, expanded-key consistency checking
and pure ML-DSA-65 signing are implemented.** The core enforces the fixed project
sampler/attempt caps and bounded-verifies every signature before returning it.
This is a separate Python reference module; the existing production adapters still
fail closed. It does not activate an issuer, manager, DID or persistence service.

## Contract and preservation

Authority is [the task](data/s2_bounded_mldsa_keygen_sign_1/task-specification.txt),
[AGENTS.md](../AGENTS.md), manuscript **Sections II–VIII**, SPEC-001–004,
[R-009/R-032/R-033](implementation_spec.md), the unchanged
[active manifest](../configs/suite.json) and [bounded plan](bounded_mldsa_plan.md).
The manuscript SHA-256 remains
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The preflight verified all 45 entries in the preceding composition-review seal,
its digest `1ad3080a2698f41edf5561c88015c73686c5cf0b4a824d53c9199e5b4de028d8`,
and the 53 assessed source/input identities. Historical reports, vectors, source,
dependency pins/native build, active parameters and original baselines remain
protected. Existing reports receive append-only updates.

The [concrete-security assessment](stage2_concrete_security_assessment.md) and
[composition review](stage3_outer_oracle_composition.md) are reused, including
their unresolved terms and separate model/profile distinctions. No RISC Zero,
BC-1, outer-hash or protocol encoding change is made.

| Frozen profile rule | Implemented semantics |
| --- | --- |
| RejNTTPoly: 1,026 bytes per call | Unchanged verifier helper; every three-byte candidate, accepted or rejected, consumes budget; candidate 342 may complete |
| RejBoundedPoly: 512 bytes per call | New eta=4 sampler; low nibble then high nibble; reject 9..15; charge each whole byte, including rejected nibbles; byte 512 may complete |
| SampleInBall: 256 total bytes | Unchanged helper; eight initial sign bytes and every accepted/rejected index count; byte 256 may complete |
| Signing: at most 1,024 candidates | Candidate indices 0..1023, kappa=5*index; mask nonces kappa..kappa+4, two-byte little-endian; last nonce 5119 |
| Exhaustion | Abort the entire keygen/import/sign operation; no output, reseed, restart, cap increase or uncapped fallback |
| Ordinary candidate rejection | Advance to the next candidate within the same 1,024-attempt allowance and same derived mask seed |
| Before signature return | Existing bounded verifier, exact derived public key, message and external context; failure is final, with no signing retry |

These numbers are project-profile limits, **not exact limits prescribed by
FIPS 204**. Frozen limits match the specification and manifest; no discrepancy or
parameter decision was needed. ExpandMask is a fixed 640-byte SHAKE256 output per
polynomial, not RejBoundedPoly or a rejection sampler; it is not incorrectly capped
at 512 bytes. Hashlib may evaluate a final rate block internally, but the sampler
readers expose only the permitted prefix and check before each read. No byte after
a sampler cap can be consumed by the algorithm.

## Interfaces and implementation

New source: [bounded_mldsa_sign.py](../src/pqdid/bounded_mldsa_sign.py).
The unchanged [bounded_mldsa.py](../src/pqdid/bounded_mldsa.py) supplies NTT/inverse
NTT, matrix expansion/product, unpacking, decomposition, SampleInBall and final
verification. This is integer reference arithmetic using the existing stdlib
SHAKE implementation; it is not an operation/gate trace or circuit equivalence
claim. The new algorithms are implemented from the numbered standard procedures;
no upstream implementation is copied into the production code.

| Interface | Input/output and boundary |
| --- | --- |
| `reference_keygen_mldsa65(seed)` | Explicit immutable 32-byte seed for reproducibility; returns `ReferenceKeyPair(public_key, secret_key)` only after full completion; 1,952-/4,032-byte expanded encodings |
| `reference_public_key_mldsa65(sk, expected_public_key=None)` | Bounded import consistency: exact length, eta coefficient ranges, recomputed t0 and tr, optional exact expected public key; returns the derived public key, no activation |
| `reference_sign_mldsa65(sk, message, context=..., randomness=...)` | Explicit immutable 32-byte randomness for synthetic reproducibility; pure external-context processing; returns only a complete 3,309-byte signature after bounded verification |
| `bounded_keygen_mldsa65()` | Reference-only operational-randomness wrapper; exactly one `secrets.token_bytes(32)` draw, then bounded keygen |
| `bounded_sign_mldsa65(sk, message, role=...)` | Reference-only hedged wrapper; trusted caller chooses one of nine fixed roles; exactly one fresh 32-byte draw; no randomness/context/cap override |

The signing wrapper uses `PQ-DID/<role>/v1` for `credential`, `state`, `update`,
`did-record`, `did-read`, `control`, `request`, `current` and `revreq`. It receives
the already canonical body; it does not concatenate a role into that body, add a
second framing layer, prehash it, or accept an external-mu shortcut. Existing
credential/state/update/DID constructors are unchanged. Arbitrary contexts up to
255 bytes are allowed only by the explicitly named reference interface for
standard interoperability tests. An application must still pin its authorised
role, instance and key; possession of an API argument is not authority.

The numbered algorithm contract is [FIPS 204, August 2024](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf),
with the existing DEP-001 algorithm/editorial dispositions:

- Algorithms 1/6: seed expansion includes k=6 and l=5; ExpandA uses row/column
  order; ExpandS uses independent nonces 0..10; compute As1+s2, Power2Round,
  public/expanded-secret packing and tr.
- Algorithms 2/7: decode/check the expanded secret key; compute NTT secrets and
  the matrix; absorb `tr || 00 || len(context) || context || message`; derive the
  mask seed from `K || rnd || mu`; compute each candidate, all strict rejection
  conditions, hints and canonical signature encoding. Import consistency reuses
  the same bounded matrix, so it does not add a second signing ExpandA.
- Algorithms 15/31/33: eta=4 nibble rejection and ordered short-vector expansion.
  Algorithms 16–20/22/24–26 cover packing; Algorithms 34/35/36/39 cover masks,
  rounding, decomposition and hints. Existing Algorithms 29/30/32/41/42 are reused.

Import checks reject invalid eta encodings, inconsistent rho/s1/s2/t0/tr and an
expected-key mismatch. The 32-byte K field is a free PRF seed; its origin, entropy
or freshness cannot be inferred from an expanded key. Algebraic consistency does
not prove provenance, ownership, registration, secure storage or authority. Key
generation returns no partially usable pair on exhaustion. No pairwise signing
test is silently inserted into keygen or counted as an ordinary protocol action.

Candidate checks are strict: z norm below 524092, r0 norm below 261692, ct0 norm
below 261888 and hint weight at most 55. Hints use the FIPS high-bit comparison,
then ascending indices and cumulative row counts with zero padding. Modular
centred representatives and little-endian polynomial/nonce packing are distinct
from the protocol's big-endian record encoding.

## Failure, randomness and disposal

`BoundedMLDSAError.reason` is one of `INVALID_INPUT`, `SAMPLER_EXHAUSTED`,
`ATTEMPTS_EXHAUSTED`, `ENTROPY_FAILURE` or `RELEASE_REJECTED`. Errors contain only
the constant category, never a partial key/signature, attempt count, seed or
secret-dependent intermediate. Unexpected runtime/resource errors propagate;
they cannot become acceptance. The wrappers do not turn missing/short/non-byte
entropy into zeroes. OS entropy errors produce explicit failure without another
draw. This uses the established Python OS-entropy convention, not a claim of a
FIPS-validated random-bit generator.

No implementation interface accepts a sampler reader, candidate callback,
verifier callback or cap override. Tests use pytest monkeypatch on private helpers
only, without changing native global randomness. Python module mutability is not
a hostile-caller security boundary; this restriction concerns the callable API,
not protection against code execution in the same interpreter.

Explicitly retained mutable secret arrays and mask buffers are cleared on normal
exit and exceptions, including rejected candidates before the next iteration.
Partially built short polynomials are cleared on sampler failure. There is no
ordinary diagnostic output; the keypair's representation omits its secret key.
This is **best effort only**. Python immutable bytes/integers, temporary lists,
hashlib state, allocator copies, exception tracebacks and caller-owned key/seed
inputs cannot be reliably erased by this implementation. It is variable-time and
does not satisfy a production secure-erasure or side-channel claim. Returned keys
remain the caller's sensitive data. No private operational data was retained here.

## Validation and provenance

[Focused tests](../tests/unit/test_bounded_mldsa_sign.py) and
[native differential tests](../tests/integration/test_bounded_mldsa_sign_native.py)
run in the package guard. **49 focused + 9 final interoperability + 12 scoped
regressions pass.** Nine preliminary interoperability invocations are also retained:
**79 total invocations, 70 distinct tests, 58 new tests**, within the unchanged
100-invocation implementation allowance. No functional test failed or hit a
resource ceiling. The unrelated historical suites were not restarted.

The source-reviewed ABI correction is preserved in
[abi-review-correction.json](data/s2_bounded_mldsa_keygen_sign_1/abi-review-correction.json).
The first ctypes harness supplied an unnecessary final null integration-context
argument. The pinned `common.h`/`sign.h` macros and `config_c.h` remove that argument:
the exact compiled entry points have three keygen and nine signing arguments.
Only the nine interoperability tests were repeated with the corrected declarations;
their retained deterministic output digests are identical. The initial source,
runner, logs and results remain evidence; final interoperability claims use
`interop-final.xml` and `differential-evidence-final.json`.

| Check | Evidence and scope |
| --- | --- |
| Complete key encoding | Two explicit synthetic seeds; reference public and expanded secret keys exactly equal pinned portable-native outputs; imported expected pk agrees |
| Complete signature encoding | Six identical seed/rnd/message/context cases: empty, binary, 255-byte, credential, state and update contexts; exact reference/native signatures agree |
| Verification/mutations | Each of six cases has six paired bounded/native outcomes: valid, changed message, wrong context, changed signature, changed public key and duplicate context framing; 36 outcome pairs |
| External key import | One ordinary native-generated test key imports and signs successfully; verification outcome only, not a deterministic key/signature comparison; no generated key is retained |
| All role wrappers | All nine fixed contexts, two independent synthetic draws/signatures per role; exact accepted message/context and distinct signatures |
| Short sampler | Byte-511/512 success, both last-byte nibbles, byte-513 refusal/all-rejected input, nibble order and bad-reader propagation; eleven independent budgets/nonces; keygen abort at first/middle/last secret polynomial |
| Matrix/challenge propagation | Every keygen matrix entry can finish at byte 1026; real capped matrix exhaustion reaches keygen/import/sign without retry; first signing challenge exhaustion aborts immediately |
| Candidate boundary | Actual 1,024-entry loop with test-only candidate substitution; success on the last candidate still undergoes real verification; all-rejected loop stops before 1,025; all kappa values and last mask nonces checked |
| Rejection conditions | Both signs at each strict norm boundary, modular representatives, forced z/r0/ct0/hint-weight rejection, hint wraparound/packing; no rejected candidate output |
| Release/error boundary | Invalid/exhausted final verification returns no signature and does not retry; malformed keys/inputs, entropy failure and resource-error propagation; retained mutable work arrays cleared on injected failure |
| Reused verifier regression | Twelve unchanged frozen native vectors, 96 valid/mutated outcome pairs; original arithmetic/sampler unit evidence reused without rerunning entire suites |

Native oracle: unchanged liboqs/liboqs-python 0.16.0, liboqs commit
`5a1a854b0dc9f2141bdc771c555ee60c37950183`, vendored mldsa-native commit
`9b0ee84f4cf399043eca59eca4e5f8531ca1d61b`. Deterministic tests call the installed
portable `PQCP_MLDSA_NATIVE_MLDSA65_C_keypair_internal` and `signature_internal`
symbols directly, with `externalmu=0` and the exact pure-mode prefix. These native
operations do not enforce the project caps. Their purpose is independent functional
comparison, not boundedness evidence or a replacement signer.

[Provenance](data/s2_bounded_mldsa_keygen_sign_1/provenance.json) pins source/build,
library, manifest and fixture identities. The deterministic evidence retains only
explicitly labelled **public synthetic test** seeds/randomness/messages/contexts
and output digests. It does not store expanded private keys. These are differential
vectors, not official NIST validation vectors or certification. Artificial
boundary streams are test control inputs, not estimates of sampler probabilities.

## Resource envelope and remaining work

The [configuration](data/s2_bounded_mldsa_keygen_sign_1/config.json) uses the existing
bounded implementation workflow: separate 300-second implementation allowance,
100 test invocations including repeats, one worker/two CPUs, 256 MiB cgroup memory
including worker/descendants and charged file-cache/kernel memory, zero swap,
60 seconds per command/55 per child. Existing 8 MiB temporary, 10 MiB package,
1 MiB file, 60 KiB command-log, diagnostic/storage stops and 2 GiB headroom reserve
remain enforced. A five-second conservative operator/final-bookkeeping charge is
included. Commands and per-job effective limits are in the
[run ledger](data/s2_bounded_mldsa_keygen_sign_1/run-ledger.json).

The security-analysis allowance remains **270.181481168 seconds** (the user's
270.181-second rounded figure); none is repurposed. The paused isolation budget
remains **250.22 seconds**, including its ten-second reserve, with 100 historical
invocations and 22 actual-identity cases pending. Existing safely-stopped,
unactivated evidence is reused. No host/deployment activation occurred; transient
user services are solely the established local validation guard.

DEP-002's *reference* keygen/sign/import subtask is now implemented. This does not
close production signing, entropy assurance, side-channel/erasure, storage,
authorised key import or all-role durable release obligations. No new signer is
connected to the existing fail-closed production adapters. Additional import
checks/pre-return verification have real invocation costs: signing expands 30
matrix polynomials and at most 1,024 challenges; final verification adds 30 matrix
polynomials and one challenge; explicit import adds 30. Keygen expands 30 matrix
and 11 short polynomials. Count each actually invoked check in lifetime/reduction
budgets; no wrapper caching, automatic regeneration or hidden retry is assumed.

DEP-001's corrected average/minimum guidance does not establish the conditional
`(41/51)^1024` tail. Adaptive `Delta_tail`, component advantages at reduction budgets,
SEC-001–005 and OC-REL/EXT/PRIV/BUDGET remain open. Passing a small number of tests
does not estimate rare-event probabilities or establish an overall bit-security
claim. Internally signed but unreleased messages must still be counted in the
security coupling/reduction. Full BC-1 and private-proof knowledge/privacy remain
unresolved; the RISC Zero experiments remain separate historical profiles.

**One recommended next package: S2-BOUNDED-SIGNER-RELEASE-CONTRACT-1.** Define and
test an isolated reference adapter's explicit failure mapping, trusted role/key
selection and pre-release/no-retry contract against temporary synthetic issuer/
manager/DID fixtures. Verify that failure releases no signature or partial public
state, and account for every import/sign/verify invocation. Keep production defaults
fail closed and do not activate services, alter parameters or claim tail/side-channel
closure. This would prepare reviewable integration requirements; it does not
supersede the pending actual-identity isolation cases. The package is recommended,
not started here.

Stages 2–3 remain open. No dependency installation, estimator campaign, circuit
generation, proof or zkVM execution occurred. CPU proving remains paused;
the proof ledger remains **two attempts used, one unused**.


## Measured validation closure

The single [complete preservation audit](data/s2_bounded_mldsa_keygen_sign_1/result.json)
passed content/inventory comparison, report readback and its outer resource guard,
exit **0**. Coverage: 8,759 original and
879 supplementary paths,
**9,638 disjoint content paths**,
9,653 identity-inclusive paths.
No unexpected changes, additions or removals occurred. Three historical reports
have verified append-only prefixes; all pre-existing source/vectors/parameters,
manuscript, dependencies and original evidence are preserved. The only new source
is the separate reference module and its two test files. Lint and formatting pass.

| Measurement | Result |
| --- | --- |
| Audit wall time | 2.330812694 s |
| Audit cgroup memory.peak | 23,130,112 bytes |
| Audit sampled process-tree RSS | 41,025,536 bytes |
| Maximum guarded-job cgroup memory.peak | 48,275,456 bytes, below 268,435,456 |
| Maximum observed guarded-job tree RSS | 63,823,872 bytes; separate metric |
| Guarded commands | 11, 6.616396493 s total; all completed |
| Separate implementation charge | **11.616396493/300 s** including five bookkeeping seconds |
| Remaining implementation allowance | **288.383603507 s**, **21/100 test invocations** |
| Test invocations | 49 focused + 9 preliminary + 9 final interoperability + 12 regressions = 79 |
| Functional failures/resource breaches | 0/0; one source-reviewed FFI harness correction retained |
| Temporary storage | 0 observed peak bytes; zero retained |
| Package bytes at outer audit completion | 397,221 |

The audit's unchanged **256 MiB** metric is cgroup-v2 memory.peak for the complete
worker/descendant tree, including charged file-cache/kernel memory; swap is zero.
The external RSS sample can count shared pages more than once. No execution/proving
cost inference is made. The final bookkeeping has a separate 256 MiB address-space,
CPU/alarm-five-second, two-CPU and 1 MiB-file bound, within the five-second charge.
It checks new outputs, exact names, links and report prefixes, then writes the
[closure](data/s2_bounded_mldsa_keygen_sign_1/validation-closure.json) and
[new additive seal](data/s2_bounded_mldsa_keygen_sign_1/manifest.json) once; it does
not repeat the protected content scan or regenerate a historical baseline.

Analysis **270.181481168 s** and isolation **250.22 s** remain untouched. Stages
2–3 remain open; DEP-001/002 production obligations, adaptive Delta_tail, side
channels/erasure and complete private-proof knowledge/privacy remain unresolved.
Isolation stays safely stopped/unactivated. No proof/zkVM/activation occurred;
proof ledger two used/one unused. Next recommendation remains the bounded
**S2-BOUNDED-SIGNER-RELEASE-CONTRACT-1**; it is not started.
