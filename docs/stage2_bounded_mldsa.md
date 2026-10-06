# Stage 2 bounded ML-DSA-65 and local CredValid

This records the bounded-verifier work package. Its then-pending complete local relations
have since been implemented; see [stage2_relations.md](stage2_relations.md). The test
counts and next-task discussion below retain their work-package context.

17 September 2026. **The separate bounded Python reference verifier and complete local
CredValid predicate are implemented and tested. Stage 2 remains in progress.** No
installed native code, dependency pin, lockfile or existing vector was changed.

## Authority, architecture and provenance

Only Sections II–VIII of the selected manuscript are authoritative; SHA-256 remains
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
VII-A.1/.5/.6, pp. 14–16, fixes ML-DSA-65, credential context/message, local CredValid
and the sampler caps. V-A/B, pp. 7–8, supplies the credential/opening interfaces;
VIII-A, pp. 17–18, supplies the separate conditional cap-loss discussion. SPEC-001
and SPEC-002 are unchanged and introduce no new signature-message fields.

[`bounded_mldsa.py`](../src/pqdid/bounded_mldsa.py) is an original Python implementation
of the verification algorithms in [FIPS 204, August 2024](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf),
with the manuscript's exhaustion behaviour. The inspected PDF has SHA-256
`57239b9f84c03227eda3ca0991204dc7764c79af9ce2e6824eda774918d46b6b`.
NIST's published algorithms are the source; no upstream C source or twiddle table was
copied or translated. There is therefore no copied third-party implementation requiring
a bundled source licence. US federal government specification provenance is distinct
from any claim of NIST/FIPS validation.

The unchanged ordinary backend was inspected and used as an independent oracle:
liboqs 0.16.0 commit `5a1a854b0dc9f2141bdc771c555ee60c37950183`, liboqs-python
commit `c6378cd5c8db74c0adf34ddcfbb96ee9c99f8061`, vendored mldsa-native commit
`9b0ee84f4cf399043eca59eca4e5f8531ca1d61b`. Its inspected source headers offer
`Apache-2.0 OR ISC OR MIT`. Source paths, functions, hashes and dispatch are preserved
in [bounded_mldsa_plan.md](bounded_mldsa_plan.md) and
[native/dependencies.json](../native/dependencies.json). Those sources were reference
evidence, not the new runtime dependency or a modified native build.

The implementation uses Python integer residues and the numbered FIPS NTT/inverse NTT,
with twiddles derived from 1753 and eight-bit reversal. It uses no floating-point or
Montgomery arithmetic. SHAKE128/256 are actual stdlib `hashlib` computations; on this
preserved environment they use `_hashlib`. No ordinary ML-DSA verification is called
by the bounded verifier or CredValid. There is no global matrix cache, SIMD path or
caller-selectable alternative algorithm.

This is a **Python reference with native stdlib hashing**, not an optimised native
verifier. Future performance comparisons must report this language/backend, full-prefix
buffering and optimisation level. It is not constant-time, does not guarantee erasure
of Python objects and does not provide a private-input BC-1 hash/arithmetic circuit.
Hashlib executes real hashing; per-round/gate traces and exact circuit lowering remain
Stage 3 work. The test timings below are execution evidence, not performance claims.

Implementation identity:

| File | SHA-256 |
|---|---|
| `src/pqdid/bounded_mldsa.py` | `18b5402247086ccee88d4c4f452234f672d0db15d0324164ad1c2523f531f7f1` |
| `src/pqdid/credentials.py` | `6398edf081d147eb07927ae528e2a8c2676ddab31b4f777fcfba5c64e86f406d` |
| `tests/fixtures/mldsa65_native_vectors.json` | `014804d8a554d37e0c98275872755e533a88f31a7374937abf2b7a2853d3ad88` |

## Specification-to-code mapping

| Requirement/source | Implemented operation |
|---|---|
| R-009/R-032; FIPS 204 §3.6.2, Algorithm 3, printed p. 18 | `bounded_verify_mldsa65` / `_verify_diagnostic`: exact bytes, pk=1952, σ=3309, context≤255; pure `00 \|\| len(ctx) \|\| ctx \|\| M`, formatted exactly once |
| R-032; Algorithm 8, p. 27 | `_verify_internal`: public-key/signature decode; malformed hint rejection; ExpandA; tr/mu hashing; SampleInBall; NTT arithmetic; UseHint; w1/challenge hashing; final strict norm and full challenge comparison |
| R-032; Algorithms 18/19/23/27, pp. 31/33/35 | `_unpack_poly`, `_decode_public_key`, `_decode_signature`: little-endian bit packing, 10-bit t1, signed 20-bit z, 48-byte c-tilde |
| R-032; Algorithm 21, p. 32 | `_decode_hints`: six cumulative counts nondecreasing and ≤55, strictly increasing indices within each row, zero unused slots; reject before sampling |
| Verification subset of R-033; Algorithms 14/30/32, pp. 29/37/38 | `_Budget`, `_rej_ntt_poly`, `_expand_a`: 30 independently capped invocations, 3-byte masked candidates, rejected candidates consumed, row/column seed order |
| Verification subset of R-033; Algorithm 29, p. 36 | `_sample_in_ball`: eight sign bytes, then all accepted/rejected index bytes; standard assignment and sign-bit order |
| R-032; Algorithms 41/42, pp. 43–44; ring arithmetic | `_ntt`, `_inverse_ntt`, `_matrix_vector_product`: modular integer butterflies, products and ordered sums; inverse factor 8347681 |
| R-032; Algorithms 36/40/28, pp. 40/41/35 | `_decompose`, `_use_hint`, `_encode_w1`: centred remainder, wraparound, high bits 0..15, low-nibble-first packing |
| R-032; Algorithm 8 final test | `_norm_ok`: every z coefficient has absolute value <524092; compare all 48 challenge bytes |
| R-023; V-A/B and VII-A.5, pp. 7–8/15 | `credentials.cred_valid`: expected-instance/cert/m/rid/ρ structure, same-B holder opening, single `build_mcred`, bounded signature under expected pkI and exact credential role context |

The Python reference follows Algorithm 8's displayed ordering; in particular, all hint
decoding precedes expansion and the norm check remains at the end. The ordinary backend's
early norm/per-row hint schedule is not copied. DEP-001's recorded algorithmic NTT,
challenge-input and UseHint dispositions apply. Python's ordinary modular arithmetic
does not introduce the native Montgomery interval issue or claim BC-1 checked widths.

## Public APIs and failure behaviour

```python
bounded_verify_mldsa65(public_key, message, signature, *, context) -> bool
cred_valid(expected_parameters, credential, holder_secret) -> bool
```

The first API is pure ML-DSA-65 with fixed budgets. Context is a separate external
signing context, not a presentation context. For credentials, the second API always
uses `CREDENTIAL_SIGNING_CONTEXT=b"PQ-DID/credential/v1"`, expected `pp.pkI`, and
the sole unchanged `build_mcred` implementation. The normal APIs accept no verifier,
stream, cap override, skip-cryptography flag, prehash or externally supplied mu.

Malformed inputs and ordinary cryptographic failure return `False`. Sampler exhaustion
also returns `False`. Internal `_verify_diagnostic` distinguishes `_Status.INVALID`
from `_Status.EXHAUSTED`, recording only sampler name and consumed count for exhaustion;
only `_Status.VALID` is mapped to `True`. `_Budget` raises `_SamplerExhausted` before
an over-budget read; partial polynomials never reach arithmetic or success. Unexpected
runtime/resource failures propagate as exceptions and represent non-completion, never
acceptance. The API has no native fallback or retry path.

Credential structural errors (`EncodingError`) return `False` at the complete predicate.
The existing structural codecs retain their original raising/return contracts. Full
CredValid receives a holder secret because it checks the manuscript's local opening;
this is not a proof that a remote party knows that secret. It does not establish issuer
trust, authorised release, current non-revocation, request approval, presentation
freshness or privacy-preserving proof validity. Expected pp must come from the caller's
trusted configuration; a credential does not itself choose its verification key.

All 1952-byte public-key bit strings have a defined pkDecode representation: six
polynomials with 10-bit coefficients and a 32-byte matrix seed. No extra byte-pattern
rejection rule is invented. The verifier now performs that decoding and bounded matrix
expansion; it does not establish key generation provenance, possession of a secret key,
keypair consistency, registry authorisation or setup randomness. Revocation-key/service
validation remains outside this credential predicate.

## Exact sampler accounting and buffering

Each sampler creates its own `_Budget`. RejNTTPoly permits 1026 bytes, exactly 342
three-byte candidate reads. A candidate masks the top bit of its third byte and is
accepted only below q; every rejected candidate still consumes all three bytes.
Matrix expansion executes all 6×5 invocations with seeds `rho || column || row` in
increasing row/column order. No budget is pooled across polynomials or reset on rejection.

SampleInBall permits 256 **total** bytes: the first read of eight little-endian sign
bytes leaves at most 248 single-byte index reads. For i=207..255, every j>i consumes
its byte; an accepted j follows the standard `c[i]=c[j]` then signed assignment to c[j].
Reusing an index is handled by that assignment, not by resampling to a fresh position.

`hashlib.digest(n)` returns a prefix rather than advancing a stream. `_shake_reader`
therefore materialises one prefix of exactly 1026 or 256 bytes and `_PrefixReader`
advances within it. There is no restart/reseed or digest-prefix concatenation.
The logical sampler budget is charged on each requested read, independently of buffered
bytes. Bytes beyond the cap are never buffered or exposed. Computing a whole allowed
prefix can perform more squeezing than an early-completing sampler needs; this is a
documented reference optimisation and must be visible in performance work. Underlying
Keccak rate blocks may contain unused lanes; those do not become sampler input.

The guard is `consumed + requested > limit`, before calling the reader. Completion on
byte 1026 or 256 succeeds. Needing candidate 343 or byte 257 raises exhaustion without
reading it. Exhaustion propagates from expansion/challenge through verification and
CredValid without a second attempt, partial output, higher budget or uncapped fallback.

## Fixtures and differential evidence

The new [fixed signature fixture](../tests/fixtures/mldsa65_native_vectors.json) contains
12 signatures generated independently of this verifier by the **ordinary, uncapped**
pinned native signer and checked by its native verifier. It is not a NIST validation
vector set and does not validate bounded signing. There was no filtering or retry based
on the bounded verifier. The file records the generator hash, dependency commits,
installed-library hash and earlier fixture hash. Private signing keys were never saved.
The three credential openings are explicitly public, synthetic test material.

[Generator](../tests/reference/generate_mldsa65_fixtures.py) output mode refuses to
overwrite existing fixtures. Regeneration produces new ordinary signatures/keypairs;
the checked-in bytes are the reproducible verification inputs. Original structural,
encoding and binding/Merkle vectors remain unchanged.

Nine general vectors cover empty/binary messages and contexts, message lengths
135/136/137/167/168/169, a 2048-byte message and a 255-byte context. Three further vectors
are exact Mcred messages: two distinct credentials in one instance and one in another,
with different binding/attribute/identifier/key combinations for splice tests.

All 12 verify under the bounded implementation. The native differential test compares
eight cases per fixed vector (96 comparisons): original, changed key seed, changed t1,
changed message, changed challenge, malformed hints, truncated signature and wrong
context. Every fixed case completes within the limits and agrees with the ordinary
oracle. Four fresh native key/signature cases also pass with empty, credential, binary
and maximum-length contexts; 256-byte contexts reject. An exhausted bounded operation
is permitted to reject an otherwise ordinary-valid signature; agreement is not used to
relax the caps.

Forty SHAKE comparisons across two already-installed independent implementations,
`hashlib`/`_hashlib` and CPython `_sha3`, cover empty, rate−1/rate/rate+1/multiple-block
inputs and boundary/multiple-block output lengths. The four existing fixed NIST
SHA3-384/SHAKE256 tests were rerun as relevant hash regression, not as setup repetition.
Direct liboqs SHAKE differential calls were unavailable because its SHAKE symbols are
hidden in this build; those initial test failures were replaced by the available
independent extension comparison. No native rebuild or symbol exposure was introduced.

## Deterministic boundary, arithmetic and credential tests

Artificial streams live only in [test helpers](../tests/unit/sampler_streams.py).
Tests inject readers at underscored internal boundaries with pytest monkeypatch; the
normal API always selects actual SHAKE. These streams are not cryptographic vectors.

| Executed tests | Evidence |
|---|---|
| [test_bounded_samplers.py](../tests/unit/test_bounded_samplers.py) | RejNTT completion at 768/771/1023/1026 bytes; requiring candidate 343 and all-rejected streams stop at 1026; q−1/q/masked-high-bit/order cases |
| Same sampler file | SampleInBall completion at 57/58/255/256 bytes; requiring byte 257 and all-rejected indices stop at 256; eight sign bytes counted, little-endian signs and collision assignment tested |
| Same sampler file | Reader request logs prove no over-budget read; SHAKE prefix reads cross 168-/136-byte boundaries correctly; malformed internal reader results fail explicitly |
| [test_bounded_mldsa.py](../tests/unit/test_bounded_mldsa.py) | Exhaust each of the 30 matrix positions and the challenge through the top-level API; check diagnostic category, no further calls and public False; all 30 separate budgets also succeed exactly at 1026 |
| Same verifier file | Each hint row rejects excessive/decreasing counts and duplicate/reversed indices; unused padding rejects, weight 55 and cross-row index reuse decode; z extremes and strict ±524092 norm boundary |
| Same verifier file | Independent direct polynomial evaluation checks NTT, known inverse results and independent quadratic negacyclic convolution checks products; Decompose/UseHint wrap/tie boundaries and exact w1 nibble order |
| Same verifier file | Fixed real signatures, message/key/signature/context mutations, duplicate framing/prehash substitutions, malformed types/lengths and runtime-error propagation; public API has no bypass arguments |
| [test_cred_valid.py](../tests/unit/test_cred_valid.py) | Three real signed credentials pass; synthetic/zero/altered signatures fail despite structural validity; changed certified fields with consistent openings fail original signatures; wrong secrets/issuer/instance and cross-credential splices reject |
| Same credential file | Both real sampler exhaustion paths reach False in CredValid with no retry; runtime resource failure propagates; structural/empty-ρ/repeated-metadata failures reject |

The verifier tests passed **before** CredValid was integrated: 172 cases including
150 sampler/verifier unit cases, 18 differential cases and four existing hash cases.
The later 36 CredValid cases then passed. Artificial streams never establish a genuine
signature or bounded signer, and tests of local opening do not establish knowledge proofs.

## Commands and final results

All implementation/tests use the existing `.venv`; no dependencies were installed.
The public FIPS PDF was retrieved to `/tmp` for inspection with `pdftotext -layout`;
the manuscript itself was not modified or re-extracted from excluded sections.

```bash
.venv/bin/ruff format src/pqdid/bounded_mldsa.py
.venv/bin/ruff format tests/reference/generate_mldsa65_fixtures.py tests/unit/mldsa_cases.py
.venv/bin/python tests/reference/generate_mldsa65_fixtures.py --output tests/fixtures/mldsa65_native_vectors.json
.venv/bin/ruff format tests/unit/sampler_streams.py tests/unit/test_bounded_samplers.py tests/unit/test_bounded_mldsa.py
.venv/bin/ruff format tests/integration/test_bounded_mldsa_native.py
.venv/bin/python -m pytest tests/unit/test_bounded_samplers.py tests/unit/test_bounded_mldsa.py tests/integration/test_bounded_mldsa_native.py tests/smoke/test_hashes.py -q
.venv/bin/ruff format src/pqdid/credentials.py tests/unit/test_cred_valid.py
.venv/bin/python -m pytest tests/unit/test_cred_valid.py -q
.venv/bin/python -m pytest tests/unit/test_bounded_samplers.py tests/unit/test_bounded_mldsa.py tests/unit/test_cred_valid.py tests/integration/test_bounded_mldsa_native.py tests/smoke/test_hashes.py -q
.venv/bin/python -m pytest tests/unit tests/integration tests/smoke/test_hashes.py -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

**208 focused tests passed in 0.95 s. 689 regression tests passed in 1.23 s:**
666 unit tests (all 480 earlier +186 new), 19 integration tests (the earlier one +18 new),
and four relevant hash tests. Lint passed; formatting passed. One line-length finding
in the new differential test was corrected by formatting. Expected fixtures and limits
were not changed to make the tests pass. No project-native code was added, so new native
memory/undefined-behaviour builds are not applicable; the pinned native backend remains
the previously established uncapped oracle.

Preservation and document audit: of 6784 snapshotted pre-existing protected files,
6782 remain byte-for-byte unchanged. The two intentional changes are `credentials.py`
(local predicate integration) and `configs/suite.json` (implementation evidence only).
Every other suite section, including confirmed parameters and SPEC-001/002, matches
the pre-change snapshot. The manuscript, original plan, pinned sources/installed native
library, lockfiles, earlier source/tests/vectors, setup/environment and editor files
remain unchanged. Source/fixture/generator/native-library/prior-fixture hashes match
their recorded provenance. All 52 requirement definitions match the 52 main traceability
rows; 115 local links resolve and 27 Markdown tables have consistent columns across
the eight updated documents. The audit used an ephemeral standard-library script and
made no environment changes.

## Remaining obligations and next task

DEP-002 is complete for the bounded verification path and local CredValid integration.
It stays open for bounded key generation (RejBoundedPoly ≤512 plus matrix expansion),
bounded signing (≤1024 attempts plus invoked sampler limits), all-role service integration,
key setup/import consistency and bounded verification before every signature release.
Original-B logging and atomic release/state behaviour are still lifecycle work.
DEP-001 signing-tail/Δtail validation remains unchanged; cap tests do not validate its
conditional loss estimate. SPEC-001/002 author wording updates remain outstanding.

**The next task can be complete executable local enrolment and authentication reference
relations.** It must add typed statements/witness parsing, expected public-instance/state
checks and required bounded state/control signature checks, composing this same-B/m/rid
CredValid with the existing zero-leaf path and disclosure/policy checks. Treat trusted
configuration and authenticated service/session facts as explicit inputs; do not invent
service-success placeholders. Bounded signing is separate from evaluating such fixtures.

Complete relations, current-state/freshness/atomic services, circuit synthesis and
privacy-preserving proofs remain unimplemented. This work claims neither formal
verification, FIPS validation, BC-1 circuit equivalence, complete PQ-DAA correctness nor
an overall security-strength result.
