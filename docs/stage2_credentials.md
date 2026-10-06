# Stage 2 parameter and credential structures

This is the earlier structural work-package record. Its then-pending bounded verifier
and full local CredValid have since been implemented and tested; see the current
[bounded ML-DSA/CredValid evidence](stage2_bounded_mldsa.md). The scope, counts and
remaining-work discussion below describe the structural package at its completion.

At completion of the structural package on 17 September 2026, typed immutable records,
structural validation and exact Mcred were implemented. Full CredValid and bounded
ML-DSA were still pending then; their subsequent completion is recorded above. Complete
relations, lifecycle services and privacy-preserving proofs remain unimplemented.
**Stage 2 is in progress.**

## Source and scope

The unchanged selected manuscript SHA-256 is
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
Only Sections II–VIII are authoritative. SPEC-001's raw sibling path and SPEC-002's
strict unsigned POSIX expiry remain unchanged; neither adds fields to the credential.

| Implemented operation | Exact manuscript location | Requirements (partial where noted) |
|---|---|---|
| Six-field pp, two-field µ; schema/issuer/key/namespace agreement | IV-A, p. 5; VII-A.1 Setup, pp/refI/µ equations and repeated-instance rule, p. 14 | R-001/R-004 structural subset |
| Tagged encodings, nesting, widths and malformed-input rejection | VII opening enc/LP/I2OSP equations, p. 14 | R-005, reusing R-006 schema/attributes |
| ML-DSA-65 key/signature byte representations and external credential context | VII-A.1, p. 14, and A.5 issuance, p. 15 | Representation/context subset of R-009 |
| Binding, cert, vc, empty ρ and same attributes; exact Mcred | V-A/B, pp. 7–8; VII-A.5 displayed Y/B/Mcred and cert/vc definitions, p. 15 | Structural/message portions of R-021/R-023; component for R-024 |
| Credential independence from presentation context and updated witness | IV-C, pp. 6–7; V-D, p. 9; VII-A.5/.6/.8, pp. 15–17 | Representation boundary for R-004/R-026/R-031 |
| Bounded backend source inspection | VII-A.6 bounded computation, pp. 15–16; VIII-A, pp. 17–18 | R-032/R-033 integration plan only |

## Implemented records and APIs

[`parameters.py`](../src/pqdid/parameters.py) defines frozen `PublicParameters`
with exactly `(suite, issuer_reference, namespace, issuer_public_key,
revocation_public_key, schema)`, corresponding to pp. Frozen `InstanceMetadata`
contains exactly `(issuer_reference, namespace)`, corresponding to µ. Derived
`.domain` and `.metadata` properties add no encoded fields. `HashDomain` remains the
existing representation for hashes/binding/tree operations.

`validate_parameters_structure` checks the sole supported suite, canonical refI and
schema, exact repeated schema agreement, issuer/key identifiers of 1..256 bytes,
32-byte namespace and two immutable 1952-byte public-key representations. The suite
fixes λ=128, ML-DSA-65, depth 20 and BC-1; there are no new negotiable wire fields.
Optional `expected=` checks the **entire** supplied pp, including both public keys.
`decode_parameters(..., expected=...)` performs this check after canonical parsing.
Without `expected`, parsing establishes structure only and never pins a trusted instance.
`encode_parameters`, `encode_instance_metadata` and `decode_instance_metadata`
use the existing codec; metadata APIs require caller-supplied expected pp.

The local aggregate `params=(pp,cfgD,trust)` is not given an invented wire format.
Registry configuration, trust authorisation and persistent registration remain later
work; a single object cannot establish that a refI was never rebound in storage.

[`credentials.py`](../src/pqdid/credentials.py) defines frozen `Certificate(binding,
signature)` and `Credential(certificate, attributes, revocation_identifier, auxiliary,
metadata)` with exactly the manuscript fields. They reuse `BindingRepresentation`
and the canonical 1024-byte attribute block. Private records suppress field reprs.

`validate_certificate_structure` checks the binding's full schema encoding and
3309-byte signature representation. `validate_credential_structure` additionally
requires µ to match expected pp, canonical attributes equal to **all** attributes in B,
integer `0 ≤ rid < 2^20` (excluding Boolean values) and immutable empty bytes for ρ.
Both codecs (`encode_/decode_certificate`, `encode_/decode_credential`) enforce these
checks. Constructors enforce local type/size/equality invariants; checks requiring an
expected schema/instance are explicit in the validators and codecs.

Parsing uses canonical framing and rejects wrong tags/counts/lengths/trailing data.
Structural validation raises `EncodingError` on malformed or mismatched records and
returns `None` on success. Cryptographic verification is a distinct, absent layer:
there is no accepting verifier stub or fallback. Errors contain no private inputs.

## One exact certified-message constructor

`build_mcred(expected_parameters, metadata, binding, revocation_identifier)` is the
sole production constructor, usable before a signature exists and later by verification:

```text
E(µ)    = enc_meta(refI, ns)
E(B)    = enc_binding(Y, Esch(m))
Mcred   = enc_cred(suite, E(µ), E(B), I2OSP(rid,4))
E(cert) = enc_certificate(E(B), σ)
E(vc)   = enc_credential(E(cert), Esch(m), I2OSP(rid,4), ε, E(µ))
```

Every `enc` uses the existing four-byte length prefixes/count and displayed order;
the nested encodings are inserted once. There is no digest, prehash, extra layer or
context field. Pass `CREDENTIAL_SIGNING_CONTEXT=b"PQ-DID/credential/v1"` separately
to the external-context ML-DSA API. The message tag remains `cred`.

The constructor validates metadata/pp agreement, B's canonical attributes and rid.
When processing a stored credential, first validate its full structure; then pass
that same metadata, certificate binding and identifier. Future full CredValid must
also check its holder opening and signature. No caller may substitute a different
binding or identifier after opening/decoding.

Changing suite (unsupported values reject), issuer/key reference, schema inside refI,
namespace, Y, canonical attributes or rid changes the certified bytes. Neither σ,
presentation context, epoch/root/path nor ρ is added to the message; ρ must be empty.
The pp public keys are not separate Mcred fields: changing a key must fail expected-pp
agreement and later signature/trust checks, rather than silently changing the formula.
The credential itself contains no pp key copies that a structural checker could compare.
Metadata alone cannot prove which key produced an opaque signature, or that Y opens
under that instance. Those are cryptographic checks.

## Tests and independent fixtures

[`credentials_vectors.json`](../tests/fixtures/credentials_vectors.json) contains
**synthetic structural fixtures, not authentic credentials**, including signature-shaped
bytes that have not passed FIPS signature decoding or verification. Public keys are
deterministic byte patterns, not keys claimed to have been generated by ML-DSA.
Fixture SHA-256:
`29fafe047dcbe0c12567b35f01d2e7c094b158ea0c7fc8e6e98d05668e2852a3`.

[`credentials_reference.py`](../tests/unit/credentials_reference.py) independently
assembles the new expected bytes using `struct`, literal field order and earlier fixed
binding/metadata vectors, with **no pqdid imports**. Its output mode refuses to overwrite
an existing file. Tests compare production outputs against the frozen file and separately
check provenance/reproduction. Original encoding and binding/Merkle vectors are unchanged.

| Fixture | Exact bytes |
|---|---|
| E(pp) | 4610 |
| E(µ) | 386 |
| E(cert) | 4431 |
| E(vc) | 5883 |
| Mcred | 1526 |

These lengths describe this labelled fixture, not universal credential sizes or
performance benchmarks. Seven independently assembled Mcred variants cover rid, Y,
attributes, issuer, key identifier, namespace and schema changes.

[`test_credentials.py`](../tests/unit/test_credentials.py) contains **112 passing cases**:
fixed bytes/round trips, wrong framing/nested fields, truncation/hostile lengths/padding,
unsupported suites, repeated schema/instance/key agreement, identifier boundaries,
mutable/wrong-sized key/signature inputs, empty ρ, attribute splices, immutable/private
record behaviour and exact message changes. Two different valid supplied-root paths
for unrevoked rid 43 in the earlier old/updated trees leave its credential/Mcred unchanged;
external presentation inputs are stored separately. This is reuse evidence, not production
witness updating or freshness/authentication evidence.

[`test_credentials_uncapped.py`](../tests/integration/test_credentials_uncapped.py)
is a separate **ordinary, uncapped library integration test**. An ephemeral issuer key
signs `build_mcred` with the correct external context; after credential round-trip the
same constructor yields the verified bytes. Changed message/rid/signature, other/empty/
abbreviated context and context concatenation reject. Its synthetic revocation key is
unused. This test establishes message/API interoperability only; it does not establish
complete CredValid, authorised issuance, bounded verification or cap-exhaustion behaviour.
Secrets remain in memory. Missing native setup fails explicitly through the existing
guarded loader; no installation or implicit fallback is attempted.

Commands executed:

```bash
.venv/bin/python tests/unit/credentials_reference.py --output tests/fixtures/credentials_vectors.json
.venv/bin/ruff format src/pqdid/parameters.py src/pqdid/credentials.py tests/unit/credentials_reference.py tests/unit/test_credentials.py
.venv/bin/ruff format tests/unit/test_credentials.py tests/integration/test_credentials_uncapped.py
.venv/bin/python -m pytest tests/unit/test_credentials.py tests/integration/test_credentials_uncapped.py -q
.venv/bin/python -m pytest tests/unit -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Results: **113 focused cases passed** (112 structural + 1 uncapped integration) in
0.18 s on the final focused run; **480 unit tests passed** in 0.30 s, including all
368 earlier cases. Lint passed; final formatting passed (47 files). Times are test-run
evidence only. Initial new-test import and padding-fixture mistakes were corrected;
no expected vector or production algorithm
was changed to make them pass. No environment reinstallation, native rebuild or completed
setup verification was repeated; existing smoke tests/editor selection remain unchanged.

A preservation audit confirmed all 6773 snapshotted pre-existing protected files are
unchanged, including dependency source/install files, prior code/tests/vectors, suite
manifest, manuscript, plan, pins, environment evidence and editor configuration. The
52 specification requirements still match the 52 main traceability rows; all 88 local
links checked in the updated documents resolve. Fixture provenance/digests also match.

## Remaining work at the structural package boundary

Length checking is not complete key validation. Pending work includes bounded public-key
matrix expansion, FIPS signature/hint decoding, strict norms, all hash/arithmetic/challenge
checks, key setup/import consistency and trusted instance registration. Existing local
holder-opening checks must be composed over the same credential in full CredValid.
Opaque signature-shaped bytes may pass every structural check here.

[`bounded_mldsa_plan.md`](bounded_mldsa_plan.md) records actual pinned source functions,
demonstrated native checks, missing caps, exact byte/attempt boundaries, failure propagation
and planned tests. Next implement a separately versioned bounded verifier with per-invocation
RejNTTPoly ≤1026 and SampleInBall ≤256, including all required FIPS computation and explicit
failures. Validate it before composing full CredValid. Keygen RejBoundedPoly ≤512,
signing ≤1024 attempts and all-role pre-release bounded validation remain separate work.

No new specification conflict was found. SPEC-001/002 remain agreed with author wording
updates outstanding. DEP-002 remains implementation work; DEP-001's signing-tail/Δtail
validation and Stage 3 circuit/proof feasibility remain unresolved in their existing
categories. No private-input check has been moved to a presentation service.
