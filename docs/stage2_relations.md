# Stage 2 executable reference relations

**Complete local enrolment and authentication reference relations are implemented
and tested. Stage 2 remains in progress.** The contract below was recorded before
coding; the implementation/evidence sections record the completed work package.

## Contract recorded before implementation — 17 September 2026

Authority is only manuscript Sections II–VIII, SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The definitions below were checked against V-B/C, p. 8, VII opening/A.1, p. 14,
VII-A.5/.6/.7, pp. 15–17, and confirmed specification R-005–R-009/R-020–R-029.
SPEC-001/002 and the frozen suite remain unchanged.

Enrolment has public `Xen=(pp,µ,mapp,rid,B,nI,rse)` and only the private witness
`xH` (32 bytes, 256 bits). Its private predicate is `BindOpen(pp,B,xH,mapp,ε)`:
canonical domains, `Y=SHA3-384(enc_holder(suite,E(µ),xH))` and equality of B's
complete canonical attributes to mapp. Holder secret and controller keys are distinct.
Public domains/state validation and comparison to the issuer's separately approved
vector belong to surrounding checks; controller authorisation, registration, pending
issuer nonce, approval, allocation, proof verification and fresh pre-certification reads
remain surrounding algorithms. This package will provide the stateless domain/state/
approved-vector checks separately, without implementing those services or a proof.

Authentication has public `X=(pp,µ,ctx,rse,D,mD)` and private
`ξ=xH || Esch(m) || [rid]4 || σ || s0 || ... || s19`. Reconstruct B from this xH
and this entire canonical m, and reconstruct `cert=(B,σ)`, `ρ=ε`, µ from X. No B,
second attribute vector, second identifier, auxiliary opening or controller key is
accepted as an additional witness field. The full local relation is exactly V-B:

```text
PubOK(X) AND CredValid(pp,µ,cert,xH,m,rid,ε)
         AND PathRoot(rid,0,we)=Ae
         AND projD(m)=mD AND Ppub(mD,ctx).
```

`CredValid` already checks the opening and single exact Mcred with bounded verification.
Public `PubOK` checks canonical domains, the externally expected pp and repeated suite/
reference/schema/namespace, supported policy and matching D, disclosure encoding,
`ctx.refe=(rse.ns,rse.e,rse.root)`, and bounded state-signature verification under pkR.
`Ppub` evaluates only the disclosed values. These public checks remain separate from
the private circuit/reference predicate, but both are mandatory in the full local
authentication evaluator. State signatures use `PQ-DID/state/v1` over
`enc_state(suite,E(µ),[e]8,Ae)`; τ is not part of that signed body.

| Encoding | Exact fields/order and size |
|---|---|
| `enrol-statement` | `E(pp), E(µ), Esch(mapp), [rid]4, E(B), nI, E(rse)`; normal tagged LP framing |
| `auth-statement` | `E(pp), E(µ), E(ctx), E(rse), [mask(D)]2, mD`; normal tagged LP framing |
| Enrolment witness | Raw xH: 32 bytes / 256 bits, no tuple or length prefix |
| Authentication witness | Raw xH 32 + attributes 1024 + identifier 4 + signature 3309 + path 20×48 = 5329 bytes / 42632 bits |
| Nested public values | `context`, `rstate`, `rref` use R-005's displayed field order; epoch/expiry uint64, nonce 32, namespace 32, root 48, signature 3309 bytes |

Witness integer bytes are unsigned big-endian; path order is leaf to root per SPEC-001.
Later circuit input bits enter most-significant-bit first in serialised byte order
(VII-A.6 BC-1/R-034). FIPS internal conversions remain inside the unchanged verifier.

All public fields enter canonical E(X) for future `view`/`challenge` transcripts
(VII-A.6/R-039/R-040). A well-formed audience, session, nonce or expiry mutation need
not falsify the relation; it must change E(X). Enrolment rid/nonce/state similarly
enter E(Xen) without becoming a hidden constraint on xH. Actual transcript binding
will be implemented by the proof system, not by these encoders.

Audience/session registration, request authenticity, approval, trusted-time `now<texp`,
current-state reads and atomic consumption/replay rejection remain lifecycle checks
(IV-A, p. 5; VII-A.7, pp. 16–17; R-016/R-017/R-028). An old correctly signed state
and matching old path can satisfy the local relation. No clock, nonce store, issuer
authorisation table or remote verifier API will be added to the reference evaluator.

Codecs/validators will raise `EncodingError` for malformed representations. Boolean
reference evaluators will return False for domain/relation failure and bounded exhaustion;
unexpected runtime/resource failures will propagate without acceptance. Immutable
records and explicit expected-parameter arguments are engineering interface choices.

## Implementation and public interfaces

This is Python reference composition of the existing canonical primitives and bounded
ML-DSA verifier. No existing production function or native backend was modified. The
native library is used only for independent fixture generation and existing integration
tests. The composition neither substitutes an ordinary verifier nor weakens either cap.

| Module | Interface and responsibility |
|---|---|
| [statements.py](../src/pqdid/statements.py) | Frozen `StateReference`, `RevocationState`, `Context`, `EnrolmentStatement`, `AuthenticationStatement`; typed validators and encode/decode functions; single exact `build_state_message` |
| [witnesses.py](../src/pqdid/witnesses.py) | Frozen private `EnrolmentWitness`/`AuthenticationWitness` with suppressed repr; exact raw encode/decode, schema-dependent validation, derived width/bit constants and `witness_bits` MSB-first conversion |
| [public_checks.py](../src/pqdid/public_checks.py) | `state_auth`, `pub_ok`, `public_policy_ok`, `enrol_public_ok`; no private witness argument; bounded state signatures and disclosed-only policy |
| [relations.py](../src/pqdid/relations.py) | `enrol`, `auth_private`, `auth`; local witness-consuming reference predicates only |

Every statement codec and evaluator takes externally expected pp. Records themselves
are immutable data, not validity tokens: validation occurs at every codec/evaluator
boundary, including records made with `dataclasses.replace`. Structured encoders reject
inconsistent fields rather than normalising them. Decoders reject invalid nested tags,
counts, widths, padding, trailing bytes, wrong metadata/keys/namespace, policy/mask and
state-reference disagreement. `encode_auth_statement` and `encode_enrol_statement` use
only the prescribed tagged fields and enforce the E(X) length bound. State/context
codecs do not claim signature authentication merely because bytes can be parsed.

`enrol(expected_parameters, statement, witness)` evaluates the complete specified
enrolment private relation. Its xH is never a controller key. `enrol_public_ok(pp,Xen,
approved_attributes)` separately validates public domains, exact equality with the
issuer-supplied approved canonical vector and bounded StateAuth. It is only the stateless
subset of the surrounding enrolment algorithm; it does not represent approval or a
pending nonce by an accepting placeholder. An invalid state signature can leave BindOpen
true while this public check rejects, exactly as tested.

`auth_private(pp,X,witness)` is explicitly the private-circuit target only. It validates
all five witness fields, computes B once from this xH/m, constructs one `Credential`
with this σ/rid/µ and empty ρ, calls the unchanged `cred_valid` (including its holder
opening and sole `build_mcred`), checks this rid's zero-leaf path, then compares this m's
projection with mD. There is no separately supplied B/certificate or alternative m/rid.
The top-level `auth(pp,X,witness)` always evaluates **PubOK AND auth_private AND Ppub**.
There is no optional flag, caller-supplied verifier or mode that can skip a conjunct.

Malformed/domain failures become False at Boolean evaluators; codecs raise `EncodingError`.
Credential or state signature failure, including actual sampler exhaustion, rejects.
Unexpected resource/runtime exceptions propagate without acceptance. The internal bounded
verifier diagnostics remain available at underscored test boundaries; the relation exposes
only its ordinary Boolean result. No private values are logged. Python execution is not
constant-time and does not guarantee secure erasure; it is not BC-1 execution.

Implementation identity is recorded in `configs/suite.json` under implementation evidence,
separate from confirmed parameters. The record includes all fourteen transitive project
modules used by the relation, while emitter identity remains unset.

| File | SHA-256 |
|---|---|
| `src/pqdid/relations.py` | `138659b145b4453955ab0a70ce684c7f6641e93086024f0cff47bddb80c0bd4d` |
| `src/pqdid/statements.py` | `f7c055eda59f070f18dc1add2202296205529ea7785d3433f466314bcaeae659` |
| `src/pqdid/witnesses.py` | `317d5fa1cd2c33d450864d73d7e3c78baa9fb4415bf44ba263a2c879f96154b0` |
| `src/pqdid/public_checks.py` | `11089658718831ba6b1475d5c1fe3fdf657a52127ff928f323f0107cfdc87430` |
| `tests/fixtures/relations_vectors.json` | `e2e5981ffa88eb5efef5ec3c6c6af424c3a5f35aa020c8cb4abf2b5f6c2661f2` |

## Fixture provenance and independent outcomes

[relations_vectors.json](../tests/fixtures/relations_vectors.json) is new synthetic test
data. [Its generator](../tests/reference/generate_relation_fixtures.py) reuses the existing
independent `record`/`SparseReferenceTree` builder, with manual field framing and field
slicing. It imports no production statement, witness, relation or bounded verifier.
The global sparse-tree construction determines roots/siblings independently of PathRoot;
the expected revocation result follows set membership. Selected canonical fields and
explicit satisfied public clauses determine disclosure/policy expectations independently.

The fixture uses two synthetic instance configurations, three credentials (alpha-42,
alpha-43 and beta-42), and empty/old/updated depth-20 trees in each instance. Old revocations
are `{1,7,9,1024,524291,1048574}`; the update adds 42. Twelve authentication cases cover
empty, scenario-A, scenario-B and full disclosure, distinct audience/session contexts,
ten true outcomes and two revoked false outcomes. Three enrolment cases have true outcomes.

The unchanged pinned **ordinary native signer** generates fresh issuer/manager keys,
three credential signatures, six correctly contextualised state signatures and six
deliberately wrong-role state signatures. Each generated signature is checked by the
ordinary native verifier under the context actually used. No fixture was selected,
retried or filtered using the bounded verifier or relation. This does not validate
bounded key generation/signing. Signing secrets stay only in memory; stored xH values
are explicitly public synthetic test openings. The new configurations are isolated
fixtures, not key rotation within a registered deployment or replacements for old vectors.

The fixture records generator/tree-builder/prior-fixture/library digests and exact pinned
dependency records. Tests rebuild sparse roots and paths and check provenance. Exclusive
output creation prevents accidental regeneration over a frozen file. Before freezing
the final fixture, an initial formatting-only generator correction was made and its
candidate output moved to `/tmp`; the final file was generated once with the final
source digest. No existing vector or expected outcome was changed to satisfy a test.

## Acceptance conditions and executed tests

| Condition/layer | Code | Evidence |
|---|---|---|
| Canonical public and private domains, fixed fields and sizes | `statements` validators/codecs; `witnesses` codecs | [test_relation_encodings.py](../tests/unit/test_relation_encodings.py): exact independent statement/witness bytes; all 5329 auth truncations, extra bytes, field/tail padding, Boolean domain, identifier high bits, wrong nested fields, nonce/epoch/expiry/mask/policy/metadata cases |
| Witness ordering/width and future input bit order | `AUTH_FIELD_WIDTHS`, raw codecs, `witness_bits` | Derived manifest widths, exact offsets 0/32/1056/1060/4369/5329, 256/42632 bits, MSB-first round trip; no extra witness fields |
| Enrolment BindOpen | `relations.enrol` | [test_relations.py](../tests/unit/test_relations.py): three signed-fixture openings, incorrect secret/Y/mapp; coherent alternate mapp opens but fails separate original issuer-approval comparison |
| Public state/instance conjunction | `pub_ok`, `state_auth` | Other configured key/instance/metadata failures; state signature, role, epoch and root mutations; structural success shown separately from cryptographic failure |
| Same-credential authenticity/opening | `auth_private` → unchanged `cred_valid` | Secret/attribute/rid/signature splices are given otherwise valid paths/projections/public checks; signature rejects; altered/zero signatures and other issuer signatures reject |
| Same certified rid's zero leaf | `auth_private` → `verify_non_revocation_path` | Non-uniform substituted path explicitly shown invalid for the target; credential and public checks still pass. Equal paths in empty subtrees correctly remain valid |
| Canonical certified disclosure projection | `auth_private` → `project_attributes` | All 64 masks for the fixture schema; a disclosed value still satisfying the public range fails projection against the genuine credential |
| Public disclosed policy | `public_policy_ok` → existing `evaluate_policy` | Unsatisfied supported policy leaves private predicate and PubOK true but full auth rejects; hidden-field/unsupported/non-canonical policies reject structurally |
| Actual bounded failure | Existing sampler logic through `state_auth` or `cred_valid` | Targeted real-limit streams for RejNTTPoly and SampleInBall independently exhaust state or credential verification; credential tests first establish PubOK still passes; exactly one exhausted stream per call, no over-budget read/retry |
| Runtime/domain error boundary | Boolean wrappers catch only `EncodingError` | Invalid object/private-field inputs reject; synthetic `MemoryError` propagates and never accepts |

The negative composition tests assert the unaffected conjuncts where necessary: a false
disclosure still satisfies the public policy; a path swap retains credential validity;
spliced certified fields retain canonical disclosures and a valid path for their candidate
identifier; a manager-key substitution preserves the private predicate. This avoids
mistaking failure in an unrelated preliminary check for evidence of composition.

## Context, freshness and lifecycle boundary evidence

After revoking 42, alpha-43 uses a changed correct path against the new signed root,
retaining its original secret, attributes, identifier and credential signature. Alpha-42's
updated path reconstructs that root only with leaf status 1; the required zero leaf fails.
The original alpha-42 credential/path still satisfies the old matching signed statement.
No local relation can infer which root is the latest authenticated snapshot.

Audience/session/nonce/expiry mutations change canonical E(X) and can still accept
locally, including expiry 0. The separate existing expiry helper rejects at `now=texp`;
the relation has no clock. A different satisfied policy also changes E(X), whereas an
unsatisfied policy fails the explicit public conjunct. Repeated reference calls can
accept the same context because no challenge is consumed. Enrolment nonce/rid/state
mutations change E(Xen) without changing a valid opening; allocation and nonce freshness
are surrounding requirements. Wrong context-state references reject under PubOK.

These encodings prepare the exact future proof transcript inputs. There is no proof
generation/checking, remote presentation service or evidence of actual Fiat–Shamir binding.
The local witness serialisation must never be sent as a presentation. Request/controller
authentication, holder approval, trust, current-state reads and atomic replay protection
remain necessary lifecycle work; no hidden-attribute policy or hidden DID check was added.

## Validation commands and results

Executed using the existing `.venv`, without installation, native rebuilding or setup reruns:

```bash
.venv/bin/ruff format src/pqdid/statements.py src/pqdid/witnesses.py src/pqdid/public_checks.py src/pqdid/relations.py
.venv/bin/ruff format tests/reference/generate_relation_fixtures.py tests/unit/relation_cases.py
.venv/bin/ruff check tests/reference/generate_relation_fixtures.py
.venv/bin/python tests/reference/generate_relation_fixtures.py --output tests/fixtures/relations_vectors.json
.venv/bin/ruff format tests/unit/test_relation_encodings.py tests/unit/test_relations.py
.venv/bin/python -m pytest tests/unit/test_relation_encodings.py tests/unit/test_relations.py -q
.venv/bin/python -m pytest tests/unit tests/integration tests/smoke/test_hashes.py -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Final results: **201 focused tests passed in 2.31 s; 890 regression tests passed in
3.48 s** (867 unit, 19 integration and four fixed hash cases). Ruff lint passed and
formatting passed (65 files). Test timings are execution evidence, not performance
claims. The first codec test incorrectly rejected extensions of valid variable-length
audience/session fields; corrected it to require acceptance with changed canonical bytes.
Two unused test imports and generator formatting were corrected. Neither a specification
constant nor production acceptance behaviour was changed to accommodate those test fixes.

The preservation audit checked 6793 pre-existing protected files. All 6792 outside
`configs/suite.json` are byte-for-byte unchanged; only implementation evidence changed
in that manifest. Every other manifest section, including confirmed parameters and
SPEC-001/002, matches the pre-change snapshot. The manuscript, original plan, all
earlier source/tests/vectors, dependency sources/installed native files, lockfiles,
environment record and editor/setup files are preserved. Fourteen implementation
module hashes and all new fixture provenance hashes match their records. The 52
specification requirements still match the 52 main traceability rows; 128 local links
and 27 Markdown tables across seven updated documents passed the document audit.

## Remaining Stage 2 work and Stage 3 entry

The complete executable enrolment/private and authentication/full relation deliverable,
typed statements/witnesses, bounded state authentication and composition tests are complete.
Stage 2 remains in progress for bounded key generation (including RejBoundedPoly ≤512),
signing (≤1024 attempts and all invoked caps), key setup/import checks, and remaining
DEP-002 all-role pre-release/release integration. DEP-001's conditional signing-tail/Δtail
validation remains separate. Production authenticated witness-update processing and
the remaining allocation/revocation reference procedures are still outstanding; the
fixture tree builder is not production UpdateWit. Full issuance, controller/request/
current-state services and atomic acceptance remain later lifecycle integration.

Stage 3 can now begin progressive BC-1 feasibility work against these frozen reference
inputs/outcomes: checked arithmetic/selectors and canonical parsing; SHA3/SHAKE gadgets;
the enrolment predicate; bounded ML-DSA and the Merkle path; then the complete authentication
private predicate with mandatory public checks. Validate deterministic CGen from kind/X,
gate/wire order, active-path rejection and reference/circuit agreement before proof work.
Measure component/total AND gates, generation/liveness/memory/storage and projected raw
proof cost with the unchanged 480-repetition profile. No seeded tapes, smaller profile
or alternative lowering is selected here. Emitter/gate traces remain unimplemented.

This work does not establish zero knowledge, remote knowledge soundness, unlinkability,
BC-1 circuit equivalence, complete PQ-DAA execution, formal validation or overall security.
The work package stops at executable reference relations and their evidence.
