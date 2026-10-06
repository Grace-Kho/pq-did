# Project status — Stage 1 complete; Stages 2–3 in progress

Updated 19 September 2026. **Stage 1 is complete.** SPEC-001 and SPEC-002 were agreed
by the user, checked against the authoritative manuscript and recorded consistently.
**Stage 2 is partially complete:** canonical codec, schema/attributes/disclosure,
public equality/range policies, deterministic expiry, holder-binding consistency,
depth-20 Merkle primitives, typed parameter/certificate/credential structures, exact
Mcred, the separate bounded Python ML-DSA-65 verifier, complete local CredValid and
executable enrolment/authentication reference relations are implemented and tested.
Typed statements/witnesses, bounded public StateAuth and disclosed-policy composition
are complete. [S2-VERIFY-STATE-1](stage2_verifier_state.md) adds a tested reference
verifier lifecycle: signed request/current-state checks, stored expected context,
strict expiry and atomic at-most-once consumption, with a public-only proof adapter
that fails closed by default. **58 focused and 29 scoped regression tests pass.**
[S2-UPDATE-WIT-1](stage2_witness_updates.md) now implements bounded holder-local
reference witness updates: exact signed public chains, zero-to-one transitions,
immutable witness/state results and explicit authenticated revocation/failure.
**70 focused and 25 scoped regressions pass**, including all 20 divergence levels
and local authentication/verifier-state composition. Each call admits at most
16 records / 178,592 update bytes and makes no freshness claim.
[S2-REVOKE-STATE-1](stage2_revocation_state.md) adds the bounded manager reference:
issuer-authorised zero-to-one transitions, bounded validation of generated
signatures, atomic tree/state/nonce/log commit, ordered current reads and public
history pages compatible with the holder limit. **73 focused and 25 scoped
regressions pass.** Imported allocation/nonce state is trusted; signing defaults
to unsupported. The finite store retains all committed records and stops at capacity.
The final preservation audit completed content checks but reached the **256 MiB
cgroup ceiling**; the guard failed and validation stopped without retry or a limit
increase. A clean final-audit resource result remains unresolved in that historical package.
Persistent/distributed state and production lifecycle services, bounded key
generation/signing, durable issuance/release integration and active-profile
proofs remain unimplemented. [S2-REVOKE-AUDIT-1](stage2_revocation_audit.md) corrects audit cache retention
and manifest parsing under the unchanged ceiling. **44 fixture tests and final
lint/format pass; the single complete preservation audit passes** at **20.8125 MiB
cgroup peak / 1.053191021 s**, with no resource event. All 8,759 original entries
and 30 supplementary historical entries are accounted for, with exact permitted
changes and no missing or unauthorised changes. Report generation and the outer
guard both completed. The prior ceiling failure remains preserved; this separate
follow-up audit obligation is resolved. Reuse this audit for the next separately
scoped reference-lifecycle package; no further implementation or proving starts here.

[S2-ISSUE-ENROL-1](stage2_issuance_enrolment.md) adds the issuer/enrolment and holder
acceptance reference: manager-owned permanent ID reservation, exact approved Xen,
controller authorisation, public-only fail-closed proof adapter, current DID/state
rechecks, bounded pre-release credential verification and atomic certification/nonce
commit. Holder-local acceptance checks its intended opening/attributes/instance and
stores credential with witness/state consistently. **64 focused + 30 scoped regressions
pass**, including presentation/revocation/witness-update reference composition.
Initial negative-fixture construction failure is retained; corrected tests pass.
Final lint/format and the complete preservation audit pass: **22.1367 MiB cgroup
peak / 2.140307967 s**, with no resource event. All 8,827 historical paths are
accounted for, with only the exact manager extension and permitted documentation
changes. Original baselines and earlier failure evidence are retained. Real signing/proof
backends, DID service validation, persistence/recovery and security review remain open.
No new proofs/zkVM executions; proving stays paused at **two used / one unused**.

[S2-DID-STATE-1](stage2_did_state.md) adds bounded signed DID registration,
rotation, terminal deactivation, current/historical full-chain resolution and
in-process pending-publication recovery. Issuance uses the current validated
controller; two independent verifier instances preserve expected parameters and
resolve only explicitly disclosed historical DID/version when configured. Hidden
DID presentation makes no registry lookup. **74 focused + 14 scoped regressions
pass** under the unchanged 256 MiB guard. All pre-existing source files remain
unchanged. Final lint/format and the single complete preservation audit pass:
**21.8711 MiB cgroup peak / 2.050973451 s**, no resource events, all **8,872 historical
paths** and the 494-entry inventory accounted for. Original baselines/evidence remain intact.
Bounded key generation/signing, durable/distributed recovery, service authentication,
DID Core interoperability and the existing proof/security obligations remain open.
The recommended S2-LIFECYCLE-REVIEW-1 is completed by the subsequent review below.
No proofs/zkVM executions; CPU proving stays paused at **two used / one unused**.

[S2-LIFECYCLE-REVIEW-1](stage2_lifecycle_review.md) completes the cross-service
invariant/failure review and durable-state requirements. **28 new focused + 50 selected
regression cases pass**. Two focused cases are explicitly unsafe-restart negative
controls: stale manager allocation state can reuse an ID, and a stale verifier store
can reaccept a consumed challenge. These demonstrate the existing trusted-checkpoint/
shared-store deployment gap; they are not safe-recovery evidence. Supported live-state
transitions, lost-response handling and privacy boundaries are consistent; **no
functional source change** was needed. Proceed only to bounded recovery-admission
reference work, not restartable/replicated deployment. Requirements cover complete
role checkpoints, atomic persistence, retained nonces/history, private-role separation
and an independently trusted rollback/fencing authority that remains unselected.
Final lint/format and the complete preservation audit pass: **21.1094 MiB cgroup
peak / 2.049593098 s**, no resource events, **8,903 historical paths** and **525
inventory entries** accounted for. Original baselines/failure evidence are retained. Recommend
S2-RECOVERY-ADMISSION-1 was the next recommendation; its completed package is below.
Durable services, interoperability,
bounded signing and private-proof/security obligations remain separately open.
No proof/zkVM execution; ledger **two used / one unused**, CPU proving paused.

[S2-RECOVERY-ADMISSION-1](stage2_recovery_admission.md) implements bounded typed
checkpoints and recovered-service gates for manager, issuer, verifier, DID registry,
resolver/controller and holder. **59 new focused/scoped cases + 28 unchanged lifecycle
regressions pass**, including both preserved unsafe-restart controls. Independent
complete-role evidence and an exclusive final activation lease are mandatory; the
default fails closed. Stale allocation and lost-consumption images cannot activate
through recovered interfaces when evidence disagrees. Missing/inconsistent data,
expired challenges and authority changes cannot create partial admission. In-flight
PREPARING/CLAIMED issuer sessions remain rejected. No storage engine, production
rollback authority, distributed fencing or crash-safety claim is supplied.
Deployment recovery remains blocked; Stages 2–3 stay open. Next recommendation:
**S2-RECOVERY-AUTHORITY-DESIGN-1**, a bounded concrete authority/fencing design review.
No new proofs/zkVM executions; ledger **two used / one unused**, CPU proving paused.
Final lint/format and the single complete preservation audit pass: **20.7539 MiB
cgroup peak / 2.072833665 s**, zero resource events, **8,934 historical paths** and
**566 inventory entries** accounted for. [Final result](data/s2_recovery_admission_1/result.json)
retains exact original baselines and historical failures; no pre-existing source/test
files changed. The fixture-based admission result does not close deployment recovery.

[S2-RECOVERY-AUTHORITY-DESIGN-1](stage2_recovery_authority_design.md) completes the
**design-only** authority, fencing and interrupted-issuance package. It recommends
separate role-owned SQLite stores with DELETE/EXTRA, atomic checkpoint/head/outcome
commits, per-commit and per-publication writer generations, and explicit manager/
issuer reconciliation. The existing Python links SQLite **3.46.1**; WAL-reset patch
coverage is unverified, WAL is not selected, and no environment setting was changed.
The design targets process crashes and stale service copies with intact authority;
it cannot detect an internally consistent rollback of the authority store itself.
Verifier A/B and holder-private checkpoints remain separate. No production source,
functional tests, persistence/crash experiments, proofs or zkVM executions changed/run.
Existing functional evidence is reused. The deployment recovery blocker stays open.
Recommended next package: **S2-DURABLE-AUTHORITY-PILOT-1**, bounded local storage,
manager allocation, verifier consume and issuer-journal reconciliation tests, with
remaining role adapters disabled until integrated. No implementation starts here.
Documentation/data consistency and final lint/format pass; the single complete
preservation audit passes at **20.5195 MiB / 2.057240563 s**, with **8,975 historical
paths** and **607 inventory entries** accounted for. The initial E501 lint failure
is retained; no resource ceiling was reached. [Final result](data/s2_recovery_authority_design_1/final_checks/result.json).
CPU proving remains paused at **two used / one unused**; Stages 2–3 remain open.

**Stage 3 is in progress:** its bounded foundation package is complete. Deterministic
gate emission/evaluation, three storage modes, checked arithmetic, selectors, active
rejection and proof-size accounting are implemented and tested. SPEC-003's equality
and multiplication initialisers are agreed; the production path already follows them.
Full SHA3/SHAKE schedules and the complete local enrolment compiler are implemented.
All 17 previously deferred tests and all nine diagnostic probes now complete under
the approved extended profile. The latest supervised regression passes 1432 tests, no skips.
Authentication witness/attribute parsing and checked division/residue/scalar ring
gadgets are implemented. SPEC-004's exact division recipe is now agreed, including
explicit sign-correction wiring and Q-then-R validity order. Full BC-1 conformance, complete authentication circuits and
privacy-preserving proofs remain unverified/unimplemented. See [the foundation](stage3_bc1_foundation.md) and
[validation report](stage3_hash_enrolment.md#confirmed-convention-and-extended-validation),
and [parsing/arithmetic report](stage3_auth_parsing_arithmetic.md). The earlier
[signature/input package](stage3_signature_inputs.md) adds private FIPS response/hint
decoding and exact same-witness credential message/key preparation. Component/fragment
validation passes. The [counting-only preflight](stage3_resource_preflight.md)
completes message preparation at 2034776 gates; hints, signature with norm and full
preparation with decoding each stop at 32000000 gates. The subsequent authorised
[message pilot and feasibility review](stage3_feasibility_review.md) passes all nine
message-only cases at the same fingerprint, within 2.1M gates/192 MiB RSS/256 MiB AS.
The hint-prefix cost is core work in the current lowering. Its conditional 3.253 GB
raw authentication proof projection warrants a reviewed concrete-profile change before
larger integration. Exact inclusion in full CGen(auth) and complete hint/signature/
preparation validation remain open; the 64M/2 GiB proposal stays inactive.

The [concrete-profile proposal](stage3_profile_change_proposal.md),
[draft benchmark targets](benchmark_targets.md) and
[separate draft amendments](stage3_profile_spec_draft.md) are now prepared for review.
The subsequently authorised [R0-SUCCINCT-FEASIBILITY-1 experiment](stage3_r0_succinct_feasibility_1.md)
built isolated SDK 3.0.6 enrolment/CredValid guests. Three sampler/arithmetic tests
and 35 native reference comparisons passed. Enrolment executed successfully at
196311 user cycles; the first CredValid execution reached the hard 4194304-cycle
session limit. Execution/proving stopped without a cap increase: **zero proof
attempts, no receipts**. Guest equivalence and real succinct proving remain unverified.
The subsequent [R0-CREDVALID-CYCLE-1 attribution package](stage3_r0_credvalid_cycle_attribution.md)
is complete: five bounded execution-only runs attribute the original cap to matrix
SHAKE expansion. One demand-driven XOF correction reduces an isolated polynomial's
measured interval by 20.26%; six native tests and all 35 comparisons pass. The
corrected uninstrumented full guest reached the unchanged 4194304-cycle cap in that
package; its slot 5 remained unused. The subsequently authorised
[R0-CREDVALID-EXEC24-1 package](stage3_r0_credvalid_exec24.md) reuses the same release
image and completes `cred-alpha-42` at **16313474 user cycles**, with the exact public
journal and **463742 cycles (2.76%)** below its authorised 2^24 cap. One existing
canonical identifier mutation reaches the reference signature verifier and rejects
in the guest without a successful acceptance journal. Both executions stay within
2 GiB/no swap and the retained limits. No guest optimisation or dependency change
was made; six native tests and 35 comparisons were reused. At that boundary, zero
proofs/receipts had been produced and all three proof attempts were unused.
The subsequently authorised [R0-SUCCINCT-PROOF-1 pilot](stage3_r0_succinct_proof_1.md)
ran one real local CPU Succinct pipeline for enrolment. All 10 segment proofs,
five lifts and four joins completed; the **600-second deadline stopped the sixth
lift**, with **no final Succinct receipt**. Peak cgroup memory was 1521070080 bytes,
below 2 GiB. CredValid and the optional repeat were not launched. At that boundary,
one proof attempt was used and two remained, with no actual receipt verification.
The subsequently authorised [R0-ENROL-PO17-1 package](stage3_r0_enrol_po17.md)
measured **three po2-17 segments**, down from ten, with unchanged 196311 user cycles
and an exact journal. Its conditional proof completed: **343.792883 seconds SDK
pipeline, 1.429939 GiB kernel memory peak and a 238485-byte Succinct receipt**.
Fresh-process verification and all eight tamper checks passed. The subsequent
[R0-CREDVALID-PO17-1 package](stage3_r0_credvalid_po17.md) completed the single corrected
CredValid execution: **182 segments (181 × po2 17 + one × po2 15)**, down from 582,
unchanged **16313474 user cycles**, exact journal, **0.302628 s API / 0.392469 s guarded**
and **48640000-byte kernel peak**. Its phase-based proving forecast, including 50%
engineering uncertainty, is **35615.572 s (~9.89 hours)**, far beyond the 600-second
pipeline deadline; aggregate proving memory remains unresolved. **No CredValid proof
was launched. Two cumulative attempts are used; one remains.** This package is closed.
The subsequent [R0-DESIGN-REVIEW-1](stage3_r0_design_review.md) verifies the forecast,
including one 50% allowance on the complete subtotal, and recommends **keeping the
current two-thread RISC Zero CPU proving configuration paused**. Accelerated Keccak
and independently bound public-key preprocessing could preserve the mathematical
credential relation but require concrete profile/interface changes; conditional
savings do not establish a path to the unchanged application targets. Neither of
the two inspected redesigns (zkDilithium, LaZer) supplies the required complete
private relation and security evidence. The recommended next package is the bounded
reference-only **S2-VERIFY-STATE-1** lifecycle model, subject to separate authorisation.
No execution/proof/install/profile change occurred in this review. **Two attempts
remain used and one unused.** Full guest equivalence, authentication and
proof/security obligations remain open.
The subsequently authorised S2-VERIFY-STATE-1 package is now complete at its
reference-model boundary; its service/proof obligations above remain open. It
generated no proof or zkVM execution and preserved the same attempt balance.
RISC Zero's ZK qualifications, security accounting and Section VIII
extraction/simulation remain adoption blockers. Experimental dependencies are isolated;
the active suite, production environment, draft targets and inactive 64M proposal are
unchanged. No replacement profile is approved.

## Persistent manuscript authority

The selected manuscript is `docs/manuscript/PQ_DID__Implementation.pdf`, the sole
project PDF already selected during setup. It has 24 pages; no matching LaTeX source
or alternative revision was found. Identify it by digest, not similarity to the V3
filename in the original plan.

| Source | SHA-256 |
|---|---|
| Selected manuscript | `d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca` |
| `PQ_DID_Implementation_Plan_v1.md` | `33964f46d33e00419973e71de12dcbb2393970fca5f038201978a86bb825497d` |

**Only manuscript Sections II–VIII are authoritative for this task and subsequent
implementation. These are section numbers, not PDF page numbers.** The abstract,
Section I and Sections IX onwards remain unrevised and excluded from specification
extraction, consistency checks, parameter selection and performance evidence. Do not
edit them; the user will revise them after implementation. This restriction remains
in [AGENTS.md](../AGENTS.md). The manuscript and original plan are unchanged.

## Stage 1 completion and agreed clarifications

| Completion criterion | Evidence/status |
|---|---|
| Source identity and authoritative scope | PDF digest verified; II–VIII scope persisted in AGENTS/specification/manifest/status |
| Complete specification and traceability | [implementation_spec.md](implementation_spec.md) contains 52 requirements; [traceability.md](traceability.md) covers every requirement and distinguishes private/public/lifecycle checks |
| Parameter/encoding records | [suite.json](../configs/suite.json) version 2 separates confirmed manuscript parameters from agreed user clarifications and unset deployment inputs; [encoding examples](encoding_examples.md) contain fixed positive/negative data |
| Material conventions | SPEC-001 and SPEC-002 agreed on 17 September 2026, with no explicit in-scope conflict found |
| Synthetic schema/policies and representation design | Labelled engineering fixtures and W3C mapping in the specification; deployment values, extension publication/conformance and experiment budgets remain inputs for their later stages |
| Environment | Previously verified and preserved; evidence reused |

**SPEC-001:** encode the path payload as `s0 || ... || s19`, exactly twenty 48-byte
siblings in manuscript order. Preserve the enclosing LP, tags and field counts.
The five-field `rupdate` transport and six-field `update` signing message are separately
specified and tested; they share a path payload, not an entire encoding. VII-A.5/.6/.8
supports this clarification. An explicit outer path-payload sentence remains a
manuscript wording update for the author; the PDF was not edited.

**SPEC-002:** unsigned 64-bit POSIX seconds since `1970-01-01T00:00:00Z`, big-endian;
require `now < texp`. At/after expiry reject; invalid timestamp types, lengths and
ranges reject. All later request/presentation/verifier expiry checks must use this
interpretation, including the final atomic recheck before challenge consumption.
IV-A/VII-A.1/.7 contains no conflicting epoch/equality rule. Those sections still
need wording that names the agreed convention. The helper implements only the
predicate and representation, not trusted-time/freshness/atomic services.

Both decisions are identified as user-agreed clarifications, not original manuscript
quotations, in the specification, manifest, issue register, traceability and examples.
There is no remaining Stage 1 implementation decision. DEP-001/002 and proof feasibility
remain open under their appropriate later work items below.

## Preserved environment evidence

The unchanged [environment record](environment.md) documents Python 3.14.4,
pinned uv/dependencies, liboqs/liboqs-python 0.16.0, GCC/G++ 15.2.0, CMake/Ninja,
WSL2/VS Code configuration and two-job native builds. Its previously passed 14 Python
smoke tests, C/C++ linkage, environment verification, discovery, lint/format and offline
fresh-environment check establish setup readiness only.

During those earlier Stage 2 packages, no installation, dependency update, native build
or completed environment verification was repeated. Python reference tests and independent native interoperability checks use
the established environment. Four relevant fixed hash tests were rerun as cryptographic
regressions; this was not a setup rerun. Ordinary signing remains explicitly uncapped.
The separate verifier has its own deterministic cap tests. Earlier tests, lockfiles,
setup scripts, native records and editor settings remain unchanged; `credentials.py`
was extended to compose CredValid, and new reference/test files were added.

## Stage 2 implementation and evidence

| Scope | Implemented/tested | Requirement coverage |
|---|---|---|
| [codec.py](../src/pqdid/codec.py) | Big-endian integers, LP fields, known tagged-record arities, bounded parsing, raw path packing/unpacking | R-005 framing subset; SPEC-001; R-030/R-031 byte subset |
| [schema.py](../src/pqdid/schema.py) | Validated immutable schemas, attribute types/capacities, fixed 1024-byte vectors, masks and selected-field projection/decoding | R-006; disclosure part of R-007 |
| [policy.py](../src/pqdid/policy.py) | Canonical equality/range clauses, disclosed-only evaluation, ordering/duplicate/domain rejection | Public-policy part of R-007, now composed with certified projection in auth; approval remains lifecycle work |
| [expiry.py](../src/pqdid/expiry.py) | uint64 POSIX representation and deterministic strict comparison with explicit supplied time | SPEC-002; timestamp subset of R-008; future use by R-016/R-026/R-028 |
| [hash_domain.py](../src/pqdid/hash_domain.py) | Supported suite, canonical issuer/key/schema reference, namespace and metadata bytes | Hash-domain subset of R-001/R-005; no trust/complete-pp validation |
| [binding.py](../src/pqdid/binding.py) | Real SHA3-384 holder value, complete binding representation/codecs and local opening consistency | R-010/R-020/R-023 subset; no certificate/signature or proof |
| [merkle.py](../src/pqdid/merkle.py) | Leaves, level-specific nodes, default subtree roots, PathRoot and zero-leaf supplied-root checking | Mathematical subset of R-029 and component of R-024; no authenticated/current state or allocation |
| [parameters.py](../src/pqdid/parameters.py) | Immutable pp/µ records, canonical codecs, repeated schema and complete expected-pp agreement | Structural subsets of R-001/R-004/R-005/R-009; key lengths are not key validation or trust |
| [credentials.py](../src/pqdid/credentials.py) | Immutable cert/vc, structure/expected-instance checks, exact Mcred and complete local `cred_valid` with same-B opening and bounded signature | Local R-023 predicate; no knowledge proof, non-revocation/freshness or issuer release service |
| [bounded_mldsa.py](../src/pqdid/bounded_mldsa.py) | Complete pure ML-DSA-65 reference verification; exact RejNTTPoly/SampleInBall budgets, real hashing, FIPS decoding/arithmetic and explicit exhaustion | Reference verification of R-009/R-032 and verification caps of R-033; no bounded signer/keygen or BC-1 circuit |
| [statements.py](../src/pqdid/statements.py), [witnesses.py](../src/pqdid/witnesses.py) | Immutable state/context/statements and private witnesses; canonical codecs, expected-instance agreement, exact 32-/5329-byte fields and MSB-first bits | R-005/R-008/R-020/R-024 inputs; prepares E(X), actual proof transcript binding remains pending |
| [public_checks.py](../src/pqdid/public_checks.py) | Bounded StateAuth, PubOK, disclosed-only Ppub and separate stateless enrolment public checks | Public part of R-020/R-024/R-025; no request/controller/current-state or trust/session service |
| [relations.py](../src/pqdid/relations.py) | Enrolment BindOpen, authentication private conjunction and mandatory complete local Rauth over one witness | R-020/R-024 reference predicates complete; no remote presentation verifier or proof |
| [verifier_state.py](../src/pqdid/verifier_state.py) | Reference signed requests/current reads, expected context, expiry and atomic consumption; unsupported default proof adapter | R-016/R-017/R-027/R-028 partial; production services and proofs remain open |
| [witness_updates.py](../src/pqdid/witness_updates.py) | Exact public update codec, bounded authenticated chain and local witness/state update; atomic batch result or typed failure | R-031 reference procedure; R-030 public record/transition subset, not manager-side revocation or freshness |
| [revocation_state.py](../src/pqdid/revocation_state.py) | Bounded manager reference: issuer request authentication, staged zero-to-one change, validated state/update signatures, atomic snapshot commit, current reads and public history pages | R-030 reference transition/publication; R-017 manager response and R-031 composition; trusted bootstrap, real signing and durable/distributed services remain open |

API contracts, error behaviour, actual test mappings and limitations are in
[stage2_codec.md](stage2_codec.md), [stage2_binding_merkle.md](stage2_binding_merkle.md),
[stage2_credentials.md](stage2_credentials.md), [stage2_bounded_mldsa.md](stage2_bounded_mldsa.md)
and [stage2_relations.md](stage2_relations.md), with [traceability.md](traceability.md). Generic record
framing is not full validation of every nested state/credential/context domain. Type-0
DID/version attributes are opaque bytes here; method/controller checks are later layers.
Public policy satisfaction is not proof that the disclosed values were certified.

Earlier codec work-package commands, retained as evidence:

```bash
.venv/bin/ruff format src/pqdid/codec.py src/pqdid/schema.py src/pqdid/policy.py src/pqdid/expiry.py tests/unit
.venv/bin/python -m pytest tests/unit -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Earlier codec result: **189 tests passed in 0.09 seconds**; lint passed; formatting check passed
(30 files already formatted). This is unit-test execution time, not cryptographic
performance evidence. The first run's new capacity-boundary fixture error and iterator
lint finding were corrected; fixed expected vectors were not changed. Existing default
pytest/VS Code discovery still targets `tests/smoke`; use the explicit unit-test command.

The tests exercise 44 applicable records from the now 46-vector file. Original E01–E32
remain byte-for-byte equivalent as JSON objects; new E33–E46 encode the agreed decisions
and were calculated independently of the implementation. E15/E28 and eight proof-size
arithmetic cases remain Stage 3 records. Canonical bytes, rejection boundaries,
disclosure and policy semantics, distinct update encodings, hostile declared lengths
and expiry boundaries are covered. No protocol acceptance or security theorem is proved.

## Holder-binding/Merkle work-package validation

New [synthetic binding/Merkle fixtures](../tests/fixtures/binding_merkle_vectors.json)
were frozen independently of the production traversal. Their builder uses manual
`struct` framing and globally indexed sparse trees, with no `pqdid` imports or
PathRoot calls. Fixed data cover five instance domains, complete holder-hash inputs/
digests/B, leaves/nodes, default roots and 48 paths across three actual depth-20 trees.
The empty/old/updated trees store 0/78/84 non-default nodes, avoiding a million-leaf
allocation. Existing vectors and the suite manifest are unchanged.

Commands executed after adding the reference modules and tests:

```bash
.venv/bin/python tests/unit/binding_merkle_reference.py --output tests/fixtures/binding_merkle_vectors.json
.venv/bin/ruff format src/pqdid/hash_domain.py src/pqdid/binding.py src/pqdid/merkle.py tests/unit/binding_merkle_reference.py tests/unit/binding_merkle_cases.py tests/unit/test_hash_domain.py tests/unit/test_binding.py tests/unit/test_merkle.py
.venv/bin/python -m pytest tests/unit/test_hash_domain.py tests/unit/test_binding.py tests/unit/test_merkle.py -q
.venv/bin/python -m pytest tests/unit -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

**179 new focused tests passed; 368 total unit tests passed**, including all 189 earlier
codec/schema/policy/expiry cases. Lint passed; formatting passed (39 files already
formatted). Initial lint findings in new test/fixture code were corrected without
changing expected data or the production algorithms. No environment installation,
native setup or completed environment verification was repeated.

Tests establish local binding consistency and the zero-leaf path condition against a
supplied root, including malformed inputs, wrong instances, every sibling position and
old/new root behaviour. The old-root path can remain mathematically valid: no primitive
claims root authenticity/currentness, allocation, credential issuance/signature validity
or proof of certified-secret knowledge. Stage 2 stays in progress.

## Credential work-package validation

The new structural fixture was assembled independently using manual `struct` framing
and earlier fixed B/metadata. Its key/signature patterns are labelled synthetic and
unauthenticated. Exact pp/certificate/credential/Mcred vectors and seven message variants
cover all applicable signed-field changes. Expected parameters compare both public keys;
credential metadata/attributes/rid/ρ checks do not claim signature validity. Presentation
inputs and old/updated supplied-root paths remain separate from the credential.

```bash
.venv/bin/python -m pytest tests/unit/test_credentials.py tests/integration/test_credentials_uncapped.py -q
.venv/bin/python -m pytest tests/unit -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

**113 focused cases passed (112 structural + 1 uncapped integration); 480 unit tests
passed**, including all 368 previous cases. Lint and formatting passed (47 files on
the final check).
The native integration test signs/verifies the exact Mcred using the external credential
context and rejects altered messages/contexts/signatures. Its success is not evidence
of manuscript sampler limits. Detailed commands, fixture digest and limitations are in
[stage2_credentials.md](stage2_credentials.md).

In that earlier package, actual pinned source and build interfaces were inspected without modification.
[bounded_mldsa_plan.md](bounded_mldsa_plan.md) maps all verification operations, native
checks, missing RejNTTPoly/SampleInBall caps, failure propagation and planned boundary
tests. Ordinary signing has a different default attempt bound; keygen/signing/release
work and DEP-001 signing-tail validation are recorded separately. The bounded verifier
was implemented in the next package below, followed by the complete local relations.

## Bounded verifier and local CredValid validation

[stage2_bounded_mldsa.md](stage2_bounded_mldsa.md) records the original Python FIPS 204
reference, source digests, exact budget accounting and complete validation commands.
Both sampler caps apply before reads, count rejected candidates and permit completion
on the final allowed bytes. Internal diagnostics distinguish exhaustion from invalid
signatures; both reject publicly, with no retry or uncapped fallback.

The verifier passed 172 checks before CredValid integration. The subsequent local
predicate combines expected-instance/structural checks, the existing same-B opening,
the unchanged exact Mcred constructor and bounded verification under expected pkI and
the fixed credential context. It supplies no knowledge proof, non-revocation or freshness.

```bash
.venv/bin/python -m pytest tests/unit/test_bounded_samplers.py tests/unit/test_bounded_mldsa.py tests/unit/test_cred_valid.py tests/integration/test_bounded_mldsa_native.py tests/smoke/test_hashes.py -q
.venv/bin/python -m pytest tests/unit tests/integration tests/smoke/test_hashes.py -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

**208 focused tests passed in 0.95 s; 689 regression tests passed in 1.23 s** (666 unit,
19 integration, four fixed hash cases). Lint/format passed. The 12 frozen ordinary-native
signatures supply 96 differential comparisons, and four freshly generated signatures
also pass. Forty SHAKE comparisons use separate `_hashlib` and `_sha3` implementations.
Deterministic streams exercise both exact limits and exhaustion at every matrix entry
and the challenge, through verification and CredValid. Tests include malformed hints,
norm/packing/arithmetic boundaries, field/issuer splices and resource failure.

The suite manifest's implementation records identify the separate Python verifier and
local CredValid source hashes; confirmed parameters and agreed clarifications are
unchanged. Fixture signing does not validate bounded signing. No new C/native code or
native memory-check build was introduced. Timings are test evidence, not benchmarks.

## Executable relation work-package validation

The contract in [stage2_relations.md](stage2_relations.md) was recorded before coding
from V-B/C and VII-A.1/.5/.6/.7. Authentication includes PubOK with bounded state
verification, existing CredValid, the same certified-rid zero-leaf path, the same
canonical attribute projection and public disclosed-policy evaluation. Enrolment
checks BindOpen; stateless public state/approved-vector checks are separate from
controller authorisation, approval, pending nonce/allocation and freshness services.

The new synthetic fixture uses independently framed statements/witnesses and the existing
global sparse-tree builder, plus ordinary-native signatures. It covers two instances,
three credentials, six signed states and twelve authentication cases (ten valid and two
revoked), plus three enrolment cases. It has no bounded-verifier/relation filtering and
does not validate bounded signing. All 64 disclosure masks for its schema are tested.

```bash
.venv/bin/python -m pytest tests/unit/test_relation_encodings.py tests/unit/test_relations.py -q
.venv/bin/python -m pytest tests/unit tests/integration tests/smoke/test_hashes.py -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

**201 focused tests passed in 2.31 s; 890 regression tests passed in 3.48 s** (867 unit,
19 integration, four fixed hash cases). Lint and formatting passed (65 files). Tests
derive the 256-/42632-bit witness widths, verify exact independent encodings and
reject malformed domains/fields/padding, wrong credentials/instances/signatures,
disclosures and paths. Targeted failures first establish the unaffected conjuncts.
Both real sampler limits propagate from state or credential verification through auth.

Revoking 42 rejects its zero leaf against the updated root while 43 reuses the same
credential with its updated path. The old matching root/path still accepts locally.
Well-formed audience/session/nonce/expiry mutations change E(X) but need not reject;
actual transcript binding and lifecycle freshness/expiry/replay protection are future
work. No local witness is packaged as a presentation, and no proof or service was added.

## Document/data consistency review

The Stage 1 review established all 52 requirement-to-traceability mappings, sourced
manifest groups, witness/path/DID/admission arithmetic, fixed vector structure and local
links. The post-decision review checks those relationships again, with SPEC-001/002 in
an explicit agreed-clarifications section rather than unresolved fields. The original
vector records and protected environment/source digests are compared against the
pre-change snapshot. Final results: 52 requirement definitions match 52 main traceability
rows; 14 manifest parameter groups and both agreed clarifications have valid references;
all 32 original vector objects and eight arithmetic cases are unchanged; 14 new vectors
give 46 total. Independent framing checks confirm the five-/six-field update distinction.
All 23 protected environment/source files in the pre-change snapshot match their hashes,
including the manuscript, plan, pins, native records, original code/tests and editor
configuration. All 52 local links and 17 Markdown tables checked successfully. These
data/document checks used a temporary standard-library audit and changed no dependencies.

The holder-binding/Merkle review additionally confirmed all 38 protected pre-existing
files are unchanged, including the manuscript, suite manifest, previous vectors, earlier
source/tests, environment evidence, dependency pins, setup/native files and editor
configuration. All 52 main traceability rows still match the specification. The new
fixture's 48 paths/five domains and source digest match the fixed profile; its builder
has no production imports. Checked 78 local links and 20 Markdown tables successfully.
The new fixture digest and its provenance are recorded in `stage2_binding_merkle.md`.

The credential work-package preservation audit confirmed all 6773 snapshotted protected
files remain unchanged, including pinned dependency sources/installed files, earlier
code/tests/vectors, suite manifest, manuscript, plan and environment/editor records.
All 52 requirement definitions still match the 52 main traceability rows, all 88 local
links checked in the updated documents resolve, and fixture source/prior-vector digests
match. New implementation and synthetic fixtures were added alongside the existing work.

The bounded-verifier audit checked 6784 protected pre-existing files: 6782 remain
unchanged; only `credentials.py` and the suite's implementation evidence changed within
that set. All confirmed suite sections and SPEC-001/002 are unchanged. Manuscript,
plan, native sources/install, pins/lockfiles, earlier tests/vectors and environment/editor
records match. Source/fixture provenance matches; 52 requirement definitions match 52
main traceability rows. All 115 local links and 27 Markdown tables checked across the
eight updated documents pass. New verifier, fixtures/tests and evidence are separate files.

The relation work-package audit checked 6793 pre-existing protected files. All 6792
outside the suite manifest remain unchanged, including every earlier production/test
file and vector. Only implementation evidence changed in the manifest; confirmed
parameters and SPEC-001/002 are unchanged. Fourteen relation/dependency module hashes
and fixture provenance match. The 52 main traceability rows still match all requirements;
128 local links and 27 Markdown tables across seven updated documents pass.

The Stage 3 foundation preservation audit checked 6802 protected pre-existing files:
all 6801 outside the suite manifest remain unchanged. The manifest changed only in
implementation evidence; confirmed groups and SPEC-001/002 match the pre-change
snapshot. Current foundation/measurement and previous relation source digests match.
All 52 main requirement rows, 115 local links and 22 Markdown tables across the five
updated overview/foundation documents pass consistency checks. The PDF digest still
matches the recorded authority. Twelve component mode comparisons and three clean
resource non-completions were also checked against the machine-readable record.

## Earlier findings and remaining work

Earlier construction differences in the abstract/I/later conclusion, a different
unrevised prototype/assumption, and unrevised evaluation sizes/timings/hardware remain
**deferred author edits or excluded performance evidence**. They are not implementation
blockers and contributed no parameters or benchmark claims to this work.

| Open work | Stage and effect |
|---|---|
| DEP-001 signing-tail/Δtail validation following FIPS 204 potential updates | Stage 2 bounded-operation/security review; current conditional numerical bounds remain unvalidated, caps unchanged |
| DEP-002 remaining keygen/signing and release integration | Bounded reference verification and local CredValid complete; ≤512 keygen sampling, ≤1024 signing attempts, key setup/import and all-role pre-release checks remain open |
| Production witness updates and remaining allocation/revocation reference procedures | Remaining Stage 2 work; complete local enrolment/authentication relations and typed statement/witness/public checks are now implemented; fixture transitions are not production UpdateWit |
| Full BC-1 compiler conformance after agreed SPEC-003/004 | Both clarification issues are resolved; complete independent lowering/identity audit and full circuit/security accounting remain open |
| Complete BC-1 circuits, exact 480-repetition raw-view proof and resource feasibility | Stage 3 foundation now implemented/measured; full circuit/proof work pending, no seeded tapes, reduced repetitions or substitute profile authorised |
| Stateful freshness/atomic verifier, DID/issuer/revocation/KYC services and W3C conformance | Later integration; expiry helper and byte codecs do not implement these services |

**The preceding relation work package is complete.** Remaining Stage 2 exit work
includes bounded keygen/signing and setup/import checks, outstanding revocation/witness
procedures, DEP-001 quantitative validation and remaining DEP-002 release obligations.
Controller/request/current-state authentication and atomic lifecycle services are still
separate integration work; their checks were not moved into the private relation.

That relation package found no new unresolved specification issue. The subsequent
foundation package records SPEC-003 separately; SPEC-001/002, DEP-001/002 and the
remaining Stage 2 obligations retain their existing meanings.

## Stage 3 foundation — completed bounded work package

[The foundation report](stage3_bc1_foundation.md) records the authoritative BC-1
contract, exact development recipe, APIs, tests, budgets and limitations. New modules
under `src/pqdid/circuits/` provide symbolic-input emission, internal trace fingerprints,
materialised Boolean evaluation, shared counting/streaming emission, 64-bit checked
add/subtract/multiply, comparisons, bit rewiring, scanned selectors, branch muxes and
sticky active rejection. Positive-constant division/reduction, ring arithmetic, checked
integer shifts, complete sampler-loop lowering and full relation circuits remain pending.

Validation: **135 focused tests and 1025 regression tests passed** (1002 unit,
19 integration, four fixed hash). Ruff lint passed and all 77 Python files passed
format checking. Full commands and recorded source hashes are in the report and
[machine-readable measurements](data/stage3_bc1_measurements.json).

Four demonstration predicates were measured in all three modes, one subprocess at
a time. Counts/fingerprints agree between modes. Checked multiplication plus target
comparison/rejection emitted 47643 gates, including 21322 AND, with 47773 wires and
810020 trace bytes. Materialised generation/evaluation took 0.165541/0.168949 seconds
and peaked at 24.664 MiB RSS; counting took 0.147084 seconds, retained zero trace bytes
and peaked at 23.266 MiB RSS. Timings include tracemalloc instrumentation and are single
component runs, not full-circuit feasibility evidence. Counting still retains inputs
and live compiler values; no proof-sized allocation was made.

Gate/storage/time failure probes returned non-completion, with no completed circuit.
The unchanged authentication proof-size formula has an integer-only calculator; all
assumed full-authentication AND counts are labelled projections. Component counts are
not authentication counts or automatic rigorous lower bounds.

**The preceding foundation package is complete.** Its identified next package was
SHA3/SHAKE Boolean gadgets and canonical parsing gadgets, validated
against independent/reference expectations, followed by the complete enrolment circuit.
SPEC-003 was subsequently agreed, while full canonical BC-1 conformance and
proof/security accounting remain independently unverified. Bounded ML-DSA, Merkle traversal,
complete authentication and unchanged 480-repetition raw-tape proofs follow later.

## Stage 3 hash/enrolment — historical implementation boundary

[The hash/enrolment report](stage3_hash_enrolment.md) records the SPEC-003 alternatives,
precise proposed wording, FIPS/manuscript mapping, APIs, public/private boundaries,
official vector provenance, commands and resource limits. At that earlier boundary,
SPEC-003 was pending:
1/zero-seeded folds and first-term folds agree in tested acceptance but have different
traces/counts (64-bit multiplication differs by 255 ANDs). No convention was marked
user-approved. Hash construction retains literal FIPS operations and all 24 rounds.

The complete enrolment circuit derives solely from public pp/X, has 256 private bits,
checks the holder hash and public attribute equality, and agrees with the local Stage 2
reference on valid/invalid openings and relevant public mutations. Malformed public
domains reject before construction. State signatures and externally approved attributes
remain separate stateless checks; controller/nonce/current-state checks remain services.
There is no private variable-length enrolment field and no new private range restriction.

**57 focused passed, 17 skipped; 1082 regression passed, 17 skipped.** Lint passed;
all 89 Python files passed format checking. Fifteen official NIST CAVP vectors were
selected without production imports, nine of which run at the original cap. Independent
hashlib and integer-lane expectations, literal gate-order checks, mode equality and
same-circuit valid/invalid evaluations supplement those vectors. The 17 skips cover
additional private absorption/squeeze blocks, and are not claimed as validated cases.

The [resource record](data/stage3_hash_enrolment_measurements.json) contains 18 completed
fresh component/mode probes and nine clean gate-limit terminations, one worker, original
limits and 256 MiB process address space. Enrolment: 194691 gates, 38787 AND, 194949 wires,
3309836 trace bytes, generation/evaluation 1.038508/0.617258 s, peak RSS 32.637 MiB.
Counting generation took 0.969948 s with zero retained trace bytes and 25.508 MiB peak
RSS. Timings include tracemalloc; counts and identity remain provisional. A separate
evaluation reused the circuit with a wrong opening and rejected, without reconstruction.
The d=256 calculated proof size is 9587104 bytes; no privacy-preserving proof exists.

All larger probes terminated at 200000 gates; partial output is not a completed circuit.
An optional 2000000-gate/40 MiB profile was prepared with existing time/process limits,
and was then awaiting approval. The validation-only follow-up below resolves that
choice and runs the deferred cases; routine defaults remain unchanged.

**Stage 3 remains in progress.** Stage 2 bounded keygen/signing, setup/import, production
revocation/witness updates, DEP-001 quantitative validation and remaining DEP-002 release
obligations remain open. SPEC-001/002, suite/security parameters and raw-tape repetitions
are unchanged. This work package does not start the subsequent authentication/proof work.

Hash/enrolment preservation audit: 6816 protected pre-existing files checked, all 6815
outside the suite manifest unchanged; manifest changes restricted to implementation
evidence. All previous and current source/provenance hashes match, including the pinned
manuscript and prior vectors. The 52 main requirement rows, 119 local links and 22
Markdown tables across five updated overview/report documents pass consistency checks.
No dependency, toolchain, editor, native source/install or prior implementation changed.

## Stage 3 confirmed-convention validation — complete

**SPEC-003 agreed clarification, 17 September 2026:**

> Initialise equality with public 1. Initialise magnitude multiplication with a public 128-bit zero accumulator; add all 64 shifted partial products in increasing order using full-width ripple addition, retaining terminal carry operations.

This resolves those initialisers/full-width additions only. Existing gate/operand
order, checked arithmetic and public-only folding are preserved. VII-A.6 on printed
p. 16 needs later author wording alignment; the manuscript is unchanged. Production
code already follows the agreement, and diagnostic alternatives are not selectable
through canonical compilation. Full BC-1 conformance is not inferred from adoption.

The separate [operational profile](../configs/validation_profiles.json) permits
2000000 gates and exactly 41943040 trace bytes per case, with one active worker.
After inspecting 7.57 GiB WSL usable RAM/5.07 GiB available and free guest storage,
validation retained the existing kernel 256 MiB address-space cap and added a
128 MiB sampled RSS watchdog. Existing 10-second generation, 5-second evaluation
and 30-second per-case wall controls are retained. Sampled RSS can overshoot between
polls; measured RSS is distinct from the watchdog threshold and trace-storage limit.

**17/17 previously skipped tests passed; 9/9 previously capped probes completed;
2/2 historical stability cases passed.** Six count/stream probe successes check
construction/digests only; three materialised probes also evaluate their predicates.
All exact identifiers, functionality, times, gates/ANDs/wires/trace bytes and RSS are
reported in [the report](stage3_hash_enrolment.md#all-17-previously-skipped-tests) and
[new JSON](data/stage3_hash_enrolment_validation.json). No unfinished case is counted
as correctness. Original nine cap failures and old measurements remain unchanged.

The exact multiplication demonstration still has 47643 gates / 21322 AND, 47773 wires,
810020 trace bytes; enrolment still has 194691 / 38787, 194949 wires, 3309836 bytes.
Historical fingerprints/counts match. Fresh original/extended materialised and streamed
traces compare literally, counting digests match, and independent small traces plus
the actual-width schedule check the agreed seeds and terminal carry operations.
Historical raw trace files were not stored, so old trace comparison is through the
recorded digest rather than an unavailable byte file. No algorithm was changed.

**1106 regression tests passed in 31.91 seconds, no skips**; seven new trace/control
tests passed separately in 0.13 seconds. Ruff lint passed; all 93 Python files pass
format checking. Complete commands and coverage distinctions are in the report.
Peak RSS was 87.484 MiB across individual tests, 72.859 MiB across diagnostic probes
and 109.934 MiB for regression. All ran within the selected controls.

**Ready for the next bounded implementation package:** authentication private parsing
and checked positive-constant division/reduction/ring gadgets. No deferred validation
case remains open from this package. Further independent conformance/lowering work,
full authentication and proof feasibility remain open; 9587104 enrolment proof bytes
is still a calculation, with no proof generated or verified. Stage 2 obligations and
DEP-001/002 remain open as above. The work stops after validation.

The final [preservation and consistency audit](data/stage3_validation_audit.json)
checks all 6836 protected pre-existing files and preserves every prior production
source, test/vector, measurement, dependency/native/editor file and the pinned PDF.
Only authorised documentation/instruction/manifest records change; confirmed suite
parameters and SPEC-001/002 are unchanged. New operational scripts/tests/data are
separate additions.

## Stage 3 authentication parsing/scalar arithmetic — bounded package complete

Historical package record: SPEC-004's pending status and provisional fingerprints
below are superseded by the adoption/preflight record at the end of this document.

[The package report](stage3_auth_parsing_arithmetic.md) records the contracts, exact
source/call-site mappings and implemented boundaries. `circuits.auth_parsing` splits
the unchanged 5329-byte / 42632-bit witness, validates private schema-defined lengths,
types/padding/rid, and compares the same complete padded attribute fields with public
D/mD. All original signature bytes remain available to the future private FIPS
verifier. Validly encoded credential mutations can pass parsing and fail the existing
full reference relation; parsing is not complete authentication.

`circuits.division` provides signed64 floor divmod by positive public constants and
canonical/centred residues. `circuits.scalar_ring` composes checked scalar add/sub/mul
with mod-q at the prescribed positions, explicit coefficient/NTT domains, Decompose,
HighBits/LowBits, UseHint, strict norm and one forward NTT butterfly. Products remain
128-bit intermediates and failures remain sticky before reduction. No private advice,
coefficient narrowing, early reduction or Montgomery/Barrett replacement is introduced.

**SPEC-004 is newly proposed, not agreed:** VII-A.6 fixes division's direction and
signed correction but not the exact restoring-register/subtraction/quotient schedule.
The issue register records a concrete 65-bit-workspace/64-round development recipe.
Its mathematical behaviour and deterministic trace are tested; full canonical BC-1
identity remains unverified. SPEC-001/002/003 and all suite parameters are unchanged.

**217 focused tests pass; 1323 regression tests pass, no skips; all 36 component/mode
probes complete.** Ruff lint passes and all 105 Python files pass formatting. The
approved one-worker 2000000-gate/41943040-byte profile retains 10/5-second generation/
evaluation, 30-second per-case wall, kernel 256 MiB AS and sampled 128 MiB RSS controls.
Peak measured RSS was 40.273 MiB for probes and 118.840 MiB for regression. The
maximum-capacity attribute case really ran beyond the routine 200000-gate cap.

| Measured predicate | Gates | AND | Serialised bytes |
|---|---:|---:|---:|
| Authentication parsing/disclosure, existing alpha fixture | 88214 | 29709 | 1499727 |
| Full-capacity attribute parsing | 280729 | 94066 | 4772482 |
| Signed64 divmod by q, including public-target checks | 36280 | 13462 | 616849 |
| Canonical mod-q | 36087 | 13397 | 613568 |
| Centred mod-523776 | 37004 | 13725 | 629157 |
| Private/private scalar multiplication mod q | 83535 | 34653 | 1420184 |
| UseHint scalar | 184266 | 68373 | 3132611 |
| One forward NTT butterfly | 155658 | 61451 | 2646275 |

These include their measurement predicates, are not complete authentication counts
and were not inserted into a proof-size formula. Count/stream success establishes
construction/digests; materialised probes also evaluate their predicates. Initial
pre-review measurements are preserved separately; the final centred helper reuses
wide-result wires when narrowing, with no duplicated low-word mux. All old source,
vectors, measurements, environment/native/editor files and the PDF remain unchanged;
[the audit](data/stage3_auth_arithmetic_audit.json) records preservation and consistency.

**Next integration:** private FIPS signature/hint decoding and verifier input wiring,
then bounded full NTT/matrix/sampler/Merkle composition. Resolve SPEC-004 before
claiming the exact canonical division identity; independently audit the complete
lowering before canonical CGen/security claims. No full authentication circuit or
privacy proof is implemented, and 9587104 enrolment proof bytes remains a calculation.
All earlier Stage 2/DEP-001/DEP-002 and Stage 3 proof-feasibility obligations stay open.
This bounded package stops here.


## Stage 3 private signature/input preparation — 18 September 2026

Historical package record: the later adoption/preflight record below supersedes
its pending SPEC-004 status and counting limits; earlier evidence is preserved.

[The package report](stage3_signature_inputs.md) contains the complete pending
SPEC-004 recommendation, source map, API/witness contracts, exact byte framing,
independent fixture comparisons and resource accounting. SPEC-001/002/003 and the
manuscript are unchanged. Existing division implementation is unchanged; new
compare-then-subtract diagnostics show why functional correctness does not settle
its canonical identity (35894 versus 56566 core gates at public divisor q).

Implemented: direct response/challenge/hint extraction, complete bounded hint-decoder
source with private scan operations, separate strict norm helper, expected public-key
decoding, and exact holder/B/Mcred/pure credential context/tr/FIPS representative
input wiring. No separate B/Mcred/decoded coefficient/hint witness is accepted by the
preparation entry point. The authentication witness remains 5329 bytes / 42632 bits.
Named validity outputs are preparation-only; no partial signature/auth verifier is
exposed. The existing reference verifier/relations/environment/vectors are preserved.

**81 focused and 1404 regression tests pass, no skips; Ruff lint/format pass (115
Python files).** The approved profile retains one worker, 2000000 gates / 40 MiB trace,
256 MiB AS, sampled 128 MiB RSS, 10/5-second generation/evaluation and 30-second
per-case wall controls. Tests use fresh sequential module processes after two initial
combined runs hit the RSS watchdog; those records remain explicit. No budget was
raised. Final regression high-water RSS is 118.188 MiB.

**39 probes complete and 12 stop cleanly at the gate cap**, across three storage
modes. Completed components include 336643-gate response decoding, 1520649-gate
response+norm, 281751-gate parsing/holder/message framing and a 1753024-gate standalone
message-hash kernel. Every new core retains required validity; test output observation
adds zero gates. Historical multiplication/butterfly predicates add respectively
193/386 test gates beyond their 83342/155272-gate private-operand cores. Public-left
multiplication is separately measured at 82757 gates; operand classes are not interchangeable.

**Not executed to completion:** full hint reconstruction, full signature decoding,
complete holder/message-hash composition, and complete input preparation. Fragment
chains test actual evaluated data but do not substitute for these complete traces.
No complete authentication AND/proof-size estimate is made.

**Next justified work:** review SPEC-004 and arrange a separately approved resource
plan for complete hint/message/preparation validation; then bounded sampling,
forward/inverse NTT and matrix/w1/challenge composition can be integrated in source
order. Same-rid Merkle/full authentication, independent BC-1 conformance and all
proof/Stage 2/DEP-001/DEP-002 obligations remain open. This package stops here.

## SPEC-004 adoption and resource preflight — 18 September 2026

Historical package record. The subsequent bounded pilot/review below supersedes
its next-work recommendation; earlier measurements and proposals are preserved.

**SPEC-004 is agreed.** [The adopted wording and report](stage3_resource_preflight.md)
fix the 65-bit correction sequence, explicitly public-zero negative-remainder false
arm, named reuse and Q-then-R checks followed by b>0. MIN's unsigned magnitude is
valid. Both outputs, terminal carries, divisor restrictions and active sticky rejection
remain. The manuscript is unchanged; VII-A.6 p. 16 needs a later wording update.
Gate/AND/fold counts and trace lengths are unchanged, but fingerprints change for
all ten affected component predicates, refreshed in all three modes. Three core-only
counts also refresh their identities and retain separate test-comparison costs.

**241 focused / 1421 regression tests pass without skips; Ruff passes (119 files
formatted).** The environment, parameters, SPEC-001/002/003, vectors and historical
JSON evidence are preserved. No full BC-1 claim follows from this issue resolution.

The authorised count-only profile uses 32M gates, 1 GiB logical trace, 10 MiB diagnostics,
300 seconds and one worker, retaining stricter 128 MiB RSS / 256 MiB AS controls.
Ordinary/materialised limits remain unchanged. No full trace or wire-value array was
stored. Message preparation completes at **2034776 gates / 413709 ANDs**; complete
hints, signature+norm and preparation+decode+norm each stop at exactly **32M gates**
in about 55 seconds, with worker RSS below 51 MiB. These are incomplete prefixes,
not full counts. Later norm/representative stages remain unreached where applicable.

The [evaluation plan](data/stage3_evaluation_resource_plan.json) recommends a later
message-preparation pilot at 2.1M gates / 40 MiB trace / 192 MiB RSS / 256 MiB AS,
10 s generation + 5 s evaluation / 30 s wall. Each hint-containing target needs
feasibility review, a complete count and a tested file-streaming evaluator first.
Their conditional proposed envelope is 64M gates / 2 GiB storage / 256 MiB RSS /
512 MiB AS, 300 s generation + 120 s evaluation / 600 s wall, one worker. It is a
ceiling for a future decision, not an estimated full count or an activated profile.
Existing streaming emission does not provide streaming evaluation. Materialising
even the measured prefixes exceeds present memory limits.

No further escalation, sampler/NTT integration or proof work was undertaken. Full
hint/preparation validation, BC-1 conformance, authentication, proofs and remaining
Stage 2/DEP-001/DEP-002 obligations remain open. This package is complete and stops here.

## Message-preparation pilot and feasibility decision — 18 September 2026

[The review](stage3_feasibility_review.md) records nine fresh complete message-only
evaluations: original valid input; four malformed/disclosure failures; and four
well-formed mutations. All pass the preparation contract and independent byte/hash
expectations, with unchanged 2034776 gates / 413709 ANDs / fingerprint. Certified-field
mutations can change the message without rejection until signature verification.
Generation takes 3.686–3.768 s, evaluation 0.437–0.458 s, peak RSS 102.406 MiB.
The separate authorised pilot profile leaves ordinary/count profiles unchanged.

A single attributed count reproduces the 32M-gate hint prefix / 13532448 ANDs,
without a graph or value array. It stops in the 285th of 330 slots; private write
selectors/muxes account for about 69% of ANDs and read selectors about 25%. No
source-grounded implementation error or test-only circuit overhead was demonstrated.

The frozen formula gives **3253150624 bytes (3.253 GB)** at that AND count.
Semantic hint inclusion is mandatory, but exact numerical inclusion in the absent
complete CGen(auth) is not independently established: record this as a **conditional
projection**, with the continuation assumptions in the review. No overlapping prefix
counts are added, no proof exists, and generation time is not proving latency.

**Recommendation: prepare a reviewed concrete-profile change proposal**, first
defining numerical KYC acceptance criteria and auditing the full inclusion argument.
Faithful streaming/disk storage can help memory but not raw communication. Any changes
to widths, indexing, folding, repetitions or raw views require explicit review of
VII-A.6/.7 and affected VIII analysis. No replacement is implemented or authorised.
The conditional 64M/2 GiB proposal remains inactive; no sampler/NTT integration began.
Validation: 119 focused / 1432 regression tests pass without skips; Ruff lint and
formatting pass (123 Python files). Prior vectors, production circuits, environment,
agreed clarifications and historical JSON evidence remain unchanged.
Correctness, full conformance, authentication/proofs and outstanding Stage 2 work
remain open. This package stops here.

## Concrete-profile proposal and draft targets — 19 September 2026

The documentation/source-review package is complete. The
[proposal](stage3_profile_change_proposal.md) compares revised Boolean/MPC-in-the-head,
RISC Zero, Winterfell, zkDilithium and LaZer using pinned primary sources. It preserves
the same-witness/private credential-authenticity requirement, existing application
bytes/primitives, public-check placement and lifecycle freshness. Source limitations,
missing integrations and quantum extraction/simulation gaps are explicit. LaZer's
documented AVX-512 requirement is absent from the inspected WSL flags. No candidate
was installed, built or used to generate proofs.

The proposed `PQDID-R0S-EXP1` identity and exact guest/journal/receipt changes appear
only in [draft amendments](stage3_profile_spec_draft.md). The
[targets](benchmark_targets.md) propose 10 MiB raw/12 MiB presentation, 30 s prover/
2 s verifier/45 s end-to-end p95, 4 GiB/1 GiB RSS and an exploratory 1 MiB/10 s
scenario. These are project proposals, not KYC standards, approved requirements or
execution authority. Independent arithmetic confirms the 5,363,104-byte frozen
floor and 21,344-AND maximum at 10 MiB; 1 MiB is impossible for the frozen encoding.

Recommended next package **after review**: R0-SUCCINCT-FEASIBILITY-1, an isolated
CPU-only port and at most three local Succinct proof attempts (enrolment then a
same-witness credential-verification fragment), with proposed 2 GiB aggregate prover
memory, 2 CPU threads, bounded cycles/wall time, independent host headroom and explicit
stop criteria. This is not complete authentication or p95/security validation.

Review the profile separation/encodings, security gaps, draft targets/network model
and future build/execution envelope. All Stage 2 keygen/signing/release/revocation/
service work and DEP-001/002 remain open; original full hint/signature/preparation,
authentication/proofs and BC-1 conformance remain open. SPEC-001–004, the manuscript,
active configuration, production implementation, dependencies, fixtures and earlier
evidence are preserved. The 64M/2 GiB proposal remains inactive. Documentation/data
checks are recorded in [the package audit](data/stage3_profile_proposal_checks.json);
prior 119 focused/1432 regression and Ruff results are reused without rerunning them.

## R0-SUCCINCT-FEASIBILITY-1 — 19 September 2026

The user authorised the isolated implementation, installation and bounded experiment;
this supersedes the preceding proposal's waiting-for-review status only for that
engineering package. [Report](stage3_r0_succinct_feasibility_1.md),
[manifest](../experiments/r0_succinct_feasibility_1/evidence/manifest.json),
[run ledger](../experiments/r0_succinct_feasibility_1/evidence/run_ledger.json) and
[resource stop](../experiments/r0_succinct_feasibility_1/evidence/STOP.json) retain the
actual outcome. Both guests implement complete selected reference predicates; the
CredValid port takes an independent private certificate binding and full credential.
It includes real SHA3/SHAKE, external ML-DSA context and exact sampler exhaustion.

Build and native comparison passed. Guest comparison stopped on the second case:
enrol-alpha-42 accepted with the exact public journal; cred-alpha-42 reached 2^22
user cycles. This is an execution resource stop, not a false credential rejection.
The remaining 27 guest cases were not run. All 29 relation cases and six separate
signature-context cases passed natively; that is not guest-wide equivalence evidence.
Three forbidden receipt variants and six malformed containers were rejected using
synthetic inputs; no actual receipt was generated or verified. Proving remained gated,
so the three-attempt allowance was unused. No p95, proof-size or security result exists.

Toolchain/crate provenance, transitive guest advisories, local IPC and witness
isolation controls were checked and recorded. SDK and binary dependency security
qualifications remain explicit. The complete proving process-tree ceiling was 2 GiB,
with no worker swap. No resource limit was increased or unchanged failure retried.
The recommended next package is execution-only cycle attribution and a reviewed
semantics-preserving optimisation plan under explicit limits, before another proof pilot.

All remaining Stage 2 bounded keygen/signing, release/revocation/update integration,
request/controller/approval/session/freshness/atomic-consumption services and DEP-001/002
remain open. Full authentication, selective disclosure/non-revocation integration,
BC-1 conformance, original MPC proofs and Section VIII security review remain open.
The manuscript, SPEC-001–004, active parameters, production source/dependencies,
original fixtures and previous evidence are preserved. Prior production validation
(119 focused / 1432 regression, no skips) is reused; experimental checks are separate.


## R0-SUCCINCT-PROOF-1 — 19 September 2026

The [bounded real-proof pilot](stage3_r0_succinct_proof_1.md) is complete and stopped
after its first pipeline reached the unchanged 600-second deadline. Both guest ELFs,
images, fixtures, locks and expected journals were frozen. The existing SDK 3.0.6
binary's embedded recursion archive matched its pinned digest; no download or guest
rebuild was needed. Host-only preparation/build took 160.117499 seconds.

Enrolment execution completed with the exact 15380-byte expected journal and ten
segments. All ten segment proofs completed before recursion. Five lifts and four
joins completed; the sixth lift was in progress at the time limit. The guarded
pipeline lasted 600.128431 seconds including teardown, with kernel memory peak
1521070080 bytes, no swap or OOM, and 436542 bytes of temporary storage. No final
receipt exists. Real component proof work does not satisfy complete Succinct receipt
generation or independent verification. Fresh verifier isolation controls were
prepared/probed; actual-receipt verification/tampering tests could not run.

One attempt was consumed and two remain unused. No retry, CredValid proof, optional
repeat, resource increase or fallback was performed. The earlier 20.26% remains an
isolated execution result. Complete proving costs, receipt sizes, percentiles,
privacy and quantum-security claims are not established. Recommend one separately
authorised execution-only enrolment segmentation check at po2 17, preserving the
guest/fixture and existing memory/time limits, before spending another proof attempt.

The [results](../experiments/r0_succinct_proof_1/evidence/results.json),
[pre-launch manifest](../experiments/r0_succinct_proof_1/evidence/manifest-before-launch.json)
and [STOP](../experiments/r0_succinct_proof_1/evidence/STOP.json) preserve the evidence.
Full authentication/selective disclosure/non-revocation/lifecycle integration,
complete BC-1 and guest equivalence, final proofs and receipt verification,
privacy/ZK/quantum security, Section VIII, DEP-001/002 and remaining Stage 2 obligations
remain open. Production configuration, manuscript and historical evidence are unchanged.


## R0-ENROL-PO17-1 — 19 September 2026

The [enrolment segmentation/proof package](stage3_r0_enrol_po17.md) is complete.
Only the actual executor segment setting changed from 16 to 17; the prover maximum
remains 22, with unchanged verifier parameters, CPU settings, pinned prover binary,
guest ELF/image, fixture and 2^22 user cap. The host is an offline optimised release
build; known cache/timer-scope qualifications are recorded. No guest/prover rebuild
or dependency change occurred, and unchanged reference validation was reused.

One execution completed with three po2-17 segments, 196311 user cycles and the exact
15380-byte journal. The single conditional proof completed all three segment proofs,
three lifts and two joins, returning a real Succinct receipt in 343.792883 seconds
SDK time (343.898930 seconds whole guarded pipeline), with 1535385600-byte kernel
peak, zero swap/OOM and 236187-byte temporary-file peak. The raw seal is 222668 bytes;
the complete receipt is 238485 bytes. Fresh independent verification took 0.011628
seconds; eight focused tamper cases rejected without any new proof generation.

The [receipt](../experiments/r0_enrol_po17_1/receipts/attempt2.bin),
[measurements](../experiments/r0_enrol_po17_1/evidence/results.json),
[cumulative ledger](../experiments/r0_enrol_po17_1/evidence/cumulative_attempt_ledger.json)
and [STOP](../experiments/r0_enrol_po17_1/evidence/STOP.json) preserve the evidence.
Two of three cumulative attempts are consumed, one remains. No exact overall speedup
against the earlier timeout is defined. No CredValid execution/proof occurred here.

Retain the final attempt: the measured enrolment cost does not establish feasibility
for CredValid under the same 600-second/2 GiB plan. Recommend one separately authorised
CredValid execution-only admission check at po2 17, same corrected image/fixture,
2^24 user cap and existing 60-second/2 GiB/no-swap/storage limits, to measure its actual
partition before deciding on that final proof. No automatic limit increase follows.

The active profile is unchanged. Full authentication, CredValid proving, selective
disclosure/non-revocation/lifecycle integration, complete guest equivalence/BC-1,
privacy/ZK/quantum security, Section VIII, DEP-001/002 and remaining Stage 2 work remain
open. The new evidence establishes the selected experimental enrolment proof and
receipt checks only; it does not activate a replacement profile or prove unlinkability.


## R0-CREDVALID-PO17-1 — preflight passed, proof not admitted

The [report](stage3_r0_credvalid_po17.md) records one accepted execution and the exact
original 5147-byte public journal under 2^24 SDK user cycles, 60 seconds, 2 GiB/no swap
and retained storage limits. Actual partition: 182 segments; padded capacity 23756800,
combined non-user/padding residual 7443326. Separate paging/system counters are not
available through execute IPC. This output is not a receipt.

The pinned sequential prover requires 182 base proofs, 182 lifts and 181 joins.
Separate measured enrolment base/lift/join timings yield a 23743.715-second scenario
before an explicit 50% uncertainty allowance, 35615.572 seconds with it. The one
po2-15 terminal pair uses a labelled proxy; memory retention/working-set bounds are
unresolved. No calibration or final proof was launched. The cumulative budget is
**two used / one remaining**, and STOP closes this package. This is an engineering
forecast, not measured CredValid proving time or application p95 acceptance.

The existing real enrolment receipt and eight tamper checks are preserved. Full
authentication, disclosure/non-revocation integration, lifecycle protections, actual
CredValid proofs, BC-1/guest equivalence, privacy/ZK, quantum-security and Section VIII
reviews and remaining Stage 2 obligations remain open. The next recommendation is
a design review of total proved credential-verification/recursion work against the
provisional application targets, retaining the final attempt until a credible
latency/memory case exists. No profile adoption or automatic limit increase.


## S2-DURABLE-AUTHORITY-PILOT-1 — bounded local process-crash evidence

19 September 2026. [Report](stage2_durable_authority_pilot.md),
[implementation](../src/pqdid/persistence/lifecycle.py) and
[guarded evidence](data/s2_durable_authority_pilot_1/run-ledger.json).
**38 distinct focused cases and 28 unchanged lifecycle regressions pass**; three
non-resource development failures and their corrections remain recorded (69 total
case instances). Eighteen fixture-owned application-barrier SIGKILLs exercise fresh
process recovery; these do not establish power-loss durability or whole-store rollback
detection. Default policy denies; only the tests install synthetic operator identities.

REC-001/002 gain durable manager allocation and one-time verifier consumption for
separate audience stores, including stale same-root checkpoint refusal. REC-003/004,
REC-006 and REC-007 gain local checkpoint/head/outcome commits, per-transition and
publication generation/head fencing, conservative interrupted-issuer reconciliation,
permanent orphan reservations and exact original-recipient credential redelivery.
STORAGE-001 now has installed SQLite 3.46.1 DELETE/EXTRA readback, bounded SQL/storage
failures and application process-crash evidence. The APIs are narrow durable pilot
facades, not a complete restartable issuer/manager/verifier deployment.

Production admin/recipient/OS isolation and IPC, full durable begin/finish and other
role operations, bounded production signing/proofs, retention/backup, host flush
qualification and REC-005 whole-authority rollback remain blockers. Matching a head
inside the same rolled-back store is not rollback detection. The original unsafe
controls and historical failures remain unchanged. Full authentication/BC-1,
selective-disclosure/non-revocation integration, DEP-001/002 and security/privacy
review remain open. No proofs or zkVM executions; CPU proving paused, two attempts
used and one unused. Stages 2–3 remain incomplete. Recommend the bounded
S2-AUTHORITY-OWNER-BOUNDARY-1 design/test package before deployment.


**Final S2-DURABLE-AUTHORITY-PILOT-1 validation:**
[One complete preservation audit](data/s2_durable_authority_pilot_1/result.json) passes,
exit 0 in **2.111892061 s**, cgroup peak **24,236,032 bytes
(23.11328125 MiB)** under the unchanged 256 MiB ceiling; zero memory-limit/OOM/swap
events. All **9,016 historical paths** and the **690-entry inventory** are accounted
for with completed content/report/readback/outer guard. Only the exact three allowed
existing documents changed. Final lint/format and **38 focused + 28 unchanged
lifecycle cases** pass; development failures remain preserved. Fifteen guarded commands
share the unchanged budget and total **38.300096529 s**. Temporary stores are removed.
The pilot is complete; deployment recovery, Stages 2–3 and the named security/proof
obligations remain open. No proofs or zkVM executions; CPU proving paused, ledger
two attempts used and one unused. Next bounded recommendation:
S2-AUTHORITY-OWNER-BOUNDARY-1; no further work is launched in this package.


## S2-AUTHORITY-OWNER-BOUNDARY-1 — authenticated local IPC pilot

19 September 2026. [Report](stage2_authority_owner_boundary.md),
[owner implementation](../src/pqdid/persistence/owner_service.py) and
[guarded evidence](data/s2_authority_owner_boundary_1/run-ledger.json).
**28 IPC cases and 28 unchanged lifecycle regressions pass.** Named operations now
require a configured scoped capability plus kernel UID/GID and an operation-specific
permission. Separate admin, service-writer, observer and issuance-recipient grants
retain fixed store/instance/namespace bindings, original DELETE/EXTRA persistence,
commit/publication generation/head fences and immutable recipient delivery.
Independent client processes cover live writer replacement, already connected stale
clients, one-time concurrent consumption, exact lost-result delivery, malformed
frames, connection/processing limits and unavailable owners. No automatic fallback.

This is a **same-UID pilot (1000:1000)**. Its capabilities and approved delivery
sessions use trusted test provisioning; local IPC is not PQ-DAA authentication.
Raw store, capability-file, signer and Python internal access remain bypasses for
that OS identity. Production application approval/admin and recipient provisioning,
OS isolation, full lifecycle integration and bounded signing remain separate open
obligations. The unchanged previous 38 durable-pilot cases/18 owned crash injections
are reused; only targeted IPC crash boundaries were added. Earlier development
failures remain recorded. Final lint and formatting pass; preservation results
follow below. Stages 2–3 remain open. CPU proving paused, two proof attempts used,
one unused; no proofs or zkVM executions. Recommend only the bounded design package
**S2-AUTHORITY-ISOLATION-PLAN-1** before account or deployment changes.


**Final S2-AUTHORITY-OWNER-BOUNDARY-1 validation:**
[Complete preservation audit](data/s2_authority_owner_boundary_1/result.json) passes,
exit 0, **2.134272240 s**, cgroup peak **24,907,776 bytes (23.75390625 MiB)** under
unchanged 256 MiB. All **9,099 historical paths** and **773 inventory entries** are
accounted for; content/report/readback and outer guard complete, with zero
memory-limit/OOM/swap events. Final **28 IPC + 28 unchanged lifecycle cases**, lint
and formatting pass; 78 total case instances include the retained corrected fixture
failures and justified access repeat. Sixteen guarded commands total **55.803938689 s**;
maximum cgroup peak **114.01953125 MiB**, sampled tree RSS **173.59765625 MiB**.
No old source, tests, dependencies, manuscript, ledger or historical result changed.
Same-UID/direct-store access and test-only provisioning remain explicit limitations.
The package is complete; Stages 2–3, production authorisation/OS isolation, full
lifecycle, bounded signing and proof/privacy/security obligations remain open.
No proofs/zkVM executions; CPU proving paused, two attempts used/one unused.
Recommend S2-AUTHORITY-ISOLATION-PLAN-1; stop here without deployment changes.


## S2-AUTHORITY-ISOLATION-PLAN-1 — uninstalled deployment proposal

19 September 2026. [Plan](stage2_authority_isolation_plan.md),
[staged templates/runbook](proposals/s2_authority_isolation_plan_1/README.md) and
[validation ledger](data/s2_authority_isolation_plan_1/run-ledger.json).
Select four dedicated owner UIDs, separate writer/client UIDs, scoped transport
access and root-protected configuration/runtime. The 13-account matrix preserves
independent verifier stores, holder-private data, application ACLs, fencing and
immutable recipient delivery. It specifies a fresh protected Python environment,
private credential provisioning/revocation and 22 actual-identity acceptance cases.

**No deployment protection is implemented or activated by this plan.** The current
0700/0600 same-UID socket checks need an explicit cross-UID endpoint adapter; trusted
launch/preflight/provisioning and bounded system-manager test coordination are also
missing. Templates remain uninstalled. No accounts, host settings, dependencies,
production source or existing store permissions changed. Static checks cannot
establish hostile-client isolation; existing functional evidence is reused.

Recommend only **S2-AUTHORITY-ISOLATION-PILOT-1**: implement the specified blockers,
then separately approve the concrete privileged actions and run the bounded real-ID
synthetic test plan. Production approval, full lifecycle integration, bounded
signing/DEP-001/002, proof feasibility and privacy/security review remain separate
open obligations. Stages 2–3 remain open. No proofs or zkVM executions; CPU proving
paused, two attempts used/one unused. Final preservation/static results follow below.


**Final S2-AUTHORITY-ISOLATION-PLAN-1 validation:**
[Static policy/unit checks](data/s2_authority_isolation_plan_1/static-accepted-validation.json),
final lint and formatting pass. The final installed-systemd syntax parser reports
no warnings. [One complete preservation audit](data/s2_authority_isolation_plan_1/result.json)
passes, exit 0 in **2.066424324 s**, cgroup peak **21,860,352 bytes (20.84765625 MiB)**
under unchanged 256 MiB. All **9,183 historical paths** and **851 inventory entries**
are accounted for; content/report/readback and outer guard complete. No memory-limit,
OOM or swap event. Thirteen guarded commands total **3.629145615 s**; temporary
stores are absent. Original code, tests, dependencies, manuscript and history remain
unchanged; only the exact three existing documentation files changed.
No functional/actual-ID tests or activation were performed. The plan is complete,
with deployment protections still **unimplemented**. Recommend only the gated
S2-AUTHORITY-ISOLATION-PILOT-1; full lifecycle, bounded signing, proof feasibility
and privacy/security obligations remain open. Stages 2–3 incomplete; CPU proving
paused, ledger two attempts used/one unused; no proofs or zkVM executions.


## S2-AUTHORITY-ISOLATION-PILOT-1 — implementation staged; approval boundary

[Implementation report](stage2_authority_isolation_pilot.md) and
[exact activation runbook](proposals/s2_authority_isolation_pilot_1/README.md): explicit
cross-UID endpoint policy, protected fresh-runtime provisioning, fail-closed launch,
fixed-identity clients, rollback and 22 prospective cases are implemented. Final
focused prerequisites: 28 passed; existing owner regressions: 28 passed; earlier
20 focused passes retained. Static parser passes with no warnings; original lint
and static failures/corrections retained, with no resource event or limit increase.
No privileged activation was authorised or performed. Actual IDs and all 22
real-identity outcomes are pending, not inferred from mocked/static evidence.
The unchanged 256 MiB envelope applies; final preservation results follow in the
report. Only exact IPC source changes and this package's new files/docs are allowed.

Request the user's §5 approval for the concrete runbook before creating accounts,
protected paths or system units. After actual isolation passes, recommend bounded
full lifecycle integration. Production bounded signing, DEP-001/002, complete
private-proof feasibility, integration and privacy/security review stay open.
Stages 2–3 remain incomplete; no proofs or zkVM executions; CPU proving paused,
ledger two attempts used/one unused.


**Final S2-AUTHORITY-ISOLATION-PILOT-1 validation:**
[Preservation](data/s2_authority_isolation_pilot_1/result.json) passes: one complete
run, exit 0, 2.163518033 s, cgroup peak **22,597,632 bytes (21.55078125 MiB)** under
unchanged 256 MiB. All 9,261 historical paths and 974 inventory entries accounted
for; content/report/outer guard complete, no memory/OOM/swap event. Exactly two
IPC source files and three existing status/traceability/issues documents may differ;
original manuscript, dependencies, vectors, historical results and ledger preserved.
Final lint/format pass; 28 focused prerequisites and 28 owner regressions pass,
with 20 earlier focused invocations retained. Twenty-one guarded commands total
35.443476731 s; five reviewed non-resource failures remain recorded.
Implementation is staged, **activation awaits explicit user section 5 approval**,
and all 22 actual-identity cases remain pending. Stages 2–3 remain open; CPU proving
paused, two attempts used/one unused, zero new proofs/zkVM executions. Next: approve
only the exact activation runbook; recommend bounded full lifecycle integration
only after actual isolation passes. Bounded signing and full private-proof
feasibility remain unresolved core obligations.


## S2-AUTHORITY-ISOLATION-PILOT-1 — conditional approval; preflight blocked

The user's activation approval is recorded, subject to its explicit preflight
conditions. [Targeted review](stage2_authority_isolation_pilot.md#conditional-activation-approval--preflight-stopped-19-september-2026)
found that the launcher cannot read its 155,989-byte ledger through a 65,536-byte
reader, the required `/etc/sysusers.d` parent is absent, and complete emergency/
shutdown coverage is not established. Provisioning runs outside `pqiso.slice`;
shutdown accepts empty failed systemd queries. Corrections change sealed privileged
behaviour, so activation stopped before any privileged mutation, as instructed.
All 22 cases are **not run**, with no pilot resources created and no rollback needed.

The existing source seal matches all 96 source inputs/eight fixtures and exact
inventories; all 126 preceding package entries matched before this documentation
append. Neither seal was regenerated. The read-only diagnostic completed under the
unchanged 256 MiB guard: 21,561,344-byte cgroup peak, 0.133094973 s, no memory/OOM/
swap event; this is not an isolation pass. New-script lint/format pass. Existing
functional and preservation evidence is reused; metadata-probe failures are retained.
Next: review concrete guard/prerequisite/stop corrections, then reassess activation.
Bounded full lifecycle integration remains conditional on successful actual-ID
validation. Stages 2–3, production signing and full private-proof feasibility remain
open; CPU proving paused, ledger two attempts used/one unused, no proofs/zkVM runs.

## S2-AUTHORITY-ISOLATION-PILOT-1 — version-2 correction, activation withheld

The [targeted correction](stage2_authority_isolation_pilot.md#targeted-correction-pass--version-2-no-activation)
implements the dedicated bounded ledger reader, explicit absent-only sysusers-parent
creation and independent stop/strict shutdown/rollback. Original sources, seal,
runbook and failed preflight remain immutable. The
[revised runbook](proposals/s2_authority_isolation_pilot_1/v2/README.md) identifies
only the added host actions for approval; original-scope approval is retained.
No activation or privileged host mutation occurred. All 22 actual-ID cases remain
pending. Focused validation is **24/24 passed**, 100 cumulative executed invocations,
22 pending and two unallocated slots under the amended 124 ceiling; no further
focused invocation is authorised by the spent additional allowance. Static parsing
passes. Final quality/audit/resource closure is appended in the implementation
report. Production signing, full private-proof feasibility, full integration and
privacy/security review remain open; Stages 2–3 incomplete. No proofs/zkVM runs;
CPU proving paused, ledger two used/one unused.

**Version-2 correction closed:** 24/24 focused invocations, final lint/format and
static parsing pass. The corrected full audit passes (9,403 historical paths,
1,084 inventory entries), 2.206143964 s and 33,054,720-byte cgroup peak. No activation.
Corrected source/control seal:
`994327b3b0d32d22b6ce9aa09a5125ec798d509ebbdcfa79819bf2225f1a6c32`.
44.775401107 s charged, 255.224598893 s remain including a 10 s emergency reserve;
no resource ceiling changed. The additional 24-test allowance is spent; 100
cumulative invocations, original 22 actual-ID cases pending, two slots unallocated.
No known correction blocker remains; request approval only for the concrete
changed host actions in the [version-2 runbook](proposals/s2_authority_isolation_pilot_1/v2/README.md).
Original-scope approval is retained. Stages 2–3 and signing/private-proof obligations
remain open; no proofs/zkVM runs, ledger two used/one unused.


## S2-AUTHORITY-ISOLATION-PILOT-1 — version-2 activation approved; authentication pending

The user approved the exact version-2 seal
`994327b3b0d32d22b6ce9aa09a5125ec798d509ebbdcfa79819bf2225f1a6c32` and command/host-effect
delta. [Live preflight and current disposition](stage2_authority_isolation_pilot.md#version-2-approval-and-live-preflight--authentication-pending)
confirm all 116 sealed inputs and collision-free real-host prerequisites.
The original sealed runbook and histories remain unchanged. The tool session lacks
interactive sudo authentication; the operator has been asked to execute provision
once and return its final JSON. No privileged command or identity case was launched
by the assistant; all 22 cases remain pending, cumulative invocations 100.
A supplemental five-second observation charge leaves 250.22 s, including the 10 s
emergency reserve, before activation. No resource limit or test allowance is reset.
Do not treat preflight as isolation or shutdown success. After this attempt, the
user-designated next package is **S2-CONCRETE-SECURITY-ASSESSMENT-1**, before further
lifecycle integration, with its task still to be supplied. Stages 2–3, bounded
production signing and complete private-proof feasibility remain open; no proofs
or zkVM executions, proof ledger two used/one unused, CPU proving paused.


## S2-CONCRETE-SECURITY-ASSESSMENT-1 — initial assessment, 24 September 2026

The [task schedule](../PQ_DID_Security_Assessment_Codex_Task.md) and
[initial report](stage2_concrete_security_assessment.md) distinguish assessment
completion from a justified security claim. Source inventory
`b2d0b57afe4b10c1ee6f41fc32ac031da96e332f79a98c6040aaebe1fd07c3a3`;
only manuscript II–VIII plus SPEC-001–004. Active configuration and production
source unchanged. Separate analysis budget; no estimator, proof, zkVM or deployment
execution. Proving remains paused, two attempts used and one unused.

The ideal-QROM rows reproduce extraction `<2^-148`/`<2^-116` and privacy
`<2^-150`/`<2^-134` at Q=2^64/2^80, N=2^32. All four model tail inequalities
hold. `Delta_tail`, component advantages at reduction runtime, concrete outer
SHAKE256 instantiation and complete private-proof evidence remain unresolved.
No overall classical/quantum bit level is justified. ML-DSA-65 Category 3 is a
component classification; historical RISC Zero enrolment is separate evidence.

Isolation is safely stopped **unactivated**, verified by strict read-only host
queries. The pending 22 identity cases, approval, original failures and separate
250.22-second allowance are retained. No isolation validation is claimed.

| Trigger | Required security checkpoint |
| --- | --- |
| Current Stages 2–3 | Initial actual-profile/source/calculation assessment; completed with explicit unresolved terms, not an overall security claim |
| Stage 2 bounded key generation/signing/release | Randomness, caps, exhaustion, pre-release verification, lifetime invocation totals and `Delta_tail`; retain DEP-001/DEP-002 |
| Stage 3 before adopting/freezing any proof profile | Exact circuit/program, mode and recursion/compression; soundness/knowledge/ZK and quantum assumptions; refresh affected bounds |
| Stages 4–5 complete PQ-DAA/KYC integration | Same certified witness/holder/disclosures/rid, journal leakage, currentness/replay/revocation, side channels and deployment |
| Stages 6–8 baselines/comparisons/benchmarks | Exact comparator profiles, multi-key/target effects and lifetime nonce/cap counts; refresh parameter/dependency/proof-mode changes |
| Stage 9 reproduction/manuscript claims | Final revision/workload/current primary evidence against II–VIII; omit unsupported overall numbers |

Next bounded recommendation: **S3-OUTER-HASH-SECURITY-REVIEW-1**, source-only
quantitative instantiation and exact game-mapping review before profile adoption
or substantial lifecycle integration. No alternative profile is adopted.
Stages 2–3, bounded production signing, recovery/isolation and complete private-proof
feasibility remain open. Refresh only affected findings at each trigger; no timed
or background automation is established. Validation closure is appended after the
single guarded preservation audit.


Security-assessment validation closure (24 September 2026): eight independent
checks, lint and formatting passed. The single [complete preservation audit](data/s2_concrete_security_assessment_1/result.json)
passed comparison, report readback and the unchanged 256 MiB outer guard: 9,487
content paths, 9,500 identity-inclusive paths, no unexpected changes/removals;
2.310877172 seconds, 23,543,808-byte charged cgroup peak. Separate assessment
accounting is 8.593910845 / 300 seconds; this consumes no isolation/proof allowance.
Only the exact new analysis/evidence and append-only report updates were permitted.
Initial assessment complete with unresolved terms; no overall security number,
Stage 2/3 completion, deployment validation or production signing claim. No
estimator/proof/zkVM execution; two proof attempts used and one unused.


## S3-OUTER-HASH-SECURITY-REVIEW-1 — 24 September 2026

The [outer-hash review](stage3_outer_hash_security_review.md) is complete with an
explicit conditional-profile decision. ACMT arXiv:2504.16887v2 Theorem 7.22 supports
quantum domain extension in the random-permutation model. Fixed Keccak, the joint
internal/outer-hash game, DFMS compressed-oracle extraction and GHM adaptive
simulation still require distinct arguments. No additive concrete knowledge/privacy
loss or overall bit-security number is established; a weak bound is not an attack.

The existing ideal-QROM rows and model tails are preserved. New analysis records
canonical framing/block lengths and query/simulator mappings, with full-authentication
quantities symbolic. The theorem's unspecified constants are not set to one.
No profile change: retain current SHAKE256 only as a qualified research reference;
compare a joint-game contract revision and one unadopted balanced-sponge option.

Next bounded recommendation: **S3-OUTER-ORACLE-COMPOSITION-1**, a written typed
shared-permutation/game/extractor/simulator mapping for VIII-C/D before any proof
profile adoption. Deliver a compatible lemma or identify the exact incompatible
interface; no execution, deployment or profile change is inferred. SEC-001–005,
adaptive Delta_tail, component advantages at reduction budgets, bounded production
signing, complete private-proof knowledge/privacy and Stages 2–3 remain open.

Safe-stopped unactivated isolation, 100 historical invocations, 22 pending cases,
approval and 250.22 s including the ten-second reserve remain unchanged. No new
proof, zkVM, estimator, circuit generation, dependency installation or activation;
CPU proving paused, proof ledger two attempts used and one unused. Separate
security-analysis accounting carries forward 8.593910845 s of its 300 s allowance.
Final guarded validation/preservation measurements are appended after completion.


Outer-hash review validation closure: the [complete audit](data/s3_outer_hash_security_review_1/result.json)
passed comparison, report readback and the unchanged 256 MiB cgroup guard, exit 0:
9,543 content paths / 9,556 identity-inclusive paths; 2.349347859 s,
22,405,120-byte charged cgroup peak, no unexpected changes.
Four distinct mapping checks pass after one preserved non-resource harness failure
(five group invocations including the aborted first group); lint/format pass.
Continued security-analysis charge 16.956706719/300 s, remaining 283.043293281 s;
no isolation/proof allowance consumed. Historical baselines and report prefixes
remain intact. [Review and decision](stage3_outer_hash_security_review.md): retain
qualified current profile; next S3-OUTER-ORACLE-COMPOSITION-1. No quantitative concrete
knowledge/privacy guarantee, overall security number or Stage 2/3 completion.
No proof/zkVM/activation; ledger two used and one unused, proving paused.


Finalisation addendum: the first post-guard bookkeeping command exited 1 when the
write-once report helper correctly refused a second write to the newly created
closure record. The full audit and its report/readback/outer guard had already
completed successfully and were not repeated. The initial closure and unsealed
manifest placeholder are retained verbatim inside the final records, together with
the error and narrowly scoped finalisation. No resource breach or historical
record replacement occurred; the audit engine is unchanged.

An additional conservative five-second finalisation charge supersedes the preceding
accounting totals: **21.956706719 / 300 s charged,
278.043293281 s remaining**. This reduces the existing
security-analysis allowance; no ceiling is increased or isolation/proof time used.
The final evidence records one guarded validation-harness failure/correction and
one post-guard bookkeeping failure/finalisation. All four mapping checks, final
lint/format and the single complete preservation audit passed. The recommendation
and open obligations remain unchanged.


## S3-OUTER-ORACLE-COMPOSITION-1 — finite decision, 25 September 2026

The [composition review](stage3_outer_oracle_composition.md) completes the bounded
assessment with precisely stated missing lemmas. ACMT 7.22 supports a defined
ordinary bounded oracle-wrapper comparison. DFMS terminal extraction/event
restriction and GHM/raw-view privacy simulation remain supported in the stated
fixed-relation ideal-QROM model. Neither supplies the shared-permutation BC-1
relation, a legal shared-oracle extractor, or the complete joint privacy simulator.
No automatic indifferentiability-error addition or concrete Keccak security number
is made. The separated-primitive diagnostic model is explicitly not an adoption.

OC-REL, OC-EXT, OC-PRIV and OC-BUDGET refine SEC-002; A-K-MODEL remains an explicit
fixed-Keccak modelling assumption. These are finite findings, not a claim of attack
or impossibility. SHAKE256 remains the qualified research reference. Future proof
profile adoption/claims must resolve the applicable obligations, including complete
circuit equivalence and the separate RISC Zero knowledge/privacy questions.

**Next implementation recommendation: S2-BOUNDED-MLDSA-KEYGEN-SIGN-1.** Implement the
bounded fixed-parameter reference core, setup/import consistency and fail-closed
signer adapter, with sampler/attempt exhaustion and pre-release validation. Retain
DEP-001/002, conditional signing tails, adaptive Delta_tail, enlarged component
reduction budgets, randomness and production release/side-channel obligations.
This recommendation does not begin another package or activate signing/services.
No additional composition review is scheduled automatically.

Source, active parameters, dependencies, manuscript and all prior evidence remain
protected. Only II–VIII and SPEC-001–004 are authoritative. Stages 2–3 stay open;
no installations, circuits, estimator runs, proofs, zkVM executions or activation.
Isolation remains safely stopped unactivated: 100 invocations, 22 pending cases,
approvals/failures and 250.22 s including its ten-second reserve unchanged. CPU
proving paused, proof ledger two used/one unused. Analysis allowance carries forward
21.956706719007343 s charged / 278.04329328099266 s remaining, without borrowing
isolation/proof time. Final measured validation closure is appended below.


Composition-review validation closure: one documentation-contract check and
lint/format pass. The single [complete preservation audit](data/s3_outer_oracle_composition_1/result.json)
passed comparison, inventory, report readback and the unchanged 256 MiB cgroup guard,
exit 0: 9,596 content paths,
2.155260734 s, 22,163,456-byte charged peak.
No new failure, resource breach or retry; historical failures and seals preserved.
Continued analysis accounting **29.818518832/300 s**, **270.181481168 s remain**;
no isolation/proof allowance consumed. Numerical/functional validation was reused.
Finite review complete with the specified missing lemmas; no concrete knowledge/
privacy transfer or overall bit-security claim. Next implementation recommendation
S2-BOUNDED-MLDSA-KEYGEN-SIGN-1, not started. Stages 2–3 and existing obligations
remain open; isolation unactivated, proof ledger two used/one unused.

## S2-BOUNDED-MLDSA-KEYGEN-SIGN-1 — reference core, 25 September 2026

[The bounded keygen/signing report](stage2_bounded_mldsa_keygen_sign.md) records a
new, separate ML-DSA-65 reference core. Exact expanded-key generation, bounded
import consistency, pure context processing, hedged signing wrappers, all fixed
sampler/candidate caps and bounded verification before signature return are
implemented. Existing production adapters and the verifier remain unchanged.

49 focused tests, nine final interoperability tests and 12 scoped frozen-vector
regressions pass. Two keypairs and six signatures match the pinned portable native
implementation byte for byte. A source-reviewed native ABI harness correction
required nine targeted repeats: 79 total invocations, including retained preliminary
results, within the 100-invocation implementation allowance. It did not change the
algorithm, native library or global random machinery. No functional test failed.

DEP-002 reference keygen/sign/import is implemented, not production release
readiness. DEP-001, adaptive Delta_tail, component reduction budgets, secure erasure,
side channels, key storage/authority, service integration and complete proof
knowledge/privacy remain open. This package uses a separate bounded implementation
budget; the 270.181481168-second analysis and 250.22-second isolation allowances
are unchanged. Isolation is safely stopped/unactivated, with 22 cases still pending.
Stages 2–3 stay open; proof ledger two used/one unused, CPU proving paused. No host
activation, installations, circuits, proofs or zkVM executions.

Next bounded recommendation: **S2-BOUNDED-SIGNER-RELEASE-CONTRACT-1**, isolated
synthetic role/key/failure and no-partial-release adapter checks while production
defaults remain fail closed. No next package is started. Complete preservation
and measured resource closure follow below.


Bounded-keygen/signing validation closure: lint/format and all selected tests pass,
79/100 implementation invocations including nine source-reviewed ABI repeats.
The single [complete preservation audit](data/s2_bounded_mldsa_keygen_sign_1/result.json)
passed content/inventory, report readback and the unchanged 256 MiB cgroup guard:
9,638 disjoint content paths,
2.330812694 s, 23,130,112-byte audit peak.
Maximum new-job peak 48,275,456 bytes; zero functional failures/resource breaches.
Separate implementation budget 11.616396493/300 s charged,
288.383603507 s remaining. Analysis 270.181481168 s and isolation 250.22 s
unchanged. New reference core only; original code, vectors, parameters and historical
evidence preserved. Production signing, DEP-001/002, Delta_tail and full proof
knowledge/privacy remain open; Stages 2–3 incomplete. Next recommendation
S2-BOUNDED-SIGNER-RELEASE-CONTRACT-1, not started. No activation/proofs/zkVM;
proof ledger two used/one unused, CPU proving paused.

## S2-BOUNDED-SIGNER-RELEASE-CONTRACT-1 — reference adapters, 25 September 2026

[The release-contract report](stage2_bounded_signer_release_contract.md) records
isolated adapters for all nine existing signing contexts. Trusted owner configuration
pins the role/key reference/public identity/instance; typed canonical operations,
default-deny authorisation and pre/post-sign admission use the completed bounded core.
The old lifecycle engines, production defaults and primitive source remain unchanged.

18 focused synthetic checks pass: permanent issuance reservation/log-before-release,
atomic in-memory revocation, DID rotation/deactivation, nonce retention, entropy and
exhaustion failure, post-verification rejection, durable issuer commit/fencing and
recipient-bound recovery/redelivery without a new signature. Temporary SQLite and
application fault tests establish the exercised transaction contracts, not power-loss
durability or actual-UID isolation. No native ABI harness/historical suites repeated.

Implementation accounting continues from 11.616396492929198/300 s and 79/100 tests;
18 new invocations bring the total to **97/100, three remaining**. Final measured
lint/format/preservation and wall-accounting closure follow below. Analysis
270.1814811680233 s and isolation 250.22 s remain separate and unchanged. Isolation
is safely stopped/unactivated, 22 identity cases still pending. No installation,
host activation, estimator/circuit/proof/zkVM work. Proof ledger two used/one unused.

DEP-002 reference adapters advance; production custody/entropy/erasure/side channels,
all-role durable release and live authority integration remain open, alongside DEP-001,
adaptive Delta_tail and complete proof knowledge/privacy. Stages 2–3 remain open.
One next bounded implementation recommendation: **S2-BOUNDED-MANAGER-DURABLE-RELEASE-1**,
temporary synthetic atomic manager publication/recovery/fencing, with no deployment.
Its test plan must respect the remaining allowance or obtain an explicit amendment.


Bounded-signer release validation closure: lint/format and all 18 new tests pass,
97/100 cumulative implementation invocations, three remaining; no new repeats.
The single [complete preservation audit](data/s2_bounded_signer_release_contract_1/result.json)
passed content/inventory, report readback and the unchanged 256 MiB cgroup guard:
9,701 disjoint content paths,
2.286035420 s, 23,945,216-byte audit peak.
Maximum new-job peak 49,573,888 bytes; zero functional failures/resource breaches.
Continued implementation budget 30.539082389/300 s charged,
269.460917611 s remaining. Analysis 270.181481168 s and isolation 250.22 s
unchanged. New opt-in reference adapters only; original code, vectors, parameters and historical
evidence preserved. Production signing, DEP-001/002, Delta_tail and full proof
knowledge/privacy remain open; Stages 2–3 incomplete. Next recommendation
S2-BOUNDED-MANAGER-DURABLE-RELEASE-1, not started. No activation/proofs/zkVM;
proof ledger two used/one unused, CPU proving paused.

## S2-BOUNDED-MANAGER-DURABLE-RELEASE-1 — reference publication, 25 September 2026

[The durable manager report](stage2_bounded_manager_durable_release.md) records a
new opt-in facade using the unchanged SQLite store, bounded signing adapter and
recovery contracts. Signed state/update, complete manager checkpoint/history/nonce
set, operation outcome and head commit in one database transaction before release.
Signing occurs privately; commit rechecks the exact head, state and writer fencing.
Stored public retrieval signs zero times; stale writers and superseded current
replies cannot enqueue. Recipient-bound issuer delivery remains separate.

**24 new cases pass**: 22 individually counted manager integration cases plus two
real child-process SIGKILL cases at rows-before-commit and commit-before-ack. The
first recovers the original state with no outcome; the second recovers the complete
committed result and exact redelivery using an independently retained test head.
Simulated faults are labelled separately. No power-loss/whole-store-rollback or
live-identity protection is inferred. No existing implementation source is changed.

The explicit user amendment raises the cumulative ceiling **100 → 124**; prior
97 plus new 24 means **121/124 used, three remaining**, with no test failures/repeats.
Time carries forward from 30.539082388975658/300 s charged; the measured final
lint/format/preservation closure follows. Analysis 270.1814811680233 s and isolation
250.22 s stay untouched. Isolation safely stopped/unactivated; 22 cases pending.
No installation, activation, circuits, proofs or zkVM; proof ledger two used/one unused.

The specific reference durable-publication obligation advances. Production
custody/entropy/erasure/side-channel resistance, all-role integration, DEP-001,
adaptive Delta_tail and complete proof knowledge/privacy remain open. Stages 2–3
remain open. Next bounded recommendation: **S2-DURABLE-ISSUER-MANAGER-INTEGRATION-1**,
synthetic intent/reservation/reconciliation integration without cross-store atomicity
claims, scoped to the remaining allowance or an explicit amendment; not started.


Bounded-manager durable-release validation closure: lint/format and all 24 new tests pass,
121/124 cumulative implementation invocations, three remaining; no new repeats.
The single [complete preservation audit](data/s2_bounded_manager_durable_release_1/result.json)
passed content/inventory, report readback and the unchanged 256 MiB cgroup guard:
9,754 disjoint content paths,
2.347716602 s, 23,076,864-byte audit peak.
Maximum new-job peak 59,478,016 bytes; zero functional failures/resource breaches.
Continued implementation budget 48.714120727/300 s charged,
251.285879273 s remaining. Analysis 270.181481168 s and isolation 250.22 s
unchanged. New opt-in durable manager only; original code, vectors, parameters and historical
evidence preserved. Production signing, DEP-001/002, Delta_tail and full proof
knowledge/privacy remain open; Stages 2–3 incomplete. Next recommendation
S2-DURABLE-ISSUER-MANAGER-INTEGRATION-1, not started. No activation/proofs/zkVM;
proof ledger two used/one unused, CPU proving paused.

## S2-DURABLE-ISSUER-MANAGER-INTEGRATION-1 — synthetic proof lifecycle, 25 September 2026

[The integration report](stage2_durable_issuer_manager_integration.md) records a new
owner-local path joining the unchanged bounded issuer, durable manager and separate
authority stores. Intent, permanent reservation, attachment, pending nonce, signing
claim and certification keep their individual commits; explicit reconciliation
retires incomplete work without reallocation. Original-recipient redelivery uses
committed bytes without signing; existing holder checks precede atomic acceptance.

**24 new cases pass**, including two actual SIGKILLs after reservation/certification
commit. All positive cases explicitly inject a narrowly bound test-only synthetic
proof verifier. The normal proof adapter remains unsupported/fail-closed; this is
not complete PQ-DAA, anonymous authentication or real-proof security evidence.
Manager changes before the final ordered read abort issuance; later changes do not
retroactively invalidate its old checkpoint or establish current non-revocation.

The user amended the invocation ceiling **124 → 148**: prior 121 + new 24 =
**145/148 used, three remaining**, no test failure/repeat. The 300-second allowance
carries forward from 48.71412072714884 s charged / 251.28587927285116 s remaining.
Final measured lint/format/preservation closure follows below. Analysis
270.1814811680233 s and isolation 250.22 s remain untouched; isolation is safely
stopped/unactivated with 22 pending cases. No installation/activation/proof/zkVM.

Stages 2–3 remain open, including production custody/entropy/erasure/side channels,
real proof verification, durable holder and verifier integration, recovery freshness,
adaptive Delta_tail and complete proof knowledge/privacy. Proof ledger two used/one
unused, CPU proving paused. Next bounded recommendation:
**S2-DURABLE-VERIFIER-LIFECYCLE-INTEGRATION-1**, synthetic bounded request/current and
durable challenge/consumption integration with default proof failure preserved;
not started, and subject to the actual remaining invocation allowance.


Issuer-manager lifecycle validation closure: lint/format and all 24 new tests pass,
145/148 cumulative implementation invocations, three remaining; no new repeats.
The single [complete preservation audit](data/s2_durable_issuer_manager_integration_1/result.json)
passed content/inventory, report readback and the unchanged 256 MiB cgroup guard:
9,809 disjoint content paths,
2.369247573 s, 23,175,168-byte audit peak.
Maximum new-job peak 89,354,240 bytes; zero functional failures/resource breaches.
Continued implementation budget 85.601982479/300 s charged,
214.398017521 s remaining. Analysis 270.181481168 s and isolation 250.22 s
unchanged. New synthetic-proof lifecycle integration only; original code, vectors,
parameters and historical evidence preserved. Production signing, DEP-001/002,
Delta_tail and full proof knowledge/privacy remain open; Stages 2–3 incomplete.
Next recommendation
S2-DURABLE-VERIFIER-LIFECYCLE-INTEGRATION-1, not started. No activation/proofs/zkVM;
proof ledger two used/one unused, CPU proving paused.

## S2-DURABLE-VERIFIER-LIFECYCLE-INTEGRATION-1

[Verifier lifecycle integration](stage2_durable_verifier_lifecycle_integration.md)
connects two independent durable verifier stores/audiences to bounded request
signing and authenticated durable-manager reads. Existing full-context/public-policy,
proof, final read, strict expiry and atomic consumption semantics are preserved.
24 distinct cases pass, with three retained assertion-label failures and three
reviewed repeats: **145 + 27 = 172/172 invocations**, none remaining. No new process
crash or private-relation evaluation is claimed; existing verifier crash evidence
is reused. Normal missing proof verification stays fail-closed; positive outcomes
use test-only exact synthetic public statement/token acceptance.

Consumption/checkpoint/outcome/head commit precedes ACCEPTED. Lost post-commit
acknowledgement leaves consumption; restart cannot replay or publish verifier
acceptance as redelivery. Ordered manager read and local consumption are separate
transactions. Stages 2–3 remain open, including real proof knowledge/privacy,
production custody/entropy/erasure/side channels, Delta_tail and durable holder/KYC
integration. Isolation remains safely stopped/unactivated, 22 identity cases pending;
proof ledger two used/one unused. Next proposed package:
S2-HOLDER-WITNESS-REVOCATION-INTEGRATION-1, subject to a new test allowance, not started.


Verifier lifecycle closure: 24 distinct cases finally pass, three assertion failures
and targeted repeats retained; **172/172** cumulative invocations, zero remaining.
Lint/format and the single
[preservation audit](data/s2_durable_verifier_lifecycle_integration_1/result.json) pass:
9,865 disjoint content paths, complete reporting,
2.406519050 s, 23,465,984-byte cgroup peak
under unchanged 256 MiB. Maximum job peak 70,217,728 bytes; no resource breaches.
Implementation **116.659475644/300 s** consumed, **183.340524356 s** remain, including
failed tests and bookkeeping. Analysis/isolation unchanged. Synthetic proof acceptance
only; production signing/security and proof knowledge/privacy remain unresolved.
Stages 2–3 open; isolation safely stopped/unactivated; proof ledger two used/one unused.
Next recommendation S2-HOLDER-WITNESS-REVOCATION-INTEGRATION-1, not started; an explicit
new test allowance is required.

## S2-HOLDER-WITNESS-REVOCATION-INTEGRATION-1

[Holder integration and KYC checklist](stage2_holder_witness_revocation_integration.md)
connect issued credentials and initial authenticated witnesses to bounded public
updates, atomic in-memory witness/state replacement and prepared inputs for two
durable verifiers. The scenario distinguishes A real bounded cryptography, B complete
local auth with a private witness, and C synthetic public-only proof acceptance.
Own revocation returns REVOKED without mutation; local auth rejects at the new root
without invoking a synthetic rejection verdict.

All **22 cases pass first run**, no repeats; **194/199** cumulative invocations,
five remaining. Existing replay/crash/core/max-batch evidence reused. No holder
wallet durability, real proof, live service or W3C interoperability claim. Stages
2–3 remain open, including production signing/custody/entropy/erasure/side channels,
adaptive Delta_tail and complete proof knowledge/privacy. Isolation safely stopped/
unactivated, proof ledger two used/one unused. Next recommendation:
S2-KYC-INTEROPERABILITY-CONTRACT-1, not started, within existing or amended budgets.


Holder integration closure: all 22 cases pass first run, **194/199** cumulative
invocations, five remain. Lint/format and the single
[preservation audit](data/s2_holder_witness_revocation_integration_1/result.json) pass:
9,958 disjoint content paths, completed reporting,
2.375583138 s and 24,059,904-byte audit
cgroup peak under unchanged 256 MiB. Maximum job peak 112,439,296 bytes; no functional failures,
repeats or resource breaches. Two lint diagnostics are retained.
Implementation **178.704218466/300 s** consumed,
**121.295781534 s** remain; separate analysis/isolation unchanged. Evidence A actual
bounded crypto, B complete local auth and C synthetic verifier acceptance remain
separate. No durable wallet or complete private-proof security claim. Stages 2–3
open; safely stopped isolation and proof ledger two used/one unused preserved.
Next: S2-KYC-INTEROPERABILITY-CONTRACT-1, not started.

## S2-KYC-INTEROPERABILITY-CONTRACT-1

[Application contract](stage2_kyc_interoperability_contract.md) maps issuer, private
holder, two verifiers, registry/resolver and public revocation services to existing
canonical inputs and release/retrieval semantics. Fifteen labelled synthetic JSON
examples separate holder-private material from public disclosed presentations.
Proposed base64url/decimal-string/parser conventions do not alter signed bytes.
DID Core 1.0 (2022-07-19) and VC Data Model 2.0 (2025-05-15) requirements are mapped;
no registered method/cryptosuite/status mechanism or W3C conformance is claimed.

Starting balance194/199 invocations and121.295781534 implementation seconds; four
new example checks planned. A preflight-helper assertion typo and its source-reviewed
correction are retained and charged; no historical functional suite is repeated.
Final measurements follow below. KYC-INT-001–004 remain open, along with durable
wallet storage, real proof integration, downstream KYC action/reply recovery and
production security. Stages2–3 open; isolation safely stopped/unactivated,22 pending
identity cases and separate allowance preserved; proof ledger two used/one unused.
Next recommendation:S2-KYC-CONTAINER-ADAPTER-1, with a new focused test allowance;
not started. No installation, activation, profile change, proof or zkVM execution.


KYC contract closure: four example checks pass, **198/199** cumulative invocations,
one remaining; lint/format pass. One preflight-helper typo failure and its corrected
follow-up remain charged and preserved. No functional repeat or resource breach.
The single [audit](data/s2_kyc_interoperability_contract_1/result.json) passes complete
content/inventory/reporting and unchanged256MiB guard:
10,030 disjoint content paths,
2.316034001s, 23,195,648-byte peak.
Implementation 187.316291120/300s consumed, **112.683708880s remain**;
analysis/isolation unchanged. Proposed container mapping, no W3C conformance or
secured-VC/VP claim. Production sources preserved. Stages2–3 open; isolation stopped/
unactivated, proof ledger2used/1unused. Next:S2-KYC-CONTAINER-ADAPTER-1, not started;
a new focused test allowance is needed for implementation validation.

## S2-KYC-CONTAINER-ADAPTER-1

[Bounded container adapter](stage2_kyc_container_adapter.md) adds one isolated source
module and24 individually counted tests, all passing first run. Version
`pqdid-application-container-1` adopts strict bounded project-local JSON/base64url/
decimal-string conversion; frozen receiver/instance and independent context/query
bindings prevent metadata trust overrides. Outputs are unverified typed inputs.
Synthetic inspection is separate; ordinary proof, DID-method and verification-outcome
admission remain unsupported. No W3C or complete proof-security claim.

User amendment199→223,198 previously consumed; now **222/223**, one left. Starting
implementation balance112.683708880s; measured closure follows. No lifecycle/native
suite replay. Source-level preallocation guarantees and allocated-string/result limits
are explicit in the report. KYC-INT-001–004, durable holder storage, production security,
Delta_tail and complete proof knowledge/privacy remain open. Stages2–3 remain open;
isolation safely stopped/unactivated,22 identity cases pending, separate budget intact;
proof ledger two used/one unused. No installation, activation, proof or zkVM execution.
Next recommendation:S3-AUTH-PROOF-FEASIBILITY-PLAN-1, bounded source/evidence planning
for the complete KYC authentication proof, not started and no execution implied.


Container adapter closure: **24/24** distinct cases pass first run; lint/format pass,
**222/223** cumulative invocations, one remaining. No failure/repeat/resource breach.
The single [audit](data/s2_kyc_container_adapter_1/result.json) passes complete content,
inventory/reporting and unchanged 256 MiB guard: 10,100
disjoint content paths, 2.425557629 s,
23,527,424-byte audit peak. Implementation
195.863037117/300 s consumed, **104.136962883 s remain**; analysis/isolation unchanged.
Structural input conversion only; no authentication, proof or W3C conformance claim.
Existing code/parameters/evidence preserved; Stages 2–3 open, isolation stopped/
unactivated, proof ledger two used/one unused. Next recommendation:
S3-AUTH-PROOF-FEASIBILITY-PLAN-1, not started; no execution or proof attempt authorised.


## S3-AUTH-PROOF-FEASIBILITY-PLAN-1 — negative adoption decision

The [complete-private-authentication plan](stage3_auth_proof_feasibility_plan.md)
separates the full local predicate, public PubOK/Ppub and lifecycle checks from
BC-1 fragments and R0 enrolment/CredValid evidence. **No evaluated route presently
has an evidenced path to the complete security and proposed KYC performance
requirements.** CPU proving stays paused; no final attempt is admitted. CredValid's
9.893-hour forecast is unmeasured and already includes its 50% allowance; neither
that fragment nor the measured enrolment receipt is a complete authentication proof.

A construction decision is needed on separately replacing BC-1 lowering and raw
MITH proof representation while preserving the same mathematical private relation.
One proposed next package: **S3-PRIVATE-HINT-LOWERING-PILOT-1**, a bounded isolated
complete-decoder/equivalence/count screen. At most eight individually counted cases
and 30 charged implementation seconds, including required evidence, are proposed;
the additional eight-invocation amendment (223→231) and new lowering are **inactive
until authorised**. Success would admit only a component, never a profile/proof.

This planning package uses the existing analysis allowance. Implementation stays
104.136962883 s and 222/223 tests; isolation remains safely stopped/unactivated,
22 identity cases pending, 250.22 s retained. Proof ledger two used/one unused.
Stages 2–3 remain open. Complete proof knowledge/privacy, concrete security/tails,
production custody/entropy/erasure/side channels, durable holder storage and
KYC-INT-001–004 W3C mappings remain unresolved. No execution/build/install/activation.


Authentication feasibility planning closure: helper lint/format and one documentation
consistency check pass. The single
[complete audit](data/s3_auth_proof_feasibility_plan_1/result.json)
passes 10,145 disjoint content paths, exact inventory,
report readback and unchanged 256 MiB outer guard: 2.283966482 s,
24,895,488-byte cgroup peak. Two E501 lint failures
are retained, with a final passing named check; no resource breach or full-audit retry.
Analysis 38.184259331/300 s charged, **261.815740669 s remain**.
Implementation unchanged **104.136962883 s, 222/223 tests**; isolation unchanged
250.22 s, safely stopped/unactivated. No cryptographic executions, new calculations,
builds, proof guests or proofs. No route/profile admitted. Stages 2–3 remain open,
proof ledger two used/one unused. Next proposed for authorisation only:
**S3-PRIVATE-HINT-LOWERING-PILOT-1**; no active lowering or allowance change.


## S3-PRIVATE-HINT-LOWERING-PILOT-1 — isolated component result

The [pilot](stage3_private_hint_lowering_pilot.md) completes one generation probe
and eight distinct differential cases: all pass. Candidate **383,420 gates /
203,142 ANDs**, generation0.451736s, with original42,632 private positions, complete
endpoint/order/padding validation and all1,536 signed64-compatible hint outputs.
The original13,532,448-AND result is a capped prefix, not a complete matched decoder.
No complete-authentication speedup or updated R0 forecast follows. The active
BC-1 source-order/scanning/compiler rules and all historical evidence are unchanged.

Decision: a justified component candidate for integration into a **separately
reviewed lowering/profile**, not canonical BC-1 and not a selected proof backend.
All malformed cases reject with unusable outputs; finite tests are not universal
equivalence. Active/inactive upstream integration needs later dedicated coverage.
Full polynomial/NTT arithmetic, path composition, compiler equivalence and proof
knowledge/privacy remain unresolved. Next proposed only:
S3-MLDSA-ARITHMETIC-LOWERING-REVIEW-1, bounded source/range design; not started.

The user amendment223→231 preserves222 historical invocations; one generation plus
eight cases consumes the nine available. Analysis/isolation budgets unchanged.
Package validation/closure below records actual implementation charge within30s.
Stages2–3open, safely stopped/unactivated isolation, proof ledger2used1unused.
No proof, guest execution, installation, activation or active parameter change.


Private-hint pilot closure: **one generation + eight differential cases pass**,
**231/231** cumulative invocations, zero remaining. Candidate complete:
383,420 gates / 203,142 ANDs; original
13,532,448-AND result is a capped prefix, not a complete matched baseline.
A useful component candidate under a proposed new lowering, **not BC-1** or a
full-authentication/proof result. Lint/format and the
[single audit](data/s3_private_hint_lowering_pilot_1/result.json) pass:
10,205 disjoint paths,
2.423156706 s,
23,277,568-byte cgroup peak under256MiB.
Package 9.760450599/30 s charged, implementation
205.623487716/300 s used, **94.376512284 s remain**; analysis/isolation unchanged.
No failures, repeats or resource breaches. Active parameters/compiler preserved.
Stages2–3open, isolation stopped/unactivated, proof ledger2used1unused.
Next proposed only:S3-MLDSA-ARITHMETIC-LOWERING-REVIEW-1; not started.

## S3-MLDSA-ARITHMETIC-LOWERING-REVIEW-1 — source-only candidate decision

The [arithmetic review](stage3_mldsa_arithmetic_lowering_review.md) selects one
implementation-ready experimental public-constant modular multiplication kernel:
canonical23 operands, exact46 product and fixed restoring remainder. Canonical
entry guards and boundary range proofs are mandatory; the generic signed64 gadget
cannot be replaced for arbitrary inputs. The actual verifier's public factors,
ordinary NTT/inverse scaling, ordered reductions, norm and exceptional decomposition
semantics are mapped. Existing post-SPEC-004 counts are reused, not remeasured.

This is a proposed new lowering, not BC-1 conformance, hint-profile adoption or a
full-authentication/proof saving. ARITH-LOWER-001 is open. Next proposed only:
**S3-MLDSA-MODMUL-LOWERING-PILOT-1**, 16 explicitly listed invocations and ≤30 charged
implementation seconds, all allowances inactive. This review uses analysis only;
implementation94.376512284s and231/231 tests unchanged. Isolation remains safely
stopped/unactivated; CPU proving paused, proof ledger two used/one unused.
Stages 2–3 and production/adaptive Delta_tail/complete proof-security obligations
remain open. No tests, probes, circuit generation, builds or activation occurred.


Arithmetic lowering review closure: source/documentation checks and the
[single preservation audit](data/s3_mldsa_arithmetic_lowering_review_1/result.json)
pass, 10,250 disjoint content paths,
2.485872072 s, 23,232,512-byte
cgroup peak under the unchanged 256 MiB ceiling. Analysis charge
46.393514843/300 s; **253.606485157 s remain**. Implementation unchanged
**94.376512284 s; 231/231 tests**, no tests/probes/circuits generated. No failures
or retries. Canonical-residue 23-bit multiplication is selected for an inactive
S3-MLDSA-MODMUL-LOWERING-PILOT-1 proposal; no profile adopted. ARITH-LOWER-001,
HINT-LOWER-001, complete authentication/proof and security obligations remain open.
Stages 2–3 open, isolation safely stopped/unactivated; proof ledger two used/one unused.

## S3-MLDSA-MODMUL-LOWERING-PILOT-1 — isolated public scalar lowering

The [modmul pilot](stage3_mldsa_modmul_lowering_pilot.md) implements a separate
canonical23/exact46/restoring25-bit kernel with complete private-input guards,
public-constant validation and unusable masked outputs. Production BC-1 stays
unchanged. Two paired generation probes target actual ordinary-residue constants
4808194/8347681; ten distinct differential and four constant-rejection cases form
the16-invocation amendment231→247. Complete results and actual accounting follow
in the measured closure. No tests beyond those sixteen are authorised.

No signed-entry conversion, complete transform/verifier or proof saving is inferred.
ARITH-LOWER-001 remains open for composition/conformance. Implementation starts
94.376512284s, package≤30s including audit; analysis/isolation remain untouched.
Stages2–3open, isolation safe-stopped/unactivated, CPU proving paused, proof ledger
2used1unused. Production/security/Delta_tail/complete knowledge/privacy stay open.

Measured scalar outcome: all16 invocations pass; for both4808194 and8347681,
complete guarded baseline83,032 gates/34,550 ANDs versus candidate15,158/6,161.
No capped prefix, retries or resource stop. The candidate merits only a separately
bounded butterfly composition experiment; signed-entry conversion, complete
transforms/authentication and proof security are still unvalidated.


Modmul pilot closure: **merits-bounded-composition**. Two paired generation probes, ten differential
cases and four invalid-constant cases pass: **247/247** cumulative, zero remaining.
Both public-constant kernels have complete matched guarded counts in the
[report](stage3_mldsa_modmul_lowering_pilot.md); no full-transform/proof claim.
Lint/format and the [single audit](data/s3_mldsa_modmul_lowering_pilot_1/result.json)
pass 10,290 disjoint paths, 2.465593635s,
23,232,512-byte cgroup peak under256MiB.
Package8.827576857/30s; implementation214.451064573/300s used,
**85.548935427s remain**. Analysis/isolation unchanged. No failures/retries.
ARITH-LOWER-001 remains open for composition/conformance; Stages2–3open,
proof ledger2used1unused. Next proposed only: S3-MLDSA-BUTTERFLY-COMPOSITION-PILOT-1: separately bounded forward/inverse butterfly composition with exact entry conversions, guards and matched counts.


## S3-MLDSA-BUTTERFLY-COMPOSITION-PILOT-1 (26 September 2026)

Authorised isolated forward-butterfly composition; see the
[contract, individual outcomes and measured closure](stage3_mldsa_butterfly_composition_pilot.md).
The user adds16 invocations,247→263, with≤30 implementation seconds from
85.54893542698119s remaining. Analysis/isolation allowances are unchanged.
Existing generic signed64 input acceptance is retained through exact overflow
predicates and complete signed-to-canonical conversions; the two-node fragment
uses actual forward twiddles4808194 and3765607. The third frontier input is
explicit, not a generated full layer. No trusted-input or inverse-transform claim.
ARITH-LOWER-001 remains open for complete transform composition and proposed
compiler/profile adoption. Production arithmetic, active BC-1, parameters,
manuscript and historical scalar/hint evidence are preserved. Final measured
outcome and remaining balances follow in the closure below.
Stages2–3 remain open. Complete proof knowledge/privacy, adaptive Delta_tail and
production security remain unresolved. CPU proving paused; isolation safely
stopped/unactivated; proof ledger two used/one unused. No further package started.


Butterfly pilot closure: **supports-bounded-transform-experiment**. Two paired generation probes, twelve
differential cases and two invalid-twiddle cases pass: **263/263** cumulative,
zero invocations remaining. Full signed64 matched boundaries and the two-node
actual schedule fragment have complete counts in the
[report](stage3_mldsa_butterfly_composition_pilot.md). single forward butterfly: 66,213 fewer total gates (42.6076%), 27,724 fewer AND gates (45.1164%). two-node schedule fragment: 132,426 fewer total gates (42.6076%), 55,448 fewer AND gates (45.1164%).
Experimental lowering is not canonical BC-1 or a complete transform/proof result.
Lint/format and the [single audit](data/s3_mldsa_butterfly_composition_pilot_1/result.json)
pass 10,336 disjoint paths,
2.427376434s, 23,633,920-byte
cgroup peak under256MiB. Package10.171600435/30s;
implementation224.622665008/300s used; **75.377334992s remain**.
Analysis/isolation unchanged; no failures/retries. ARITH-LOWER-001 remains open
for transform composition/conformance; Stages2–3open, proof ledger2used1unused.
Next proposed only: S3-MLDSA-FORWARD-NTT-STAGE-PILOT-1: a separately authorised, bounded stage/transform counting and differential experiment with actual schedule, all conversion costs, explicit output invariants and unchanged gate/memory caps.


## S3-MLDSA-FORWARD-NTT-STAGE-PILOT-1 (26 September 2026)

Authorised dependency-complete four-lane fragment across forward lengths128/64;
see [contract and measured closure](stage3_mldsa_forward_ntt_stage_pilot.md).
Exact lanes0,64,128,192 and twiddle indices1,1,2,3. External signed64 acceptance
and overflow rejection are preserved. Only internal producer-validated canonical
representations bypass repeated normalisation; this remains experimental non-BC-1.
User amendment:16 invocations,263→279; at most30s from the exact
75.37733499205206s implementation balance, including checks/audit/bookkeeping.
Analysis and isolation allowances are unchanged. Four generation probes and
12 complete schedule cases; reference partitions cover A/B and C/D without overlap.
No full transform or entire128-butterfly stage, inverse experiment or proof is run.
ARITH-LOWER-001 stays open for full schedule/entry coverage and compiler conformance.
Stages2–3 and complete proof knowledge/privacy, adaptive Delta_tail and production
security remain open. CPU paused; isolation safely stopped/unactivated; proof
ledger two used/one unused. Final individual results and balances follow below.


Forward-stage pilot closure: **supports-bounded-full-forward-experiment**. Four generation probes and twelve
complete four-lane schedule cases pass, **279/279** cumulative, zero remaining.
Measured complete reference 621,868/246,058
total/AND gates; representation-reuse candidate
213,448/81,838. Four internal mod64 calls
are omitted only on producer-validated edges; all external/overflow checks remain.
[Report](stage3_mldsa_forward_ntt_stage_pilot.md) records complete partitions,
individual outcomes and limits. Lint/format and the
[single audit](data/s3_mldsa_forward_ntt_stage_pilot_1/result.json) pass
10,382 disjoint paths, 2.535323883s,
25,112,576-byte cgroup peak under256MiB.
Package14.112603900/30s; implementation238.735268908/300s consumed,
**61.264731092s remain**. Analysis/isolation unchanged;
one preserved lint-only failure was corrected;
no test/probe retry or resource breach.
ARITH-LOWER-001 stays open for full schedule coverage/compiler conformance;
Stages2–3open and security obligations unresolved; proof ledger2used1unused.
Next proposed only: S3-MLDSA-FULL-FORWARD-NTT-PLAN-1: a bounded source-only plan for complete schedule coverage, exact entry normalisation, invariant-preserving partition boundaries and separately authorised counting/differential resources.


## S3-MLDSA-FULL-FORWARD-NTT-PLAN-1 (26 September 2026)

[Complete forward-NTT plan](stage3_mldsa_full_forward_ntt_plan.md): source analysis
maps all eight stages/1,024 butterflies and specifies 97 private-state partitions.
All 256 signed64 entry values are normalised before butterflies; canonical
producer invariants retain their entire accepted domain. Future composed counts
require complete alias/coverage accounting, not a sum of unrelated fragments.
No tests, circuits, builds or experiments ran. Analysis opening balance
253.60648515704088 s; implementation **61.264731091912836 s** and **279/279**
invocations remain unchanged. Measured documentation/audit closure follows.

Execution is **not admitted** under current resources. One inactive proposal:
S3-MLDSA-FULL-FORWARD-NTT-PILOT-1, 107 additional invocations (279→386), +74 s
implementation allowance (300→374 cumulative, 135 s package cap), and 30M aggregate
gates with existing 2M per-trace ceiling retained. Nominal 27,044,356 gates and
101–132 s including reserve are estimates, not measured full-transform costs.
Existing memory/storage/process ceilings remain; no 64M/2 GiB proposal activated.
Stages 2–3 open; CPU paused; isolation safely stopped/unactivated; proof ledger
two used/one unused. No next package started.


Full forward-NTT plan closure: source/documentation checks and the
[single preservation audit](data/s3_mldsa_full_forward_ntt_plan_1/result.json)
pass, 10,440 disjoint content paths,
2.442549156 s, 23,318,528-byte
cgroup peak under the unchanged 256 MiB ceiling. Analysis charge
54.576216841/300 s; **245.423783159 s remain**. Implementation unchanged
**61.264731092 s; 279/279 tests**, no tests/probes/circuits generated. No failures
or retries. The complete 97-partition plan requires a separately authorised
S3-MLDSA-FULL-FORWARD-NTT-PILOT-1; current resources do not admit execution.
Proposed only: 107 invocations, +74 implementation seconds and 30M aggregate
gates (2M per-trace ceiling retained); no profile adopted. ARITH-LOWER-001,
HINT-LOWER-001, complete authentication/proof and security obligations remain open.
Stages 2–3 open, isolation safely stopped/unactivated; proof ledger two used/one unused.


Full-forward pilot result: **Component composition/counting validated; NO-GO for integration with the unchanged raw-view proof encoding**. Complete partitions 97/97,
butterflies 1024/1,024; 386/386 invocations.
[Measured report](stage3_mldsa_full_forward_ntt_pilot.md) separates host partitioned
evaluation, logical alias/count accounting and actual circuit/proof construction.
No canonical BC-1 adoption or full-authentication performance claim. No retry.
Next recommendation only: S3-COMPACT-AUTH-PROOF-PROFILE-REVIEW-1: a bounded source-only review of compact transcript candidates, exact relation/security obligations and KYC resource admission, before more circuit integration. Stages2–3/security obligations remain open;
isolation safely stopped/unactivated; proof ledger2used/1unused.


Full-forward pilot preservation closure: audit and report guard pass,
10,482 protected content paths,
2.438798105s and24,190,976-byte
cgroup peak under256MiB. Package93.441512754/135s;
implementation332.176781662/374s, **41.823218338s remain**;
invocations**386/386**. Analysis245.423783159s/isolation250.22s
unchanged. Outcome: Component composition/counting validated; NO-GO for integration with the unchanged raw-view proof encoding. No further package started.
See [complete report](stage3_mldsa_full_forward_ntt_pilot.md).
Stages2–3/security obligations remain open; proof ledger2used/1unused.


## S3-COMPACT-AUTH-PROOF-PROFILE-REVIEW-1 (26 September 2026)

[Compact-proof review](stage3_compact_auth_proof_profile_review.md) completes a
source-only comparison of gzkbpp ZKB++, RISC Zero3.0.6 native Succinct and
Aurora–BCS native ZK R1CS. No profile is adopted and no experiment admitted.
Pause further integration/optimisation under the unchanged raw-view encoding
unless new evidence changes its feasibility: 2,568,395,104 bytes is a conditional
projection retaining the measured graph, not a universal PQ-DAA lower bound.

One proposed research decision: replace only the proof layer with Aurora–BCS,
retaining the exact complete same-witness relation. The inspected implementation
lacks a usable binary-field/non-algebraic-hash wire serialiser, and its reported
size omits query positions. Complete constraints, finite parameters and adaptive
knowledge/privacy composition also remain missing. Seek the user's research
direction for **S3-AURORA-AUTH-CONSTRUCTION-CONTRACT-1**, one source-only contract
package; its proposed 30 analysis seconds are inactive. No broad survey, further
arithmetic integration or lifecycle package is recommended.

Opening analysis245.42378315888345s; implementation41.82321833795868s and
386/386 invocations untouched. Isolation remains safely stopped/unactivated,
22 identity cases pending/250.22s preserved; CPU proving paused, proof ledger
two used/one unused. Stages 2–3 and security obligations remain open.


Compact-proof review closure: documentation/static checks and the
[single preservation audit](data/s3_compact_auth_proof_profile_review_1/result.json)
pass, 10,680 disjoint content paths,
2.597733224 s, 23,707,648-byte
cgroup peak under the unchanged 256 MiB ceiling. Analysis charge
63.325249949/300 s; **236.674750051 s remain**. Implementation unchanged
**41.823218338 s; 386/386 tests**, no tests/probes/circuits generated. Two retained
formatting-only lint failures, manually corrected with two lint rechecks;
no experimental retries. **COMPACT-PROFILE-001 open**: recommend an Aurora–BCS
construction research decision, then only S3-AURORA-AUTH-CONSTRUCTION-CONTRACT-1
with the fixed relation/wire/security deliverables in the report. No profile,
installation or experiment approved. Raw-view integration/optimisation remains
paused; ARITH-LOWER-001, HINT-LOWER-001 and security obligations remain open.
Stages 2–3 open, isolation safely stopped/unactivated; proof ledger two used/one unused.


## S3-AURORA-AUTH-CONSTRUCTION-CONTRACT-1 — construction prerequisite identified

26 September 2026. The user approved the Aurora research direction, not profile
adoption. The [construction contract](stage3_aurora_auth_construction_contract.md)
specifies the same complete authentication acceptance, constrained private witness,
proposed binary-field/BCS wrapper, bounded wire format and finite parameter dependencies.
**AURORA-BRIDGE-001 remains an admission blocker**: pin the actual implementation
and materialise the ordered oracle/query/mask manifest with a commitment/transformation
correspondence before a private prototype. No global bit-security claim follows.

COMPACT-PROFILE-001's direction decision is satisfied; profile adoption, full R1CS,
finite security parameters and concrete knowledge/privacy remain open. Proposed next
package is **S3-AURORA-TRANSCRIPT-BRIDGE-1**, source/mathematical prerequisite only,
inactive, with a decisive manifest/correspondence or no-go endpoint. No experiment
started. Original SHA3/SHAKE, signed bytes, sampler caps, active BC-1 and dependencies
are unchanged. Raw-view integration/CPU proving paused; isolation safely stopped and
unactivated, pending 22 cases preserved. Stages 2–3 remain open; proof ledger two
used/one unused. Analysis opening236.674750051s; implementation41.823218338s and
386/386 invocations untouched. Measured documentation/audit closure follows.


Aurora construction-contract closure: documentation/static checks and the
[single preservation audit](data/s3_aurora_auth_construction_contract_1/result.json)
pass, 10,739 disjoint content paths,
2.510384024 s, 23,289,856-byte
cgroup peak under the unchanged 256 MiB ceiling. Analysis charge
71.710894273/300 s; **228.289105727 s remain**. Implementation unchanged
**41.823218338 s; 386/386 tests**. One diagnosed preflight inventory-path failure
and its charged manual correction are preserved; no experimental retry or resource
breach. **AURORA-BRIDGE-001 open**: resolve the pinned oracle/query/mask manifest
and transformation correspondence before a private prototype. Proposed next package
S3-AURORA-TRANSCRIPT-BRIDGE-1 only; no experiment or profile adopted.
Stages 2–3 remain open; raw-view integration and CPU proving paused, isolation
safely stopped/unactivated, proof ledger two used/one unused.

## S3-AURORA-TRANSCRIPT-BRIDGE-1 — construction correction required

The [source review](stage3_aurora_transcript_bridge.md) concludes **Decision 2**.
Twenty-one source texts at libiop commit
`a2ed2ec2f3e85f29b6035951553b02cb737c817a` are preserved with byte hashes.
Its BLAKE2b absorption hashes only the old-state prefix and ignores the new
commitment/message digest. Initial statement binding is absent; no-PoW operation
is not implemented by setting the work number to zero. These are source findings,
not executed forgery tests. The inactive draft already requires proper binding;
the upstream implementation cannot be used unchanged.

**AURORA-BRIDGE-001 remains open.** The report maps every round, direct terminal
polynomial, coset/column exposure and wire field. Source `b=2q+1` is not established
as the joint theorem query budget. Sumcheck/LDT mask distributions, packed leaves,
FRI degree metadata, BCS/CMS knowledge/privacy hypotheses and concrete-hash/adaptive
composition remain explicit obligations. No profile, implementation or prototype
is admitted. Next recommendation only: the source-only inactive
**S3-AURORA-TRANSCRIPT-CORRECTION-CONTRACT-1**.

Analysis opened at 228.28910572698805 s remaining. Implementation remains
41.82321833795868 s; invocations **386/386**. No tests, builds, circuits, installations,
proofs, zkVM executions or host activation. Safe-stopped isolation retains 22 cases
and 250.22 s; proof ledger remains two used/one unused. Stages 2–3 and adaptive
Delta_tail, production-security and complete proof knowledge/privacy remain open.
Measured documentation/audit closure follows.


Aurora transcript-bridge closure: source/documentation checks and the
[single preservation audit](data/s3_aurora_transcript_bridge_1/result.json)
pass, 10,788 disjoint content paths,
2.542261570 s, 23,666,688-byte
cgroup peak under the unchanged 256 MiB ceiling. Analysis charge
80.005991822/300 s; **219.994008178 s remain**. Implementation unchanged
**41.823218338 s; 386/386 tests**, no tests/probes/circuits generated. No failures
or retries in validation; the preliminary source-read DNS failure is retained.
**Decision 2 / AURORA-BRIDGE-001 open:** pinned absorption ignores new digest
bytes; statement binding, no-PoW handling, algebraic masking and commitment/wire
correspondence require explicit correction. Recommend only the inactive
S3-AURORA-TRANSCRIPT-CORRECTION-CONTRACT-1 source package. No profile adopted;
complete authentication/proof and security obligations remain open.
Stages 2–3 open, isolation safely stopped/unactivated; proof ledger two used/one unused.

## S3-AURORA-TRANSCRIPT-CORRECTION-CONTRACT-1 — patch-ready contract only

The [correction contract](stage3_aurora_transcript_correction_contract.md) defines
inactive **PQDID-AURORA-TRANSCRIPT-EXP2**, exact initialisation, canonical public
statement binding, framed round absorption, scheduled challenge counters, verifier
reconstruction and fail-closed errors. An explicit pseudo-diff preserves the pinned
upstream snapshot. **Corrections are proposed, not implemented or validated.**

The source finding is now stated precisely: the selected fresh BLAKE2b chain lacks
explicit full-statement initialisation, while the verifier **does** use primary
input in its algebraic checks. No whole-protocol statement-independence or executed
forgery is claimed. AURORA-BRIDGE-001 remains open for query/masking, commitments,
transformation, adaptive knowledge/privacy and concrete-hash obligations.

Next recommendation: **S3-AURORA-TRANSCRIPT-REGRESSION-1**, the specified public-only
harness, sixteen counted cases (proposed ceiling 386→402), at most 25 implementation
seconds from the existing balance with ten seconds reserved. Proposal inactive;
no further general review is required before that narrow package once authorised.
No private prototype, proof, service or profile is admitted. Analysis opened at
219.99400817777496 s; implementation **41.82321833795868 s**, invocations **386/386**
untouched. Stages 2–3 remain open; isolation safely stopped/unactivated; proof ledger
two used/one unused, CPU proving and raw-view integration paused.


Aurora correction-contract closure: source/documentation checks and the
[single preservation audit](data/s3_aurora_transcript_correction_contract_1/result.json)
pass, 10,856 disjoint content paths,
2.632140150 s, 23,830,528-byte
cgroup peak under the unchanged 256 MiB ceiling. Analysis charge
88.486544458/300 s; **211.513455542 s remain**. Implementation unchanged
**41.823218338 s; 386/386 tests**, no tests/probes/circuits generated. No failures
or retries in this package. **AURORA-BRIDGE-001 open:** proposed transcript EXP2
repairs are specified, not implemented/validated. Algebraic primary-input checks
are distinguished from absent explicit initial statement hash binding. Recommend
only inactive S3-AURORA-TRANSCRIPT-REGRESSION-1: sixteen counted cases (386 to 402),
at most 25 implementation seconds from the unchanged balance. No profile adopted;
complete authentication/proof and security obligations remain open.
Stages 2–3 open, isolation safely stopped/unactivated; proof ledger two used/one unused.


## S3-AURORA-TRANSCRIPT-REGRESSION-1 — isolated public EXP2 regressions

The [regression report](stage3_aurora_transcript_regression.md) records **16/16
authorised public cases passed**, including the individually counted TR-02 repeat
and the TR-16 old-omission negative control. Corrections are implemented/tested
only in the isolated Python reimplementation: no native upstream patch or Aurora
proof system was executed. The correction contract and source snapshot remain
preserved. Independent expected traces agree on full preimages, states/blocks,
canonical records, counters, mapped outputs and prover/replay results. Negative
cases retain prior state and release no partial value. Finite mutation results
are not collision-resistance or forgery evidence.

The qualified finding remains: explicit initial full-statement binding was absent
from the selected fresh hash-chain path, but algebraic primary-input checks exist.
**AURORA-BRIDGE-001 stays open** for native/IOP mapping, query/masking, commitments,
compiler/relation and adaptive extraction/privacy/concrete-hash obligations.
Adaptive Delta_tail and production-security obligations remain unresolved.

Invocations are now **402/402**, with no additional probe or automatic retry.
Implementation opened at 41.82321833795868 s; the measured closure below records
this package's charge. Analysis 211.51345554180443 s and isolation 250.22 s remain
untouched. Recommend bounded source-only **S3-AURORA-ROUND-PLAN-ADAPTER-CONTRACT-1**
to specify actual registration/round/query hooks and the no-PoW transition before
any native integration. It has not started; no private prototype is admitted.
Stages 2–3 remain open. Raw-view integration and CPU proving remain paused;
isolation safely stopped/unactivated; proof ledger **two used, one unused**.


**EXP2 package completion stopped — preservation prerequisite failed.** The
[regression report](stage3_aurora_transcript_regression.md) retains all 16/16 passing
cases, but the [scope-preparation diagnostic](data/s3_aurora_transcript_regression_1/prepare.log)
exited 1: required new experiment files were outside the inherited traversal roots.
They exist; this is an inventory-scope construction error. No full preservation
audit ran; no complete preservation or successful package closure is claimed.
The failed guard and STOP marker are retained; no retry or semantic change occurred.
Lint/format passed before case execution. Source identities remain those executed.

Charge **5.676312445 implementation seconds**, including the failed preparation
and reserved bookkeeping; cumulative **337.853094107/374 s**, **36.146905893 s
remain**. Tests **402/402**; analysis **211.513455542 s** and isolation **250.22 s**
unchanged. Maximum guarded cgroup peak **23,035,904 bytes** under 256 MiB; no resource
breach. AURORA-BRIDGE-001 and Stages 2–3 remain open; proof ledger two used/one unused.
Immediate next recommendation (superseding the conditional adapter step):
**S3-AURORA-TRANSCRIPT-PRESERVATION-REPAIR-1**, adding only the exact new experiment
root to the audit traversal, preserving every inherited root/required file and the
failure, then completing checks and the still-unexecuted audit without rerunning
cases. Not started; no additional invocation or limit increase is requested here.


**S3-AURORA-TRANSCRIPT-PRESERVATION-REPAIR-1 stopped; package incomplete.**
The [repair record](stage3_aurora_transcript_regression.md) adds only traversal root
`experiments/aurora_transcript_regression_1`. Corrected preparation passed
(2,596 names, no missing/unexpected); all four false reports
are resolved. The one complete audit attempt subsequently failed at the reused
case-evidence presence check: the repair adapter checked `repair-1/TR-01.json`
instead of the retained original path. The files and original failure remain
intact. No further attempt, evidence relocation or regression rerun occurred.
10,901 baseline content comparisons completed, but final inventory/reporting
and guard success did not; **preservation is incomplete**. This audit-adapter path
error is the remaining completion blocker, distinct from AURORA-BRIDGE-001.

Audit 2.539544389 s, peak 23,654,400
cgroup bytes under 256 MiB, no resource breach. Repair charge **7.931766078 s**;
combined **13.608078523/25 s**, **11.391921477 s** remain including the
protected ten-second reserve. Implementation **28.215139815 s**
remain; tests **402/402**. Analysis/isolation unchanged. Both failed attempts and
all 16 passed regressions are preserved. Stages 2–3 and AURORA-BRIDGE-001 open;
proof ledger two used/one unused, no activation/proofs/zkVM executions. Stopped.


Repair-2 stopped before preparation/audit: original 16 case references were verified,
but static lint failed on the new audit helper's overlong accounting string (E501).
[Failure and ledger](stage3_aurora_transcript_regression.md) retained; no retry.
Package remains incomplete. Added charge 5.153995360s, combined 18.762073883/35s;
package 16.237926117s remain including ten-second reserve; implementation
23.061144455s remain. Tests 402/402; analysis/isolation unchanged.
Original failures and EXP2 inputs unchanged. AURORA-BRIDGE-001/Stages 2–3 open;
proof ledger two used/one unused. No proofs, zkVM executions or activation.


## Repair-2 stop

The authorised E501-only continuation stopped at storage admission, before
changing the helper or launching lint/format, preparation or the full audit.
The inherited package subcap counts all retained regression/repair evidence,
experimental source and the main regression report. Its exact opening usage was
262,101/262,144 bytes: only 43 bytes free. The existing helper requires another
1,100 bytes of reporting headroom even before retaining new results. Preserving
the immutable archive and unchanged storage limit therefore precludes admission.
This is a detected shortage, not an executed workload or a resource-limit breach.
No limit, baseline, allowlist, comparison or evidence location was changed.
The 41-byte pointer appended to the report leaves usage at 262,142/262,144 bytes.
This status entry is the fresh admission/closure record; no audit evidence was
relocated outside its monitored scope to obtain a pass.

Original case files remain in `docs/data/s3_aurora_transcript_regression_1/`;
`repair-2/evidence.json.xz` remains byte-identical. The existing corrected root
`experiments/aurora_transcript_regression_1` is retained. Reuse all 16 passing
cases and the previous evidence-reference checks; no cases or checks were rerun.
The E501 correction and complete audit remain outstanding. Earlier 10,901 content
comparisons are partial evidence; final inventory/reporting remain incomplete.

The established conservative five-second bookkeeping charge covers this source
inspection, storage admission check and closure; no guarded execution was charged.
It is an accounting allowance, not a measured five-second audit. The measured
storage inspection took 0.000833887 s and peaked at 18,223,104 bytes process RSS;
this is not a cgroup audit-memory measurement. No temporary files, service or
workload were created. The remaining ten-second reserve remains within the
package balance, available for completion only after the admission blocker is
resolved. Analysis and isolation balances are unchanged.

```json
{
  "package": "S3-AURORA-TRANSCRIPT-PRESERVATION-REPAIR-2",
  "continuation": "authorised E501-only continuation; stopped at storage admission",
  "opening_combined_seconds": 18.76207388297189,
  "bookkeeping_charge_seconds": 5.0,
  "bookkeeping_accounting": "Established conservative five-second operator charge; includes source inspection, byte-count inspection, reporting and cleanup. No guarded workload launched; not five seconds of measured execution.",
  "measured_storage_inspection_seconds": 0.0008338869083672762,
  "measured_storage_inspection_process_RSS_peak_bytes": 18223104,
  "combined_package_charge_seconds": 23.76207388297189,
  "package_seconds_remaining": 11.23792611702811,
  "implementation_seconds_remaining": 18.06114445498679,
  "completion_reserve_seconds": 10,
  "opening_package_bytes": 262101,
  "package_subcap_bytes": 262144,
  "opening_bytes_available": 43,
  "existing_helper_required_reporting_headroom_bytes": 1100,
  "report_pointer_bytes": 41,
  "closing_package_bytes": 262142,
  "case_evidence_input": "docs/data/s3_aurora_transcript_regression_1/",
  "retained_repair_output": "docs/data/s3_aurora_transcript_regression_1/repair-2/evidence.json.xz",
  "retained_archive_sha256": "b2f3886339159a8737d3c4cc259f9dfe39577faf4826b95e4d024aa5211d45eb",
  "traversal_root": "experiments/aurora_transcript_regression_1",
  "helper_changed": false,
  "new_lint_format_runs": 0,
  "new_preparations": 0,
  "new_audit_attempts": 0,
  "audit_exit_status": null,
  "final_inventory_complete": false,
  "audit_reporting_complete": false,
  "package_complete": false,
  "regression_invocations": 402,
  "regression_ceiling": 402,
  "new_regression_invocations": 0,
  "resource_breaches": 0,
  "temporary_retained_bytes": 0,
  "analysis_isolation_balances_unchanged": true,
  "proof_attempts_used": 2,
  "proof_attempts_unused": 1
}
```

The package remains incomplete; no further attempt was made. A storage amendment
or separately authorised retention change is required before another attempt can
retain its results; 1,100 bytes is only the helper's reporting reserve, not a full
estimate for new evidence. This continuation does not amend that limit.
Stages 2–3 and AURORA-BRIDGE-001 remain open. The Python EXP2 results do not validate
native upstream code or proof security. CPU proving/raw-view integration stay
paused; isolation stays stopped/unactivated. Proof ledger: two used, one unused.
No proofs, zkVM executions, installations or activation.


**Approved preservation continuation stopped at preparation; package incomplete.**
The E501-only helper correction passed one guarded lint/format pass and preserves
its entire parsed AST/runtime string. Inventory preparation exited 1: 2,622 names,
zero missing, one unexpected retained file:
`docs/data/s3_aurora_transcript_regression_1/repair-1/prepare.json`.
That file matches its historical seal; the inherited expected-name list omits it.
No preparation retry, audit or case rerun occurred. Complete baseline preservation,
final inventory and audit reporting remain unestablished; earlier 10,901 completed
comparisons are partial evidence only. See the [continuation outcome](stage3_aurora_transcript_regression.md#completion-continuation-outcome).

The approved 1,048,576-byte output and 40-second package caps are recorded separately;
all previous evidence counts and remains unchanged. Continuation charge
5.355415765 s = 0.355415765 guarded seconds + five established bookkeeping
seconds. Combined 29.117489648/40 s; package 10.882510352 s and implementation
12.705728690 s remain. The ten-second reserve remains inside that balance.
Cgroup peak 25,104,384 bytes under 256 MiB, no resource breach. Tests 402/402;
analysis/isolation unchanged. Only the inventory omission remains for a separately
authorised repair; the present stop rule prohibits another attempt.
Stages 2–3/AURORA-BRIDGE-001 open; EXP2 remains isolated Python evidence, not native
or proof-security validation. Isolation stopped/unactivated, CPU proving paused;
proof ledger two used/one unused. No proofs, zkVM executions or installations.


**Aurora transcript preservation finalisation complete.** The exact protected
`docs/data/s3_aurora_transcript_regression_1/repair-1/prepare.json` entry was restored;
its original digest and content seal are unchanged. Reconciliation of 88 retained
manifest names found no further omission. One preparation and one complete audit
passed, both exit 0. Audit: 8,759 primary entries (8,756 unchanged plus three
previously authorised documentation changes) + 2,142 unchanged supplemental
entries = **10,901 disjoint comparisons**, 10,936 identity-inclusive paths,
2,644-name inventory with no missing/unexpected entries. Final report/readback
and outer guard passed. Earlier failed records are retained; they are superseded
for package completion, not rewritten. See the [complete finalisation record](stage3_aurora_transcript_regression.md#inventory-finalisation-result).

Audit 2.834623713 s; cgroup peak 28,528,640 bytes
under 256 MiB, no resource breach. Finalisation charge 8.148349031 s including
five existing bookkeeping seconds; combined 37.265838679/40 s. Package
2.734161321 s and implementation 4.557379659 s remain. The reserve was used
inside the same cap as authorised. Tests **402/402**, all 16 prior cases reused;
analysis/isolation unchanged. Only the existing package is complete: Stages 2–3
and AURORA-BRIDGE-001 remain open; native correspondence and proof security are
unestablished. CPU proving/raw-view integration paused, isolation stopped/unactivated;
proof ledger two used/one unused. No new package, proof, zkVM execution, installation
or activation. Historical baselines, parameters and cryptographic inputs preserved.


## S3-AURORA-NATIVE-TRANSCRIPT-PILOT-1 — dependency-blocked

The [native pilot report](stage3_aurora_native_transcript_pilot.md) records **no native
patch, build or test**. The source snapshot at libiop
`a2ed2ec2f3e85f29b6035951553b02cb737c817a` passed 21 file/blob identity checks;
eight relevant files were copied unchanged into an isolated experiment. Sodium
development headers/pkg-config metadata, libff development/source closure and the
complete libiop header tree are unavailable. Transitive revisions remain unpinned.
The installed libsodium runtime does not establish those build prerequisites.
All TR-01–TR-16 native outcomes are unexecuted; independent Python expectations
were reused unchanged. Build attempts **0/2**; native invocations **0/24**;
cumulative **402/426**, no hidden probe or regression rerun.

The hard-coded `/usr/bin/rg` preflight launcher error and its source/results are
preserved and charged. Metadata completion used the installed tool; no native
code or negative control ran. Lint/format and the complete preservation audit
passed: **10,901 disjoint content comparisons**, 10,936 identity-inclusive paths,
2,688-name inventory, no missing/unexpected entries, report/readback and guard pass.
Audit 2.643288025 s; cgroup peak 30,203,904 bytes
under 256 MiB. Package charge 8.249009901/300 s, including failure and five
bookkeeping seconds; **291.750990099 package seconds** and
**296.308369758 implementation seconds** remain. The 30-second completion
reserve is inside the package balance; analysis/isolation untouched.

This closes the package with a dependency blocker and successful preservation;
it does not establish native transcript correspondence. AURORA-BRIDGE-001 stays
open for native callers, query/masking, commitment transformation, extraction/privacy,
concrete-hash and complete authentication. Stages 2–3 remain open. Next recommendation:
a bounded complete-source/dependency-lock and prerequisite-provisioning proposal,
not started. Production code, BC-1, manuscript, dependencies and old evidence remain
protected. Isolation stopped/unactivated; CPU proving/raw-view integration paused;
proof ledger two used/one unused. No proof, zkVM execution, installation or activation.


## S3-AURORA-NATIVE-DEPENDENCY-LOCK-1 — provisioning proposal

The [dependency report](stage3_aurora_native_dependency_lock.md),
[proposed lock](data/s3_aurora_native_dependency_lock_1/dependency-lock.json) and
[runbook](proposals/s3_aurora_native_dependency_lock_1/README.md) resolve the selected
libiop/libff/libfqfft revisions and exact sodium/GMP development-package identities.
Project-local acquisition/static linking is proposed; no host installation is
necessary. Native build admission remains pending acquired-checkout integrity,
archive-member/header/library/ABI checks and actual compiler/resource compatibility.
The runbook consolidates acquisition approval and a narrow artifact-file exception;
no provisioning or build was performed. The interrupted lookup and 7,203-byte output
overrun remain failures under their original ceiling. The authorised continuation
uses 12,386,485 cumulative bytes and the unchanged 2 MiB package cap. It reuses
successful metadata and the 16 Python regressions; the unfinished requests passed.
The current full-audit and resource outcome will be appended after finalisation.

DEP-001/DEP-002 and AURORA-BRIDGE-001 are not closed by dependency metadata.
The dependency-pin question for the selected native support path is answered at
the metadata layer; acquired artifacts, native EXP2/caller correspondence,
query/masking, commitment transformation, extraction/privacy and concrete-hash
composition remain gates. Stages 2–3 remain open. Isolation stays stopped/unactivated,
CPU proving/raw-view integration paused, proof ledger two used/one unused. Native
291.750990099 s, implementation 296.308369758 s, both build attempts and all 24 native
invocations remain unused; cumulative 402/426. Next step: approve only the concrete
local provisioning/resource proposal, then apply its admission checks.


Dependency-lock finalisation: focused checks, preparation and the one full audit
passed (exit 0; 10,901 disjoint comparisons; 2,790 inventory names; report/readback/guard
complete). Audit 2.655091408s and 33,660,928bytes
cgroup peak, below 256 MiB. Earlier 7,203-byte overrun remains preserved as failure.
Analysis package charge 31.717931544/60s; analysis balance 179.795523998s.
Current [closure](data/s3_aurora_native_dependency_lock_1/continuation-1/validation-closure.json)
records final output accounting. Proposal ready for its specified local acquisition
approval; actual archive/source verification and native build admission pending.
No provisioning/native execution occurred; 402/426 and all native/implementation
allowances unchanged. Stages 2–3 and AURORA-BRIDGE-001 remain open.


## Native provisioning integrity stop

Approved local provisioning stopped before dependency admission: pinned libiop
HEAD `a2ed2ec2f3e85f29b6035951553b02cb737c817a` and fsck passed, but its acquired
root tree `2e2588ccb085242dd2237875c3b9adf1a0fc958c` differs from the approved
lock's tree field (which equals the commit ID). Retained API metadata was interpreted
as a tree ID without object-type verification. This is a lock/metadata discrepancy,
not demonstrated checkout corruption. See the appended
[native report](stage3_aurora_native_transcript_pilot.md) and
[failure analysis](data/s3_aurora_native_transcript_pilot_1/provisioning-1/failure-analysis.json).
The proposal-readiness conclusion is superseded by this failed admission gate.
No pins changed, no retry, no archives or other repositories acquired; partial
libiop checkout retained in its approved isolated prefix. No native build or case:
0/2 builds, 0/24 native invocations, 402/426 cumulative. Next bounded recommendation
is source/tree identity reconciliation before a corrected lock or acquisition.
DEP-001/DEP-002 and AURORA-BRIDGE-001 remain open; Stages 2–3 open. Isolation
stopped/unactivated; CPU proving paused; proof ledger two used/one unused.
Final preservation result and resource balances follow after the audit.


Stopped native-provisioning closure: preservation passed (exit 0; 10,901 disjoint
content comparisons; 3,080 inventory names; report/readback/guard complete). Audit
2.636536615 s, 28,880,896 bytes cgroup peak under 256 MiB.
Partial checkout retained (2,030,216 bytes); no archives/builds/native cases.
Continuation charged 9.061018428 s; native balance 282.689971671 s and
implementation balance 287.247351330 s. Analysis/isolation unchanged; 402/426, two
unused builds, all 24 native invocations and proof ledger two used/one unused.
See [current closure](data/s3_aurora_native_transcript_pilot_1/provisioning-1/validation-closure.json).
Tree-identity reconciliation is the only recommended next step, not started.
Stages 2–3 and AURORA-BRIDGE-001 remain open.


## Verified dependency reconciliation and native build stop

The authorised commit/tree reconciliation passed with replacement-object substitution disabled. The libiop commit remains `a2ed2ec2f3e85f29b6035951553b02cb737c817a`; its stored tree header, `^{tree}` resolution and tree object agree on `2e2588ccb085242dd2237875c3b9adf1a0fc958c`. The same commit-versus-root-tree metadata error was verified and corrected for the selected libff and libfqfft commits. Only the three tree fields changed in a new lock version; the original lock, seals, failed acquisition and all gitlink commit IDs remain protected.

See the [v2 runbook](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/runbook-v2.md), [correction proof](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/lock-correction.json) and [provisioning result](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/provision-result.json). Corrected lock SHA-256: `0e33258c861764eacb8e4f04d21962425e7b7fedd7f27e79cecc4176deec1736`.

Project-local provisioning passed: all three selected source trees, all recorded gitlinks, 21 retained source snapshots and eight historical source copies matched. Both unchanged Debian archive hashes, members, destinations, header versions and static-library x86-64 ELF members passed inspection. Nothing was installed globally or into the existing Python/liboqs environment. Build compatibility was then tested and failed; static dependency readiness is not compilation success.

Both native build attempts are consumed. Build 1 stopped on private `bigint_repr()` access in an unused libff BLS12-381 source. The one authorised build-only correction narrowed `ff` to pinned binary-field/common sources. Build 2 built that target but stopped on non-existent `index`/`coeff` members in pinned libiop `relations/variable.tcc` (lines 63, 129, 171, 177–178). No native executable was produced. No native function/caller or negative control was executed, and no correspondence is established. The prepared patch/harness and both failures are retained. No further build was attempted.

All TR-01–TR-16 outcomes are individually [recorded as not run](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/native-case-outcomes.json). Native invocations remain 0/24; cumulative 402/426. Existing 16 Python results are reused, not rerun. DEP-001/DEP-002 and AURORA-BRIDGE-001 remain open. The exact acquisition prerequisite is now satisfied; compiler compatibility and native transcript correspondence remain unresolved.

Recommended next package: a bounded source-only native build-compatibility correction contract addressing the observed libff friend-access and libiop stale-member errors, with exact isolated changes and an explicit future build-attempt request. Do not substitute dependencies or start that package automatically. Stages 2–3 remain open; query/masking, commitment transformation, extraction/privacy, concrete hash and complete authentication obligations remain open. Only manuscript Sections II–VIII and agreed clarifications are authoritative. Isolation stays stopped/unactivated; CPU proving paused; no proofs or zkVM executions; proof ledger two used/one unused.

Final preservation/guard outcome and actual resource balances are appended below after completion.


Reconciliation/native closure: the complete preservation audit passed, exit 0,
with 10,901 disjoint baseline content comparisons, 10,936 identity-inclusive paths
and 4,884 inventory entries at audit time. Report generation/readback and outer
guard passed; audit 2.939619946 s, 30,527,488 bytes cgroup peak under
256 MiB. New artifact inventory covers 1,988 entries (1,983 regular files and five
exact symlink targets); retained artifact bytes 11,228,057 / 134,217,728. No baseline,
seal, historical failure or expected result was replaced. No resource breach.

Native builds: attempt 1 exit 1 in 1.371514156 s; attempt 2 exit 1 in
3.603540356 s. Largest native cgroup peak 258,568,192 bytes / 1 GiB;
largest sampled native tree RSS 211,906,560 bytes; sampled temporary-storage peak
669,692 bytes / 8 MiB. These are separate memory metrics, not sums. All launched
guarded workers exited and temporary work is empty. Local checkouts, archives,
static-library prefix, patched sources and partial builds remain isolated and
retained. Both build attempts used; all 24 native invocations unused; 402/426.
No executable, native transcript result, or successful caller comparison exists.

Provisioning/reconciliation sub-limit conservatively charged 18.156349560/60 s,
leaving 41.843650440 s without resetting the old charge. This continuation
charged 18.318097987 s: actual guard durations plus the existing five-second
bookkeeping convention. Native package total 35.628126316/300 s; balance
264.371873684 s, with its 30-second reserve preserved. Overall implementation
balance 268.929253343 s. Analysis 179.795523998 s and isolation 250.22 s unchanged.
The first static pass recorded E741/E501; the authorised cosmetic identifier and
string-wrapping corrections preserved runtime values, and the second lint/format
pass succeeded. Both diagnostic sets remain; static checks consumed no native cases.

The additive [closure and final output accounting](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/validation-closure.json)
and [seal](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/manifest.json)
record final inventory and bytes. Preservation is complete; the native pilot is
closed at a build blocker, not successful correspondence. A source-only compiler
compatibility correction contract is the sole next recommendation, not started.
Stages 2–3 and AURORA-BRIDGE-001 remain open. Proof ledger two used/one unused;
no proofs/zkVM, host activation or additional native work.


## S3-AURORA-COMPILER-COMPATIBILITY-CONTRACT-1

Source-only contract prepared; no acquired/experimental native source mutation,
configuration, compiler probe, build or native case. The ten logged `index`/`coeff`
errors affect four functional operators, not printing. The minimal separate patch
selects declared `index_`/`coeff_` members; eight proposed semantic cases are required
before unchanged TR-01–TR-16. This fits the existing 24 unused invocations but remains
inactive. Request one additional build attempt (2 → 3), no other allowance increase,
with a 150-second native/implementation subcap and existing finalisation reserve.
See the [contract](stage3_aurora_compiler_compatibility_contract.md) and
[inactive exact runbook](data/s3_aurora_compiler_compatibility_contract_1/runbook.md).

AURORA-COMPILER-001 remains open pending semantic validation and a successful build.
Related latent member errors in three other combination/free-operator paths are
recorded and left unchanged; no general relations-module correctness claim.
The libff target-selection workaround retains binary fields/common support but does
not repair prime-field friend/stream access. Historical wording “built that target”
is clarified: eight translation units compiled; the sealed build inventory has no
build-produced `.a` archive, and no link/native executable was completed. Both failed
builds and their original reports remain protected.

Balances remain native 264.371873684 s, implementation 268.929253343 s, provisioning
41.843650440 s; builds 2/2 used; native invocations 0/24; cumulative 402/426. Analysis
opens at 179.795523998 s, separate from those allowances; actual charge follows in
final contract closure. Stages 2–3 and AURORA-BRIDGE-001 remain open, including full
native caller coverage, query/masking, commitment transformation, extraction/privacy,
concrete hash, adaptive Delta_tail and production security. Isolation remains
stopped/unactivated; CPU proving paused; proof ledger two used/one unused.


Completed source-only contract: lint/format and all three textual patch-applicability
checks passed; no source mutation, compiler invocation or native test. The complete
preservation audit passed, exit 0, with 10,901 disjoint content comparisons,
10,936 identity-inclusive paths and 4,915 inventory entries at audit time. Final
inventory, reporting/readback and outer guard passed. Audit 3.020466007 s,
30,470,144 bytes cgroup peak under 256 MiB; sampled tree RSS 48,529,408 bytes.
Largest analysis-worker cgroup peak was 36,962,304 bytes. No resource breach or
retained temporary data. Historical build failures, original seals and native
source/artifacts remain preserved.

Analysis charge 8.535517291/30 s, including existing five-second bookkeeping
accounting; package residual 21.464482709 s and analysis balance 171.260006707 s.
Native 264.371873684 s, implementation 268.929253343 s, provisioning 41.843650440 s,
isolation 250.22 s, builds 2/2 consumed and invocations 402/426 remain unchanged.
Exact final byte accounting and the additive seal are in
[the contract closure](data/s3_aurora_compiler_compatibility_contract_1/validation-closure.json)
and [manifest](data/s3_aurora_compiler_compatibility_contract_1/manifest.json).

The functional patch's SHA-256 is
`8a28d44432c4dfd2ff41a07bb4affd1a154b52ae781289210410586b43e4c357`.
It remains unapplied. One extra build plus eight semantic cases and TR-01–TR-16
is an inactive request requiring approval; no broader resource increase is requested.
Stages 2–3 and AURORA-BRIDGE-001 remain open; proof ledger two used/one unused.


### Native functional-correction continuation: build 3 guard stop

The approved ten-reference patch and semantic target were applied only in the
fresh isolated `dependency-prefix-v1/compatibility-v1` subtree after seal checks.
Build 3 configured successfully, then stopped at 2.299439995 seconds under the
new-output guard: compiler temporary files were included in evidence accounting
(569,344 sampled temporary bytes versus the 393,216-byte reservation). The log
contains no compiler diagnostic; neither executable linked. No SEM-01–SEM-08 or
TR-01–TR-16 case ran. Builds are 3/3 used; invocations remain 402/426. No further
build or correction is automatic. Containment and the empty temporary directory
are recorded; the partial build and every earlier failure are retained.

See [the native report](stage3_aurora_native_transcript_pilot.md) and its
`docs/data/s3_aurora_native_transcript_pilot_1/compatibility-1` evidence. Required
preservation finalisation is recorded separately below; a passing audit cannot
establish compilation, operator semantics or native correspondence. Recommended
next work is a source-only compiler-scratch/evidence accounting correction
contract before a new build request. Stages 2–3 and AURORA-BRIDGE-001 remain
open, with query/masking, commitment transformation, extraction/privacy,
concrete-hash and complete-authentication obligations unresolved. Isolation
remains stopped/unactivated and CPU proving paused; proof attempts remain two
used and one unused. Analysis/provisioning allowances are unchanged.


### Final outcome of the third-build continuation: incomplete, stopped

Formatting/lint passed. Preparation passed over **5,907 inventory entries** with
no missing or unexpected paths. The sole full preservation audit exited **1**
after **3.082952 seconds**, at **29,663,232 bytes** cgroup peak
(**47,603,712 bytes** sampled tree RSS), under the unchanged **256 MiB** ceiling.
It completed **8,759 original + 2,142 supplemental = 10,901** disjoint baseline
comparisons, report-prefix checks and assessed/sealed input checks. These remain
partial evidence: final inventory, final documentation checks and complete report
readback were not reached.

The failure is `changed prior resource controls`: this continuation's
`checks.py::current_checks` included the authorised **1 GiB native preflight** in
the legacy `check_runs` list, whose resource validator requires **256 MiB**.
This is an integration error in the new audit wrapper, not a measured audit
memory breach or a demonstrated protected-content mismatch. The error, phases,
outer result and STOP record are preserved. No audit was repeated and no
comparison requirement was removed. **The package is not complete.**

**AURORA-NATIVE-GUARD-001 remains open:** review the compiler scratch/evidence
accounting boundary and make phase-specific validation explicit while retaining
all ceilings. This is the one recommended bounded next contract; neither a repair
execution nor another build begins here. Build attempt three remains consumed,
with no complete linking and **zero** semantic/transcript invocations. Each
SEM-01–SEM-08 and TR-01–TR-16 outcome is recorded as not run. The previous Python
results do not establish native correspondence or proof security.

Accounting: **11.543774/150 seconds** charged (five conservative bookkeeping
seconds plus **6.543774** measured guarded seconds); **138.456226**
remain under this stopped subcap. Native balance **252.828099 s**;
implementation **257.385479 s**. Analysis remains
**171.260006707 s**, provisioning **41.843650440 s**. Builds **3/3** used;
invocations **402/426**, all **24** native cases unused. The guarded workload
terminated; cleanup retained the empty assembler artifact and left no temporary
entries. New artifacts: **3,995,318 bytes / 956 entries**, aggregate artifacts
**15,223,375/134,217,728 bytes**.

Final retained new evidence and document appendices: **000000224338 bytes**;
cumulative **000011879147/12,386,485 bytes**, headroom
**000000507338 bytes**; native package evidence
**000001262780/2,097,152 bytes**. These retained totals do not erase the
build-time guard exceedance caused by temporary-file accounting. Exact records
are in `docs/data/s3_aurora_native_transcript_pilot_1/compatibility-1/validation-closure.json`.
The new manifest seals this incomplete outcome; it does not replace old seals or
claim a successful audit. No final inventory is claimed after the failure.

Stages 2–3, AURORA-BRIDGE-001, query/masking, commitment transformation,
extraction/privacy, concrete-hash and complete-authentication obligations stay
open. Isolation remains stopped/unactivated, CPU proving paused, and the proof
ledger two used/one unused. No proof, zkVM execution, installation or activation
occurred. Stop after this report.


S3-AURORA-RESOURCE-GUARD-REPAIR-1: eight tooling cases and one targeted rerun
passed (411/438); complete preservation pending. See the native transcript report.
Builds remain 3/3; all 24 native cases remain unexecuted.


Resource-guard repair complete: audit passed; 411/438 invocations, builds 3/3. See native report.

Fourth-build approval recorded; admission stopped before configuration/build.
Retained build outputs classified by the sealed policy require 344,971 evidence
bytes, exceeding the 200,000 reservation and 267,653 opening headroom before
completion. AURORA-NATIVE-ADMISSION-001 is open. Builds 3/4 used; all SEM/TR cases
not run; ledger 411/438 unchanged. See the native report and its
`build-4-admission-1/admission-result.json`. Preservation finalisation follows.
Stages 2–3/AURORA-BRIDGE-001 remain open; isolation stopped/unactivated, CPU
proving paused, proof ledger two used/one unused.


Fourth-build admission finalised: preservation passed (10,901 comparisons; final inventory 6008; report/readback complete), no build or cases launched. Charged 9.005019 s; native 233.290628 s, implementation 237.848007 s remain. Builds 3/4; ledger 411/438. Evidence-budget blocker and AURORA-BRIDGE-001 remain open; see native report.


Fourth-build storage resumption: 784,736 historically artifact-only bytes now
additionally charged once as evidence; 16 MiB cumulative/4 MiB native/2 MiB new
reservation reconciled without altering old ledgers. Preflight E501 stopped native
admission before copying/configuring/building. Formatting-only correction and
completion lint passed; no preflight retry. Builds 3/4, ledger 411/438; every SEM/TR
case not run. See native report and `build-4-resumption-1/` evidence. Storage gap
addressed; static-stop resumption remains pending. Stages 2–3/AURORA-BRIDGE-001 open.


Stopped preflight finalised: audit exit 0; 10,901 comparisons, final inventory 6041, reporting/readback complete. Charged 8.976094 s; subcap 82.018887 s, native 224.314534 s, implementation 228.871913 s remain. Builds 3/4, ledger 411/438; all native cases not run. Unchanged 55+30-second build/completion reservation no longer fits; resolve admission before resumption. Historical failures remain failures. See native report; Stages 2–3/AURORA-BRIDGE-001 open.


Fourth-build total amended prospectively to 120 s; 17.981113 s retained as consumed.
Source admission then found AURORA-NATIVE-SEAL-001: unchanged preflight uses older
full-file hashes for five legitimately appended reports. Current hashes match the
latest seal and historical prefixes are intact. Stop before preflight/build;
non-formatting validation correction is not authorised here. Native launcher and
worker unchanged; all SEM/TR cases not run, builds 3/4, ledger 411/438. See native
report and `build-4-time-admission-1/`. Stages 2–3/AURORA-BRIDGE-001 remain open.


Time-admission finalisation complete: audit passed, 10,901 comparisons, 6066 final inventory entries and report readback complete. Charged 9.044320 s; fourth-build 92.974568 s, native 215.270214 s, implementation 219.827594 s remain. No preflight/build/case launched. Builds 3/4; ledger 411/438. AURORA-NATIVE-SEAL-001 needs the explicit non-formatting preflight correction described in the native report. Stages 2–3/AURORA-BRIDGE-001 remain open.


AURORA-NATIVE-SEAL-001 corrected: explicit five-report allowlist, protected prefix
checks and pinned complete seals/lengths. Eight fixtures passed once; stable-snapshot
preflight passed. The authorised fourth build configured then failed compiling
`libiop/algebra/utils.cpp`: `utils.hpp:40` has undeclared `size_t`. No functional fix
or fifth build; AURORA-NATIVE-COMPILE-002 open for a bounded source-only correction
review. No native SEM/TR case ran; builds 4/4, ledger 419/448. All 24 native cases,
two new fixture reruns and three older tooling reruns remain unused. Historical
failures preserved; see native report and `seal-repair-1/` evidence. Stages 2–3 and
AURORA-BRIDGE-001 remain open; proof ledger two used/one unused.


Seal repair/fourth-build finalisation: preservation passed, 10,901 comparisons, 7073 final inventory entries, complete reporting/readback. Charged 18.074351 s; native 197.195863 s, implementation 201.753243 s, fourth-build subcap 124.900217 s remain. Eight seal fixtures/preflight passed; fourth build failed at utils.hpp undeclared size_t, all native cases unrun. Builds 4/4, ledger 419/448. AURORA-NATIVE-SEAL-001 resolved at this layer; AURORA-NATIVE-COMPILE-002 and AURORA-BRIDGE-001 remain open. See native report.


Fifth-build continuation: the exact approved standard-size correction compiled and both targets linked; the outer monitor failed on an unregistered 1,387,120-byte CMake harness object. This is an incomplete guarded run. SEM-01–SEM-08 and TR-01–TR-16 are all not run; builds 5/5, ledger 419/448, all 24 native invocations retained. AURORA-NATIVE-COMPILE-002 is resolved at declaration/compilation level. AURORA-NATIVE-ARTIFACT-001 is open: exact CMake target-local object registration and exception-safe monitor termination/reporting need a bounded correction; no such correction was made here. Full preservation admission exited 1 before a worker, with zero fresh baseline comparisons. The previous 10,901 comparisons remain historical only. Final name inventory passed (8078 entries); failure reports/readback completed, not a successful audit.

Measured compiler body 6.052475 s; worker 6.115275 s and cgroup-v2 memory.peak 450,625,536 bytes under 1 GiB. Outer wall/RSS completion metrics are unavailable. Conservative charge 73.345883 s comprises preflight 1.345883, existing unfinished-run fallback 60, failed-audit reservation 7 and bookkeeping 5; it is not a measured 60-second build. Remaining: build continuation 51.554334 s; parent 59.478106 s; native 123.849980 s; implementation 128.407360 s. Analysis/provisioning unchanged.

Stages 2–3 and AURORA-BRIDGE-001 remain open: query/masking, commitment transformation, extraction/privacy, concrete-hash and complete authentication remain unestablished. Isolation remains stopped/unactivated; CPU proving paused; proof ledger two used/one unused. No native comparison, proof, zkVM execution, installation or activation occurred. Evidence and additive failure seal: `docs/data/s3_aurora_native_transcript_pilot_1/header-correction-1/`.

Final retained-byte accounting: new evidence 000002002278 bytes; combined reservation 000003622250/4,194,304, remaining 000000572054; cumulative 000015845249/18,874,368; native 000005228882/6,291,456. No bytes removed from prior charges. Aggregate artifacts 27,839,915/134,217,728 bytes, including all 8,253,592 new bytes; the existing per-file classification breach remains unresolved. See the additive failure seal and validation-closure.json; package is **not complete**.


### Output registration/monitor repair and retained native execution

The consolidated continuation passed five tooling fixtures, then a complete pre-native preservation audit, then SEM-01–SEM-08 and TR-01–TR-16 once each. Native binaries were reused without rebuilding. Cumulative ledger is **448/450** (419 opening + 5 tooling + 24 native); two targeted tooling reruns remain unused and are not native retries. Builds remain **5/5**, with no new attempt. The first tooling command failed lint before admitting any fixture (two unused imports and an unbound loop-variable warning); the log and source snapshot are retained, the narrow correction passed lint/format, and no test was rerun.

The 22 retained compiler/linker output identities, target rules, dependencies, source overlays and successful link records were verified against the retained failure seal before execution. Exactly two CMake target-local harness object paths were added to the prospective registration. Logs/textual metadata and unregistered paths retain their evidence/fallback roles. All historical charges, including 1,844,237 bytes of build-tree evidence and the prior 73.345883-second charge, remain paid. The failed fifth-build outer guard is not retroactively marked successful.

The existing monitor now preserves a primary fatal error before containment, attempts bounded termination/reaping of its exact workload, and records cleanup/reporting errors separately. Unavailable timing/memory remains explicit; the established missing-time fallback remains 60 seconds. GUARD-04 exercised the shared fatal handler with an active harmless child, killed/reaped with exit -9; GUARD-05 exercised it after termination, retaining null measurements and a failed result. These are focused handler fixtures, not exhaustive transport/persistence fault injection or validation of the separate isolation controller.

Native results establish only the demonstrated patched-library public transcript correspondence and eight tested GF(2^192) operator behaviours. The common BCS caller, EXP2 state/round/challenge/finish paths, native public-record replay and original absorbed-digest omission control were exercised. Full Aurora proving/verifying, complete authentication, other field families and unrelated latent R1CS defects were not tested. TR-16 reproduces the original omission; it is not a forgery experiment. Existing algebraic primary-input checks remain distinct from the historical missing explicit hash-chain initialisation.

Stages 2–3 and **AURORA-BRIDGE-001 remain open**: query/masking, commitment transformation, extraction/privacy, concrete-hash composition, complete authentication and production-security obligations are unchanged. Isolation stays stopped/unactivated; CPU proving paused; proof ledger two used/one unused. No installation, configuration, compilation, proof or zkVM execution occurred in this continuation. Final preservation and exact balances are appended below after its single final audit.


Finalisation complete: the final audit exited 0 after **3.982068 seconds**, with **49,991,680 bytes** cgroup-v2 memory.peak under 256 MiB; sampled tree RSS 70,905,856 bytes. It repeated the complete 10,901 disjoint baseline content comparisons and 10,936 identity-inclusive paths with all frozen inputs/artifacts, without replacing them with prior partial evidence. Final audit inventory 8188; closure inventory 8193, no missing or unexpected paths. Both audit reporting/readback and outer guards passed. New report appendices are covered by the additive completion seal.

Charge **16.585722 seconds** = 11.585722 measured guarded wall seconds (including the retained initial static failure) + five conservative bookkeeping seconds. Remaining: continuation **94.968612 s**; parent **102.892385 s**; native **107.264258 s**; implementation **111.821638 s**. Analysis 171.260007 s and provisioning 41.843650 s remain unchanged. The old 73.345883-second conservative charge remains intact. No build reservation remains; builds 5/5 unchanged. All five tooling and 24 native cases passed once, ledger **448/450**, two narrowly reserved tooling reruns unused. The retained audit template's generic test fields are unpopulated; the individual fixture/native ledgers and closure record the actual 29 invocations.

This completes the isolated native public-input transcript pilot and its preservation continuation, not Aurora as a whole, complete authentication or proof security. AURORA-NATIVE-ARTIFACT-001 is resolved at the demonstrated repair layer; AURORA-BRIDGE-001 and Stages 2–3 stay open. No further work starts here.

Final exact evidence accounting: new 000000349206 bytes; retained-plus-new reservation 000003971456/6,291,456, remaining 000002320000; cumulative 000016194455/18,874,368; native 000005578088/8,388,608. No historic charges reclaimed. Artifacts remain 27,839,915/134,217,728 bytes; no new artifacts. Closure and additive seal: `output-guard-repair-1/validation-closure.json` and `manifest.json`.


### S3-AURORA-QUERY-MASKING-CONTRACT-1 — source contract

The [query/masking contract](stage3_aurora_query_masking_contract.md) separates the completed public native EXP2 pilot from untested private IOP/commitment code. Native continuation closed; 2,320,000 unused evidence-reservation bytes released without refunding consumption. No new functional invocations, builds or proof work.

TB-05 is refined by the full Aurora §4.7 shared-domain position convention: scalar disclosure totals are not its RS masking budget. TB-04 still requires a joint-view distribution correction/argument; TB-06 packed/selectively salted commitments and TB-09 classical restoration/quantum extraction/concrete-hash correspondence remain open. TB-01/02 are demonstrated only at the tested public native layer; TB-03/07/08/10 remain private-integration obligations. Recommend the source-only S3-AURORA-MASKING-CORRECTION-CONTRACT-1, with exact mask/message changes and a joint simulator mapping. No private prototype admitted.

Stages 2–3 and AURORA-BRIDGE-001 remain open. Isolation safely stopped/unactivated; raw-view integration and CPU proving paused; proof ledger two used/one unused. Analysis alone is charged; native107.26425821718294s and implementation111.82163787621539s remain unchanged. Preservation outcome follows in the package closure.

Finalisation: static checks and full preservation audit passed (exit0; 10,901 disjoint content comparisons; final inventory/readback complete). Audit 3.589761s, peak 48,013,312 bytes under256MiB. Package charged26.590041s; analysis remains144.669966s. No new invocations; native/implementation balances unchanged. Source contract complete; required construction corrections and all stated security gates remain open. See [closure](data/s3_aurora_query_masking_contract_1/validation-closure.json).


## S3-AURORA-MASKING-CORRECTION-CONTRACT-1 — proposed algebraic correction

The [masking correction contract](stage3_aurora_masking_correction_contract.md) defines the unrestricted sumcheck mask/disclosed sum, unit-pad general reducer and corrected folded-degree registration, with a joint adaptive classical ideal-oracle simulator. This is a supported correction for its explicit admissible algebraic family; no source patch or private profile is adopted. The current zero-sum/random-pad variant is different and unproved, not demonstrated broken. Packed commitments, private source/field correspondence and complete proof knowledge/privacy remain open.

The completed query/masking package is closed; release 919,201 unused reservation bytes without refund. Opening analysis144.66996550441067s; only analysis charged. Native107.26425821718294s and implementation111.82163787621539s unchanged. No new invocations/builds:448/450 and5/5. Recommend the inactive public synthetic S3-AURORA-SUMCHECK-MASK-CORRESPONDENCE-PILOT-1; no further work started. Stages2–3 open; isolation stopped/unactivated; CPU proving paused; proof ledger two used/one unused. Preservation completion is recorded in the new package closure.

Finalisation: complete audit exit0, 10,901 disjoint comparisons, inventory/reporting/readback passed; 3.894257s and 49,020,928 bytes cgroup peak under256MiB. One E501 static failure retained; formatting correction passed separately. Package charged18.392586s; analysis remains126.277380s. Native/implementation and448/450 invocations,5/5 builds unchanged. Contract complete, source proposals inactive and security obligations open; see [closure](data/s3_aurora_masking_correction_contract_1/validation-closure.json).


## OCT31-KYC-NATIVE-MILESTONE-1 — consolidated proposal, not execution

The [October milestone](october_implementation_milestone.md) consolidates supported native masking corrections, a real ML-DSA-65 baseline binding a persistent holder public key, independent durable verifier A/B state and a reproducible measurement harness. It replaces the inactive stand-alone sumcheck-pilot recommendation with one direct implementation request. Production/active BC-1 remain unchanged; baseline full disclosure/linkability is explicit.

One prospective approval covers scope and resource amendments: implementation674→4274s, invocations450→1050, builds5→13, evidence18→32MiB, command60/55→300/295s and up to2 jobs under2GiB aggregate with unchanged1GiB native/256MiB audit limits. No amendment is active. Initial plan392 counted invocations plus208 shared correction slots; no further general review. Native blockers leave independent baseline/harness work available after approval.

Preparation uses only the existing analysis/evidence allowance; close the completed masking contract and release873,382 unused reservation bytes, no refund. Stages2–3/AURORA-BRIDGE-001 remain open; isolation stopped/unactivated, CPU proving paused, proof ledger2used/1unused. Final preparation checks and balances follow in the proposal closure.

Preparation complete, awaiting one consolidated execution approval: static checks and full audit passed,10,901 disjoint comparisons, final inventory/reporting/readback complete. Audit3.506725s/41,791,488B cgroup peak; preparation charged19.222742s; analysis remains107.054637s. Implementation/native balances and448/450 invocations,5/5 builds unchanged. Proposed resource amendments remain inactive; see [closure](data/october_implementation_milestone_1/validation-closure.json).

## OCT31-KYC-NATIVE-MILESTONE-1 execution checkpoint

See [the execution report](oct31_kyc_native_milestone.md). B:48 cases passed in50
invocations. H:16 harness and11 distinct integration cases passed;276 exclusive
real-signature benchmark trials passed/read back. N:24 cases passed on build2;
build3 compiles the stronger N04 caller test, but revalidation/TR01–16/C09 remain
blocked by automatic approval review applying an older native cap. No bypass or
additional native cases ran. Milestone incomplete; final preservation pending its
recorded outer result. Stages2–3 and AURORA-BRIDGE-001 remain open. Proof ledger
two used/one unused; isolation stopped/unactivated and CPU proving paused.

OCT31 final preservation checkpoint: the full audit passed (exit 0), including
10,901 disjoint historical content comparisons, immutable/prefix checks and a
10,625-entry inventory. The first preparation exceeded the fixed 10,000-entry
traversal admission; its retained failure was corrected by complete disjoint-root
partitions without altering that per-partition limit or coverage. Guarded audit
time 6.058319 s; cgroup memory peak 51,773,440 B below 256 MiB. Native admission
and final-binary coverage remain open; overall milestone completion is not claimed.
See [final closure](data/oct31_kyc_native_milestone_1/validation-closure.json).

OCT31 final readback and exact-unit cleanup passed; no milestone worker remains.
Charged 381.396519 implementation seconds; 3330.425119 remain, with
826/1050 invocations and 8/13 builds used. Full preservation is complete while
final native validation remains blocked; see the execution report and closure.
Production, active profiles, historical evidence, proof/isolation ledgers and open
security obligations are preserved.

## OCT31 native finalisation — 29 September 2026

Direct user confirmation resolved **OCT31-NATIVE-ADMISSION-001** through normal
automatic review; neither rejection was bypassed. **OCT31-NATIVE-COVERAGE-001** is
resolved at the public component layer: 24 final-binary N cases, 16 retained-vector
TR cases and C-09 passed once (M1-0379–M1-0419). No build, expectation or cryptographic
source changed. Earlier results/rejections remain intact. Baseline/harness/276
measurements were reused. Ledger 867/1,050; builds 8/13. Final preservation follows
in [continuation evidence](data/oct31_kyc_native_milestone_1/native-finalisation-1/).

The bounded milestone's functional checks are complete. General Aurora correctness,
nontrivial R1CS/full authentication, query/masking and commitment transformation,
knowledge/privacy, concrete-hash, adaptive Delta_tail and production obligations
remain open. Stages 2–3/AURORA-BRIDGE-001 remain open; no proof or zkVM execution.
Isolation remains stopped/unactivated and CPU proving paused; proof ledger 2 used/1 unused.

## Final milestone closure — 29 September 2026

**OCT31-KYC-NATIVE-MILESTONE-1 is complete at its approved reference/component
validation scope.** All originally planned 392 distinct cases/trials are covered,
including all 41 pending final-binary/transcript/C-09 checks. There were no native
failures or new builds in this continuation. Baseline and all 276 benchmark results
were reused unchanged; earlier-binary results, failures and rejected admissions
remain separately preserved.

The continuation's complete preservation audit exited 0: 8,759 original plus
2,142 disjoint supplemental comparisons, 10,936 identity-inclusive historical paths,
complete prior seals/report prefixes and a 10,732-entry inventory with no missing
or unexpected names. Audit worker reporting/readback and outer guard passed.
Elapsed guard time was 4.872552 s (worker 4.203994 s); cgroup memory peak was
46,354,432 B under the unchanged 256 MiB ceiling, with no memory-event breach or
swap. Separately sampled summed process-tree RSS was 63,078,400 B; shared mappings
can be counted repeatedly in that metric. All 1,520 local link checks passed.

The first preparation reported the already-sealed `benchmarks/README.md` outside
its traversal root. Content matched its historical seal. Its helper, snapshots and
failure are retained in `native-finalisation-1/failed-preparation-1`; the correction
traverses `benchmarks` in place of its existing testbed subdirectory and retains all
expected names and hashes. Corrected preparation and affected lint/format passed.
No baseline or expected digest was regenerated, no content permission broadened,
and no functional test was repeated for this tooling correction.

Final report seals, final inventory/readback, exact-unit shutdown and all time and
storage accounting are recorded in the [completed continuation closure](data/oct31_kyc_native_milestone_1/native-finalisation-1/validation-closure.json).
The invocation ledger is 867/1,050 (419 milestone invocations; 181 milestone slots
plus two separate historical tooling slots remain). Builds remain 8/13. Analysis
and isolation allowances are unchanged; completion reserves remain inside unused
implementation/evidence balances.

The next bounded native validation target is a nontrivial public R1CS fixture
through the corrected components before considering private integration; no such
work is started here. Complete Aurora correctness, authentication/private-proof
feasibility, query/masking and commitment-transformation arguments, extraction/privacy,
concrete-hash composition, adaptive Delta_tail and production security remain open.
Stages 2–3/AURORA-BRIDGE-001 remain open; isolation stopped/unactivated and CPU
proving paused. No proof or zkVM execution occurred; proof ledger two used/one unused.

## OCT31 closure and full-relation proposal — 29 September 2026

OCT31-KYC-NATIVE-MILESTONE-1 remains complete within its approved scope and is
preserved in place as **OCT31-KYC-NATIVE-MILESTONE-1/v1**, including final native
coverage and all 276 benchmark trials. The existing closure/seals are unchanged.
[OCT31-AUTH-RELATION-INTEGRATION-1](oct31_auth_relation_integration.md) is one
inactive execution proposal for complete same-witness authentication lowering,
streamed counting/checking and nontrivial native R1CS correspondence. Its explicit
request reallocates 2,550 existing implementation seconds, 128 invocations and
three builds; proposes a bounded aggregate work-event cap; and requests zero proof
attempts. No implementation/test/build budget is consumed by this source review.

AUTH-REL-001 remains open: complete private ML-DSA verification (including capped
challenge and inverse transforms), holder/disclosure/same-rid Merkle composition,
compiler equivalence and complete counts are missing. AUTH-CAPACITY-001 records a
conditional no-go for direct one-gate/one-row resident Aurora lowering: one measured
forward NTT implies a >=24 GiB codeword in the corrected family. This is not a
full-authentication measurement or a claim against all compact representations.
A complete streamed descriptor and explicit capacity decision are required before
allocation; a small native fixture cannot close full relation validation.

TB-06/BCS committed-view simulation, private transcript/query correspondence,
state-restoration/quantum round-by-round knowledge, adaptive application extraction/
privacy, finite parameters/concrete hashes, adaptive Delta_tail and production
security remain open. AURORA-BRIDGE-001 and Stages 2–3 stay open; ordinary private
proof acceptance remains fail-closed. Isolation stopped/unactivated; CPU proving
paused; proof ledger two used/one unused. No private proof by 31 October is supported
by current evidence; the proposal identifies the concrete integration/no-go endpoint.
Preparation checks and actual analysis/storage charges are recorded in the new
[proposal closure](data/oct31_auth_relation_integration_1/validation-closure.json).

Proposal preparation preservation passed: one complete audit, 10,901 content
comparisons, 10,936 historical paths, 3.922663s and 43,925,504B cgroup peak under
256 MiB. The final proposal closure records inventory/report readback and exact
analysis-only charges. No implementation, case, build or proof was executed.

## Authentication relation integration — bounded endpoint, 29 September 2026

[OCT31-AUTH-RELATION-INTEGRATION-1 result](oct31_auth_relation_integration_result.md)
implements isolated same-witness source lowering, a streaming Boolean/gf192 R1CS
interface, actual native constraint loader and fail-closed proof boundary. The
75 bounded invocations passed their documented scopes; these include a labelled
2,000,000-gate prefix, not complete authentication. Two builds were used; the first
latent vector-constructor error and one lint failure are retained. Native loader
correction uses existing add_term on validated canonical terms without changing
pinned library code. Cumulative invocations942/1050; builds10/13.

AUTH-REL-001 remains partial: full private sampler, complete verifier and joint
rejection checks, full descriptor and frontier are unvalidated. AUTH-CAPACITY-001
rejects the direct resident route: one conditional codeword lower bound is24 GiB
before other working sets. No such allocation was attempted. The baseline/v1 and
276 measurements remain unchanged. No complete private proof by31 October follows.

Recommend one bounded compact-ML-DSA/R1CS representation contract with exact
semantics and simultaneous-buffer admission before generation; stop this backend
route if none fits. AURORA-BRIDGE-001, commitment simulation, extraction/privacy,
concrete hashes/finite parameters, adaptive Delta_tail and production security
stay open. Stages2–3 remain open; ordinary private-proof verification fail-closed.
Isolation stopped/unactivated; CPU proving paused; proof ledger2 used/1 unused.
Final preservation and exact remaining resources are recorded in the result and
[closure](data/oct31_auth_relation_integration_run_1/validation-closure.json).

Integration preservation audit passed:10,901 disjoint content comparisons,10,936
historical paths and10,999 inventory entries; guard5.595654s, cgroup peak54,116,352B
under256 MiB. Final readback/accounting is recorded in the linked closure; complete
private relation/proof admission remains blocked, independent of preservation.

## Compact authentication representation — 29 September 2026

[OCT31-COMPACT-AUTH-REPRESENTATION-1](oct31_compact_auth_representation.md)
implemented exact experimental GF192 affine XOR/NOT elimination with constrained
spills, free-bit guards and every original AND retained. All29 new invocations
passed:24 candidate fixtures, four actual-native comparisons and one resource
model. Existing native binary reused; no new build. Cumulative971/1050 invocations,
10/13 builds; work27,593,603/2^32 including prior consumption.

**Full resident admission fails.** The six required measured-core NTT embeddings
retain43,401,216 AND rows, giving a conditional48 GiB per codeword and192 GiB
for four simultaneously retained codewords, before other working structures.
The complete count is unmeasured; residual hashing, sampler, inverse arithmetic,
parsing/disclosure and same-rid Merkle costs are explicitly included symbolically.
The previous2M joint stop was its declared local probe cap, not a forced2M
count-only ceiling; raising it or streaming cannot resolve resident capacity.

AUTH-CAPACITY-001 remains open with a precise no-go for AND-preserving mapping.
AUTH-REL-001 remains partial; all21 outstanding full-relation checks stay unrun.
The guarded modmul's row count falls15,224→6,367 but nonzero terms grow51,888→135,198;
row reduction is not a measured prover-memory saving. No complete private
authentication by31 October is supported. A substantive arithmetic/representation
change with field/domain/masking correspondence is required, or stop this backend
route for that target; no further work is started here.

Comparison pointv1 and276 measurements are preserved. Stages2–3, AURORA-BRIDGE-001,
commitment simulation, extraction/privacy, concrete-hash/finite parameters,
adaptive Delta_tail and production security remain open. Ordinary proof acceptance
stays fail-closed; isolation stopped/unactivated; CPU proving paused. Proof ledger
two used/one unused; zero proofs/zkVM executions. Final preservation/readback and
remaining capacity appear in the [closure](data/oct31_compact_auth_representation_1/validation-closure.json).

Compact representation preservation passed:10,901 disjoint content comparisons,
10,936 historical paths, complete inventory/reporting; guard4.400144s and cgroup
peak46,227,456B under256 MiB. Final inventory/readback/accounting is in the linked
closure. This closes the bounded experiment, not complete private authentication.


## Arithmetic R1CS feasibility — 29 September 2026

[OCT31-ARITHMETIC-R1CS-FEASIBILITY-1](oct31_arithmetic_r1cs_feasibility.md)
closes the affine candidate unsuccessfully for resource admission, preserving its
code and results. One exact direct-integer candidate, INT-R1CS-FR254-1, is specified
with canonical ranges, no-wrap quotient/remainder constraints, signed overflow,
bit/byte links, fixed bounded sampling and the same joint authentication predicate.
**No arithmetic gadget implementation was admitted.** The required final SHAKE256
alone has 268,800 chi products; under the candidate's odd-prime hash mapping these
force at least 512 MiB per codeword and 2 GiB for four simultaneous codewords,
before positive remaining costs. XOR has explicit odd-prime constraints, not free
GF192 addition. Complete prime-field counts/peak memory remain unmeasured.

AUTH-CAPACITY-001 / AUTH-R1CS-HASH-001: arithmetic-only optimisation does not solve
this final-hash obstruction, before holder binding, full sampler and twenty Merkle
nodes. The reviewed paper-masking implementation also explicitly requires additive
domains, whereas the proposed field requires multiplicative subgroups. A compatible
masking implementation/argument is absent; the storage bound optimistically retains
the existing degree/rate envelope, not reduced security settings. Stop this route
for the 31 October target unless a substantive hash-representation and compatible
masking construction addresses both gaps. No new proof experiment is proposed.

One calculation/reporting attempt was incomplete due to an omitted new cases
directory. Its original output, diagnostic and conservative work charge are retained;
one explicit routine-correction rerun passed identically. Two invocations consumed,
cumulative 973/1050, builds unchanged 10/13. All 21 full-relation checks remain
unrun; no circuit or large instance was generated. Comparison point v1 and all
276 measurements remain unchanged. Stages 2–3, AURORA-BRIDGE-001, finite-parameter,
concrete-hash, extraction/privacy, adaptive Delta_tail and production obligations
remain open. Ordinary private-proof verification stays fail-closed; isolation
stopped/unactivated; CPU proving paused; proof ledger two used/one unused.

Final preservation and accounting are in the
[closure](data/oct31_arithmetic_r1cs_feasibility_1/validation-closure.json).


Preservation completed: the single full audit exited0 with 10,901 disjoint
content comparisons and 10,936 historical identity-inclusive paths.
It took 4.844211s including the guard (4.444965s worker),
with cgroup-v2 memory.peak 46997504B under256 MiB;
sampled summed process RSS was 63,692,800B and is a distinct metric.
All retained failure records remain present. Final inventory, report readback,
exact-unit shutdown and the authoritative remaining balances are recorded in
[validation-closure.json](data/oct31_arithmetic_r1cs_feasibility_1/validation-closure.json).
No resource admission for the complete representation follows from preservation.


## Joint hash/masking construction decision — 29 September 2026

[OCT31-JOINT-HASH-MASKING-DECISION-1](oct31_joint_hash_masking_decision.md):
**Decision C — close this Aurora route for the current October delivery plan.**
Preserve the arithmetic-only NO-GO. The exact 268,800-chi subset is the internal
ML-DSA SHAKE256(mu || w1Encode(w1),48), not the outer transcript hash.
JHM-FR254-PACKED-1 specifies one prime-field/direct-integer/Boolean-hash candidate
with multiplicative masks and packed salted commitments. Its optimistic resident
codeword/salt/tree payload floor is 7.5 GiB minus 128 bytes, before other relation
components; complete counts and peak remain unknown. This exceeds the existing
limits and observed available memory. No sufficient new resource envelope is
justified by that floor, and no amendment is proposed.

AUTH-JOINT-HASH-MASK-001: close the examined candidate unsuccessfully for delivery
admission. Aurora's multiplicative sumcheck remark supports local algebra; the
native additive-only guard is not a mathematical impossibility result. Full
prime-domain masking/knowledge and packed commitment/EXP2 correspondence remain
unestablished; AURORA-BRIDGE-001 and AUTH-CAPACITY-001 remain open obligations.
The decision is construction-specific, not an attack or universal impossibility.

The concrete delivery decision is to retain 31 October for the validated reference
KYC testbed/native correspondence/comparison dataset, excluding complete private
authentication, or revise scope/deadline and separately authorise a new integrated
construction. No further component optimisation/review or proof starts here.
One bounded calculation passed; retained lint failure plus formatting-only rerun
recorded. Cumulative invocations 974/1,050, builds unchanged 10/13. The 21 full
relation checks remain unrun. Comparison point v1 and all 276 measurements are
preserved. Stages 2–3, complete knowledge/privacy, concrete-hash/finite parameters,
adaptive Delta_tail and production security remain open. Private verification
stays fail-closed; isolation stopped/unactivated; CPU proving paused; proofs two
used/one unused. Final preservation/readback/accounting is in the
[closure](data/oct31_joint_hash_masking_decision_1/validation-closure.json).


Preservation: the single complete audit exited 0, with 10,901 disjoint content
comparisons, 10,936 historical identity-inclusive paths and complete inventory
and report generation. Guard time was 4.720063 seconds (worker 4.384852 seconds).
Cgroup-v2 memory.peak was 46,858,240 bytes, including descendants and charged
cache/kernel, under the unchanged 256 MiB ceiling; sampled summed process RSS
was 63,475,712 bytes, a separate metric. No resource breach occurred.
Final inventory, sealed report readback, exact-unit cleanup and final balances
are recorded in
[validation-closure.json](data/oct31_joint_hash_masking_decision_1/validation-closure.json).
This preservation result does not admit the proposed construction.


## Full-scope implementation consolidation — 29 September 2026

**User-confirmed scope unchanged:** the goal remains the complete privacy-preserving
PQ-DID scheme, KYC testbed and benchmarking. **31 October remains the target;
current evidence does not support committing to full completion by that date.**
No scope reduction or replacement construction has been approved. The previous
recommendation to exclude private authentication was not adopted. Preserve its
historical record; this scope confirmation supersedes that recommendation.

[Implementation consolidation](implementation_consolidation.md) indexes working
reference cryptography/lifecycles, synthetic proof gates, the disclosed/linkable
baseline, native components and incomplete private authentication. Every R-001–R-052
has an evidence/gap entry, not a blanket completion claim. W3C securing mechanisms,
issuer/vocabulary binding, DID method/key representation, private status mapping
and conformance remain unfinished. Complete private-proof measurements are null/
unavailable, never inferred from baseline signatures, component timings or journals.

The exact Aurora route is closed under its assessed construction/resource conditions
(AUTH-JOINT-HASH-MASK-001); this is not impossibility of PQ-DID. The full-relation,
security and simultaneous-resource [handover](data/implementation_consolidation_1/handover.md)
specifies the admission gates for a named replacement integrated construction.
Selection, exact profile deviations, supported security claims/remaining arguments
and a complete bounded resource/validation plan require the user's construction
decision before further private-proof implementation. No replacement is selected.
DELIVERY-SCOPE-001 records this unchanged original scope and unsupported date
commitment; it does not reduce requirements or change the target.

Comparison point v1, final binaries and all 276 measurements remain sealed and
unchanged. [Reproduction information](data/implementation_consolidation_1/reproduction.md)
consolidates exact historical commands/configs and failures without reruns.
Documentary preflight verified 362 dataset/evidence files, 21 source/binary files,
24 historical command records and exactly 52 indexed requirements. No functional
case, build, new circuit or proof ran; invocations remain 974/1050 and builds10/13.
The 21 full-relation checks remain explicitly unrun. Reference holder persistence,
production custody/entropy/erasure/side channels, adaptive Delta_tail, component
advantages, complete knowledge/privacy and concrete-hash/finite parameters remain
open. Stages 2–3 and the original implementation programme are incomplete;
AURORA-BRIDGE-001 remains open. Ordinary private-proof verification stays fail-closed.
Isolation remains stopped/unactivated, CPU proving paused, proof ledger two used/
one unused. Final preservation, readback and balances are recorded in the
[consolidation closure](data/implementation_consolidation_1/validation-closure.json).


Preservation completed: one full audit exited 0 with 10,901
disjoint content comparisons and 10,936 historical
identity-inclusive paths, complete inventory and reporting. Guard time was
4.656938 seconds; worker 4.345925 seconds.
Cgroup-v2 memory.peak was 47,390,720 bytes under
256 MiB, including descendants and charged cache/kernel. Separate sampled summed
process RSS peaked at 64,061,440 bytes. No resource breach occurred.
Final report seals, inventory/readback, cleanup and balances are in the
[closure](data/implementation_consolidation_1/validation-closure.json).
Only this consolidation is complete; the original programme remains incomplete,
with unchanged scope and 31 October target, not a supported completion commitment.


## OCT31-BINIUS64-REPLACEMENT-DECISION-1 — source decision, 29 September 2026

[Decision](oct31_binius64_replacement_decision.md): **NO-GO for private authentication
at Binius64 commit441fbf51ff0bcb0bcd28f3f1b73f4954029e8577**. Its ZK APIs exist,
but the inspected wrapper publishes the private terminal oracle claim directly,
and the inner zero-padded witness path does not establish the Blueprint's required
q+2 randomisable support. These are source findings, not an executed attack.
Current native SECURITY_BITS=96/GHASH128/SHA-256 cannot establish the intended PQ
knowledge/privacy claims. The OtterSec public-input absorption correction is present
in current caller behaviour; the cited fix commit is not an ancestor, and a specific
adversarial public-input substitution regression was not identified in the inspected
coverage. No native test ran. Cargo's transitive dependency lock is unresolved.

[One conditional integrated plan](data/oct31_binius64_replacement_decision_1/implementation-proposal.md)
records exact relation mapping, native/privacy repair gates, field/hash/masking
obligations, complete live-storage accounting and an inactive consolidated envelope.
It is not an admitted private-proof milestone or adopted profile. Whole-authentication
counts/memory remain unmeasured; no sufficient new allocation is claimed. The user
must decide whether to fund correction of this named route before implementation.
No replacement was silently selected; the examined Aurora experiments remain closed.

The complete scheme, KYC testbed and benchmarking scope is unchanged;31October
remains the target without a supported full-completion commitment. W3C issuer/
vocabulary, DID/key, securing mechanism/private status mappings, holder persistence,
adaptive Delta_tail, component advantages, concrete hashes/finite parameters,
production security and complete quantum knowledge/privacy remain open. Stages2–3
and AURORA-BRIDGE-001 remain open. Ordinary private verification stays fail-closed.
Comparison pointv1/all276 observations and21unrun full-relation checks are preserved.
No tests/builds/proofs/installation/activation: invocations974/1050, builds10/13,
proof ledger2used/1unused. Isolation stays stopped/unactivated and proving paused.
Final preservation and exact balances are in the
[package closure](data/oct31_binius64_replacement_decision_1/validation-closure.json).


Preservation completed: the full audit exited **0**, with **10,901**
disjoint original/supplementary content comparisons, **10,936** historical
identity-inclusive paths, no missing or unauthorised content, and completed inventory
and reporting. Outer guard **4.539334s**, worker
**4.203199s**, cgroup-v2 memory.peak
**47,255,552 bytes** under256MiB (worker,
descendants and charged cache/kernel); sampled process-tree RSS separately
**63,913,984 bytes**. No cgroup resource event occurred.
Scoped lint/format and documentary source/v1 checks passed; no native code ran.
[Final inventory, report readback, cleanup and exact resource balances](data/oct31_binius64_replacement_decision_1/validation-closure.json)
complete this source-decision package only. Metadata acquisition used bounded reads,
per-request timeouts and256MiB process address-space limits; it has no cgroup peak
measurement and must not be conflated with the measured audit worker.


## OCT31-BINIUS64-AUTH-INTEGRATION-1 — G0 construction stop

[Report](oct31_binius64_g0.md): **NO-GO at G0**. Source tracing confirms a clear
private terminal functional and original-row query openings without inner support
randomisation. A justified repair needs committed terminal-key equality, actual
encoder support/rank correspondence and a joint masking/commitment simulator,
including affine gamma and any additional IntMul oracle. No supported native
overlay, build, functional test or proof was produced. G1–G3 remain inactive.
This is not an impossibility result for Binius64 or PQ-DID. Full scheme/testbed/
benchmark scope and 31 October target are unchanged; full completion cannot yet
be promised. Stages 2–3 open; 21 relation checks unrun; v1 and all 276 measurements
retained. Private verification fail-closed; isolation stopped/unactivated; proving
paused; proof ledger two used, one unused. Completion evidence and balances are
in `docs/data/oct31_binius64_g0_1/validation-closure.json` and `resource-closure.json`.

G0 preservation checkpoint: complete audit exit 0; 10,901 disjoint original
comparisons, 44.875 MiB cgroup peak under 256 MiB. Final readback/shutdown and
charged balances are recorded in the G0 closure; construction NO-GO unchanged.


KYC-TESTBED-COMPLETION-1 opening: G0 NO-GO accepted. The pinned Binius64
route remains paused; no G1–G3, speculative repair or backend survey is admitted.
Reopening requires the specific committed-key/support/joint-view construction
and security correspondence in the G0 report. The newly authorised KYC workstream
retains full original scope; Stages 2–3 and private authentication remain open.
Execution plan and resource/mapping decision are recorded in
`docs/kyc_testbed_completion.md`; affected tests have not run.

KYC preparation checkpoint: isolated wallet draft and 72-case/observation plan
prepared; no new functional requirement marked satisfied. Static/identity checks
and complete preservation audit passed (10,901 historical comparisons). Execution
awaits the consolidated evidence reallocation/local-mapping decision; the original
workstream approval stands. Workstream incomplete; no new baseline/private proof
measurement, build or functional invocation. See KYC preparation closure for final
accounting. G0 NO-GO and all paused-route/security boundaries remain unchanged.

### KYC testbed approved continuation (29 September 2026)

The approved evidence transfer and local mappings are implemented. Durable reference
holder storage, connected genuine ML-DSA baseline flows and local canonical-bound
projections passed 24 wallet, 14 application and ten mapping cases, plus one affected
promoted-module recovery check. Two initial call-site failures were corrected and
retained. Nineteen new baseline observations are separate from all 276 v1 results.
Four-record scaling failed at the existing issuer complete-record encoding cap;
four remaining scaling entries are unrun. No larger-storage limit/design was adopted.
See [current result](kyc_testbed_completion.md#approved-continuation-implemented-result)
and its execution resource closure. Invocations 1045/1050, builds 10/13, proofs 2/3
(two used, one unused). Original scope/31 October target unchanged, full completion
commitment unsupported. Stages 2–3 open; Binius64 paused, Aurora assessed route closed,
private verification fail-closed, isolation stopped/unactivated and proving paused.

KYC continuation preservation: complete audit passed (10,901 disjoint historical
comparisons, 10,936 identity-inclusive paths), under the unchanged 256 MiB audit
ceiling. See the execution validation/resource closures for final readback,
shutdown and balances. Functional scaling failure remains open.


### KYC-ISSUER-INCREMENTAL-STORAGE-1

The isolated v2 issuer stores bounded per-session records and atomic digest-event/head
updates, with explicit origin-bound migration and independent freshness tickets.
35 storage/recovery cases, eight genuine bounded-ML-DSA application cases and three
new baseline scaling observations passed (46 invocations; 1,091/1,146 cumulative).
The retained v1 four-record failure is reproduced on a sealed copy, then resolved in
v2; actual four-record catch-up now passes. R-2-1 and R-2-4 are newly measured.
R-1-8/R-2-8 remain unrun: the unchanged manager aggregate checkpoint needs at least
89,296 update-payload bytes before other fields, exceeding 65,536; its observed
four-record database is already 475,136/524,288 bytes. The manager needs a separately
scoped incremental history/checkpoint/outcome design before larger-scale admission.
No manager architecture or limit was changed implicitly. See
[issuer storage report](kyc_issuer_incremental_storage.md) and its new evidence series.
Original 276 and subsequent 19 observations, v1, protected sources and failures stay
unchanged. Private authentication/security/standards obligations and Stages 2–3 remain
open; this is not completion of the KYC workstream or original programme. Binius64
remains paused, private verification fail-closed, proof ledger two used/one unused.


Preservation checkpoint: the single full audit **passed**, exit 0, with
10,901 disjoint historical comparisons and
10,936 identity-inclusive paths; no changed/missing
protected content or inventory discrepancy. Guard time 4.840s; worker
`memory.peak` 48,730,112 bytes (46.473 MiB), including descendants
and charged cache/kernel, below 256 MiB with no resource breach. Final inventory,
report readback, terminated workload and actual balances are recorded in
`docs/data/kyc_issuer_incremental_storage_1/validation-closure.json` and
`resource-closure.json`. Historical failures remain failures; two eight-record
measurements remain unrun, and no missing private-authentication result is supplied.


### KYC-MANAGER-INCREMENTAL-STORAGE-1

The isolated manager-v2 storage, bounded public-state paging and atomic holder
catch-up now pass 47 distinct checks (49 invocations including two retained, corrected
failures). R-1-8/R-2-8 completed: eight updates, two 55,041-byte responses, one final
wallet update; manager DB 450,560/524,288 bytes. Largest validated history is eight.
One/four-record affected measurements are also retained as a new series. Original
276, subsequent 19 and issuer-v2 three observations remain immutable. No larger-scale
capacity, private authentication or privacy-overhead claim follows. See
[manager storage report](kyc_manager_incremental_storage.md) and its individual outcomes.
Cumulative invocations 1,140/1,146; builds 10/13; proof ledger two used/one unused.
KYC-TESTBED-SCALE-001's tested four/eight-record obstruction is resolved for v2;
production custody/rollback/power-loss, larger capacity, standards-level interoperability
and full proof/security obligations remain open. Stages 2–3 remain open; private
verification fail-closed, Binius64 paused, proving/isolation paused. The full scope
and 31 October target remain unchanged without a supported completion commitment.


Preservation checkpoint: the single full audit **passed**, exit 0, with
10,901 disjoint historical comparisons and
10,936 identity-inclusive paths; no changed/missing
protected content or inventory discrepancy. Guard time 4.878s; worker
`memory.peak` 49,483,776 bytes (47.191 MiB), including descendants
and charged cache/kernel, below 256 MiB with no resource breach. Final inventory,
report readback, terminated workload and actual balances are recorded in
`docs/data/kyc_manager_incremental_storage_1/validation-closure.json` and
`resource-closure.json`. Historical failures remain failures; two eight-record
measurements remain unrun, and no missing private-authentication result is supplied.


### Retained evidence handover checkpoint

The completed issuer-v2/manager-v2/wallet/paged-history results are registered as
`KYC-BASELINE-ISSUER2-MANAGER2-WALLET-PAGED-1` in
`docs/data/private_proof_handover_1/comparison-point.json`; earlier datasets and
failures remain unchanged. Packaging the retained G0 evidence stopped at the
1 MiB per-file ceiling (1,065,684 bytes, 17,108 over). The failed archive and guard
record are retained; archive readback/full final audit remain incomplete. See
`docs/private_proof_handover.md`. No new analysis, functional cases, builds or proofs.
Binius64 stays paused, private verification fail-closed, Stages 2–3 open; original
scope and 31 October target unchanged without a supported completion commitment.


Private-proof handover continuation: the exact-path 2 MiB prospective exception
was approved. Retained v1 is complete and reused unchanged: 1,065,684 bytes,
112 safe members, exact payload hashes, complete compression readback. No v2 was
created. The original overrun remains a failure. Current identity is
`docs/data/private_proof_handover_1/continuation-1/archive-verified.json`; final
preservation/closing records govern handover completion. No functional tests,
builds, new security analysis or proofs; Binius64 paused and private verification
fail-closed. Original scope, 31 October target, Stages 2–3 obligations unchanged.


Preservation continuation: the single complete audit passed, exit **0**, with
10,901 disjoint historical content comparisons and
10,936 identity-inclusive paths; no missing or
unexpected inventory entries. Guard time **4.767 seconds**, worker
`memory.peak` **49,307,648 bytes** (47.023 MiB), including descendants
and charged cache/kernel, below 256 MiB. The final inventory, reporting readback,
workload shutdown and exact remaining balances are recorded in
`docs/data/private_proof_handover_1/validation-closure.json` and
`resource-closure.json`. The original failure and all earlier datasets remain
unchanged; this is completion of packaging only.


### S3-BINIUS-JOINT-OPENING-CONSTRUCTION-1

[Joint-opening construction decision](stage3_binius_joint_opening_construction.md):
**NO-GO for a native correction prototype on the established correspondence.**
The joint zero-target equation has a local same-commitment binding argument and a
conditional aggregate-mask coupling. It does not establish joint-view privacy.
New pinned NTT source resolves the earlier generic example: native `E(m)[0]=m[0]`,
so randomising a trailing support cannot hide a witness-dependent first symbol.
`B64-JOINT-001` requires the explicit embedding, support/image condition and
sequential commitment/opening simulator/extractor in JOINT-OPENING-LEMMA-1, across
all oracle shapes including IntMul. Its logup helper internals remain unacquired.
The exact specialist question is in the report; no implementation package is active.

The user-supplied independent review is retained unchanged. Ten necessary source
files were obtained at the unchanged pin, with verified tree blob IDs. The
acquisition's lifetime RSS diagnostic exceeded 256 MiB while its address-space
limit was installed; no before/after baseline or cgroup trace resolves that
observation. `B64-JOINT-RESOURCE-001` remains open: do not certify that acquisition
as resident-memory-compliant. No further acquisition/probe followed. Full
preservation and its completion-worker measurements are recorded separately.

No functional tests, builds, proofs, benchmarks or activation. Invocations remain
1,140/1,146, builds 10/13, proof ledger two used/one unused. Existing analysis
allowance alone is charged; implementation/KYC balances and reserves remain
unchanged. Comparison point v1, all 276 original measurements, later KYC datasets
and 21 unrun full-relation cases remain unchanged. Binius64/proving/isolation stay
paused; private verification fail-closed; Stages 2–3 open. Full project scope and
31 October target remain unchanged without a supported completion commitment.


### Preservation completion checkpoint

The single full audit passed, exit **0**: **10,901**
disjoint historical content comparisons and **10,936** identity-inclusive paths,
with no changed/missing protected content or inventory discrepancy. Audit guard
time was **4.635 seconds**; cgroup-v2 `memory.peak` was
**47,558,656 bytes**, including descendants and charged
cache/kernel, below 256 MiB. This certifies the audit worker, not the unresolved
source-acquisition lifetime-RSS observation. The first static run's E501 failure
and exact formatting correction are retained; the affected repeat passed. No
functional case was run. Final report seal, inventory/readback and exact closing
analysis balance are in `docs/data/s3_binius_joint_opening_construction_1/` `manifest.json`, `validation-closure.json`
and `resource-closure.json`. Historical baselines and previous failure records
were not regenerated or changed. This completes a construction decision and
preservation checkpoint, not a native privacy repair or proof-security claim.


## S3-BINIUS-EMBEDDING-CORRESPONDENCE-1 — preparation only

The proposed native-embedding addendum is assessed in
[the component report](stage3_binius_embedding_correspondence.md), with the inactive
execution plan in `docs/data/s3_binius_embedding_correspondence_1/`.
The retained bit reversal, interleaving and basis contracts support the proposed
even/odd embedding and its low-degree random-polynomial rank argument. This is
source/mathematical correspondence, not an executed native comparison. The
restricted joint-view lemma requires fixed operands/public aggregate, independent
fresh masks and nonzero gamma. It excludes commitment roots, online transcript
order and extractor access; individual mask claims cannot be substituted for
its aggregate claim. Terminal joint-opening, commitment simulation, extraction,
QROM/concrete-hash and finite-security obligations remain separate and open.

`B64-JOINT-001` is narrowed by an explicit embedding proposal, not closed.
`B64-ZK-001/002` remain findings about the unchanged implementation.
`B64-JOINT-RESOURCE-001` and every earlier failure remain retained. No new source
acquisition, functional test, build, proof or activation occurred in preparation.
The requested component is inactive: 200 existing implementation seconds outside
KYC, 25 fixed cases plus three correction reruns (28 total, requiring ceiling
1,146 to 1,168), and inspection of 15 exactly pinned missing source files. Native
comparisons remain unrun/unreserved; no build or dependency installation is sought.

Invocations remain 1,140/1,146, builds 10/13 and proofs two used/one unused.
Implementation 810.6179695621813 seconds and KYC 443.3903556420428 seconds remain
unchanged, including the KYC 300-second reserve. Only existing analysis capacity
funds preparation. Comparison point v1, all 276 original measurements and later
KYC datasets are preserved; the 21 full-relation cases remain unrun. Stages 2–3
remain open; private verification fail-closed; Binius64, proving and isolation
paused. Full project scope and 31 October target remain unchanged, without a
supported commitment to full completion. Final preservation/accounting is recorded
in the component report and its closure files.


### Preservation completion checkpoint

The single full preservation audit passed with exit **0**: **10,901**
disjoint historical content comparisons and **10,936** identity-inclusive
paths; no protected changes, missing files or inventory discrepancy. Guarded wall
time was **4.742 seconds** and cgroup-v2 `memory.peak` was
**48,177,152 bytes**, covering the worker and descendants plus charged
cache/kernel memory, below the unchanged 256 MiB ceiling. Static lint/format and
preparation also passed on their first runs. The report seal and final inventory/
readback are completed through the existing workflow; their definitive outcome and
exact closing balances are in `docs/data/s3_binius_embedding_correspondence_1/`
`validation-closure.json` and `resource-closure.json`.

This completes preparation and preservation only. All EC/N cases remain unrun;
the component implementation/allowance request remains inactive. Implementation,
KYC, invocation, build and proof balances are unchanged. Historical resource
qualifications remain open; this audit does not certify the earlier acquisition.


## S3-BINIUS-EMBEDDING-CORRESPONDENCE-1 — authorised attempt, representation stop

The approved 15 source blobs (176,779 bytes) were acquired at the unchanged pin;
length, Git blob and SHA-256 records are retained. Acquisition passed the new
256 MiB cgroup guard (25,866,240-byte cgroup peak); the earlier acquisition-memory
qualification remains unresolved. No additional source or dependency was acquired.

**B64-EMBED-REP-001:** the approved files invoke but do not define `binary_field!`.
The missing `crates/field/src/binary_field.rs` (24,075 bytes; tree blob
`d073d856abf2d1a2ad58b9a0dbe6b7a49460f1df`) prevents inspection of the exact scalar
associated-constant mapping required for Gao–Mateer/IntMul correspondence.
Metadata is verified from the retained tree; this file's content is unavailable.
Per the approved stop rule, no model/adapter was substituted and EC-01–25 are all
unrun. EC-08 remains a declared-layout check, not arbitrary vector recognition.
Native N-01–04 remain unrun. The component report records acquired logup shapes,
same-Y dual openings, prefix/suffix point ordering and unresolved proof obligations.

Prospective invocation ceiling is now 1,168; consumption remains 1,140. Builds
10/13, proof ledger two used/one unused. Implementation alone pays this attempt;
KYC/analysis balances and reserves are unchanged. Per-case outcomes, final audit
and exact closing balances are under
`docs/data/s3_binius_embedding_correspondence_1/execution/`.

Production, BC-1, all baselines/measurements and historical failures are preserved.
Stages 2–3, terminal joint-opening, commitment/online simulation, extraction,
QROM/concrete security and adaptive-tail obligations remain open. Binius64,
proving and isolation remain paused; private verification fail-closed. Full scope
and 31 October target are unchanged without a supported completion commitment.
No subsequent package is active. This is an evidence-dependency stop, not a
counterexample to the embedding lemma or a NO-GO for the overall PQ-DID approach.


### Execution preservation and retained tooling corrections

Full preservation passed, exit **0**, in **4.534 guarded seconds**:
**10,901 disjoint historical content comparisons**, **10,936 identity-inclusive
paths, and no missing/changed protected file or inventory discrepancy. Cgroup-v2
`memory.peak` was **48,721,920 bytes**, including descendants and charged
cache/kernel memory, below 256 MiB. The final inventory/report seal/readback and
precise closing ledger are in `execution/validation-closure.json` and
`execution/resource-closure.json`.

Three tooling failures are retained, separately from the unrun EC cases:

1. `quality`: E501 in a diagnostic string; splitting the literal preserved its
   exact runtime value and AST. The affected `quality-2` passed.
2. `prepare`: the new helper wrote its newly collected snapshot twice; the
   established auditor refused the second write. The original partial
   `checked-inputs.json` is preserved. The correction writes once to
   `checked-inputs-v2.json` after including the isolated README; no original
   expected entries, hashes or baselines changed.
3. `quality-3`: stopped before starting a worker because the reused resume helper
   recognised the initial lint stop but not the retained preparation stop. The
   correction admits only the exact three recorded failure phases and verifies
   their retained hashes/reasons; unknown stops or resource failures still stop.
   `quality-4` passed, then `prepare-2` passed. No functional invocation was used
   for these static/preservation checks. Every failed guard/log/stop record remains.

The single full audit then passed. Finalisation preserves the approved 1 MiB
package-output cap and 2 MiB shared completion reserve. No actual resource breach
occurred in this attempt. No component result, native correspondence or security
claim is inferred from preservation success. The outstanding construction still
needs same-object terminal joint opening, commitment/online simulation and
extraction correspondence; supplying the missing macro source alone would address
only this component's representation-admission evidence.


### S3-BINIUS-EMBEDDING-CORRESPONDENCE-1 — approved scalar-source continuation

The extra 24,075-byte `binary_field.rs` at unchanged commit
`441fbf51ff0bcb0bcd28f3f1b73f4954029e8577` passed retained-tree/blob/length checks;
SHA-256 `4907b827c90b585f110186524cdb5442e37e6b5f0ded79544a1c5f343c189390`.
The 15 original files/seals are reused. `B64-EMBED-REP-001` is resolved at the
scalar Python-model admission layer. The historical blocked attempt is preserved.

Isolated layout/encoder/reference/operand/query helpers implement the approved
component; EC-01–EC-25 all passed once, with no case corrections/reruns. EC-08
checks an explicit declared parity mismatch, not arbitrary-vector detectability.
Six complete small encoder outputs match independent polynomial arithmetic;
aggregate/individual-claim controls preserve the restricted lemma's qualifications.
Native N-01–N-04 remain unrun. Detailed individual outcomes and source correspondence
are in [the report](stage3_binius_embedding_correspondence.md) and
`data/s3_binius_embedding_correspondence_1/continuation-1/case-summary.json`.

Invocations: **1,165/1,168**; three corrective slots unused; builds **10/13**;
proofs **two used/one unused**. The same 200-second package and 1 MiB evidence cap
apply, with KYC/analysis allowances untouched. The narrow README evidence-accounting
fix and both passing static checks are recorded separately; no historical failure
was rewritten. Final preservation/result and exact ledger follow below and in the
continuation closure files.

Terminal same-object joint opening, commitment/online simulation, extraction,
exceptional-challenge soundness, quantum/concrete security and adaptive-tail
obligations remain open. The historical acquisition-memory observation is still
unresolved. Production/profile/baseline datasets are unchanged. Stages 2–3 remain
open; Binius/private proving and isolation remain paused, private verification
fail-closed. No full private-authentication or native-security claim is made.


### Continuation preservation and completion record

The full comparison audit and outer resource guard passed, exit **0**, in
**4.741370 seconds**, with cgroup-v2 `memory.peak`
**49,397,760 bytes**, below the unchanged 256 MiB
ceiling. Coverage was **10,901** disjoint original/supplementary content
comparisons and **10,936** identity-inclusive paths. Content, report prefixes,
seals, documentation and inventory checks passed; no unexpected/missing protected
files or overlapping partitions were reported.

A preceding launcher failed before the comparison auditor was entered because
its preparation omitted the required `scope_sha256`. This is retained as
`continuation-1/full-audit.json`, its log/service record, `STOP.json`, and the
byte-identical failed-result snapshot `audit-failure.json`. The routine correction
restored that required scope-hash check, retained the old helpers and preparation,
and used new `quality-3`, `prepare-2` and `full-audit-2` records. Both corrected
static/preparation phases passed. There were **two launcher attempts, one failed
before comparisons, and one complete comparison audit**; nothing was refunded or
retroactively labelled successful. No case was rerun and no resource ceiling was
increased. The failed result remains separate from the successful aggregate result.

Five additional conservative correction/bookkeeping seconds are charged, making
**50** operator seconds plus all guarded continuation times, on top of the
unchanged prior **61.68825586186722 seconds**. This replaces the provisional
45-second operator figure above prospectively. Final inventory, report seals and
readback are recorded in `continuation-1/validation-closure.json`; exact consumed
and remaining balances, including all failures, are in
`continuation-1/resource-closure.json`. Those closure records determine final
completion, rather than the comparison-only evidence.

EC-01–EC-25 are passed **Python-model results**; native comparisons remain unrun.
The component resolves scalar admission and supplies independent small-instance
embedding evidence. It does not discharge terminal same-object joint opening,
commitment/online simulation, extraction or quantum/finite-parameter security.
Stages 2–3 stay open, production verification fail-closed, Binius/proving/isolation
paused, and the proof ledger two used/one unused. No subsequent package is started.


## S3-BINIUS-COMMITTED-VIEW-CORRESPONDENCE-1 — bounded construction result

The [consolidated report](stage3_binius_committed_view_correspondence.md) closes
the mathematical attempt with **CV-ONLINE-SAME-OBJECT-1 unresolved**, without
admitting a native prototype. It fixes both IntMul slots to the same Y and outer
z objects, preserves transparent suffix ordering, specifies global batching,
and derives a conditional leaf-entropy rank criterion. The concrete-root and
programmable-root simulator attempts stop at identified commitment/prefix
conditions; same-object extraction is separate. The stronger-view saturation
example is not an executed native attack.

The completed embedding package and EC-01–EC-25 remain Python-model evidence;
no new functional invocations, builds, sources or proofs are authorised here.
Allocation: up to 180 existing non-KYC implementation seconds, including 30 for
completion; 1 MiB evidence within existing shared headroom. KYC and analysis
balances are untouched. Exact final accounting and preservation are recorded in
`data/s3_binius_committed_view_correspondence_1/` at this checkpoint.
Stages 2–3 remain open. Production/private proving and isolation remain paused,
verification fail-closed, proof ledger two used/one unused. No next package is
started; the complete scope and 31 October target are unchanged, without a
supported commitment to complete private authentication by that date.


### Completed comparison audit and finalisation

The single complete preservation audit passed, exit **0**, in **5.025703 seconds**.
It completed **10,901** disjoint historical content comparisons and **10,936**
identity-inclusive paths; no content discrepancy, missing protected entry or
partition overlap was reported. The audit-time inventory contained **12,472**
paths. Documentation/link checks and report generation/readback within the audit
passed. The enclosing guard passed: cgroup-v2 `memory.peak` **48,558,080 bytes**,
sampled tree RSS **63,836,160 bytes**, swap peak zero, no memory-limit/OOM event,
under the unchanged **268,435,456-byte** ceiling. The cgroup metric covers the
worker and descendants, including charged anonymous, file-cache and kernel memory;
the external monitor is outside that cgroup. The two metrics have different
accounting scopes and must not be added or treated as interchangeable.

Static/lint/format and sealed-input checks passed in **0.327315 seconds**; inventory
preparation passed in **0.810629 seconds**. This is zero functional validation
invocations. The final inventory, sealed-report readback and termination evidence
are completed by the package's `validation-closure.json`; exact final resource
usage and remaining balances are in `resource-closure.json`. Neither earlier
comparison-only results nor this paragraph alone substitutes for that closure.

The construction result is an unresolved lemma, not a supported implementation
release. The completed embedding results and unresolved acquisition-memory
observation are preserved. No implementation/proof follows this package.


## KYC-TESTBED-DELIVERY-1 — current delivery evidence

[Delivery report](kyc_testbed_delivery.md) and
[interoperability limits](kyc_testbed_interoperability_limits.md) provide the current
reproduction entry points and requirement boundary. All 18 fixed invocations passed
once: 10 genuine baseline demonstrations, 4 export checks and 4 smoke observations.
No functional rerun occurred; one failed static pass and its correction are retained.
V2 recovery uses the versioned issuer interface, not historical Scenario.reopen.
Seven-update catch-up used two bounded pages; own revocation reached epoch eight.
The baseline wallet and private reference wallet remain different objects; the DID
registry remains an in-memory reference service.

Verified/exported 302 retained successful observations in separate 276/19/3/4
datasets, with seven historical failed invocations separately indexed; four new
runner-smoke observations remain separate. No distribution/capacity/private-proof
measurement is inferred. The earlier statements that benchmarks do not exist or
eight-record scaling remains unrun are superseded by the retained benchmark and
manager-v2 results; their historical text/evidence is preserved.

Ledger before finalisation: 1,183/1,190, four delivery correction slots and three
embedding-only slots unused, builds 10/13, proof ledger two used/one unused. The
20-second preparation charge and 80-second internal transfer are recorded once;
220-second package and 2 MiB evidence caps retain KYC's 300-second/shared 2 MiB
reserves. Exact checkpoint and balances are in data/kyc_testbed_delivery_1 closures.
KYC-INT-001–004 remain standards obligations; approved local projections are not
secured VCs/VPs or an invented cryptosuite. CV-ONLINE-SAME-OBJECT-1 remains unresolved
and its attempt closed. Full scope, 31 October target and Stages 2–3 remain unchanged;
no supported full private-authentication completion commitment follows. Private
verification is fail-closed; Binius64 proving/isolation paused. No next package.

### KYC delivery preservation correction and final checkpoint

All 18 fixed delivery cases passed once. The first preservation comparison rejected
the newly appended benchmark README because its exact documentation permission was
missing at the inherited primary layer. The retained 211-byte prefix seal matched;
the routine correction registered only that filename while retaining prefix checks,
immutable inputs and the failed attempt. Corrected static/preparation/full audit
passed: 10,901 historical content comparisons and 10,936 identity-inclusive paths.
See docs/data/kyc_testbed_delivery_1/validation-closure.json for final inventory,
readback and termination, and resource-closure.json for exact final balances.
No functional revalidation was needed for this tooling-only correction. Baseline
items alone are eligible for closure; KYC-INT-001–004 and CV-ONLINE-SAME-OBJECT-1,
private authentication/security and Stages 2–3 remain open. All pauses are unchanged.


## LIGETRON-CORRECTION-AND-ADMISSION-1 — CPU component result

The [component report](ligetron_correction_and_admission.md) records an isolated
six-path overlay against public commit 4b1cdef1bfdf4497fb3e38170db4541fba3f6c12.
Commit/tree records verify the 19 snapshot blobs plus the pinned BN254 source.
Checked entropy, seeded query blocks, bounded field rejection and separated
challenge streams are implemented in shared routines. One CPU build and all 35
fixed cases passed once; zero functional reruns. Full WebGPU/VM/proof paths remain
unrun. The retained dependency-index, static and pre-admission CLI failures are
recorded with their corrections; no historical evidence was overwritten.

LIG-PARAM-MASK-001, LIG-PUBLIC-EXPANSION-001, LIG-COMMIT-FS-001 and
LIG-KNOWLEDGE-PQ-001 remain open as detailed in the report. The strict privacy
parameter premise is not met by the unchanged direct mapping; separate-IV public
AES expansion and complete commitment/compiler correspondence are unestablished.
**Private-proof admission remains denied.** Passing components neither repairs
those construction gaps nor establishes complete authentication or a security level.

Final preservation and exact accounting are in
`data/ligetron_correction_admission_1/validation-closure.json` and
`data/ligetron_correction_admission_1/resource-closure.json`. The 30-second
preparation debit and 600-second/39-slot amendments are prospective and separately
recorded. KYC capacity/reserve and all prior reserved slots remain untouched.
Baseline datasets and failures remain preserved; Stages 2–3 stay open, Binius
correspondence stays closed/unresolved, verification fail-closed, proving/isolation
paused, proof ledger two used/one unused. No subsequent package starts.


### Final preservation result

The single complete audit passed, exit 0, in **7.187452 seconds**
(including guarded launch/completion). Audit-worker cgroup-v2 memory.peak was
**59,756,544 bytes**, below 256 MiB. It completed **10,901**
disjoint historical content comparisons and **10,936**
identity-inclusive paths. Audit-time inventory: **13,091**;
no missing/unexpected paths or partition overlap. The final inventory, complete
report seal/readback, termination and exact remaining balances are recorded in
the package validation/resource closures. No proof-security obligation is closed.


## LIGETRON-DOMAIN-MASK-CORRECTION-1 — component outcome

[Report](ligetron_domain_mask_correction.md): isolated coset/full-code-mask and
constrained linear/quadratic-mask overlay; 32 fixed cases passed once with no
corrective reruns. CPU build 1 failed before compilation (missing output parent);
build 2 succeeded. Both slots are consumed. Native field/RNG/witness-manager
checks and explicitly labelled CPU transform models are distinguished from
uncompiled/unrun GPU, VM and full prover/verifier paths. Earlier 35-case
randomness evidence and all baseline datasets remain unchanged.

The component uses k8192/ell7936/n32768, 256 padding/192 queries and a disjoint
7H_n code domain. Native public coefficient degree requires D_L=2k-1, rather
than the cited paper's k+ell-1; full theorem correspondence is not asserted.
LIG-PARAM-MASK-001, LIG-PUBLIC-EXPANSION-001, LIG-COMMIT-FS-001 and
LIG-KNOWLEDGE-PQ-001 remain open. No complete private-proof admission follows.
Prospective slot ceiling1265 and allocation360s outside KYC preserve consumption
and reserves. Exact closure: data/ligetron_domain_mask_correction_1. Stages2–3
remain open, Binius correspondence closed/unresolved, verification fail-closed,
proving/isolation paused, proof ledger two used/one unused. No next package.


## LIGETRON-FULL-PATH-ENGINEERING-1 — memory-gated continuation

The [engineering report](ligetron_full_path_engineering.md) records prospective
authorisation and the failed dual-environment memory gate: WSL3,926,478,848 bytes
available and Windows2,363,203,584 bytes free, each below4,294,967,296. No acquisition,
configuration, build, functional invocation, device workload or proof was admitted.
A separately sealed partial source overlay adds bounded file/gzip I/O, explicit
digest initialisation and offline CMake wiring; it remains uncompiled/unvalidated.
Complete statement/protobuf binding and native harness/path work remain unfinished.
E01–E40 are individually UNRUN. Builds13/17 and invocations1250/1313 retain all
historical consumption and reservations; the new synthetic-only proof attempt is
unspent alongside the original reserved attempt (two used, two separately reserved).
Final preservation/accounting: data/ligetron_full_path_engineering_1 closures.
The package is blocked, not complete; resume only after the unchanged4 GiB gate
passes in both environments. KYC383.7084432235879 seconds/reserve300, all datasets
and both completed Ligetron components remain preserved. Degree/masking,
commitment/compiler, challenge expansion, extraction/quantum obligations and
Stages2–3 remain open. Verification stays fail-closed, private proving/isolation
paused; Binius remains closed/unresolved. No automatic next package or restart.
