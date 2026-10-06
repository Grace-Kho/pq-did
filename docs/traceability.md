# Requirement traceability — Stage 1 contract and Stage 2 evidence

Authority: [selected manuscript](manuscript/PQ_DID__Implementation.pdf), SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`, **Sections II–VIII only**.
The abstract, I and IX onwards supply no requirements or performance evidence.
The full contract and equation expansions are in [implementation_spec.md](implementation_spec.md).

The 19 September [profile-change proposal](stage3_profile_change_proposal.md),
[draft benchmark targets](benchmark_targets.md) and
[separate unadopted amendments](stage3_profile_spec_draft.md) add a decision record,
not replacement implementation or security evidence. See the final table below.

Codec/schema/public-policy/expiry, holder-binding/Merkle reference functions and typed
parameter/credential structures, exact Mcred, bounded Python ML-DSA-65 verification and
complete local CredValid and executable enrolment/authentication reference relations
are implemented and tested as marked below. Other functions remain planned. Earlier coverage tables retain their work-package boundaries; the final
table records the current relation/public-check evidence.
`T-nnn` denotes the full planned test family, not a claim that all its cases exist.
Actual test files/functions are listed separately. Paths are relative to `src/pqdid/`
unless prefixed `native/` or `tests/`. Measurements remain planned observations unless
identified as executed byte/data checks. No circuit/proof performance or security
property is established by these unit tests.

Layers: **PRIV** = inside the private circuit (and Stage 2's local reference predicate);
**PUB** = public cryptographic checks; **LIFE** = stateful services/holder approval;
**PROOF** = proof/circuit construction and checking; **MODEL** = security assumptions
and validation. A row may cover several layers; its code boundaries must preserve R-025.
Stage 2 produces codecs/primitives/reference relations; Stage 3 produces circuits/proofs;
later stages integrate DAA and lifecycle services. Issue dispositions are in
[spec_issues.md](spec_issues.md).

| ID | Manuscript location | Required behaviour and layer | Module/function (see status) | Positive and negative tests (full planned family) | Relevant measurement | Status/dependency |
|---|---|---|---|---|---|---|
| R-001 | III-B; IV-A instance; VII-A.1 `refI/pp`, pp. 3,5,14 | PUB/LIFE: immutable issuer/key/schema/namespace and pinned trust; identifier bounds | `hash_domain.HashDomain/encode_metadata`; `parameters.PublicParameters/InstanceMetadata/validate_parameters_structure`; planned `trust.authorise` | T-001: accept pinned instance; reject same `refI` with changed schema/key, cross-instance data, empty/257-byte IDs | Instance/encoding bytes; rejected cross-instance cases | Canonical reference/schema/namespace and complete expected-pp agreement tested; issuer-key FIPS decoding/bounded matrix expansion exercised by CredValid; setup/keypair provenance, immutable registration and trust remain pending |
| R-002 | III-A–C; IV-B Issue; V-A/C; VI-A; VII-A.5/.6/.8, pp. 3–10,15–17 | PRIV/LIFE/MODEL: respect owners and permitted public leakage | `statements`, `witnesses`, `public_checks`, `relations`; planned wallet/issuer/transcript audit | T-002: observed fields equal authorised leakage; fail audit on public secret/binding/signature/hidden `rid`, including logs/errors | Message fields/bytes and access audit | Typed public statements omit authentication witness fields; local witness APIs are separate from public checks; remote services and privacy proof remain unimplemented |
| R-003 | III-B/C; IV-A current-state assumption; VI-E; VIII-E, pp. 3–5,13,20 | LIFE/MODEL: authenticated confidential issuance, ordering, trusted time and atomic state | `services`, `verifier.accept` | T-003: valid authenticated ordered services; reject unavailable, unauthenticated, conflicting or stale responses | Service failures; ordering/commit events | Planned; adapters and deployment inputs later |
| R-004 | IV-A/B; V-A; VII-A.1–.3/.7/.8, pp. 5–7,14–17 | LIFE: preserve parameter/state ownership and separate credentials from witnesses | `parameters`, `credentials`, `statements` state/context records and `witnesses`; planned owner/service state | T-004: reload complete owner state; reject missing/mismatched instance or inconsistent pending state | Persistent record sizes; recovery coverage | Immutable pp/µ/cert/vc/state/context/statement/witness interfaces implemented; credential/path separation tested; cfgD/trust/services/persistence pending |
| R-005 | VII opening `enc/LP/I2OSP`; VII-A.1–.8, pp. 14–17 | PRIV/PUB: canonical tagged, ordered, bounded bytes with no alternative encodings | `codec`; typed `schema`, `policy`, `hash_domain`, `binding`, `parameters`, `credentials`, `statements`, `witnesses` | T-005: cross-language exact vectors/round trips; reject wrong tag/count/order/type, duplicates, truncation, extra bytes, oversized LP, double encoding | Encoded lengths; rejection before oversized allocation | Canonical typed statements/context/state and fixed 32-/5329-byte witnesses added with independent vectors/domain tests; other service object validators remain pending; SPEC-001 unchanged |
| R-006 | VII-A.1 schema/`Ej/Esch`; V-A/B, pp. 7–8,14 | PRIV/PUB: valid immutable schema and 1024-byte attribute encoding | `circuits.auth_parsing.parse_attributes`; `schema.AttributeField/Schema`, `encode_schema/decode_schema`, `encode_attribute/decode_attribute`, `encode_attributes/decode_attributes` | T-006: legal field-count/capacity boundaries; reject repeated names/indices, wrong type length, Boolean 2, overflow, non-zero field/tail padding | Capacity sum; vector length; boundary cases | Private circuit length/type/field-and-tail padding checks now match the local parser, including maximum capacity and uint64 maximum; credential/DID-control validation remains separate |
| R-007 | V-A; VII-A.1 policy/disclosure, pp. 7,14 | PRIV/PUB/LIFE: padded projection, ordered disclosed-field-only policy, approval | `circuits.auth_parsing.link_disclosure`; `schema.encode_disclosure_mask/decode_disclosure_mask`, `project_attributes/decode_disclosed_attributes`; `policy.make_policy/encode_policy/decode_policy/evaluate_policy` | T-007: masks A/B and satisfied clauses; reject hidden predicate, unused bit, duplicate/unsorted clause, inverted range, changed disclosure | Disclosure and policy bytes; clause counts | Same raw private padded fields are linked to public D/mD in gates; public policy remains disclosed-only, with state/lifecycle and full credential circuit integration pending |
| R-008 | IV-A `ctx`; VII-A.1/.7, pp. 5,14,16–17 | PUB/LIFE: bind complete expected context including expiry and reference | `statements.Context/encode_context/decode_context`, auth statement codec; `expiry` helper; planned lifecycle verifier | T-008: exact registered context; alter each field independently, reject empty/oversized audience/session and stale reference | Context bytes; per-field mutation outcomes | Context domains/expected instance/state-reference agreement and canonical E(X) tested; audience/session/nonce/expiry mutations change bytes; actual proof binding, pending-session/expiry/freshness checks remain later work |
| R-009 | VII-A.1–.8 signature contexts, pp. 14–17 | PRIV/PUB/LIFE: ML-DSA-65 and nine genuine external contexts | `bounded_mldsa.bounded_verify_mldsa65`; credential and `public_checks.state_auth` contexts; remaining role integration pending | T-009: all role signatures and expected sizes; reject wrong context/key/message/length and malformed signature | Key/signature sizes; sign/verify time by role | Credential and state signatures use bounded verification with exact pure role contexts; state wrong-role/key/signature failures tested; signing and other role/service integration pending |
| R-010 | VII-A.1/.2/.4–.8; VIII-A, pp. 14–18 | PRIV/PUB/PROOF: exact SHA3-384, outer SHAKE256 output and fresh random values | `binding.holder_binding_value`, `merkle.leaf_hash/node_hash`; `circuits.keccak`; later randomness/proofs | T-010: fixed FIPS vectors and tagged inputs; fail altered input/domain/output-length tests, reject RNG failure | Hash blocks; random bytes drawn; gadget gates later | Full 24-round hash schedules implemented; private single-permutation and mixed-public-prefix cases tested; multiblock/XOF extended tests gated by budget; protocol randomness/proofs and full canonical identity pending |
| R-011 | IV-B Setup; V-C Setup; VII-A.1, pp. 5,8,14 | LIFE: single independent instance, empty tree/state and no partial activation | `lifecycle.setup`, `daa.setup` | T-011: λ=128 creates valid initial state; reject other λ, failed expansion/signature/RNG with no active partial instance | Setup time/bytes; cap counts; activation events | Planned; bounded adapter DEP-002 |
| R-012 | IV-B; VII-A.2 `d/did`, pp. 5,14 | LIFE: independent holder/controller secrets and exact 171-byte DID | `did_state.make_did`, `DIDConfiguration`; bounded independent key/secret generation pending | T-012: recompute identifier and independent secrets; reject invalid key/RNG and changed registry/salt/case/length | KeyGen time; DID length; no publication events | Identifier derivation and supplied-key expansion validation implemented/tested; independent xH/ζ sampling and bounded keygen remain open |
| R-013 | IV-B; VII-A.3 `qk/Rk/vD`, pp. 5–6,14–15 | PUB/LIFE: authenticated genesis and atomic valid successor/rotation/deactivation | `did_state.ReferenceDIDRegistry`, `ReferenceDIDController`, typed `DIDBody/DIDRecord` | T-013: genesis/rotation/deactivation chain; reject wrong predecessor/key/salt, unsupported flags, post-deactivation or index overflow | Record/chain bytes; append conflicts; commit latency | Bounded in-process genesis/update/rotation/deactivation, predecessor authority and atomic conflict handling tested in S2-DID-STATE-1; production signing/services remain open |
| R-014 | VII-A.3 recovery, p. 15 | LIFE: durable pending record and safe retry/key retention | `did_state.ReferenceDIDController.publish/recover`, `ControllerSnapshot` | T-014: recover timeout before/after commit and replay identical pending record; reject conflicting successor without deleting possibly active keys | Recovery events; key-retention audit | In-process pending bytes/key retention, identical explicit resend, conflict retirement and confirmation after deactivation tested; durable recovery remains open |
| R-015 | IV-B Resolve; VII-A.4, pp. 6,15 | PUB/LIFE: nonce-bound ordered full-chain resolution and exact minimal JSON | `did_state.ReferenceDIDResolver`, `ReferenceDIDRegistry.read`, `IssuanceDIDAdapter`, `DIDLifecycleProvider` | T-015: current/historical active endpoints and authenticated absence; reject replayed nonce, broken chain, inactive endpoint, bad selector, redirects/extra document fields | Chain validation cost/bytes; document bytes | Bounded signed complete-chain current/history resolution and lifecycle integration tested; no hidden DID lookup; ordered-service trust retained, W3C conformance and remote services open |
| R-016 | IV-A; VII-A.7 request, pp. 5,17 | LIFE: signed registered request, unique nonce, holder approval | `verifier_state.ReferenceVerifier.create_challenge`, `InMemoryChallengeStore`; holder approval remains a deployment interface | T-016: approved pinned request; reject wrong audience key, reused nonce, unapproved policy or signature included inside `ctx/vp` | Request bytes; nonce/state events | Reference signed challenge registration/collision/failure semantics tested; complete durable nonce/pending state and holder approval service remain open |
| R-017 | IV-A current-state assumption; VII-A.7 CurrentState, pp. 5,17 | PUB/LIFE: authenticated ordered current snapshot and final-read logical epoch | `revocation_state.ReferenceRevocationManager.read_current`, `verifier_state.ReferenceVerifier._current` | T-017: accept matching state; update before final read forces failure/new request, update after read preserves defined epoch; reject signed stale/replayed reply | Ordered event trace; state-read latency/bytes | Bounded signed ordered current reads implemented; real-manager interleavings confirm final-read logical epoch. Authoritative recovery/rollback protection remains open |
| R-018 | IV-B Issue; V-C Enroll; VII-A.5, pp. 6,8,15 | LIFE: permanent next-ID allocation, root unchanged, pending fresh issuer nonce | `revocation_state.ReferenceRevocationManager.reserve_identifier`, `issuance.ReferenceIssuer.begin` | T-018: sequential allocation and valid zero path; abort then allocate a new ID, reject exhausted counter/reused nonce | Counter/root transitions; allocation counts | Permanent live allocation and abort/lost-response retention tested; REC-001 demonstrates stale trusted bootstrap can reuse IDs, so restart admission remains open |
| R-019 | IV-B Issue; V-C Enroll; VII-A.5, pp. 6,8,15 | LIFE: issuer evidence/controller checks and holder approval of exact `mapp` | `issuance.ReferenceIssuer.begin/finish`, `did_state.IssuanceDIDAdapter` | T-019: matching current DID/version and approved claims; reject swapped approved vector, stale DID/state or invalid controller | Issuance stages/round trips; abort reasons | Exact approved vector, current controller and separate final DID/manager reads implemented/tested; evidence/channel services and durable reconciliation remain open |
| R-020 | V-C Enroll; VII-A.5 `Xen/BindOpen`, pp. 8,15 | PRIV/PUB/LIFE: holder-only 256-bit secret, enrolment proof and controller signature | `issuance.ReferenceIssuer`, `relations.enrol`, typed statements/witnesses | T-020: valid secret opens issuer-approved public B; reject wrong secret/B/approved attributes/nonce/instance/controller/proof; issuer API never takes `xH` | Enrolment witness bits; input-access audit; later gates/proof bytes | Public-only fail-closed enrolment adapter, exact Xen/controller signature and retained nonce implemented/tested; real admitted proof backend and complete recovery image remain open |
| R-021 | V-A certification; VII-A.5 `Mcred/cert/vc`, pp. 7,15 | PRIV/LIFE: direct certification, bounded release and original-B authorisation log | `issuance.ReferenceIssuer._commit`, `HolderAcceptance.accept` | T-021: verify same B/m/rid and log before release; reject changed B/rid/µ/signature or bounded failure; no release before durable log | Certificate/credential bytes; release/cap events | Pre-release bounded verification, log-before-release and whole holder-pair commit tested including interruption/lost responses; durable transactions/release recovery remain open |
| R-022 | IV-B Issue; VII-A.5 abort paragraph, pp. 6,15 | LIFE: retire issuer nonce, retain allocations/certifications/commits across abort | `issuance.ReferenceIssuer.abort/begin/finish`, manager permanent allocation | T-022: recover aborted transcript with correct updated states; fail assertions if nonce/ID is reused or a released certificate disappears from log | Durable state delta per failure point | Live failures retain reservations/certifications and retire claimed nonces; same-session replay rejects. Interrupted reconstructed phases need explicit recovery admission/retirement |
| R-023 | V-A/B `BindRep/BindOpen/CredValid`; VII-A.5, pp. 7–8,15 | PRIV: signature and opening certify the same B, attributes, secret and rid | `credentials.cred_valid`; `binding.check_binding_consistency`; structural validators and `build_mcred`; `bounded_mldsa.bounded_verify_mldsa65` | T-023: valid same-credential opening; splice B, σ, m, xH or rid from another credential, reject non-empty ρ/wrong instance; no private issuer-table query | Predicate outcomes; signed-body bytes | Complete local CredValid tested with real signatures, same-B opening and splice/exhaustion rejection; no remote knowledge proof, issuer trust, freshness or non-revocation claim |
| R-024 | V-B `Rauth`; VII-A.6 `X/ξ`, pp. 8,15–16 | PRIV/PUB: full conjunction over one 5329-byte witness and exact statement | `circuits.auth_parsing.parse_auth_witness/compile_auth_parsing`; `relations.auth/auth_private`; `public_checks.pub_ok/public_policy_ok`; typed `statements` and `witnesses` | T-024: full valid conjunction; independently mutate every witness/public component, mix certificates/paths/rids/attributes and demand rejection | Witness bits 42632; per-check outcomes | Local full reference remains tested; exact 42632-position parsing/disclosure component now implemented; signature/hash/Merkle private circuit composition and proof remain absent |
| R-025 | V-B `PubOK/Rauth`; VII-A.6/.7, pp. 8,15–17 | PRIV/PUB/LIFE: retain mandatory boundary between private predicate, public checks and services | `relations.auth_private/enrol/auth`, `public_checks`, `statements`; later services/proofs | T-025: local reference and later proof agree; fail public verifier API/audit if it receives xH/σ/hidden m/rid/w, or missing public/lifecycle check is accepted | Check-to-layer coverage; verifier input audit | Private/public/full reference boundaries implemented and tested; no witness argument in public checks; clocks/trust/approval/controller/current-state/replay remain service work |
| R-026 | IV-B Present; V-C/D; VII-A.6, pp. 6,8–9,15–16 | PRIV/PROOF/LIFE: approved fresh proof, local witness maintenance, unchanged credential | `wallet.present`, `daa.auth` | T-026: two fresh presentations from one credential; reject wrong secret, invalid witness, stale request/expiry or unapproved policy; no stable hidden fields | Present time/bytes/randomness; unchanged record digests | Lifecycle/proof work planned; SPEC-002 agreed and expiry helper tested, service integration pending |
| R-027 | V-C Verify; VII-A.7, pp. 8–9,16 | PUB/PROOF: stateless complete DAA verification against expected instance | `public_checks.pub_ok/public_policy_ok`; planned `daa.verify`, `proofs.check` | T-027: valid public statement/proof; reject tampered disclosures, policy, state signature, context or proof; repeat stateless call without inventing consumption | Parse/public/proof time separately | Public structural/state/policy checks implemented; actual proof verification and remote/stateless presentation API remain unimplemented |
| R-028 | IV-B Verify; VII-A.7; VIII-E Thm 10, pp. 6,16–17,20 | PUB/LIFE: full pending-context match, optional approved DID pair, final freshness and atomic consumption | `verifier_state.ReferenceVerifier.verify`, `InMemoryChallengeStore.consume` | T-028: one acceptance; race replicas, expire between precheck/commit, stale final root, altered context or only one DID field disclosed all fail appropriately; pre-consumption rejection leaves pending; lost post-commit reply retains consumption | Accept/abort events; concurrent success count | Public-only live acceptance, final expiry/read, concurrency and post-commit lost return tested; REC-002 demonstrates stale-store rollback can reaccept, so shared durable recovery remains open |
| R-029 | VII-A.1/.5 tree/PathRoot; V-B, pp. 7–8,14–15 | PRIV/PUB: exact depth/hash/order/domain and zero leaf for certified rid | `merkle` primitives, composed by `relations.auth_private`; `public_checks.state_auth` separate | T-029: first/last IDs, both branch directions, empty tree; reject rid≥2^20, wrong depth/sibling/namespace/root, reversed order or revoked leaf | Path bytes 960; hash calls; sparse-tree storage | Same certified-rid zero leaf now jointly checked with credential and public signed root; non-uniform substitution/revoked/surviving/old-root tests pass; allocation/freshness still separate |
| R-030 | IV-B Revoke; VII-A.8 `MR/Mu`, pp. 6,17 | PUB/LIFE: authorised allocated-ID revocation and atomic signed update | `revocation_state.ReferenceRevocationManager.revoke/updates` | T-030: revoke issued or aborted allocation; reject unallocated/already-revoked ID, replay, stale reference, invalid signature or epoch overflow; delivery failure preserves committed update | Update/state bytes; atomic events; signing cap counts | Atomic live state/tree/nonce/update commit and outage retrieval tested; retained authoritative history, durable commit and recovery remain open |
| R-031 | IV-C; V-D; VII-A.8 local update equation, pp. 6–7,9,17 | PRIV/PUB/LIFE: local path update after authenticated consecutive transitions; reject revoked credential | `witness_updates.update_witness/update_authentication_witness` | T-031: sibling changes at each divergence level and multi-epoch update; reject target revocation, gaps/reorder/bad endpoint/root/signature; no remote private-ID request | Updates processed; hashes/time; public versus private bytes | Bounded complete local update and no-partial-output behaviour tested through outage/catch-up; caller must persist matching witness/state and retain private-role separation |
| R-032 | VII-A.6 Bounded computation, pp. 15–16 | PRIV/PUB/PROOF: full FIPS verification/hash computation and exact sampling order | `bounded_mldsa`; `circuits.division/scalar_ring`; `circuits.keccak`; later bounded `circuits.mldsa` | T-032: differential admissible ordinary/reference/gadget results and FIPS vectors; reject malformed hints/norms/hash/context, wrong UseHint boundaries/order | Subroutine traces; hash blocks; gates later | Bounded reference verification remains complete; hash circuits plus scalar Decompose/UseHint/norm and forward butterfly now tested; private FIPS decoding/full NTT/matrix/sampler lowering remain absent |
| R-033 | VII-A.6 caps; VIII-A loss accounting, pp. 15–18 | PRIV/PUB/LIFE: exact byte/attempt caps and bounded validation before every signature release | `bounded_mldsa._Budget/_rej_ntt_poly/_sample_in_ball/_expand_a`; `credentials.cred_valid`; planned keygen/signer and `crypto.release_policy` | T-033: boundary success; force exhaustion of each sampler/signing cap and pre-release verify failure, assert abort/no hidden retry/no release | Bytes/attempts/cap failures for every role | Both verification caps tested through complete auth for credential and state paths; exact-limit/exhaustion logic unchanged; bounded keygen/signing and all-role pre-release integration pending; DEP-001 numeric loss unvalidated |
| R-034 | VII-A.6 BC-1 arithmetic, p. 16 | PROOF: prescribed widths, checked narrowing, modular representatives, bit order | `circuits.words/division/scalar_ring` | T-034: signed/unsigned/FIPS boundary vectors; reject overflow and wrong endian/sign extension/modular representatives | Component gate counts and measured memory | Checked signed64 add/sub/mul, public-constant floor divmod, canonical/centred reduction and scalar ring helpers tested at prescribed widths; SPEC-004 agreed and audited, integer shift/full integration still pending |
| R-035 | VII-A.6 BC-1 gates/order, p. 16 | PROOF: exact lowering for arithmetic, comparisons, mux and evaluation order | `circuits.emitter/words/keccak/division/scalar_ring` | T-035: exhaustive small-width truth tables plus 64-bit boundary checks; reject changed mux orientation, carry/sign/remainder or emission order | Deterministic gate/wire trace and development digest | SPEC-003/004 agreed; restoring steps, explicit correction muxes/reuse/validity order, overflow propagation and butterfly source order tested; complete canonical compiler identity unverified |
| R-036 | VII-A.6 BC-1 control/numbering/folding, p. 16 | PROOF: scanned private access, masked fixed loops, sticky active rejection, limited folding | `circuits.control`, `circuits.emitter` | T-036: true/false paths and simultaneous updates; reject active invalid read/write/overflow, allow inactive fault masking; detect forbidden CSE/reassociation | Counts, generator memory, trace digest | Foundation public-only folding, numbering, active rejection, branches and scanned selectors tested; full fixed-capacity/sampler programme lowering and compiler liveness remain pending |
| R-037 | VII-A.6 admission; VIII-A capacity, pp. 16,18 | PUB/PROOF: derive circuit from kind/X and enforce encoding bounds before allocation | `circuits.enrolment/parsing/auth_parsing/emitter/accounting`; `witnesses`, `statements`; later auth CGen/proof admission | T-037: matching independent generator/vector digests; reject unsupported kind, prover-selected circuit, oversized statement/view or overflow using symbolic limits | Generation time both sides; total/AND gates; admitted bytes | Complete local enrolment compiler from public pp/X and 256 positions; budget/mode identity unchanged, 17 deferred hash tests/nine probes and subsequent 36 parsing/scalar probes complete under explicit extended controls; full canonical CGen/auth/proof admission pending |
| R-038 | VII-A.6 Shared prover, p. 16 | PROOF: 480 three-party raw-tape repetitions and specified AND sharing | `proofs.mpc`, `proofs.prove` | T-038: reconstruct true toy-circuit outputs over all shares; reject false/wrong-length witness and altered AND/tape; audit no seeds replace raw tapes | Random bits, repetition count, raw view bytes | Planned Stage 3 |
| R-039 | VII-A.6 `view/cj,i/A`, p. 16 | PROOF: exact packed view, salts and output/commitment order | `proofs.views`, `proofs.commit` | T-039: canonical bit packing and commitment vectors; reject non-zero terminal padding, wrong indices/tag/order/salt or output byte 2 | V, commitment/preimage/A sizes | Planned Stage 3 |
| R-040 | VII-A.6 challenge equation, p. 16 | PROOF: fresh post-commit nonce and exact biased modulo-to-trits map | `proofs.challenge` | T-040: u=0, powers of 3, boundary and maximal 1024-bit u; reject endian/trit-order substitutions and altered X/A/nonce | Challenge input bytes; map vectors; RNG events | Planned Stage 3; no uniform-trit substitution |
| R-041 | VII-A.6 transcript; VII closing size equation, pp. 16–17 | PROOF: exact ν/A/Z order and computed proof length | `circuits.accounting/enrolment_accounting`; later `proofs.transcript` | T-041: arithmetic vectors and later actual lengths agree; reject truncation, extra bytes, wrong opened order and wrong g/d assumptions | Projected raw proof bytes; envelope bytes separately | Integer-only auth/enrol formulas tested separately; enrol d=256/g=38787 gives calculated 9587104 bytes under agreed initialisers, no generated proof or full conformance claim; full auth count absent |
| R-042 | VII-A.7 Check, p. 16 | PUB/PROOF: both commitments/outputs/padding, first opened party's AND checks, all repetitions | `proofs.check` | T-042: all challenge values on toy circuits and later full proofs; alter every transcript region/repetition, reject wrong outputs/AND/commitments/padding | Per-check time; rejected mutation coverage | Planned Stage 3 |
| R-043 | VII-A.6 erasure; VIII-D Thm 7, pp. 16,19 | PROOF/MODEL: fresh randomness, erased transients and no reopening | `proofs.session`, `randomness`, `privacy.audit` | T-043: independent retries with closed old session; reject second challenge/reopening and instrumented randomness reuse/secret logs | Randomness/session lifecycle; retained secret buffers | Planned; secure erasure not established by Python tests |
| R-044 | V-A; VI-B; VIII-A/B, pp. 7,10–11,17–18 | PRIV/MODEL: certification, binding and certified-ID non-revocation under stated assumptions | `relations.auth`, `public_checks`, `credentials`, `merkle`; planned security review | T-044: valid authorisation matches original B/rid; reject certificate/opening/path splices; review all assumptions/reductions separately | Predicate coverage; proof-review findings | Executable joint certification/opening/same-rid path tests pass with independent fixtures; tests do not prove security assumptions, reductions or issuer authorisation history |
| R-045 | V-B; VI-B; VIII-C Thm 6, pp. 8,10–11,18–19 | MODEL: fresh-statement, actual-history target-preserving extraction of full witness | `security/extraction_review.md`, `tests/models` | T-045: classify fresh statements and actual history correctly; reject aux-only freshness, simulated history edits and one-transcript extraction claims | Reduction/runtime/query-budget record | Mathematical review planned; no extractor implemented |
| R-046 | VI-A/C; VIII-A/D, pp. 9–12,17–19 | LIFE/MODEL: QPT/classical protocol, honest authorities, sequential oracles and matched leakage | `tests/models/privacy_game`, `security/privacy_review.md` | T-046: eligible matched candidates and cumulative disclosures; reject forbidden corruption, interleaved enrolment, mismatched eligibility/leakage | Oracle/event and leakage trace | Planned model tests and proof review |
| R-047 | VI-D; VIII-D/E Thms 9/11, pp. 12–13,19–20 | MODEL: two-phase historical privacy with post-challenge revocations/public old paths | `tests/models/historical_privacy`, `security/privacy_review.md` | T-047: close challenge phase then revoke candidate and publish real updates; reject renewed challenge access, hidden-index-driven service calls or protected compromise | Continuation-query/leakage trace | Planned; no post-compromise guarantee |
| R-048 | IV-C; V-E; VIII-A completeness, pp. 6–7,9,18 | PRIV/PROOF/LIFE/MODEL: correctness only for admissible valid unexpired pending runs | `tests/scenarios/honest_run`, `security/correctness_review.md` | T-048: true admitted honest reference/proof accepts; distinguish cap/resource/service failures, reject consumed/stale/expired runs | Success/abort counts by cause | Planned; no completed protocol correctness evidence |
| R-049 | VIII-A cap-loss and cost equations, pp. 17–18 | MODEL: count all relevant capped calls and retain Δtail/conditional assumptions | `measurements.cap_accounting`, `security/bounds_review.md` | T-049: synthetic event counts including pre-release verify/cache; reject missing service calls, double-counted cached expansion and unjustified Δtail=0 | nK/nS/nV/nA, cT/cB/cC/cS, failures, query/runtime budgets | Planned; DEP-001 blocks validated signing-tail claim |
| R-050 | VIII-A/C/D/E Thms 6–9, pp. 17–20 | MODEL: preserve exact QROM loss expressions and all continuation queries | `security/bounds_review.md`, `measurements.security_budget` | T-050: independently check expression evaluation/clamping at declared Q,N; reject omitted queries, altered square root/modulo terms or λ-only security claims | Declared Q,N and conditional losses | Expressions recorded; derivations unverified |
| R-051 | VI-E Thms 2–3; VIII-E Thms 10–11, pp. 13,20 | LIFE/MODEL: service-authenticity loss plus actual-history authentication/privacy composition | `security/composition_review.md`, `tests/scenarios/services` | T-051: account for all key roles and nonce classes; reject corrupted-key coverage claims, omitted record-hash/read-nonce terms or stale-service acceptance | Key/signing/query budgets; security-review results | Planned; service assumptions and DEP-001 retained |
| R-052 | III-A architecture; VII-A.4 DID JSON, pp. 3,15 | PUB/LIFE: experimental W3C mapping preserves exact signed/proved claims and anonymity | `did_state.ReferenceDIDResolver`, `DIDLifecycleProvider`; remaining `adapters.w3c`, `tests/conformance` | T-052: external fields reconstruct exact binary statement; reject altered/extra acceptance claims, stable hidden IDs or per-credential status leakage | Wrapper bytes; official/custom conformance results | Exact minimal DID JSON/media and public historical adapter implemented/tested; dated DID Core 1.0 mapping retained, complete Stage 5 representation/IRIs/conformance pending |


## Cross-credential binding test requirement

T-020/T-023/T-024/T-029 form one shared fixture family. Construct two valid synthetic
credentials under one instance and another under a different instance. Start from a
valid full witness; replace **one** of `xH`, canonical `m`, `rid`, `σ` or `w` while
keeping the public statement fixed. Also replace combinations that could accidentally
pass isolated signature or path checks. In particular, a valid certificate for one
identifier plus a valid zero path for another must fail, and a valid certificate for
one attribute vector plus disclosures from another must fail. A replacement is an
intended rejection vector only when the predicate actually changes; identical values
or genuinely shared empty-tree sibling paths alone need not cause failure. Include
a tree with distinguishing revoked leaves so path/rid substitutions exercise direction
and binding, rather than relying on unequal-looking bytes.

The private reference predicate must reconstruct a single `B=(H(holder(suite,µ,xH)),
Esch(m))`, a single credential body containing that B and rid, and a path at that same
rid. Projection comes from the same m. Public checks bind this to one `X`; lifecycle
checks bind that X to the registered request and final current-state read. The later
proof must establish this entire private predicate without sending its inputs to a verifier.

## Engineering decisions and evidence boundary

E-001 (module/error conventions) is covered by T-003/T-004/T-025 and all failure tests.
E-002 (synthetic schema/policies) supplies labelled inputs to T-006/T-007/T-020/T-024;
it is not a manuscript-mandated deployment. E-003 (representation design) maps to T-052.
E-004 (explicit experiment budgets) maps to T-033/T-037/T-048 and future run manifests.
These decisions do not create new cryptographic requirements or substitute for proof review.

Existing [environment evidence](environment.md) reports 14 Python smoke tests and
native linkage verification. In particular, `tests/smoke/test_mldsa.py` covers ordinary
ML-DSA-65 API/context/representation behaviour; `tests/smoke/test_hashes.py` covers
fixed hash vectors. The original environment results are reused; four fixed hash cases were also rerun
for the bounded-verifier regressions. Smoke success alone does not mark a full
requirement above implemented. The document/manifest checks and first Stage 2 test evidence are recorded in
[status.md](status.md) and [stage2_codec.md](stage2_codec.md).

## Actual Stage 2 codec functions and tests — first work package

The first work package passed 189 codec/schema/policy/expiry tests. At the next
holder-binding/Merkle work-package boundary, the full unit suite passed 368 tests.
The following mappings describe executed tests; the full T-families above remain
broader plans. SPEC-001/002 are agreed user clarifications, checked against the
manuscript and recorded separately from its original wording in the manifest.

| Requirements | Implemented functions | Actual tests | Remaining boundary |
|---|---|---|---|
| R-005; SPEC-001 | [codec.py](../src/pqdid/codec.py): integer/LP/record encode/decode and raw path pack/unpack | [test_codec.py](../tests/unit/test_codec.py): integer/tag/count/truncation/hostile-length cases, `test_path_order_and_distinct_update_encodings`; [test_vectors.py](../tests/unit/test_vectors.py): E01–E03/E09–E14/E16/E25–E27/E31/E33–E35/E44–E46 | Generic framing does not validate all nested protocol objects, issuer trust, signatures or instance equality |
| R-006 | [schema.py](../src/pqdid/schema.py): immutable descriptors/schema and field/vector encode/decode | [test_schema.py](../tests/unit/test_schema.py): required indices/types/capacities, full-vector round trips/padding; fixed vectors E04–E08/E17–E20/E29 | Issuance-time DID/control and credential authenticity are later layers; this historical Stage 2 row predates private circuits |
| R-007 | `schema` mask/projection/disclosure functions; [policy.py](../src/pqdid/policy.py): clause/policy codecs, `make_policy`, `evaluate_policy` | `test_schema.py::test_disclosure_projection`; [test_policy.py](../tests/unit/test_policy.py): A/B success/failure, inclusive ranges, hidden-field/duplicate/order rejection; fixed E09–E13/E21–E24/E30/E32 | Public disclosed-only policy and reference projection at this historical Stage 2 boundary; later private circuit linkage is recorded below |
| R-008; SPEC-002 | [expiry.py](../src/pqdid/expiry.py): `encode_timestamp`, `decode_timestamp`, `is_unexpired` | [test_expiry.py](../tests/unit/test_expiry.py): before/equal/after, uint64 boundaries and invalid types/representations; fixed E36–E43 | No trusted clock, final state read, pending-context service or atomic consumption |
| R-030/R-031 codec subset | Shared raw path with distinct `update` six-field signing body and `rupdate` five-field transport framing | `test_codec.py::test_path_order_and_distinct_update_encodings`, fixed E33–E35/E44–E46 | No signed-update verification, tree transition or witness-update implementation |

E01–E32 remain unchanged. E15/E28 and the proof-size arithmetic cases are retained
for Stage 3 rather than counted as proof tests in this run. The existing environment
smoke checks were not rerun; dependency/toolchain/editor files remain unchanged.

## Actual Stage 2 holder-binding and Merkle coverage — 17 September 2026

At this earlier boundary, the focused suite passed 179 tests; all 368 unit tests passed, including the 189
existing regression cases. The independently frozen synthetic fixtures and verification
boundaries are detailed in [stage2_binding_merkle.md](stage2_binding_merkle.md).
No requirement involving credential authenticity, proof verification or lifecycle
freshness is marked complete merely because these local reference functions exist.

| Requirements | Actual functions | Actual test coverage | Remaining scope |
|---|---|---|---|
| R-001/R-005 subset | [hash_domain.py](../src/pqdid/hash_domain.py): `HashDomain`, `encode_metadata` | [test_hash_domain.py](../tests/unit/test_hash_domain.py): `test_fixed_metadata_and_schema`, identifier bounds, wrong suite/namespace, malformed reference/schema | Cryptographic key/trust/registration checks; full pp agreement now covered below |
| R-005/R-010/R-020 subset | [binding.py](../src/pqdid/binding.py): `encode_holder_input`, `holder_binding_value`, `create_binding`, binding codecs | [test_binding.py](../tests/unit/test_binding.py): fixed preimages/digests, fixed complete B and canonical attributes, tag/count/length/padding rejection | Issuer/session/controller checks and enrolment proof |
| R-023 subset | `binding.check_binding_consistency` | `test_wrong_secret_and_altered_attributes`, `test_altered_binding_bytes`, `test_wrong_instance_does_not_open_binding`, malformed/private-input cases | This helper alone is not CredValid; later local composition is recorded below; issuer/session authorisation remains pending |
| R-010/R-029 mathematics | [merkle.py](../src/pqdid/merkle.py): `leaf_hash`, `node_hash`, `default_subtree_roots` | [test_merkle.py](../tests/unit/test_merkle.py): fixed real hash preimages/digests/default roots, node level/child order and instance separation | No randomness generation, circuit gadgets, allocation or signed state |
| R-029 path subset; R-024 component | `merkle.path_root`, `verify_non_revocation_path` | `test_fixed_depth20_paths_and_non_revocation` (48 paths); every altered sibling, reversed order, boundary IDs, statuses, lengths/root and non-uniform mismatch | Only the supplied-root zero-leaf condition; no allocation, root authenticity/currentness or certified-secret claim |
| R-031/R-017 boundary evidence only | No production UpdateWit or CurrentState function added | `test_old_and_updated_roots_do_not_implement_freshness`; independent sparse-tree roots/paths | Witness updating, signed ordered chains and lifecycle freshness remain pending |

The tests use [binding_merkle_vectors.json](../tests/fixtures/binding_merkle_vectors.json),
with expected values constructed by [binding_merkle_reference.py](../tests/unit/binding_merkle_reference.py)
without production imports or PathRoot calls. The non-uniform fixture deliberately
distinguishes identifiers 0 and 2; uniform-tree equal paths are explicitly accepted.
This avoids an invalid assumption that every different identifier must fail every path.

## Actual parameter/credential coverage — 17 September 2026

The following earlier work-package checks are structural/message checks, not full CredValid, authorised issuance
or proof verification. [stage2_credentials.md](stage2_credentials.md) records exact
source locations, APIs, fixed fixture provenance and the 112 structural / 1 uncapped
integration cases. Its remaining-scope column records that historical boundary;
subsequent bounded verification/CredValid completion is recorded in the final table.
Stage 2 remains in progress.

| Requirements | Actual functions/evidence | Tests executed | Remaining scope |
|---|---|---|---|
| R-001/R-004/R-005 subset | `parameters.PublicParameters/InstanceMetadata`, validators and canonical codecs | `test_fixed_encodings_and_round_trips`, `test_repeated_schema_and_nested_structure`, `test_external_parameter_and_metadata_agreement`, key substitution and identifier-boundary cases | Full key validation, trust, immutable registration and owner state |
| R-005/R-009/R-023 subset | `credentials.Certificate/Credential`, structural validators/codecs | Wrong framing/nested fields, malformed byte representations/padding, required empty auxiliary, identifier bounds, attribute splice and wrong record types in [test_credentials.py](../tests/unit/test_credentials.py) | FIPS signature/hint decoding, opening/signature composition and full CredValid |
| R-021/R-023; component of R-024 | `credentials.build_mcred` | `test_fixed_message_before_signing_and_after_parsing`, seven independently specified signed-field variants, `test_signature_is_outside_its_message` | Bounded credential signature and complete same-credential conjunction; logging/release |
| R-004/R-026/R-031 representation boundary | Exact credential fields omit ctx/state/witness | `test_presentation_and_witness_reuse`: different old/updated paths for unrevoked rid 43 preserve credential/message | Present/UpdateWit services, authenticated state, freshness and proofs |
| R-009 ordinary interoperability only | Existing guarded backend and new Mcred constructor; genuine external credential context | [test_credentials_uncapped.py](../tests/integration/test_credentials_uncapped.py): native signing/round-trip verification, changed message/rid/context/signature rejection | No cap or full CredValid claim; all-role bounded integration pending |
| R-032/R-033 plan only | [bounded_mldsa_plan.md](bounded_mldsa_plan.md): actual pinned source/dispatch, operation map and precise changes/tests | Source inspection; no bounded tests implemented or run | Internal counters and failure propagation, FIPS/reference validation, signing/keygen/release work; DEP-001 separate |

At that boundary, all 480 unit cases passed, including the 368 earlier cases; lint and formatting passed.
Fixed [credential vectors](../tests/fixtures/credentials_vectors.json) are explicitly
synthetic, assembled by [independent framing](../tests/unit/credentials_reference.py)
without production imports. Existing vectors and confirmed suite parameters are unchanged.

## Actual bounded verifier and local CredValid coverage — 17 September 2026

The separate Python implementation passed verifier checks before CredValid integration.
[stage2_bounded_mldsa.md](stage2_bounded_mldsa.md) records provenance, source digests,
public failure semantics, exact budgets, commands and limitations. **208 focused and
689 regression checks passed**, with lint/format passing. The regression suite contains
666 unit cases (480 earlier +186 new), 19 integration cases and four fixed hash cases.

| Requirements | Actual functions | Executed evidence | Remaining scope |
|---|---|---|---|
| R-009/R-032 reference | `bounded_mldsa.bounded_verify_mldsa65/_verify_internal`, decoders, NTT/inverse, UseHint, w1, real SHAKE | [test_bounded_mldsa.py](../tests/unit/test_bounded_mldsa.py): 12 independent real signatures; field/context/type/length failures; every hint row, norm/packing extremes, independent polynomial evaluation/convolution and decomposition boundaries | No formal/FIPS validation; Python integer reference is not BC-1 checked-width execution or a circuit |
| R-032 context/hash/differential | Same verifier and `_shake_reader` | [test_bounded_mldsa_native.py](../tests/integration/test_bounded_mldsa_native.py): 96 bounded/native comparisons with completed samplers, four fresh signatures, 40 independent SHAKE comparisons; four existing fixed hash cases | Ordinary fixture signing does not validate bounded signing; no per-round hash/gate trace or forced native dispatch claim |
| R-033 verification caps | `_Budget`, `_rej_ntt_poly`, `_sample_in_ball`, `_expand_a`, `_verify_diagnostic` | [test_bounded_samplers.py](../tests/unit/test_bounded_samplers.py) plus verifier tests: real 1026-/256-byte bounds, rejected-byte/sign accounting, exact-limit success, one-candidate/byte over failure, all 30 invocations, no extra read/retry and explicit propagation | RejBoundedPoly/keygen, signing attempts and all-role pre-release/state integration remain pending |
| R-023 complete local predicate; component of R-021/R-024 | `credentials.cred_valid`, existing `build_mcred`, structure/instance checks and `binding.check_binding_consistency` | [test_cred_valid.py](../tests/unit/test_cred_valid.py): 36 cases with three real signed credentials, invalid/synthetic signatures, wrong opening/issuer/instance, coherent changed fields and splices, both sampler failures and resource errors | No remote knowledge proof, trust/log/release authorisation, non-revocation or freshness; full enrolment/authentication relations remain next |

Real fixtures in [mldsa65_native_vectors.json](../tests/fixtures/mldsa65_native_vectors.json)
were generated by the pinned ordinary native signer, without importing or filtering
through the bounded verifier; the generator/provenance is recorded alongside them.
Artificial sampler streams are separate test data and do not purport to be signatures.
Earlier vectors, confirmed parameters and SPEC-001/002 remain unchanged.

## Actual executable relation coverage — 17 September 2026

[stage2_relations.md](stage2_relations.md) records both contracts before implementation,
source references, exact input/encoding definitions, fixture provenance and commands.
**201 focused and 890 regression tests passed** (867 unit, 19 integration, four hash);
lint and formatting passed. Existing code and vectors were preserved. The earlier
verification work-package table above records its historical remaining-scope boundary.

| Requirements | Actual implementation | Executed evidence | Remaining boundary |
|---|---|---|---|
| R-005/R-008/R-020/R-024 | [statements.py](../src/pqdid/statements.py) and [witnesses.py](../src/pqdid/witnesses.py) | [test_relation_encodings.py](../tests/unit/test_relation_encodings.py): independent exact E(Xen)/E(X), nested state/context, derived field widths/offsets and MSB-first bits, all auth truncations, malformed padding/identifier/policy/mask/metadata | E(X) prepares future proof binding; actual transcript and circuit input handling remain Stage 3 |
| R-020 | `relations.enrol`, `public_checks.enrol_public_ok` | Three valid openings, wrong secret/Y/mapp, separate issuer-approved-vector mismatch; nonce/rid/state encoding mutations preserve the intended private predicate | Controller proof/authorisation, holder approval, pending nonce/allocation/registration and current issuance reads remain surrounding algorithms |
| R-009/R-024/R-025 public | [public_checks.py](../src/pqdid/public_checks.py): `state_auth`, `pub_ok`, `public_policy_ok` | Bounded state verification, wrong key/context/signature/root/epoch; false public policy while private predicate remains true; structural/domain mismatch | State authenticity is not currentness; request/current/control/update integration and proofs pending |
| R-023/R-024/R-029 joint | [relations.py](../src/pqdid/relations.py): `auth_private`, complete `auth` | [test_relations.py](../tests/unit/test_relations.py): real signed credentials, 64 masks, same-witness reconstruction, isolated signature/secret/attribute/rid/projection/path splices | Local witness evaluation is not remote knowledge verification or a privacy proof |
| R-026/R-029/R-031 boundary | Same certified-rid path predicate with independent fixture transitions | Revoked 42 rejects zero leaf at updated root; surviving 43 reuses unchanged credential with changed correct path; non-uniform wrong path fails, equal empty-subtree paths correctly pass | Fixture trees do not implement production witness updates, allocation or revocation services |
| R-008/R-017/R-025/R-028 boundary | Canonical context/statement encoders and local evaluator | Old signed root/path still true; repeated contexts and expiry 0 can satisfy the relation; well-formed audience/session/nonce/expiry/policy mutations change E(X) | Proof binding, request authentication, trusted time, pending-session/current-state/replay/atomic consumption are separate future checks |
| R-032/R-033 verification composition | Unchanged bounded verifier through StateAuth/CredValid into `auth` | Deterministic 1026-/256-byte exhaustion separately targets each signature role; candidate private failures first establish PubOK; no extra read/retry; runtime error propagation | Bounded keygen/signing, all-role release integration and DEP-001 tail remain open |

[relations_vectors.json](../tests/fixtures/relations_vectors.json) supplies two isolated
synthetic instances, three credentials, six states, three enrolment and twelve authentication
cases. Independent framing/global sparse trees establish expected bytes/roots/path outcomes;
ordinary native signatures are verified without relation filtering. No private signing keys
are saved; fixture holder openings are explicitly public synthetic material. This completes
the executable relation work package and supplies Stage 3 circuit-feasibility inputs.


## Historical Stage 3 foundation coverage — 17 September 2026

[stage3_bc1_foundation.md](stage3_bc1_foundation.md) records the extracted contract,
provisional compound recipes, APIs, limits and full commands. **135 focused / 1025
regression tests passed**, with lint/format passing. Source hashes and twelve measured
component runs are in [the resource record](data/stage3_bc1_measurements.json).
At that boundary SPEC-003 was unresolved; its later adoption is recorded below.
Full canonical compiler conformance remains independently unverified. The explicit basis/order/folding rules and Boolean outcomes are
independently testable; no full relation/proof requirement is marked complete.

| Requirements | Actual implementation | Executed evidence | Remaining boundary |
|---|---|---|---|
| R-034/R-035 subset | `circuits.words` checked add64/sub64/mul64, 65/128-bit intermediates, equality/comparison/mux and rewiring | `test_bc1_words.py`: exhaustive 2/3/4-bit cases, 17 real-width boundary pairs per arithmetic operation, full signed128 products, exact ripple bytes and component counts, byte/bit order | SPEC-003 initialisers/derived recipe; division/reduction, ring/centred arithmetic, checked integer shifts and full lowering |
| R-035/R-036 basis and structure | `circuits.emitter` symbolic inputs, strict public-only folding, canonical record emission and development fingerprint | `test_bc1_emitter.py`: hand OR trace, full Boolean tables, private identities/repeated gates retained, varied true/false witnesses with identical structure, byte-identical small stream/material trace | Fingerprint is not a commitment; no CGen deriving full relation from kind/X, complete profile identity or reference equivalence |
| R-036 selection/control subset | `circuits.control.Scope` active rejection, branches, scan reads and snapshot writes | `test_bc1_control.py`: boundary/inactive indices, zero/no-op failures, sequential/snapshot writes, selected/inactive overflow, true-first construction, merge orientation and exhaustive fixed-loop masks | Gadgets are not an AST/compiler or full capped sampler programme; later source initialisers/counters/loop schedule must be preserved |
| R-037 development resource subset | Shared materialised/count/stream emitter and bounded evaluator | `test_bc1_emitter.py` exact/small resource boundaries; one-worker probes, three clean limit failures, all modes agree for four components; raw times/RSS/trace bytes recorded | Gate streaming does not bound all future live compiler state; no full public admission or auth feasibility |
| R-041 arithmetic subset | `circuits.accounting` frozen authentication formula and view-bound test | `test_bc1_accounting.py`: existing auth arithmetic vectors, rounding, huge integers, bad types and max view boundary; labelled assumed-count projections | Actual full auth AND count/transcript remain absent; component counts are not automatic lower bounds; no proof-sized allocation |

The foundation package is complete and stops here; Stage 3 stays in progress. Next:
SHA3/SHAKE and canonical parsing gadgets, followed by complete enrolment. All earlier
Stage 2 exit obligations, DEP-001 and remaining DEP-002 work remain tracked separately.


## Historical Stage 3 hash/enrolment implementation coverage — 17 September 2026

[Hash/enrolment report](stage3_hash_enrolment.md): **57 focused / 1082 regression
passed, 17 larger-profile skips in each**; lint/format passed. The source-pinned
[measurements](data/stage3_hash_enrolment_measurements.json) contain 18 complete probes
and nine original-cap terminations. SPEC-003 was pending then; these earlier results
are preserved. The subsequent adoption/extended run below supersedes that pending status.

| Requirements | Actual implementation | Executed evidence | Remaining boundary |
|---|---|---|---|
| R-010/R-032 hash subset | `circuits.keccak` full 24-round permutation and public-length SHA3-384/SHAKE128/SHAKE256 | `test_keccak_circuit.py`: nine original-cap official KATs, private message mutations, full-state integer oracle, literal theta/chi/iota order, mixed prefixes, single-block output lengths and mode agreement | Six official plus eleven native larger cases gated by resource profile; full ML-DSA and outer proof composition absent |
| R-005/R-020/R-034 parsing subset | `circuits.parsing` byte wiring/comparison, holder framing and existing public decoder/validator boundary | `test_enrolment_circuit.py`: exact reference holder bytes, MSB/FIPS round trip, malformed public framing/range/instance/padding, wrong witness length versus fixed-size wrong secret | No private variable-length enrolment fields; authentication attribute/signature/rid/path parser remains to be built |
| R-020/R-037 local circuit | `compile_enrolment`, `compile_encoded_enrolment` from public expected pp/X | Three existing real fixtures, wrong opening/target/attributes, coherent/incoherent instance substitutions, nonce/rid/state mutations, invalid state-signature boundary, zero-secret valid representation, repeated generation and evaluation/mode agreement | Functional evidence bounded by limits; SPEC-003 identity pending; controller/issuance/freshness and privacy proof absent |
| R-035/R-036 SPEC-003 | Existing unchanged fold convention; test-only first-term alternatives | `test_spec003_alternatives.py`: exhaustive small truth tables, signed64 overflow boundaries, different counts/fingerprints with equal behaviour; comparison record | Recommendation is not approval; explicit initialisers/traversal/conjunction recipe needed before full canonical identity |
| R-037/R-041 resources and size | New measurement driver; separate enrolment size calculator | Original-cap completion/failure records; d=256 view/proof arithmetic including huge integers, no buffer; enrol proof projection 9587104 bytes | Partial traces never complete; larger tests await budget choice; no proof or complete-authentication feasibility claim |

Stages 2–3 remain in progress. This historical boundary identified larger hash/XOF
validation as next; that work is now complete as recorded below. Authentication
parsing/division/reduction/ring implementation has not started. Previous Stage 2 exit
obligations and DEP-001/002 remain separate; SPEC-001/002 are unchanged.

## Actual SPEC-003 adoption and extended validation — 17 September 2026

**Agreed user wording:**

> Initialise equality with public 1. Initialise magnitude multiplication with a public 128-bit zero accumulator; add all 64 shifted partial products in increasing order using full-width ripple addition, retaining terminal carry operations.

VII-A.6's corresponding wording on printed p. 16 needs later alignment; the PDF is
preserved. Existing gate/operand ordering, checked arithmetic and public-only folding
remain mandatory. Production already follows the agreement; no canonical alternative
selector exists. Diagnostic variants stay test-only; broader historical proposals
are not implicitly agreed. Full BC-1 conformance remains unverified.

The [validation report](stage3_hash_enrolment.md#confirmed-convention-and-extended-validation)
lists every exact case, functionality, outcome and resource measurement. **17/17
deferred tests passed, 9/9 diagnostic probes completed, 2/2 stability cases passed;
1106 regression tests passed with no skips.** Six count/stream probes validate
construction/digests without evaluating witnesses; three materialised probes do both.
Ruff lint/format pass (93 Python files). The old measurements remain unchanged.

| Requirements | Added executed evidence | Remaining boundary |
|---|---|---|
| R-034/R-035 SPEC-003 | `test_confirmed_bc1.py`: literal public-1 equality, first zero-accumulator multiplication with retained terminal carry, all 64 full-128-bit partial additions in increasing shift order; previous exhaustive checked arithmetic passes | Independent full derived-recipe/compiler conformance, division/reduction/ring and sampler lowering still absent |
| R-010/R-032 hash function | Exact six previously skipped official cases plus six private multi-absorption and five longer-squeeze cases execute unchanged; all 15 official records now run, including 12 private-message cases | Finite byte-aligned/public-length tests, not CAVP certification or full ML-DSA/proof composition |
| R-020/R-025 enrolment/public boundary | Regression revalidates three fixtures against Stage 2, parser rejection, wrong openings/targets/attributes, instance/context changes, fixed witness representation and separate public checks | Controller/nonce/allocation/current-state services remain outside the circuit; privacy proof absent |
| R-035/R-037 deterministic construction | Exact historical mul64 demonstration and enrolment fixture retain gate counts/trace lengths/fingerprints. Fresh original/extended materialised traces and stream bytes compare literally; count digests agree | Historical raw traces were not saved, so historical comparison is digest-based; no full independent CGen conformance oracle |
| R-037 resource controls | Separate 2000000-gate/41943040-byte operational profile, one worker, inspected WSL RAM/storage, retained kernel 256 MiB AS, sampled 128 MiB RSS, 10/5-second generation/evaluation and 30-second per-case wall controls. Nine old capped probes now complete; resource-control unit tests pass | RSS sampling may miss transient overshoot; controls are not guarantees of future/full-circuit feasibility. Original failures remain non-completions |
| R-041 projection only | Same enrolment d=256, g=38787, V=9729, calculated proof size 9587104 bytes | No generated/verified proof; full 480-repetition raw-view implementation and feasibility remain open |

**Readiness:** the deferred hash/enrolment validation is complete and supports the next
bounded authentication parsing and checked division/reduction/ring package. No required
deferred case needs a corrective run. Full conformance/proofs and all Stage 2 keygen,
signing, revocation/update, DEP-001/002 obligations remain open. No subsequent
implementation package is started here. See [new raw evidence](data/stage3_hash_enrolment_validation.json),
[regression](data/stage3_hash_enrolment_regression.json) and [audit](data/stage3_validation_audit.json).

## Actual authentication parsing and scalar arithmetic coverage — 17 September 2026

Historical package record; the SPEC-004 adoption entry below supersedes its pending
status and provisional fingerprints without replacing the earlier measurements.

[The report](stage3_auth_parsing_arithmetic.md) records exact input/output contracts,
source positions, signedness/intermediate widths, public/private classification,
operation order, all measured costs and complete commands. **217 focused / 1323
regression tests passed, no skips; 36 probes completed; lint/format passed (105 files).**
The approved extended profile was reused without increases, including a 280729-gate
maximum-capacity attribute case. Routine defaults and all previous evidence remain
unchanged. Probe construction/evaluation outcomes remain separate from proof claims.

| Requirements | Implemented/executed evidence | Remaining dependency |
|---|---|---|
| R-006/R-007/R-024/R-025 | `auth_parsing`: fixed private witness split, canonical attribute lengths/types/padding/rid and same-field D/mD linkage; twelve existing fixtures, malformed private fields, unsigned64 max, full/zero capacity, wrong lengths/masks and validly encoded cryptographic failures | Holder/B/Mcred construction, FIPS signature/hint decoding and verification, same-rid Merkle circuit; public policy/state and lifecycle retain their separate boundaries |
| R-034/R-035 division | `division`: signed64 positive-public-constant floor divmod, canonical/centred residues; 96 actual-width vectors, small exhaustive scans, literal carry/operand trace, MIN/MAX and zero-divisor invalidity | SPEC-004 exact restoring construction is proposed, not agreed; negative/private divisors not part of the confirmed verifier profile |
| R-032/R-034/R-036 scalar verifier layer | `scalar_ring`: checked add/sub/full-128-bit mul before reduction, domain labels, Decompose/HighBits/LowBits/UseHint/norm and one forward butterfly; independent/ref boundaries, private/private and private/public cases, overflow cannot be repaired by equality/mod, active-path rejection and source-order checks | Private FIPS decoding, full forward/inverse NTT, matrix/vector order, bounded samplers, w1/challenge composition and complete verifier integration |
| R-035/R-037 deterministic/resource subset | Literal/repeated/budget/mode trace checks; 12 components x three sequential storage modes, all completed under existing process/time controls; 42632 authentication inputs, no advice | Full independent canonical compiler equivalence and complete circuit admission/feasibility unverified; counts are component predicates only |
| R-038–R-043 proof boundary | No new proof claim or full authentication projection; prior enrolment calculated size remains 9587104 bytes | Shares/raw tapes, 480 repetitions, commitment/challenge/transcript/proof checking, erasure and full feasibility absent |

SPEC-001/002/003 are preserved. SPEC-004's concrete proposal and required manuscript
alignment are recorded in the issue register; the PDF is unchanged. Next bounded
integration is private FIPS signature/hint decoding and verifier input wiring, then
full NTT/matrix/sampler and same-witness cryptographic composition. The current
package stops here; Stage 2 and full canonical/proof obligations remain open.


## Private FIPS decoding/input preparation coverage — 18 September 2026

Historical package record; subsequent adoption/counting evidence appears below.

[Contracts, exact SPEC-004 proposal and evidence](stage3_signature_inputs.md):
**81 focused / 1404 regression tests passed without skips; lint/format passed (115
files); 39 probes completed and 12 gate-limit attempts remained incomplete.** Tests
and probes use the unchanged approved profile and one sequential worker.

| Requirements | Implemented and actually validated | Remaining dependency |
|---|---|---|
| R-009/R-024/R-025/R-032 | `circuits.signature`: original witness signature wires to challenge, 1280 signed64 responses and complete bounded hint-decoder source; genuine/reference and independent synthetic response outputs, bounded hint boundary/ordering/write/padding steps, empty/55 populations and repeated positions across rows | Full hint reconstruction and full signature-decode circuit stop at 2000000 gates; no complete decode evaluation claimed |
| R-034/R-036 | Checked counters/response subtraction, full private scans and snapshot writes, active return masks/sticky rejection; separate strict norm over all 1280 responses; malformed private values retain structure | Full compiler equivalence and sampler lowering remain open; norm/syntax are not cryptographic verification |
| R-010/R-023/R-024 | `signature_inputs`: same-witness holder SHA3, canonical attributes/rid, exact binding/Mcred/pure credential context once, expected public key, tr and FIPS representative gadgets; evaluated intermediates and standalone SHAKE fragment chain match references | Whole holder/message hash and complete preparation hit the gate cap; no independently supplied B/Mcred/witness advice or fallback |
| R-034/R-035 SPEC-004 | New test-only compare/subtract alternative: same exhaustive/endpoint results, different widths-of-operations schedule counts; production core 35894 gates versus alternative 56566 | Wording does not uniquely resolve recipe; issue remains pending; affected arithmetic identities provisional |
| R-035/R-037 | Three-mode identities for completed components; required-validity core versus zero-gate host comparisons; earlier multiplication/butterfly fingerprints reproduced and extra test costs isolated | Component counts are specialised to operand classes; complete circuit execution/admission/feasibility not established |
| R-038–R-043 | No authentication proof/count projection, no placeholder success | Full raw-tape 480-repetition proof/transcript/checking/privacy implementation absent |

Source mappings and complete commands are in the report; raw focused/measurement/
regression/development/audit JSON records are linked there. SPEC-001/002/003, prior
vectors/evidence and the manuscript are unchanged. Stage 2 and DEP-001/002 remain
open. Resolve the pending lowering and full-execution resource gaps before proceeding
to bounded samplers/full transforms/matrix/Merkle/authentication composition. This
bounded package ends here.

## SPEC-004 adoption and counting preflight — 18 September 2026

[Adoption, exact counts, budgets and evidence](stage3_resource_preflight.md): **241
focused / 1421 regression tests pass without skips; Ruff lint/format pass (119 files).**

| Requirements | New evidence | Remaining dependency |
|---|---|---|
| R-034/R-035 agreed division | `test_spec004_adoption`: literal 65-bit correction sequence, all mux arms, named reuse, Q/R checks and final AND order; independent floor oracle, signed64 endpoints, identity/remainder bounds, zero and active-path rejection, fixed three-mode structure | Complete independent BC-1 lowering/compiler audit remains open |
| R-035 arithmetic identity | Public-zero false arm and validity order deliberately changed; 30 dependent probes and three core counts refreshed; counts/folds/trace lengths unchanged, fingerprints changed; frozen old source and prior JSON retained | Count equality does not imply canonical identity or interchangeable operand specialisations |
| R-009/R-024/R-025/R-032/R-037 unfinished targets | Actual canonical count emission, exact E(X)/5329-byte witness layout, zero test comparisons; message preparation complete at 2034776 gates; hints/signature+norm/preparation+decode+norm each cap at 32M | Prefixes are not complete counts; complete functional evaluations and hint-containing feasibility remain open |
| R-037 resource evidence | No full graph/trace/value array in count mode; WSL headroom checked, retained 128 MiB RSS/256 MiB AS, one worker; exact logical/stored bytes and guard tests; evaluator memory model calibrated to four completed evaluations | Streaming evaluation absent; later message pilot and conditional larger budgets are recommendations, not activated permissions/profiles |
| R-038–R-043 and Stage 2 | No full authentication count, proof projection, sampler/NTT integration or change to earlier parameters/evidence | Full conformance/authentication/raw-tape proofs and outstanding Stage 2/DEP-001/DEP-002 obligations remain open |

The manuscript is preserved; the agreed clarification requires a later VII-A.6 p. 16
wording update. No higher-cap retry or enlarged evaluation was run. This package stops here.

## Message pilot and concrete-profile feasibility review — 18 September 2026

[Report, source audit and raw evidence](stage3_feasibility_review.md).

| Requirements | New evidence | Boundary still open |
|---|---|---|
| R-006/R-007/R-010/R-024/R-025 | Nine complete message-preparation pilot cases; all eight observed byte strings match independent framing/hashes; four invalid inputs reject, well-formed certified-field mutations change preparation without claiming signature failure | Signature/Merkle/authentication correctness and proof binding are absent from this layer |
| R-035/R-037 | Same 2034776-gate/413709-AND construction and fingerprint as the completed count; zero test gates; generation/evaluation/time/RSS/AS controlled separately | Materialised pilot is not streaming evaluation or full authentication feasibility |
| R-032/R-034/R-036 | Attributed actual hint-prefix emission reproduces 13532448 ANDs; 8-bit byte cells, signed64 counters/coefficient cells, full 61-cell reads and 256-cell writes, public-only folding and required guards inspected; no demonstrated core error | Complete hint functional evaluation and independent whole-program BC-1 conformance remain open |
| R-037/R-041 | Frozen formula yields 3253150624 bytes; semantic decoder call chain required by VII-A.6/FIPS; exact integration assumptions recorded | Conditional projection only: full CGen(auth) and independently audited embedded-prefix identity absent; overlapping prefixes are not added |
| R-038–R-043/R-050–R-052 | Raw-view retention/streaming uncertainties, absence of KYC numerical targets and required VII–VIII review identified | No proof implementation, security-profile revision or replacement system; all prior proof/privacy/lifecycle/Stage 2 obligations remain |

The recommendation at this historical package boundary was to prepare a reviewed concrete-profile change proposal,
not to proceed automatically to the inactive 64M/2 GiB envelope. The message pilot is
complete; hint-containing validation, full conformance and authentication remain open.

Validation for this package: **119 focused / 1432 regression tests passed without
skips**, Ruff lint/format passed (123 files). The [preservation audit](data/stage3_feasibility_audit.json)
records unchanged production circuits, confirmed parameters, agreed clarifications,
ordinary/count profiles and all earlier vectors/raw evidence.

## Concrete-profile proposal and draft benchmarks — 19 September 2026

[Candidate/requirements/security comparison](stage3_profile_change_proposal.md),
[separate draft specification](stage3_profile_spec_draft.md),
[measurement definitions and targets](benchmark_targets.md),
[source/version/host record](data/stage3_profile_sources.json) and
[documentation/data checks](data/stage3_profile_proposal_checks.json).

| Requirements | Proposal/evidence added | Boundary still open |
|---|---|---|
| R-002/R-010/R-020/R-023–R-025/R-029/R-044 | Requirements map demands private issuer-signature verification, holder opening, same certified attributes/rid/path and both enrol/auth; public/lifecycle checks retain their positions | No candidate integration or replacement proof; native success Boolean, public signature or trusted external witness checker is insufficient |
| R-004–R-009/R-032–R-037 | Draft preserves canonical application bytes, exact bounds/rejection and checked arithmetic; proposes separate guest/image/admission contract | Guest equivalence and complete validation absent; original BC-1 requirements/SPEC-003/004 remain intact |
| R-016–R-018/R-024–R-028/R-031/R-051/R-052 | Complete E(X)/profile/kind binding and future receipt/presentation framing specified; strict expiry, final state read and atomic replay controls retained | Context/profile selection and wire adapter unimplemented; service/representation integration and all remaining Stage 2 work retained |
| R-037–R-043 | Pinned RISC Zero Succinct mode proposed; explicit Fake/Composite/Groth16 rejection, pruned claim/public journal and trusted image/control parameters | No new transcript accepted; original MPC proof work remains pending; fragment experiment cannot be registered as full auth |
| R-045–R-050/R-051 | Candidate privacy/length/quantum qualifications and Sections II–VIII impact mapped; raw-view extraction/simulation bounds explicitly inapplicable to new backend | No surveyed candidate establishes the whole required contract; actual-history full-witness extraction, complete-view simulation, concrete losses and DEP-001 remain unresolved |
| R-037/R-041/R-049 | Independent integer check: floor 5363104 bytes, max 21344 ANDs under 10 MiB; target/network/encoding/memory boundaries defined; host ISA/memory inspected | Algebraic constraints only; no full circuit/proof measurement, KYC standard, approved performance target or new execution authority |
| R-032–R-043/R-048–R-052 | R0-SUCCINCT-FEASIBILITY-1 proposed with resource admission, at most three proof attempts and pass/fail/stop criteria | Requires review before installation/build/execution; full authentication, lifecycle services, p95 benchmarks and security proofs are later work |

This package supersedes only the prior recommendation to *prepare* a proposal:
the proposal is now available for review. No active suite/profile, source module,
dependency, fixture or historical measurement is replaced. SPEC-001–004 remain
agreed, the 64M/2 GiB proposal is inactive, all remaining Stage 2/3 obligations are
retained. Existing 119 focused/1432 regression passing tests and Ruff evidence are
reused; only documentation/data checks were run for this package.

## R0-SUCCINCT-FEASIBILITY-1 implementation and resource stop — 19 September 2026

The user subsequently authorised this isolated experiment; the historical proposal's
installation/build/execution approval dependency above is satisfied for this package
only. [Report](stage3_r0_succinct_feasibility_1.md),
[manifest](../experiments/r0_succinct_feasibility_1/evidence/manifest.json),
[native comparisons](../experiments/r0_succinct_feasibility_1/evidence/native_comparisons.json)
and [guest results](../experiments/r0_succinct_feasibility_1/evidence/guest_comparisons.json).

| Requirements | Experimental evidence | Boundary still open |
|---|---|---|
| R-004–R-006/R-010/R-020/R-023 | Complete canonical enrolment and full CredValid ports; independent B/certificate, expected pp, metadata, approved/private attribute consistency, holder opening and exact Mcred; 29 native relation comparisons match Python | Only first enrolment guest case completed; first CredValid case hit the 2^22-cycle cap; remaining 27 guest cases unrun. No full equivalence claim |
| R-009/R-032/R-033 | Real SHAKE/ML-DSA context path; six native context comparisons plus proper/wrong-context full credential fixtures; actual sampler cap/exhaustion tests and negative arithmetic/inverse checks pass | No completed CredValid guest execution; bounded keygen/signing and all-role release/state integration remain open |
| R-016–R-018/R-024–R-028/R-031 | Diagnostic operation/profile/context and exact public statement bound to journal; runtime private witness, expected guest registry and verifier parameters | No full authentication, selective disclosure, Merkle/non-revocation integration, freshness or lifecycle service |
| R-037–R-043 | Both guests build; full receipt-verification API and strict Succinct policy implemented; synthetic Fake/Composite/Groth16 and malformed-input rejections pass; private-file/network isolation probe passes | Zero proof launches; no actual receipt verification, tamper tests, proof size, pipeline/recursion/verifier timing or proof privacy result |
| R-037/R-041/R-049 | Kernel cgroup descendants/memory/no-swap controls validated; 2 GiB ceiling, one worker, cycle/time/disk stops; first enrolment 196311 user cycles/10 segments, first CredValid stops exactly at 4194304 user cycles | Resource result applies to this port/envelope; no BC-1 gate equivalence, larger-hardware impossibility, p95, throughput or approved benchmark claim |
| R-045–R-050/R-051 | SDK provenance, host/guest locks, patched guest sys_read versions and remaining RustSec/upstream qualifications recorded | Candidate ZK leakage, concrete quantum security, full actual-history extraction/simulation and Section VIII adoption review remain unresolved |

No selected relation was weakened after the stop, no higher cap or unchanged retry
was used, and no profile was activated. The original manuscript, SPEC-001–004, Stage 2
obligations, DEP-001/002, full BC-1/authentication work and original proof obligations
remain intact. At that historical boundary, the recommendation was a separately scoped
execution-only cycle-attribution package, before any new proof pilot.


## R0-CREDVALID-CYCLE-1 attribution and bounded correction — 19 September 2026

The user subsequently authorised this execution-only package. [Report](stage3_r0_credvalid_cycle_attribution.md),
[manifest and build identities](../experiments/r0_credvalid_cycle_1/evidence/manifest.json),
[prefix measurements](../experiments/r0_credvalid_cycle_1/evidence/baseline-prefix.analysis.json)
and [preservation/resource audit](../experiments/r0_credvalid_cycle_1/evidence/final_audit.json).

| Requirements | New experimental evidence | Boundary still open |
|---|---|---|
| R-004–R-006/R-009/R-010/R-020/R-023 | Original runtime fixture and exact statement preserved; first 24 matrix SHAKE prefixes dominate observed capped prefix; single demand-driven matrix XOF correction retains 1026-byte rejection budget and unchanged 256-byte challenge budget; six native tests and all 35 comparisons pass | Corrected full guest still hits 4194304 cycles; no complete CredValid guest result or acceptance/rejection equivalence |
| R-032/R-033/R-037 | Pinned cycle-counter/hard-limit semantics traced; incremental phase markers survive cap; isolated original/corrected polynomial costs 142199/113393 cycles, unchanged NTT 409218 and twiddle setup 567539 | Isolated/instrumented costs are not full guest totals; inverse transforms, matrix products, final hashes/hints/norm/journal remain unmeasured in the complete guest; no BC-1 conformance claim |
| R-016–R-018/R-024–R-028/R-031 | Diagnostic counters stay outside calculations, acceptance and journal; feature-gated component wrappers use private runtime intermediate fixtures independently checked by Python | Full authentication, same-witness Merkle/non-revocation, freshness, replay and lifecycle obligations unchanged |
| R-037–R-043/R-049 | Five executions under unchanged cycle/segment/2 GiB/no-swap/wall/disk limits; slot 5 unused; execution-only host contains no proving command; originals and pinned dependencies preserved | Zero proof attempts and no receipts, all three earlier proof attempts unused; no proving memory/time/size, actual receipt verification, privacy or benchmark claim |
| R-045–R-050/R-051/R-052 | Execution limitations and one explicit next-package proposal recorded | ZK leakage, quantum/security accounting, Section VIII extraction/simulation, DEP-001/002, all remaining Stage 2/BC-1/authentication/proof obligations remain open |

The package is complete and closed against replay. At that boundary, the recommendation
was a separately authorised execution-only budget of 2^24 user cycles with fixed
corrected code, one worker, 2 GiB/no swap and at most two executions. The user's
subsequent EXEC24-1 authorisation below replaces that proposed run sequence with an
uninstrumented valid run followed conditionally by a meaningful negative run.
The active suite, manuscript, SPEC-001–004, original experiment/report/STOP marker,
existing vectors, profile drafts and inactive 64M BC-1 proposal remain unchanged.


## R0-CREDVALID-EXEC24-1 complete execution — 19 September 2026

The user authorised 2^24 SDK user cycles for this execution-only package, with all
other limits retained. [Report and one proof-pilot recommendation](stage3_r0_credvalid_exec24.md),
[machine-readable run manifest](../experiments/r0_credvalid_exec24_1/evidence/manifest.json)
and [preservation/configuration audit](../experiments/r0_credvalid_exec24_1/evidence/final-audit.json).

| Requirements | New experimental evidence | Boundary still open |
|---|---|---|
| R-004–R-006/R-009/R-010/R-020/R-023 | Existing corrected release image completes full CredValid for `cred-alpha-42`: 16313474 user cycles, `Halted(0)`, exact 5147-byte public journal. Six native tests and 35 comparisons reused after identity checks | One valid guest execution is not complete guest/reference equivalence; no broader credential coverage or full authentication |
| R-009/R-024/R-032/R-033 | Existing canonical certified-identifier mutation reaches the actual Python bounded verifier and rejects in the unchanged guest with explicit relation failure; no successful acceptance journal | Negative complete cycle count is unavailable on panic; 16298606 completed-segment user cycles are a prefix, not an estimated total |
| R-016–R-018/R-024–R-028/R-031 | Runtime private inputs, unchanged canonical public statement/profile/operation and byte-exact public output; no guest rebuild or crypto changes | Selective disclosure, Merkle/non-revocation, state/freshness/replay and lifecycle integration remain open |
| R-037/R-041/R-049 | Authorised hard cap remains SDK user cycles; valid margin 463742/2.76%, 582 segments and 38109184 padded capacity. Two sequential executions under 2 GiB/no swap, existing time/disk/output limits; no retry or resource failure | Separate paging/system counters unavailable through IPC; 20.26% remains isolated-component evidence; no whole-guest speedup, percentile or throughput claim |
| R-037–R-043/R-045–R-052 | Complete valid execution now supports a concrete bounded Succinct pilot proposal with the three remaining attempts | No actual proof/receipt generation or verification, proving memory/time/size result, privacy/ZK/security theorem, Section VIII closure or profile adoption |

This package is complete and stopped after two executions. Exactly one next package
is recommended for separate authorisation: `R0-SUCCINCT-PILOT-2`, with one enrolment
and conditionally two corrected CredValid proof attempts, existing 2 GiB/no-swap/
600-second limits and the full sequence/gates in the report. All three attempts are
still unused. Historical evidence, manuscript, active suite, SPEC-001–004, DEP-001/002,
full BC-1/authentication work and remaining Stage 2/proof/privacy/security obligations
are preserved. The 64M BC-1 proposal remains inactive.


## R0-SUCCINCT-PROOF-1 bounded real proving — 19 September 2026

The user authorised at most three local CPU Succinct attempts, with identical
CredValid inputs for the optional third attempt. The
[report](stage3_r0_succinct_proof_1.md),
[pre-launch manifest](../experiments/r0_succinct_proof_1/evidence/manifest-before-launch.json)
and [results](../experiments/r0_succinct_proof_1/evidence/results.json) record the
single attempted pipeline and the resource stop.

| Requirements | New experimental evidence | Boundary still open |
|---|---|---|
| R-004–R-006/R-009/R-010/R-020/R-023 | Frozen validated enrolment and corrected CredValid ELFs/images, fixtures and expected journals; six native tests/35 comparisons reused; pinned local recursion archive verified | No new full guest equivalence, complete authentication or cryptographic parameter approval |
| R-016–R-018/R-024–R-028/R-031 | Enrolment execution inside the proof pipeline returns Halted(0), ten segments and the exact 15380-byte public journal | Journal alone is not a receipt; selective disclosure, Merkle/non-revocation and lifecycle freshness/replay remain open |
| R-037–R-043/R-049 | Actual CPU segment proving and recursion: all ten segment proofs, five lifts and four joins complete; sixth lift interrupted at the 600-second deadline. 600.128431 s guarded wall, 1521070080-byte kernel peak, no swap/OOM | No final Succinct receipt, complete proving cost or receipt size. CredValid and repeat gated off; one attempt used/two unused |
| R-039–R-043/R-049 | Explicit Succinct/poseidon2, fixed images/control parameters, full verify_with_context path, private-fixture namespace probe and eight planned tamper cases | Actual receipt verification and tamper rejection unrun because no final receipt exists; Composite/internal recursion components cannot substitute |
| R-045–R-052 | Stop record, honest partial phase/resource evidence, source/preservation checks and one future segmentation-check recommendation | Privacy/ZK metadata, unlinkability, quantum/security accounting, Section VIII extraction/simulation, DEP-001/002 and remaining Stage 2/BC-1/proof obligations unchanged |

No proof attempt follows the timeout. The future recommendation is one separately
authorised enrolment-only execution check with segment po2 17 and unchanged guest,
fixture, 2^22 user cap, 2 GiB/no-swap and 60-second execution limit, to measure whether
fewer segments can reduce repeated recursion work. Larger-segment proving memory
and complete runtime are not known. No segmentation change or new execution occurs
in this package, and no replacement profile is adopted. Earlier three-attempt
budgets above describe their historical package boundaries; the current unused
balance is two after this authorised attempt.


## R0-ENROL-PO17-1 successful bounded enrolment proof — 19 September 2026

The user authorised one execution-only segmentation check and conditionally one
remaining proof attempt, preserving CredValid proving outside this package.
[Report](stage3_r0_enrol_po17.md),
[results](../experiments/r0_enrol_po17_1/evidence/results.json),
[receipt](../experiments/r0_enrol_po17_1/receipts/attempt2.bin), and
[cumulative ledger](../experiments/r0_enrol_po17_1/evidence/cumulative_attempt_ledger.json).

| Requirements | New measured evidence | Boundary still open |
|---|---|---|
| R-004–R-006/R-009/R-010/R-020/R-023 | Same validated enrolment ELF/image, fixture, crypto, release guest, reference evidence and 2^22 user cap; exact journal and 196311 user cycles | Full guest equivalence and unimplemented authentication/Stage 2 work unchanged |
| R-037/R-041/R-049 | Actual executor po2 17, distinct from unchanged prover max 22; registered allowed po2-17 control verified. Measured partition 10 to 3 segments, padded capacity 622592 to 393216 | Execution-only timer scopes/cache state differ; no exact overall speedup against prior timeout, percentile or throughput claim |
| R-037–R-043/R-049 | Real final Succinct enrolment proof: 3 segment proofs, 3 lifts, 2 joins; 343.792883 s SDK / 343.898930 s guarded wall; 1535385600-byte kernel peak, no swap/OOM; 238485-byte receipt | This enrolment result does not establish complete CredValid/authentication proof feasibility |
| R-016–R-018/R-024/R-039–R-043 | Independent fresh verification with private fixtures/traces inaccessible, expected image/control/parameters, successful unconditional execution and exact 15380-byte journal; seal/journal/image/public/context/operation/hash/trailing mutations reject | Lifecycle freshness/replay, selective disclosure and non-revocation composition remain open; proof alone cannot bypass those obligations |
| R-045–R-052 | One execution and one conditional proof consumed; cumulative two used/one remaining, persistent STOP, preservation and actual receipt checks | Privacy/ZK metadata, unlinkability, quantum/security and Section VIII reviews, DEP-001/002, complete BC-1 and remaining Stage 2 obligations remain open |

The final unused proof attempt is retained. Recommend one separately authorised
execution-only CredValid partition/admission check at po2 17 with its unchanged
corrected guest/fixture, 2^24 user cap, 60-second/2 GiB/no-swap and existing disk limits.
The current enrolment cost alone does not justify a CredValid proof under the fixed
600-second/2 GiB plan. There is no CredValid execution/proof or automatic limit
increase in this package. Earlier attempt balances above are historical boundaries;
the current balance is two used and one remaining. The active profile is unchanged.


## R0-CREDVALID-PO17-1 — measured partition and no-proof decision, 19 September 2026

[Report](stage3_r0_credvalid_po17.md),
[partition](../experiments/r0_credvalid_po17_1/evidence/execution.result.json),
[cost inputs](../experiments/r0_credvalid_po17_1/evidence/cost-model-inputs.json),
[admission](../experiments/r0_credvalid_po17_1/evidence/admission.result.json), and
[cumulative ledger](../experiments/r0_credvalid_po17_1/evidence/cumulative_attempt_ledger.json).

| Requirements | New evidence | Boundary still open |
|---|---|---|
| R-004–R-006/R-009/R-010/R-020/R-023 | Original corrected release guest/image/cred-alpha-42 preserved; six native tests/35 comparisons reused; exact journal and 16313474 user cycles | No optimisation, parameter or reference change; full guest equivalence/BC-1 remains open |
| R-037/R-041/R-049 | Actual partition 182 (181 × po2 17 + one × po2 15), versus 582; padded capacity 23756800. One execution at 0.302628 s API/0.392469 s guarded, 48640000-byte kernel peak, zero swap/temp/OOM | Execution journal is not a proof; separate paging/system counters and complete proving costs unavailable |
| R-037–R-043/R-049 | Pinned source requires 182 base proofs/182 lifts/181 joins; typed timing inputs plus 50% engineering allowance forecast 35615.572 s, exceeding 600 s; proof not admitted | Forecast is not measurement; unmatched terminal po2-15 timing, retained data/receipt and concurrent proving memory bounds unresolved |
| R-039–R-043 | Prior enrolment Succinct receipt, independent verification and eight tamper results preserved; no new proof or calibration run | No CredValid receipt, cryptographic verification or receipt tamper result; no full authentication/application-target acceptance |
| R-016–R-018/R-024–R-028/R-031/R-045–R-052 | Frozen evidence, enforced limits, explicit STOP and cumulative balance two used/one remaining; application-latency shortfall stated | Selective disclosure/non-revocation, lifecycle freshness/replay/consumption, privacy/ZK/unlinkability, quantum security, Section VIII, DEP-001/002 and remaining Stage 2 work open |

This package ends with preflight only. Recommend a design review to reduce total
proved credential-verification and recursion work against the provisional 30-second
generation target, preserving the exact private relation and required security
properties. Retain the final attempt until a credible latency/memory case exists;
no automatic budget increase or replacement-profile adoption. Earlier budgets above
remain historical boundaries; the current balance is two used and one remaining.

## R0-DESIGN-REVIEW-1 — CPU pause and bounded reference-work proposal

19 September 2026. [Design review](stage3_r0_design_review.md),
[reproducible calculations](data/r0_design_review_1/calculations.json),
[pinned external source records](data/r0_design_review_1/external-sources.json), and
[validation/preservation audit](data/r0_design_review_1/validation.json).

| Requirements / authoritative scope | New review evidence | Boundary and decision |
|---|---|---|
| R-037–R-043/R-049; VII-A.6/.7, VIII-A | All 182 saved segment records sum to 16,313,474 user cycles; 35,615.572 s forecast recalculated with one 50% allowance; base, recursion, execution and memory scopes separated | No new measured proving cost; actual CredValid aggregate memory/time and authentication size/latency unknown; 600 s and application targets unchanged |
| R-009/R-010/R-020/R-023/R-032–R-033 | Pinned SDK 3.0.6 and tiny-keccak source support exact SHA3-384/SHAKE128/256; new Keccak base/lift/resolve work identified; source-based batch scenario separately labelled | Adapter/image/lock changes unimplemented; FIPS/domain/output/sampler caps and exhaustion must remain exact; no unchecked host result or unresolved assumption accepted |
| R-001/R-009/R-024/R-025/R-036/R-037/R-049 | Public matrix/key/twiddle/tr derivation, canonical sizes, independent expected-key binding via journal or specialised image, cache/rotation/cold costs specified as proposals | Same mathematical relation possible only with verified derivation/binding; new interfaces/profile identity need review; full private conjunction and BC-1 unchanged |
| R-002/R-024/R-043–R-052; II–VIII | At most two prior-survey alternatives inspected: modified non-ZK zkDilithium and lattice LaZer credential showing; exact relation/hardware/same-witness gaps recorded | Neither adequate for adoption; changed signatures/issuance/hashes need new suite/security/fair-baseline arguments; privacy and quantum obligations remain open |
| R-016–R-018/R-027–R-028/R-031; IV, VII-A.7, VIII-E | One proposed next package, S2-VERIFY-STATE-1: bounded reference lifecycle state model, final ordered read, exact context/expiry and atomic consumption, explicit success/stop limits | Not implemented in review; no placeholder Check/VerifyDAA success; real proofs/services and complete PQ-DAA remain open |
| R-045–R-052 / preservation | Source hashes, calculation/document checks, 8,670-file preservation inventory; six native tests/35 comparisons reused unchanged | Current R0 CPU proving stays paused; zero new executions/proofs/installs/limit changes, ledger two used/one unused; no profile adopted |

The pause supersedes earlier next-step recommendations without altering their
historical reports or attempt balances. PROP-002 records only proposed changes.
Remaining Stage 2 work, full BC-1/authentication, selective-disclosure/non-revocation,
actual CredValid/authentication proofs and the privacy/security review remain open.

## S2-VERIFY-STATE-1 — reference lifecycle, 19 September 2026

[Report](stage2_verifier_state.md), [module](../src/pqdid/verifier_state.py),
[58 focused tests](../tests/unit/test_verifier_state.py),
[test-only harness](../tests/unit/verifier_state_cases.py),
[run records](data/s2_verify_state_1/run-ledger.json) and
[preservation audit](data/s2_verify_state_1/validation.json).

| Requirement / authoritative source | Implemented and validated | Remaining boundary |
|---|---|---|
| R-001/R-003/R-005/R-016; III-B/C, IV-A/B, VII-A.1/.7 | Full stored Context and expected pp/µ/rse; independent audience-A/B stores and keys, separate invoking session, bounded collision resampling, signed canonical request | Trusted instance discovery, holder request authentication/approval, bounded production signing and persistent nonce/session state remain open |
| R-009/R-017; IV-A, VII-A.7 | Exact existing enc_current and current context; bounded outer manager signature plus StateAuth, nonce/instance checks; final read compared to original context | Latest-state ordering and authentic network service implementation remain trusted-provider obligations; old signed state alone is insufficient |
| R-024–R-028; V-B/C, VII-A.6/.7 | X built from pinned/stored public inputs and presentation D,mD; PubOK/Ppub; public-only opaque proof adapter, unsupported default and strict verdict handling; separate harness checks complete local auth with the same witness | No real Check/VerifyDAA backend, remote-knowledge or ZK claim; reference adapter success is not a receipt |
| R-008/R-028; IV-B, VII-A.7, SPEC-002, VIII-E | Strict initial/final expiry, full-record/session atomic consumption, deterministic barrier race, replay/failure behaviour; state/expiry interleavings respect final-read logical epoch | In-process lock is not a distributed transaction; same-audience replicas need shared linearizable persistent state and trusted time |
| R-015/R-020/R-028; IV-B, VII-A.4/.7 | Optional specified DID-state check requires certified disclosed did/vD; exact document/version/media/adapter-authentication checks; hidden-DID lookup absent | Trusted registry-chain/resolution provider and application policy configuration remain open; issuance-time holder binding unchanged |
| R-029–R-031 / preservation | Old-valid/current-stale, current-revoked and updated-survivor cases reuse original credential/path evidence; 29 scoped regressions plus 58 focused cases pass; limits and attempt ledger preserved | Next proposed package S2-UPDATE-WIT-1 for holder-local reference updates; production update/revocation/services, DEP-001/002, full authentication/proofs/BC-1/privacy/security still open |

These requirements are **partially implemented**, not full lifecycle or PQ-DAA
completion. No proof, zkVM execution, dependency or proof-parameter change occurred.
CPU proving stays paused; two attempts used and one unused.

## S2-UPDATE-WIT-1 — holder-local reference updates, 19 September 2026

[Report](stage2_witness_updates.md), [module](../src/pqdid/witness_updates.py),
[70 focused tests](../tests/unit/test_witness_updates.py),
[independent construction](../tests/unit/witness_update_cases.py),
[run records](data/s2_update_wit_1/run-ledger.json) and
[preservation audit](data/s2_update_wit_1/validation.json).

| Requirement / authoritative source | Implemented and validated | Remaining boundary |
|---|---|---|
| R-005/R-030; VII-A.8, SPEC-001 | Typed five-field rupdate transport, six-field Mu, one raw 960-byte path, exact signing context; independent byte construction and malformed/framing/role tests | Issuer revreq validation, registration/allocation, nonce state, bounded manager signing and atomic publication remain open |
| R-001/R-009/R-017/R-029–R-031; IV-A/C, V-D, VII-A.1/.5/.8 | Caller-pinned issuer instance/namespace/authority, bounded state and update authentication, logical-reference chain equality and consecutive uint64 epochs, exact endpoints | Trusted instance/key registration and current-state ordering remain separate; a signed target is not freshness |
| R-029/R-031; VII-A.8 update equation | Old holder zero-leaf path, both public transition roots, exact changed ancestors/sibling condition and each resulting path; all 20 divergence levels, boundary identifiers, multistep and 16-record maximum agree with independent sparse tree | No allocation, identifier reuse or unrevoke operation; no remote path service |
| R-004/R-024/R-026/R-031; IV-C, V-B/D | Only local path/state changes, preserving all credential/secret/attribute/signature bytes; full local auth accepts updated survivor, rejects revoked; verifier lifecycle rejects stale presentation | Existing validated-credential precondition and same-witness full auth remain mandatory; test-only public adapter supplies no receipt or knowledge proof |
| R-031/R-032/R-033; VII-A.8, bounded verification | At most 16 records / 178592 encoded bytes; immutable whole-batch result; invalid history/signatures, actual sampler exhaustion and injected faults yield no partial checkpoint; explicit chunk resume | Local admission limits are engineering choices; caller retrieval allocation, durable wallet commit and production bounded signing are separate |
| R-045–R-052 / preservation | 70 focused + 25 scoped regressions, lint/format and 8723-file inventory; prior source/fixtures/dependencies/manuscript/experiment evidence preserved, only three status documents updated | Full BC-1/authentication proof integration, privacy/ZK/quantum-security, Section VIII and DEP-001/002 remain open |

R-031's bounded holder-local **reference procedure** is implemented; R-030 and
production lifecycle integration remain partial. The reported batch outcome is
atomic in memory, not a durable wallet transaction. No new SPEC decision, proof,
zkVM execution, dependency or cryptographic parameter change occurred. CPU proving
remains paused at **two attempts used, one unused**. One next bounded recommendation:
S2-REVOKE-STATE-1 manager-side reference authorisation/atomic publication, with
controlled test signers and the unchanged local envelope; not started here.

## S2-REVOKE-STATE-1 — manager reference transitions, 19 September 2026

[Report](stage2_revocation_state.md), [module](../src/pqdid/revocation_state.py),
[73 focused tests](../tests/unit/test_revocation_state.py),
[independent construction/test-only signers](../tests/unit/revocation_state_cases.py),
[run records](data/s2_revoke_state_1/run-ledger.json) and
[preservation audit](data/s2_revoke_state_1/validation.json).

| Requirement / authoritative source | Implemented and validated | Remaining boundary |
|---|---|---|
| R-009/R-010/R-030; IV-B, VII-A.8 | Exact issuer-signed MR with expected metadata/ref/rid/32-byte nonce; bounded authorisation under pinned issuer key; imported permanent allocation prefix, unused nonce and non-revocation checks | Trusted registration/bootstrap completeness; permanent allocation and issuer challenge creation remain separate R-018 work |
| R-005/R-029/R-030; VII-A.1/.5/.8, SPEC-001 | Sparse zero-to-one transition and both PathRoot checks; exact state/Mu signing bodies, unchanged raw 960-byte rupdate path, actual holder decoder roundtrip; independent root/path/message expectations | No identifier reuse/unrevoke; production bounded signer/keygen and DEP-001/002 remain open |
| R-030; IV-B, VII-A.8 | All preparation/signing/validation before local snapshot CAS; tree/epoch/nonce/public history commit together; competing preparations conflict; failures publish no partial record | Local lock is not distributed/durable storage; crash recovery, remote publication and delivery protocol still required |
| R-030/R-031; IV-C, VII-A.8 | Retain 32 public records, no eviction; namespace/version pages at most 16 records/178592 bytes; explicit target/continuation/unavailable history; two complete holder batches and post-commit delivery-loss retrieval tested | Pre-bootstrap history is explicitly unavailable in this model, not permission to discard production history; wallet persistence and network retrieval remain open |
| R-017/R-008/R-028; IV-A, VII-A.7, SPEC-002 | Exact signed current response with final local snapshot recheck; verifier performs its own signature/StateAuth checks; stale state rejects and strict expiry at texp rejects | State certificate has no invented expiry; trusted time, distributed read ordering and real verifier/DID services remain open |
| R-024/R-026/R-031; V-B/D, VII-A.8 | Actual emitted update composes with holder path update and complete local authentication; unchanged surviving credential succeeds through labelled public test adapter, revoked/stale cases reject | Test tokens are not proofs; real proof verification, knowledge/ZK and full authentication circuit/proof integration remain open |
| R-032/R-033 and preservation | Two typed signer calls maximum per transition, default unsupported; three bounded verifications, real matrix/challenge exhaustion at all three boundaries; 73 focused + 25 regressions pass within retained limits | Signing-call bounds do not bound signer internals; protected 8759-file inventory preserves manuscript/source/vectors/dependencies/history, including earlier audit failure/correction |

R-030 is complete at this **bounded reference transition** boundary, conditional on
trusted bootstrap and a valid signing adapter; production lifecycle remains partial.
No proof, zkVM execution, install, parameter change or new SPEC decision occurred.
CPU proving is paused, **two proof attempts used and one unused**. The final audit
completed its content checks but reached the 256 MiB cgroup ceiling (387 max events,
no OOM); the guard returned 125 and STOP closed validation. No retry or limit increase
followed. See the authoritative [package result](data/s2_revoke_state_1/result.json);
the earlier audit-content success flag is not a resource-envelope pass. Recommend
S2-REVOKE-AUDIT-1, read-only preservation with memory-category evidence under the
unchanged ceiling, next; not started here. Stages 2–3, BC-1, actual
CredValid/authentication proofs and privacy/security obligations remain open.


## S2-REVOKE-AUDIT-1 — preservation evidence

19 September 2026. [Audit report](stage2_revocation_audit.md) and
[exact scope](data/s2_revoke_audit_1/scope.json). The historical manager audit
completed content checks but failed its 256 MiB cgroup guard. This separate package
keeps that failure intact and corrects buffered file-cache retention and duplicate
manifest allocation under unchanged limits. The bounded diagnostic supports the
cache mechanism, not a retrospective measurement of the original peak. All 8,759
original paths retain SHA-256 checks; the historical final manifest adds a disjoint
30-file partition. The manager report is append-only with its original prefix
checked. The three original permitted documentation paths are unchanged as a set;
new audit/test/evidence paths are individually enumerated. Exact additions/removals
are also checked in five named source/configuration/documentation roots, with no
directory exclusion. The complete guarded audit now passes; see the final result below. R-030/R-031 behaviour
and prior 73 + 25 functional passes are reused, not reinterpreted. This package
introduces no cryptographic/protocol change or manuscript decision. Stages 2–3 and
all proof/security/integration obligations remain open; proving stays paused at
**two used / one unused**, with zero new proofs or zkVM executions.

**Final audit outcome:** [S2-REVOKE-AUDIT-1 result](data/s2_revoke_audit_1/final_checks/result.json)
passes with exit 0, **21,823,488 bytes (20.8125 MiB)** cgroup peak and **1.053191021 s**;
max/OOM/OOM-kill/swap events are zero. All 8,759 original plus 30 supplementary
historical entries, the original manager-report prefix and the 418-entry name
inventory pass; complete reporting and guard acceptance are recorded. **44 audit
fixture tests** and final lint/format pass; the initial B007 lint failure and its
STOP are retained alongside the documented correction and fresh final-check records.
The historical 256 MiB ceiling failure is not overwritten or reclassified. This
closes only the follow-up audit resource issue. No protocol/specification change,
proof or zkVM execution occurred. Stages 2–3, integration and privacy/security
obligations remain open; CPU proving stays paused at **two used / one unused**.


## S2-ISSUE-ENROL-1 — issuance and holder reference lifecycle

19 September 2026. [Contract and validation](stage2_issuance_enrolment.md),
[issuer/holder module](../src/pqdid/issuance.py),
[manager extension](../src/pqdid/revocation_state.py),
[focused tests](../tests/unit/test_issuance.py) and
[exact preservation scope](data/s2_issue_enrol_1/scope.json).

| Requirement / source | Implemented reference boundary | Remaining obligation |
|---|---|---|
| R-018; IV-B, V-C, VII-A.5 | Permanent next-ID reservation on the manager's existing counter/lock/snapshot; root unchanged, zero path, exhaustion, aborted-ID no-reuse and later revocation; retained fresh issuer nonce | Durable allocation/nonce recovery and authenticated remote interface |
| R-019/R-020; IV-B, V-C, VII-A.5 | Typed current DID/controller and evidence adapters, exact holder-approved vector, stored Xen, genuine bounded controller signature over E(Xen), public-only enrolment adapter, fresh final DID/state reads | Actual DID chain/registry/current-read validation, confidential authenticated channel and real enrolment-proof verifier |
| R-021/R-022/R-033; V-C, VI-A/B, VII-A.5/.6 | Existing Mcred/credential, one signing call, unchanged bounded pre-release verification, certification table and challenge retirement before release; all completed reservations/certifications survive failure | Bounded production keygen/signing/tail budget; durable distributed logging and delivery recovery |
| R-023/R-029; V-A/B/C, VII-A.5 | Holder-local intended attributes/binding/issuer/namespace/rid, exact credential/state signature and zero-path checks, one atomic credential+witness/state assignment | Wallet persistence; a matching root/path is not a currentness guarantee |
| R-024/R-026/R-031; IV-C, V-B/D, VII-A.6/.8 | Issued reference credential composes with local full-auth relation and public test verdict, manager revocation and actual holder update/revocation | Controlled tokens are not proofs; full privacy-preserving authentication and security review remain open |
| Preservation/resource boundary | 64 focused + 30 scoped regressions pass under unchanged 256 MiB cgroup ceiling; corrected auditor reused with original baselines and exact new manager-file permission | Final lint/format and complete guarded audit pass; measured result below; no stage-completion claim |

Repeated issuer challenges/sessions cannot certify twice; distinct approved sessions
for the same holder/vector can issue distinct permanent IDs. The local session key
is not a new signed field or a one-credential-per-holder policy. Local concurrency
safety does not extend the manuscript's sequential security experiment. Issuance-time
DID authority and private xH remain separate; no current hidden-DID-control check is
added to presentation. Existing encodings, SPEC-001–004, parameters and dependencies
remain unchanged. No proofs or zkVM executions, CPU proving paused, **two used / one
unused attempts**. Stages 2–3, complete BC-1 and privacy/security review remain open.

**Final S2-ISSUE-ENROL-1 validation:** [package result](data/s2_issue_enrol_1/release_checks/result.json)
passes; **64 focused + 30 selected regression cases**, no final failures/skips;
final lint/format pass. One complete preservation audit exited 0 at **23,212,032 bytes
(22.13671875 MiB)** cgroup peak and **2.140307967 s** under the unchanged 256 MiB
ceiling, with zero memory-max/OOM/OOM-kill/swap events. All **8,827 historical paths**
are accounted for (8,825 content comparisons plus two distinct manifest identities),
with only the exact authorised manager extension and three documentation changes.
The 463-entry name inventory and every original manager method's AST comparison pass.
The initial fixture-construction and lint failures/STOPs remain preserved. No baseline
was regenerated, no complete audit retried and no resource limit raised. No new
proofs or zkVM executions; CPU proving remains paused at **two used / one unused**.
The next bounded recommendation is S2-DID-STATE-1; it has not started. Stages 2–3,
production backends/recovery/integration, BC-1 and privacy/security review stay open.

## S2-DID-STATE-1 — method and lifecycle reference evidence

[Report](stage2_did_state.md), [implementation](../src/pqdid/did_state.py),
[focused cases](../tests/unit/test_did_state.py),
[guarded focused result](data/s2_did_state_1/focused.json) and
[scoped regressions](data/s2_did_state_1/regression.json).
**74 focused + 14 regressions pass**, no failures/skips. R-012–R-015 and R-052 now
map to exact method bytes, predecessor-key authorisation, immutable atomic histories,
nonce-bound current/historical resolution, bounded work and in-process recovery.
R-018–R-022/R-028 compose through current-controller issuance and independently
pinned verifier parameters; two audience stores accept issued credentials after DID
rotation/deactivation without a hidden-DID/current-controller dependency. Explicit
public DID/version checks use the certified historical state only.

The unchanged auditor is reused against the original and three later historical
manifests: 8,869 distinct content paths plus three additional manifest identities,
8,872 historical paths total, with explicit new filenames and only three allowed
existing documentation changes. [Final guarded audit](data/s2_did_state_1/result.json)
requires complete content, inventory and reporting plus a clean unchanged 256 MiB
resource guard. No pre-existing source/crypto/audit/dependency/manuscript/vector or
historical result is authorised to change. Original baseline/failure records remain.
Bounded keygen/signing, durable/distributed state, formal interoperability, actual
proofs, complete authentication/BC-1 and privacy/security review remain open.
Stages 2–3 remain in progress; no proof/zkVM run, ledger two used/one unused.

**Final DID-package validation:** the single complete audit passes at **22,933,504
bytes (21.87109375 MiB)** cgroup peak and **2.050973451 s**, exit 0; all comparison,
inventory (494 names), reporting and outer guard phases complete. No memory-max/OOM/
swap event, missing file or unauthorised change. Final lint/format pass; all 88 selected
cases pass. Historical baselines/failures and two-used/one-unused ledger are unchanged.

## S2-LIFECYCLE-REVIEW-1 — cross-service ordering and recovery requirements

[Review/invariant matrix](stage2_lifecycle_review.md),
[deterministic integration tests](../tests/unit/test_lifecycle_review.py),
[guarded focused result](data/s2_lifecycle_review_1/focused.json),
[regressions](data/s2_lifecycle_review_1/regression.json) and
[machine-readable findings](data/s2_lifecycle_review_1/review-findings.json).
**28 focused + 50 selected existing cases pass**. Of the focused cases, **two are
unsafe-restart negative controls**, not safe recovery assertions. REC-001 maps R-018/
R-022 to permanent allocation completeness: an authentic unchanged root cannot detect
a stale counter. REC-002 maps R-016/R-028 to retained audience consumption state:
a stale pending-only store can accept again. REC-003 maps R-014/R-020/R-021/R-030/
R-031 to complete role-specific recovery images; inspection snapshots/constructor
checkpoints do not reconstruct all pending inputs, private key handles or update history.
REC-004 maps all effective transitions to delivery semantics: loss after commit keeps
the effect; ordinary duplicates reject rather than inventing idempotent success.

The matrix distinguishes authority-local state assignments from independent DID,
manager, issuer, wallet and verifier read/commit points. Required durable boundaries
and recovery ordering are specified without a storage engine, new cryptographic bytes
or unapproved rollback authority. No source fix was warranted within the trusted-state
reference contract. All pre-existing source/tests remain unchanged. Trust/privacy
review retains public-only verifier inputs and no anonymous hidden-DID/controller query.

[Final preservation result](data/s2_lifecycle_review_1/result.json) requires one complete
guarded audit under the unchanged 256 MiB ceiling. Five pinned historical manifests
cover 8,899 distinct content paths plus four additional manifest-identity paths:
**8,903 historical paths**, with only three existing documentation files permitted to
change. Old failures/STOPs, original baselines, parameters, manuscript and proof ledger
remain protected. Proceed to bounded S2-RECOVERY-ADMISSION-1 reference design/validation
only; no restartable/replicated deployment, real crash guarantee or proof claim.
Stages 2–3, bounded signing, interoperability and private-proof/security work stay open;
CPU proving paused, zero new proofs/zkVM executions, two used/one unused attempts.

**Final lifecycle-review validation:** one complete audit passes at **22,134,784 bytes
(21.109375 MiB)** cgroup peak and **2.049593098 s**, exit 0, no memory-max/OOM/swap event.
Comparison, 525-entry inventory, reporting and final guard complete. All 8,903
historical paths are covered; only the three authorised existing documentation files
changed. Final lint/format pass; 28 focused + 50 regressions pass, with the two
unsafe-restart controls explicitly distinguished from safe recovery guarantees.
No implementation fix, source change, proof/zkVM execution or ledger change.

## S2-RECOVERY-ADMISSION-1 — local validation and activation

The [report](stage2_recovery_admission.md), [record schema](../src/pqdid/recovery_records.py),
[gated services](../src/pqdid/recovery.py) and [tests](../tests/unit/test_recovery.py)
add bounded reference guards to the review's recovery requirements. R-018/R-022
(REC-001) require an independently authenticated permanent allocation prefix, including
abandoned reservations; root/epoch alone is insufficient. R-016/R-028 (REC-002)
require every challenge reservation and consumed flag; a signed pending context
cannot establish later consumption. R-014/R-020/R-021/R-030/R-031 (REC-003) gain
complete typed role records, canonical-object validation, cross-record consistency,
explicit bounds, default-unavailable recovery authority and gated activation.
R-019/R-022/R-028 and REC-004 preserve logging/consumption and duplicate behaviour
across lost responses. Controller pending publication and holder credential/witness
associations retain existing rules. PREPARING/CLAIMED issuer recovery remains refused.

**59 new cases + 28 unchanged lifecycle regressions pass** across four bounded commands;
the report distinguishes initial focused evidence from two small additions checked
subsequently. Original unsafe controls retain their names and unsafe labels. Tests
establish injected-policy behaviour with a deterministic independent fixture oracle,
not a durable freshness anchor, distributed fencing or real crash recovery. Only
Sections II–VIII and SPEC-001–004 remain authoritative; no protocol field changes.
All previous source/tests/evidence are preserved. A single corrected preservation
audit is required under the unchanged 256 MiB guard with six pinned original manifests
and exact permitted changes. Deployment recovery, bounded signing, interoperability,
full private authentication/BC-1/proofs and security remain open. No proof/zkVM work;
CPU proving paused; two attempts used, one unused. Next bounded recommendation is
S2-RECOVERY-AUTHORITY-DESIGN-1; Stages 2–3 remain incomplete.

**Final S2-RECOVERY-ADMISSION-1 validation:** [result](data/s2_recovery_admission_1/result.json)
passes. One complete audit exits 0 in **2.072833665 s**, cgroup peak **21,762,048 bytes
(20.75390625 MiB)**, zero memory-limit/OOM/swap events. All **8,934 historical paths**
and the **566-entry inventory** are accounted for, with completed comparison/report/
outer guard. Only the exact three authorised existing documentation files changed;
new recovery implementation/tests and package evidence are explicitly inventoried.
Final lint/format and **87 executed cases** pass (59 new scoped + 28 unchanged
lifecycle cases, preserving both labelled unsafe controls). Independent durable
freshness/fencing and interrupted issuer reconciliation remain open. Stages 2–3
stay incomplete; no proof/zkVM executions; ledger two used/one unused.

## S2-RECOVERY-AUTHORITY-DESIGN-1 — concrete design; protections unimplemented

[Design report](stage2_recovery_authority_design.md),
[machine-readable decisions](data/s2_recovery_authority_design_1/design.json),
[linked SQLite facts](data/s2_recovery_authority_design_1/sqlite-environment.json).
R-018/R-022 and REC-001 require the manager's permanent allocation prefix and immutable
operation-to-rid outcome to commit together; no orphan is recycled. R-016/R-028 and
REC-002 require audience-separated complete challenge/consumption transactions and
current trusted time. R-014/R-020/R-021/R-030/R-031 and REC-003 require complete private
role checkpoints, retained histories/key associations and head availability.
REC-004 preserves log-before-release, exact committed outcome recovery and ordinary
duplicate rejection; a separate proposed authenticated redelivery API does not
re-certify or produce a second verifier acceptance.

The proposed authority head additionally covers local signing-attempt, grant and
outcome transitions absent from the existing protocol checkpoint digest. A head
ticket plus generation/expected-state/operation checks must fence every protected
commit and publication. The current RecoveredService local gate does not implement
that durable boundary; direct constructors, signers, SQL/file writes and publication
paths must not bypass future adapters. Seven-role ownership and eight failure classes
are mapped explicitly, with 16 future acceptance groups. No such experiments ran here.

Read-only Python inspection found SQLite 3.46.1, distribution 3.46.1-9ubuntu0.3, on
ext4/WSL2. Primary SQLite documentation and patch uncertainty support the selected
DELETE/EXTRA design; WAL was neither enabled nor tested. Same-role state/head/outcomes
share one transaction. Manager and issuer use two stores with durable intent and
idempotent allocation outcome reconciliation, never an assumed cross-store transaction.
An authority DB cannot detect its own older valid restoration; external rollback trust,
OS/administrator isolation and actual host flush guarantees remain open.

No existing source/tests/dependencies/parameters/manuscript/history changes. Prior
59 admission cases plus 28 lifecycle cases and corrected auditor fixture evidence are
reused with original labels. Only Sections II–VIII and agreed SPEC-001–004 remain
authoritative. Proposed next bounded implementation: S2-DURABLE-AUTHORITY-PILOT-1;
remaining durable role adapters and all deployment guarantees stay unimplemented.
No proof/zkVM execution; ledger two used/one unused; Stages 2–3 remain open.

**Final S2-RECOVERY-AUTHORITY-DESIGN-1 validation:** documentation/data checks and
final lint/format pass. [One complete preservation audit](data/s2_recovery_authority_design_1/final_checks/result.json)
exits 0 in **2.057240563 s**, cgroup peak **21,516,288 bytes (20.51953125 MiB)**,
zero memory-limit/OOM/swap events, with completed content/inventory/report/outer guard.
All **8,975 historical paths** and **607 inventory entries** are accounted for; exact
original baselines and old failures remain preserved. The initial formatting-only
E501 failure is retained alongside corrected final checks. All seven guarded invocations
share the unchanged budget and total 2.655893709 s. No production source/test/dependency
change, functional rerun, persistence/crash experiment, proof or zkVM execution.
The design is complete; durable implementation, deployment recovery and Stages 2–3
remain open. Recommended next: S2-DURABLE-AUTHORITY-PILOT-1; two proof attempts used,
one unused, CPU proving paused.


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


## S2-AUTHORITY-OWNER-BOUNDARY-1 — local authorisation and IPC evidence

[Report and permission matrix](stage2_authority_owner_boundary.md),
[policy](../src/pqdid/persistence/owner_auth.py),
[transport](../src/pqdid/persistence/owner_ipc.py),
[owner](../src/pqdid/persistence/owner_service.py),
[28 focused IPC tests](../tests/integration/test_owner_boundary.py) and
[resource/command ledger](data/s2_authority_owner_boundary_1/run-ledger.json).
The unchanged 28 lifecycle regressions pass; old 38-case durable/crash evidence is
reused. Local capabilities and request envelopes are engineering metadata, not new
manuscript constructions. Authority remains Sections II–VIII and SPEC-001–004.

| Contract | New evidence | Still open |
|---|---|---|
| REC-001 / manager allocation | Authenticated issuer-service grant; named reserve/lookup; exact retry/conflict; no unsafe unavailable-owner fallback | Full role integration, retention and hostile-client OS isolation |
| REC-002 / audience consumption | Independent service scopes/stores, concurrent IPC consumption, committed-but-lost acceptance returns unknown on retry | Full anonymous-authentication proof integration |
| REC-003/004/006 / admission and fencing | Admin-only exact-ticket admit/replace; inactive startup; commit and actual response publication fences; old connected client rejected after generation replacement | Production recovery authority provisioning, whole-store rollback REC-005 |
| REC-007 / interrupted issuance | Fixed manager IPC dependency, immutable approved recipient, logged certification before release, wrong-recipient/field substitution denial, exact lost-response redelivery | Production approval/recipient enrolment, full durable begin/finish, bounded signer |
| STORAGE-001 | Unchanged DELETE/EXTRA store and old crash matrix; two additional owner commit-before-IPC-response SIGKILL cases, bounded frames/connections/deadlines | Host/power-loss qualification, backups/GC and exclusive OS ownership |

All actual roles share UID/GID 1000. No hostile same-UID isolation, account separation,
production capability lifecycle or direct-store bypass closure is claimed. No holder
persistent key/identity is added to anonymous presentations. Full lifecycle,
BC-1/proof/security/privacy obligations and Stages 2–3 stay open; CPU proving paused,
two attempts used/one unused. Next bounded recommendation:
S2-AUTHORITY-ISOLATION-PLAN-1; no deployment or proving work starts here.


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


## S2-AUTHORITY-ISOLATION-PLAN-1 — planned OS and provisioning boundary

[Deployment plan](stage2_authority_isolation_plan.md),
[uninstalled artefacts](proposals/s2_authority_isolation_plan_1/README.md),
[actual-ID acceptance specification](proposals/s2_authority_isolation_plan_1/acceptance.json).
Authority remains manuscript Sections II–VIII and SPEC-001–004. These are engineering
choices and static checks, not new protocol/security or active isolation evidence.

| Contract / gap | Concrete proposed protection | Evidence limit / blocker |
|---|---|---|
| Raw-store bypass / STORAGE-001 | Separate owner/client UIDs, owner-only 0700/0600 store/journal paths and protected parents | No account or permission changes; actual access denial untested |
| REC-002 / verifier separation | Distinct A/B owner/writer identities, groups, stores, scopes and audience context | Actual-ID cross-access/restart cases planned; original same-UID evidence reused |
| REC-003/004/006 / recovery authority | Root-provisioned credential and numeric-peer map; scoped admin IPC retains exact head/generation fencing | Cross-UID endpoint/startup adapter and real provisioning unimplemented |
| REC-007 / recipient delivery | Private per-client tokens, immutable approved recipient association, stopped-owner credential rotation | Production approval/recipient enrolment open; actual wrong-recipient/rotation cases planned |
| Executable/configuration bypass | Root-protected fresh runtime at final path, pinned source/native identities, clean imports and FD discipline | Actual-identity import/linkage and inherited-FD tests not executed |

No source/dependency/parameter/manuscript/history changes. No functional rerun,
proof or zkVM execution; old 28 IPC + 28 lifecycle and 38 durable cases/18 crash
injections retain their original scope. Deployment protection stays **unimplemented**.
REC-005 whole-store rollback, WSL power-loss, full lifecycle, bounded signing,
proof feasibility and privacy/security review remain open. Next bounded package:
S2-AUTHORITY-ISOLATION-PILOT-1, with separate approval of specified privileged actions.
Stages 2–3 open; CPU proving paused; ledger two attempts used/one unused.


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


## S2-AUTHORITY-ISOLATION-PILOT-1 — approved activation preflight

| User precondition | Evidence and result |
| --- | --- |
| Sealed actual implementation and seven templates | [Comparisons](data/s2_authority_isolation_pilot_1/activation-preflight/inspection.json): 96 sources/eight fixtures, exact inventories; preceding package 126/126 before documentation append. Original seal unchanged. |
| Required host facilities and fresh resources | [Host metadata](data/s2_authority_isolation_pilot_1/activation-preflight/host-observations.json): names/paths collision-free, executables/controllers present; `/etc/sysusers.d` absent. Live manager-query confirmation incomplete. |
| Existing commands and budgets executable | Blocked: default 65,536-byte reader rejects the 155,989-byte historical ledger before provisioning. Read-only reproduction, not a pilot launch. |
| Whole-workload resource/stop scope | Common-slice limits configured; provisioning separately guarded outside it. Installed binary supports recursive slice kill, but slice-only emergency stop misses provisioning. Ignored kill/stop/show errors and no descendant-quiescence confirmation remain open. |
| Exact rollback and retention | Fixed seven configuration paths/digests checked before deletion; marker owner/mode checked separately; accounts/data/runtime retained. Shutdown defect and early partial-install entry-point gap remain. No rollback executed. |
| Twenty-two actual-ID cases | [Current outcome record](data/s2_authority_isolation_pilot_1/activation-preflight/result.json): all not-run-preflight-blocked, actual IDs null, zero new host resources. |

Conditional approval received; discrepancy stop exercised before privileged mutation.
The diagnostic's resource guard passed (21,561,344 bytes, 0.133094973 s), while the
activation gate failed. New-script lint/format pass. No suites/audit repeated, no
proofs or zkVM executions, ledger two used/one unused. Stages 2–3 remain open.
Full lifecycle integration follows only successful isolation; production signing
and complete private-proof feasibility remain unresolved. See the
[implementation report](stage2_authority_isolation_pilot.md) for required corrections.

## S2-AUTHORITY-ISOLATION-PILOT-1 — version-2 correction mapping

| Reported blocker | Corrected implementation | Focused evidence |
| --- | --- | --- |
| 155,989-byte ledger rejected by 65,536-byte reader | `scripts/isolation_pilot_v2/ledger.py`: purpose-specific 1 MiB, structural/count bounds, full historical accounting, future capacity; ordinary reader unchanged | Legitimate, oversize, malformed/truncated/duplicate, invalid time/status, incomplete and remaining-results tests |
| Missing `/etc/sysusers.d` | `shared_parent.py` and versioned provisioner: absent-only root:root 0755 creation, existing-path validation, recorded intent/result, shared-parent retention | Absent/existing/unsafe parent and partial rollback fixtures |
| Incomplete stop/shutdown/rollback | `termination.py`, `emergency_stop.py`, corrected guard/controller: fixed unit/cgroup scope, launch inhibitor/gate, strict installed-interface parsing, descendant occupancy, source-tree fallback, explicit rollback refusal | Query/transport errors, malformed properties, descendants, partial provision, inhibition, failed worker/report and uncertain rollback models |

[Corrected report](stage2_authority_isolation_pilot.md#targeted-correction-pass--version-2-no-activation)
and [approval delta/runbook](proposals/s2_authority_isolation_pilot_1/v2/README.md).
All 24 additional focused invocations pass; historical 76 retained, 100 executed,
22 actual-ID cases unchanged/pending, cumulative ceiling 124. Static parsing passes;
final quality/preservation closure follows in the report. Model tests establish
code behaviour, not actual OS isolation. No activation, proofs or zkVM executions;
two proof attempts used/one unused. Stages 2–3 and production signing/private-proof
feasibility remain open.

**Version-2 closure:** [guarded result](data/s2_authority_isolation_pilot_1/correction-v2/result.json)
requires completed content, inventory, report readback and outer guard; all passed.
9,391 disjoint content paths, 9,403 identity-inclusive historical paths and 1,084
inventory entries preserved. Final source/control seal
`994327b3b0d32d22b6ce9aa09a5125ec798d509ebbdcfa79819bf2225f1a6c32`
links to the original seal and tested candidate with 13 explained input deltas.
24 additional focused invocations passed; allowance consumed, 100 cumulative
executed, 22 original identity cases pending. Remaining aggregate time is
255.224598893 s including the 10 s emergency reserve. No host activation or
proof/zkVM execution; delta approval and actual OS evidence remain pending.
Stages 2–3, production signing and complete private-proof feasibility remain open.


## S2-AUTHORITY-ISOLATION-PILOT-1 — approved version-2 live admission evidence

The [live seal and host record](data/s2_authority_isolation_pilot_1/activation-v2-session/seal-preflight.json)
maps the user's exact manifest approval to 100 runtime, eight control and eight
fixture digest/inventory checks. Host NSS/path, parent, interpreter, systemd and
cgroup facility observations passed; they do not establish actual isolation or
post-launch effective enforcement. [Session accounting](data/s2_authority_isolation_pilot_1/activation-v2-session/session.json)
retains the failed namespace observation and sudo-authentication refusal separately
from test outcomes. All 22 identity cases remain pending; no new test invocation,
proof or zkVM execution was started by the assistant. A supplemental five-second
charge leaves 250.22 s including the ten-second emergency reserve. Frozen control
inputs are unchanged; approval and later outcomes belong to separate evidence.
See the [report](stage2_authority_isolation_pilot.md#version-2-approval-and-live-preflight--authentication-pending)
for the pending operator provision step. The next user-designated package is
S2-CONCRETE-SECURITY-ASSESSMENT-1 before further lifecycle integration. Stages 2–3,
bounded production signing and complete private-proof feasibility remain open;
proof ledger two attempts used/one unused and CPU proving paused.


## S2-CONCRETE-SECURITY-ASSESSMENT-1 — security checkpoints, 24 September 2026

The [task schedule](../PQ_DID_Security_Assessment_Codex_Task.md) and
[initial report](stage2_concrete_security_assessment.md) distinguish assessment
completion from a justified security claim. Source inventory
`b2d0b57afe4b10c1ee6f41fc32ac031da96e332f79a98c6040aaebe1fd07c3a3`;
only manuscript II–VIII plus SPEC-001–004. Active configuration and production
source unchanged. Separate analysis budget; no estimator, proof, zkVM or deployment
execution. Proving remains paused, two attempts used and one unused.

| Obligation | Implementation/specification mapping | New evidence/disposition |
| --- | --- | --- |
| Actual profile and component assumptions | R-009/010/032/033, active suite, bounded_mldsa, binding, merkle, canonical credential | [Analysis-only profile](../analysis/concrete_security/security_profile.json); standard ML-DSA-65, no prototype dimensions/profile change |
| Complete witness and proof reductions | R-034–042 and R-049–051, manuscript VII–VIII, relations.auth_private | [Calculator](../analysis/concrete_security/security_bounds.py), [raw bounds](data/s2_concrete_security_assessment_1/bounds.json); local evaluator is not a proof; SEC-002/003 remain open |
| Independent validation and preservation | Original baseline and ordered historical seals; unchanged audit engine | [Run ledger](data/s2_concrete_security_assessment_1/run-ledger.json), final audit result referenced by report; completion requires outer guard |
| Alternative proof backend | Existing R0 enrolment image/receipt and full verification path | Exact Succinct/Poseidon2 recursion reviewed; no Groth16 present, no BC-1 theorem transfer; SEC-004 open |
| Operational prerequisite | Version-2 fixed-unit/cgroup query, no active workloads/resources | [Host closure](data/s2_concrete_security_assessment_1/host-closure.json); unactivated, 22 cases pending, budget unspent by this assessment |

| Trigger | Required security checkpoint |
| --- | --- |
| Current Stages 2–3 | Initial actual-profile/source/calculation assessment; completed with explicit unresolved terms, not an overall security claim |
| Stage 2 bounded key generation/signing/release | Randomness, caps, exhaustion, pre-release verification, lifetime invocation totals and `Delta_tail`; retain DEP-001/DEP-002 |
| Stage 3 before adopting/freezing any proof profile | Exact circuit/program, mode and recursion/compression; soundness/knowledge/ZK and quantum assumptions; refresh affected bounds |
| Stages 4–5 complete PQ-DAA/KYC integration | Same certified witness/holder/disclosures/rid, journal leakage, currentness/replay/revocation, side channels and deployment |
| Stages 6–8 baselines/comparisons/benchmarks | Exact comparator profiles, multi-key/target effects and lifetime nonce/cap counts; refresh parameter/dependency/proof-mode changes |
| Stage 9 reproduction/manuscript claims | Final revision/workload/current primary evidence against II–VIII; omit unsupported overall numbers |

Next: proposed S3-OUTER-HASH-SECURITY-REVIEW-1, no execution/profile/deployment
approval inferred. SEC-001–005 track unresolved targets/workloads, outer hash,
composition/sampling, alternative backend and full lifecycle integration. Keep
Stages 2–3 open and do not replace lifetime security workloads with benchmark counts.


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

| Requirement/claim | New source mapping | Disposition |
| --- | --- | --- |
| R-010, R-037–043; VII-A.7–A.8 | SHAKE256-1024 view/challenge framing, r1088/c512, padding/output adapter; [query mapping](data/s3_outer_hash_security_review_1/query-mapping.json) | Exact parameters unchanged; canonical length envelope is not a bound on unrestricted adversarial oracle queries |
| R-049–051; VIII-A/C/D, Theorems 6–9 | ACMT 7.22, DFMS 4.2, GHM 1; shared-permutation/extractor/simulator interfaces | Conditional ideal results retained; four SEC-002 sub-obligations remain open |
| VIII-E Theorems 10–11; lifecycle composition | Whole adaptive state/history/target and actual component reduction budgets | No new concrete knowledge/privacy bound, production signer or isolation claim |
| Preservation and future checkpoint | [Explicit scope](data/s3_outer_hash_security_review_1/scope.json), unchanged corrected auditor, new additive seal | Original baselines/historical failures preserved; S3-OUTER-ORACLE-COMPOSITION-1 before profile adoption |


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

| Claim / requirement | Composition finding | Required next evidence |
| --- | --- | --- |
| R-010, R-037–043; VII-A.7–A.8 | G-K/G-M fixed circuitry differs from G-P/G-S private oracle gates; outer tags separate two ideal domains, not underlying primitives | OC-REL; no hidden-output advice, compiler or profile change |
| R-049–051; VI-B4/VIII-C Theorem 6 | J-EX preserves the target/history by terminal event restriction in the fixed-relation ideal model | OC-EXT for legal shared-oracle emulation and its enlarged runtime/query budget |
| VI-C/VI-D2; VIII-D Theorems 7–9 | J-PRIV retains complete view, all corruption/disclosure/session restrictions and post-cutoff state | OC-PRIV; distinguish S_perm and Sim_proof, including internal shared-hash calls |
| VIII-E Theorems 10–11 | Ordinary J-BIT comparison alone is not a knowledge/privacy transfer | A-K-MODEL, OC-BUDGET and component advantages/Delta_tail remain explicit |
| DEP-001/002; VII-A.6/VIII-A | Reference fixed-algorithm work can continue independently of outer proof completion | S2-BOUNDED-MLDSA-KEYGEN-SIGN-1, bounded core plus tail/coupling obligations, without production activation |
| Preservation | Original baseline plus ordered historical seals, prior review seal and exact append-only prefixes | [Scope](data/s3_outer_oracle_composition_1/scope.json), one 256 MiB guarded complete audit |


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

## S2-BOUNDED-MLDSA-KEYGEN-SIGN-1 — reference implementation evidence

Only manuscript II–VIII and agreed clarifications apply. See
[the report](stage2_bounded_mldsa_keygen_sign.md),
[new source](../src/pqdid/bounded_mldsa_sign.py),
[focused tests](../tests/unit/test_bounded_mldsa_sign.py) and
[native checks](../tests/integration/test_bounded_mldsa_sign_native.py).

| Requirement/issue | New evidence | Remaining boundary/checkpoint |
| --- | --- | --- |
| R-009; DEP-002 | FIPS ML-DSA-65 keygen, exact 1952/4032/3309-byte encodings; pure 00/context/message processing; nine fixed role contexts and OS-random hedged wrappers; two keypairs/six signatures exactly match pinned native | Not a NIST validation; no live role integration, authority decision, secure key storage or production RBG assurance |
| R-032/R-033 | Existing integer arithmetic/verifier reused; new RejBoundedPoly with 512-byte budget; unchanged 1026/256 samplers; 1024 candidates, nonce 0..5119; immediate exhaustion abort, exact-limit success, pre-return bounded verification and no fallback | Full FIPS/BC-1 operation-trace equivalence and all-role durable release integration remain open |
| R-033; DEP-002 | Expanded key import checks eta ranges, recomputed t0/tr and optional expected pk; no partial key/signature output; production adapters unchanged | Key provenance, freshness, ownership, trust and activation are separate; K cannot be validated from algebra alone |
| R-043 | Fresh one-draw wrappers, explicit synthetic reproducibility APIs, entropy failures propagated; no public injection; best-effort mutable-work clearing | Python erasure/constant-time/fault protection not established; production signing remains unresolved |
| DEP-001; SEC-003 | Frozen caps implemented and failure paths tested; invocation accounting distinguishes import, signing and final verify | No empirical tail estimate or Delta_tail=0; conditional signing model, adaptive workload loss and reduction-budget component terms stay open |
| SEC-002/004; OC-REL/EXT/PRIV/BUDGET | Prior construction/profile and composition findings preserved | Complete private-proof knowledge/privacy and concrete-oracle transfer remain open |
| Preservation/resources | 49 focused + 9 final interoperability + 12 scoped regression tests; nine preliminary ABI harness repeats retained: 79/100 invocations | Single complete audit under unchanged 256 MiB required; separate implementation allowance does not consume analysis/isolation budgets |

One next recommendation: **S2-BOUNDED-SIGNER-RELEASE-CONTRACT-1**, temporary synthetic
adapter contract checks only; preserve fail-closed production defaults and actual-ID
isolation prerequisites. Stages 2–3 remain open. Isolation safely stopped/unactivated,
100 historical invocations and 22 cases pending; proof ledger two used/one unused.


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

## S2-BOUNDED-SIGNER-RELEASE-CONTRACT-1 — adapter and release evidence

Only manuscript II–VIII and agreed clarifications apply. See
[the report](stage2_bounded_signer_release_contract.md),
[new adapters](../src/pqdid/signing_adapters.py),
[focused checks](../tests/unit/test_signing_adapters.py) and
[operation map](data/s2_bounded_signer_release_contract_1/contract.json).

| Requirement/issue | Added evidence | Remaining boundary |
| --- | --- | --- |
| R-009; DEP-002 role/context selection | Nine typed operations pin trusted instance, role, key reference and public identity; canonical whole-message bridge checks; no raw public endpoint or caller override | Owner policy/custody is trusted; default denies; no actual-identity or live deployment claim |
| R-033; DEP-002 no partial release | Completed bounded core/caps/pre-return verification reused; entropy, sampler, attempts, final verification and authority-withdrawal failures release no credential | Reference tests do not establish reliable erasure, constant time, entropy provenance or adaptive tails |
| Issuance reservation/certification; existing recovery contracts | Permanent allocation and nonce survive failure; log precedes return; single-use durable claim and exact committed outcome/recipient checked | SQLite application-fault/reopen evidence is not crash/power-loss durability; no automatic retry of uncertain signing |
| Atomic revocation and verifier request | Both bounded signatures before atomic state/history/nonce publication; final conflict publishes neither; failed request retains reserved nonce | Durable manager publication remains the next implementation gap |
| DID rotation/deactivation | Trusted predecessor/current-controller checks; stale/deactivated key denied; old controller signs rotation | Existing final lifecycle checks retained; trusted snapshot linearisation, not latest-at-delivery or live authority assurance |
| Existing durable owner/admission | Store policy plus exact generation/head before/after signing; replacement fences old writer; wrong recipient/interrupted enqueue deliver no bytes; redelivery signs zero times | All-role durable composition and actual-ID isolation remain open |
| DEP-001; SEC-001–005; OC-REL/EXT/PRIV/BUDGET | Prior security findings preserved; no new tail or bit-security number | Adaptive Delta_tail, component reduction budgets, concrete proof knowledge/privacy unresolved |
| Preservation/resources | 18 passing focused invocations; cumulative 97/100 including prior 79; old source/primitive/native evidence reused | Single full unchanged-256-MiB audit and measured closure required; separate analysis/isolation budgets untouched |

The next bounded recommendation is **S2-BOUNDED-MANAGER-DURABLE-RELEASE-1** with
synthetic stores and existing caps, subject to the actual remaining test allowance.
Stages 2–3 remain open; isolation safely stopped/unactivated with 22 pending cases;
proof ledger two used/one unused. No activation, installations, proofs or zkVM.


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

## S2-BOUNDED-MANAGER-DURABLE-RELEASE-1 — one-store commit and public retrieval

Only manuscript II–VIII and agreed clarifications apply. See
[report and 24-row matrix](stage2_bounded_manager_durable_release.md),
[new facade](../src/pqdid/bounded_manager.py),
[integration cases](../tests/integration/test_bounded_manager.py),
[crash worker](../tests/integration/bounded_manager_worker.py) and
[machine contract](data/s2_bounded_manager_durable_release_1/contract.json).

| Requirement/issue | Added evidence | Remaining boundary |
| --- | --- | --- |
| R-030 atomic revocation | Existing single SQLite transaction binds checkpoint, signed state/update history, revoked/nonces, operation outcome, head and tip; allocation/base/entries preserved | No transaction across issuer/manager stores; complete lifecycle integration remains open |
| R-009/R-033; DEP-002 | Trusted manager key/role/service/instance, existing bounded adapter/core, exact constructors/contexts, pre/post-sign authority and expected-head checks | Existing primitive/native tests reused; custody/entropy/erasure/side channels unresolved |
| Release ordering | Private candidates, repeated head/generation/state checks under commit lock, redacted ack, public bytes only from committed outcome/history | Owner-local reference facade; no live endpoint or isolation claim |
| Fencing/current freshness | Stale head, during-sign replacement, concurrent allocation/replacement and old publication denied; superseded stored current withheld | Ordering linearises at locked read/enqueue; no latest-at-delivery promise or automatic head refresh |
| Recovery admission | Missing/incomplete checkpoint/history/nonces denied; external expected ticket mandatory; exact committed redelivery signs zero times | Test coordinator retains after-commit head; lost independent freshness evidence needs authority reconciliation; whole-store rollback protection remains open |
| Process-crash evidence | Actual SIGKILL before COMMIT recovers old state; actual SIGKILL after COMMIT recovers all state/outcome and exact response | Application barriers only; not power loss, storage failure, malicious owner or arbitrary SQLite-internal interruption |
| Public/private retrieval distinction | Public namespace/epoch pages and manager outcomes have no holder recipient field; old private credential delivery unchanged | Actual deployed transport/authentication and all-role composition remain open |
| Resource/preservation amendment | 24 individually reported new cases, 121/124 cumulative; original 300-second allowance continued; unchanged 256 MiB audit | Single complete audit plus measured outer closure required; analysis/isolation not borrowed |

Next implementation recommendation: **S2-DURABLE-ISSUER-MANAGER-INTEGRATION-1**,
synthetic explicit journal/reconciliation tests within the remaining allowance or an
approved amendment. Production signing, adaptive Delta_tail, component reduction
budgets and complete proof knowledge/privacy remain open. Stages 2–3 remain open;
isolation safely stopped/unactivated, proof ledger two used/one unused.


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

## S2-DURABLE-ISSUER-MANAGER-INTEGRATION-1 — separate-store lifecycle evidence

Only manuscript II–VIII and agreed clarifications apply. See
[transition/fault matrices](stage2_durable_issuer_manager_integration.md),
[new orchestration/port](../src/pqdid/durable_issuance.py),
[24 integration cases](../tests/integration/test_durable_issuance.py) and
[machine contract](data/s2_durable_issuer_manager_integration_1/contract.json).

| Requirement/issue | Added evidence | Remaining boundary |
| --- | --- | --- |
| R-018 allocation; existing interrupted-issuance design | Intent precedes manager reservation; exact issuer/issue/reference mapping, permanent rid, explicit phase reconciliation; no repeated allocation on recovery | Separate commits, no cross-store transaction or compensation; missing authority evidence fails closed |
| R-019–020 enrolment | Canonical approval/DID checks, same original challenge/binding/rid/nonce/state, existing controller signature and required proof-verifier call | Positive tests use only an explicit test verifier for exact locally evaluated synthetic statements; real proof verification incomplete |
| R-019 final ordered read | Port obtains admitted current manager witness; reserved or other-rid revocation before read rejects; post-read update preserves original issuance ordering | Original checkpoint acceptance is not current non-revocation or authentication; no latest-at-commit distributed guarantee |
| R-021; DEP-002 release | Bounded signing, single-use claim, certification commit before recipient enqueue; exact redelivery has zero new signing/allocation; holder intent/signature/witness checks before atomic pointer update | Trusted owner policy/local transport; production custody, durable wallet and actual-ID isolation remain open |
| Existing recovery/fencing | Stale issuer/manager, conflicting operation or reservation and missing cross-service evidence reject; complete PENDING resumes unchanged, SIGNING retires, CERTIFIED redelivers | Independently retained expected head per service is required; no self-consistency-only activation |
| Persistence boundaries | Actual SIGKILL after manager reservation retains permanent orphan for retirement; after issuer certification retains exact response/heads for redelivery/holder acceptance | Test coordinator captures both heads; application-process evidence only, not power-loss or rollback protection |
| R-009/R-033 | Existing contexts, canonical constructors, bounded adapters/caps and verification-before-return reused | No primitive/native retest or changed signing format; adaptive Delta_tail/security terms unresolved |
| Resource/preservation amendment | 24 individually counted cases, cumulative 145/148, three remaining; original time ledger continued | Same 256 MiB full audit and complete report/guard closure required; separate analysis/isolation budgets untouched |

Next recommendation **S2-DURABLE-VERIFIER-LIFECYCLE-INTEGRATION-1**, without activation
or proof generation and within a concrete permitted test allowance. Stages 2–3,
production security, SEC-001–005 and complete proof knowledge/privacy remain open.
Isolation safely stopped/unactivated; proof ledger two used/one unused.


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

| Obligation | New evidence and remaining boundary |
| --- | --- |
| R-016 | Durable registration before bounded canonical request signing; two audiences/keys/stores; signing failure retains nonce; holder-side request approval integration remains open |
| R-017 | Nonce-bound committed manager read/retrieval, independent current/state signatures, stale reply and before/after-read update tests; trusted service ordering remains an assumption |
| R-027 | Existing canonical disclosures/public policy and exact X construction reused; default unsupported backend refuses; synthetic verdicts establish no private relation |
| R-028 / SPEC-002 | Strict initial/final expiry, full-record recheck, durable consume/checkpoint/outcome/head before acceptance; concurrent exact replay CONSUMED and restart UNKNOWN |
| Recovery/publication | Expected independent head and fencing, inconsistent audience denial, pre/post-COMMIT exception evidence; verifier acceptance redelivery remains forbidden |

[Report](stage2_durable_verifier_lifecycle_integration.md) lists 24 distinct passing
cases. All 27 invocations (three preserved assertion failures/repeats) are charged:
**172/172**, none remaining. Existing actual verifier crash evidence is reused, not
rerun. No production/proof-profile change, host activation or new proof/zkVM result.
Stages 2–3 remain open; proof ledger two used/one unused, isolation safely stopped.
Next: S2-HOLDER-WITNESS-REVOCATION-INTEGRATION-1 to connect issuance, public updates,
local witness maintenance and KYC presentations; test-budget amendment required.


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

| Obligation | New connection and evidence |
| --- | --- |
| R-018–R-023 | Existing certified issuance/recipient delivery supplies HolderAcceptance's initial credential/checkpoint; holder hand-off revalidates binding/rid/path/state |
| R-024/R-025 | Same issued credential and certified rid feed complete local auth before/after unrelated revocation; wrong combinations and own-revoked-root relation reject; B is not a remote proof |
| R-016/R-017/R-027/R-028 | Holder verifies approved request context/signature/state and projects canonical disclosures; two independent durable verifiers accept only via test seam C; stale old-valid inputs reject on final freshness read |
| R-029–R-031 / SPEC-001 | Bounded real signatures and Merkle processing A; public namespace/epoch retrieval, 16/178592 limits, explicit pages, whole-snapshot update and no replacement on REVOKED/error |

[Report and individual outcomes](stage2_holder_witness_revocation_integration.md):
22 first-run passes, including one counted complete reference scenario; **194/199**
invocations, five left. No new proof/native/crash suite runs. Durable holder custody,
production services, interoperability, Delta_tail and proof knowledge/privacy remain
open. Stages 2–3 incomplete; safely stopped isolation and two-used/one-unused proof
ledger preserved. Next: bounded KYC interoperability contract, not started.


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

| Existing source/obligation | Contract deliverable | Evidence boundary |
| --- | --- | --- |
| III-A, IV-B, VII-A.5; R-052/E-003 | Issuance intent, Xen, private credential/checkpoint and recipient release mapping | Existing bounded durable issuance evidence reused; no new signing format |
| V-A/B, VII-A.6–.7; E-001/002 | Two audience request/X/disclosure/result boundaries | Four individual example checks only; null proofs remain non-verifying |
| VII-A.4 | Minimal DID JSON and separate chain/version/registry evidence | Exact project mapping; DID method/key/conformance work remains open |
| VII-A.8; SPEC-001 | Authenticated state/current and public namespace/epoch history/page mapping | No holder-specific witness lookup, signature changes or new update execution |
| SPEC-002 | Decimal-string transport to uint64 POSIX seconds, strict equality rejection | Session expiry distinct from schema credential validity |
| VI, VIII-E common leakage restrictions | No private witness/credential/stable holder identity in example presentations | No proof privacy/unlinkability or hidden-DID resolver claim |
| DID Core1.0; VC Data Model2.0 | Dated primary requirements and proposed issuer/subject/status/securing mapping | KYC-INT-001–004 unresolved; no W3C conformance certification |

See [report and next-adapter acceptance checklist](stage2_kyc_interoperability_contract.md)
and [machine contract](data/s2_kyc_interoperability_contract_1/contract.json).
Existing functional, resource, isolation and proof evidence remains unchanged.
Stages2–3 open; proof ledger2used/1unused. Final validation closure follows.


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

| Contract/source | Implemented boundary | Evidence and limit |
| --- | --- | --- |
| E-003; KYC interoperability parser proposal | Exact version/route/fields, strict JSON, canonical base64url and decimal protocol integers | 19 distinct rejection cases; pre-parser size/depth/collection sentinel tests; no W3C conformance claim |
| VII-A.5 issuance and private credential | Existing typed request/challenge/delivery/holder candidates with pp, attributes and rid agreement | Exact private credential/witness/Mcred and issuer input checks; service authorisation/release unchanged |
| VII-A.6–.7 public authentication | Exact independent context/X/disclosed-claim binding; no private fields in verifier bodies | Request conversion and canonical public preview; normal proof containers unsupported |
| VII-A.8 / SPEC-001 | Existing state/current/history records; public namespace/epoch queries and fixed update encoding | Empty page conversion bound to local query/start; non-empty new parser path not independently exercised |
| SPEC-002 | Lossless uint64 seconds, exact redundant expiry equality; no clock conversion | Overflow/Boolean/float/conflicting-expiry rejection; existing strict expiry lifecycle evidence reused |
| KYC-INT-001–004 | No inferred issuer URL/vocabulary, securing mechanism, DID key/method or private status semantics | Open; ordinary DID and client acceptance admission explicitly unsupported |

[Implementation report](stage2_kyc_container_adapter.md),
[adapter](../src/pqdid/containers.py), [tests](../tests/unit/test_containers.py)
and [selected profile record](data/s2_kyc_container_adapter_1/contract.json).
24/24 cases pass,222/223 cumulative invocations; one remains. Final guard/audit balances
follow. No prior source or evidence replaced. Next:S3-AUTH-PROOF-FEASIBILITY-PLAN-1,
not started; Stages2–3 open and proof ledger2used/1unused preserved.


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


## S3-AUTH-PROOF-FEASIBILITY-PLAN-1 — source/evidence coverage

[Plan and finite next proposal](stage3_auth_proof_feasibility_plan.md);
[evidence contract](data/s3_auth_proof_feasibility_plan_1/contract.json).

| Requirement / authority | Disposition | Remaining gate |
| --- | --- | --- |
| V-B, VII-A.6; R-024/R-025 | Exact E(X), 5,329-byte witness, private issuer signature/holder opening/projection/same-rid path mapped to native, BC-1 and R0 coverage | Complete proof circuit/program and shared-witness extraction absent |
| V-B, VII-A.6/.7; R-027/R-028 | PubOK/StateAuth/Ppub remain required public checks; signed currentness, strict expiry and durable one-time consume remain wrapper work | Existing lifecycle/reference evidence cannot substitute for a cryptographic proof |
| VII encoding/cost; VIII-A | Measured fragments, capped prefixes and conditional byte/CPU projections labelled separately; 9.893h model already includes uncertainty | Complete authentication cost unmeasured; unchanged R0 proof not admitted |
| VIII-C/D; R-043–R-051 | Ideal-QROM calculation/composition findings reused, no security-number inference | OC-REL/EXT/PRIV/BUDGET, A-K-MODEL, adaptive Delta_tail, component reduction budgets and actual proof knowledge/privacy remain open |
| Construction decision | Three routes evaluated; none supported for full KYC/security adoption. Separately revised Boolean lowering plus proof representation is research only | Proposed S3-PRIVATE-HINT-LOWERING-PILOT-1 needs authorisation; no active suite/compiler change |
| R-052/E-003 and production integration | Existing KYC container and durable service evidence preserved | W3C mapping, durable holder storage, production security and pending actual-identity isolation remain open |

No functional/calculation campaign, proof, circuit generation or guest execution
ran. Implementation/isolation allowances unchanged; analysis charged independently.
Stages 2–3 open, proof ledger two used/one unused, isolation stopped/unactivated.


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


## S3-PRIVATE-HINT-LOWERING-PILOT-1 — experimental decoder coverage

[Construction and measured result](stage3_private_hint_lowering_pilot.md);
[nine-invocation record](data/s3_private_hint_lowering_pilot_1/pilot-result.json).

| Requirement / authority | Experimental evidence | Remaining boundary |
| --- | --- | --- |
| VII-A.6/FIPS decoding; R-032–033 | Exact61 hidden bytes, six256-cell rows, monotone endpoint bounds, active adjacency/order and unused padding; three valid outputs and five rejection cases agree with native reference | No full signature/auth relation or universal formal equivalence proof |
| R-034–036 / SPEC-003–004 | Candidate uses bounded byte/bit representations and shared fixed-position decoding; existing emitter public-only folding and sticky Scope retained | Deliberate proposed compiler/profile change, not BC-1 conformance; production compiler unchanged |
| R-024/R-025 same witness | Original42,632 private positions/hint slice reused, no extra decoded witness; signed64 output zero-extension has zero gate cost | Complete private signature/Merkle/authentication integration absent |
| VII/VIII cost accounting | Complete383,420 gates/203,142 ANDs; all output mask/final validity included; single construction, no comparison gates | Historical32M-gate/13,532,448-AND baseline is a capped prefix, no matched full-decoder or full-auth reduction claim |
| Resource amendment |222prior +1generation +8cases =231/231; package≤30charged implementation seconds;256MiB audit unchanged | No tests remain; next work needs a separately scoped allowance, no automatic continuation |

AUTH-FEAS-001 remains open. The candidate is suitable only for further separately
reviewed component integration. Bounded polynomial arithmetic/NTT and private path
work remain unmeasured as a full circuit; proof representation and knowledge/privacy,
adaptive Delta_tail and production-security obligations remain open. Analysis and
isolation budgets retained; Stages2–3open, proof ledger2used1unused.


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

## S3-MLDSA-ARITHMETIC-LOWERING-REVIEW-1 — arithmetic refinement proposal

[Review and inactive pilot](stage3_mldsa_arithmetic_lowering_review.md);
[reviewed source identities](data/s3_mldsa_arithmetic_lowering_review_1/reviewed-inputs.json).

| Requirement / authority | Source-review result | Open validation |
| --- | --- | --- |
| R-032/033, VII-A.5, FIPS verification | Maps ordinary-residue NTT/inverse, public matrix factors, ordered accumulations, strict original-z norm and exact UseHint/decomposition; caps/order preserved | No complete verifier circuit generated |
| R-034–036, SPEC-003/004 | Canonical guard proves product<2^46; proposed23/46/25-bit restoring kernel is a domain-restricted refinement | Deliberate new compiler/profile; generic signed64 acceptance unchanged; no canonical BC-1 identity claim |
| R-023–025, V-B | Original Mcred/context/holder binding, certified attributes and same-rid path unchanged; PubOK/Ppub retained | Kernel equivalence must compose into the complete hidden-signature relation |
| VIII-A capacity/security | Post-SPEC-004 scalar counts reused with exact public/private distinctions; no full-transform extrapolation | Full counts, adaptive Delta_tail, component reduction budgets and OC-REL/EXT/PRIV/BUDGET unresolved |
| Accounting / proposed pilot | Analysis only; implementation94.376512284s and231/231 tests untouched; proposed2 generation+12 differential+2 constructor cases explicit | No execution amendment active;16 extra invocations/≤30s need separate authorisation |

ARITH-LOWER-001, HINT-LOWER-001 and AUTH-FEAS-001 remain open. No change to
manuscript, production code, dependencies or active profile. Stages 2–3 open;
isolation safely stopped/unactivated; proof ledger two used/one unused.


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

## S3-MLDSA-MODMUL-LOWERING-PILOT-1 — guarded scalar implementation

[Contract, case matrix and results](stage3_mldsa_modmul_lowering_pilot.md).

| Requirement | Implementation/evidence scope | Remaining obligation |
| --- | --- | --- |
| R-032 modular arithmetic | Public factor with canonical private23 residue, exact46-bit product and46 fixed restoring steps; signed64 masked output | Entry normalisation and full NTT/inverse/ordered matrix composition |
| R-034–036, SPEC-003/004 | Reference core unchanged; candidate deliberately narrows widths in isolated experiment | Proposed profile change, no BC-1 identity/equivalence claim for arbitrary signed inputs |
| Active rejection/private input | High-bit/range guard, sticky Scope, same64-bit masks; no private host branch or factor override | Finite case coverage is not universal equivalence |
| Fair cost | Two paired constant-specific traces, separate complete core segments and one harness AND; all guards/masks included | No full verifier/proof/R0 projection or trusted-input count |
| Budget/preservation |231 historical+16 authorised=247 ceiling,≤30 implementation seconds,256MiB audit | No further invocations or automatic retry/integration |

Holder binding, exact Mcred/context, certified attributes and same-rid path remain
unchanged. ARITH-LOWER-001/HINT-LOWER-001/AUTH-FEAS-001 and complete proof/security
obligations remain open. Stages2–3open; isolation stopped/unactivated; proof2used1unused.

Individual outcomes: both paired generations, six valid arithmetic cases, two
active-invalid cases, inactive/sticky control cases and four invalid-public-factor
cases pass (16 total). Both factors have complete guarded counts83,032/34,550
baseline versus15,158/6,161 candidate (total/AND). Exact words, flags, gate segments
and paired fingerprints are retained in the machine-readable run record. This
satisfies only the bounded scalar comparison obligation.


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


## S3-MLDSA-FULL-FORWARD-NTT-PLAN-1 traceability (26 September 2026)

| Obligation | Source / proposed implementation boundary | Evidence and status |
| --- | --- | --- |
| Full forward schedule | FIPS204 Algorithm41; bounded_mldsa._ntt | [Eight-stage formula/table](stage3_mldsa_full_forward_ntt_plan.md); all1,024 nodes mapped by source, no generated schedule |
| Complete signed64 entry | _ntt initial modulo; SPEC-004 mod64 |256 conversions/masks included; MIN/MAX preserved; raw fragment overflow domain not misapplied |
| Canonical producer reuse | Isolated stage kernel and range induction |97-partition state/alias contract; gates remain experimental, not canonical BC-1 |
| Full-transform comparison | Pinned uninterrupted reference plus independent odd-root Horner oracle |Six proposed full cases, two entry refusals, two checkpoint refusals; none executed |
| Complete connected count | Private aliases, unique coverage, actual per-partition XOR/AND/NOT |97 proposed generation probes; nominal gate totals are estimates; no measured full reference saving |
| Resource admission | Current279/279 invocations and61.264731091912836 s |Not admitted; inactive107-invocation/+74 s/30M aggregate-gate proposal |
| Security/profile | ARITH-LOWER-001; OC-REL/EXT/PRIV/BUDGET; Delta_tail |No conformance, proof knowledge/privacy or security conclusion; Stages2–3 open |

Analysis-only accounting and preservation closure are appended below. Historical
scalar, butterfly, fragment and hint counts/fingerprints remain protected. No
proof/zkVM/activation; proof ledger two used/one unused; isolation unchanged.


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


## S3-MLDSA-FULL-FORWARD-NTT-PILOT-1 measured traceability

| Obligation | Evidence | Result and remaining boundary |
| --- | --- | --- |
| Complete forward schedule |97 partition records and pilot-summary.json |All8 stages/1,024 unique butterflies,256 entry lanes,255 twiddle assignments, one final boundary |
| Whole signed64 entry and rejection |V0..V5, M0/M1, T0/T1 records |All ten cases pass; six full paths each compare97 partitions; 582+582 evaluation/observer calls |
| Independent complete output oracle |Pinned _ntt and separate odd-root Horner module |All256 final canonical values/bytes agree with the stated active/rejected wrapper |
| Private composition accounting |Alias descriptors, frontier hashes, global offsets |27,044,356 total/10,679,298 AND gates; host partitioned evaluation, no monolithic circuit/proof |
| Provisional KYC target |Frozen raw-view encoding under unchanged-subgraph embedding |Conditional2,568,395,104 bytes exceeds10MiB; no-go for retaining that encoding, no proof produced |
| Remaining obligations |ARITH-LOWER-001; OC-REL/EXT/PRIV/BUDGET; Delta_tail |Full-verifier/compiler/security work open; next source-only compact-proof review proposed |

See [measured report](stage3_mldsa_full_forward_ntt_pilot.md) and the
[machine summary](data/s3_mldsa_full_forward_ntt_pilot_1/pilot-summary.json).
Actual invocations386/386; no further cases authorised. Final time/resource and
preservation closure follows. Production/profile/dependencies/history unchanged.


Full-forward pilot preservation closure: audit and report guard pass,
10,482 protected content paths,
2.438798105s and24,190,976-byte
cgroup peak under256MiB. Package93.441512754/135s;
implementation332.176781662/374s, **41.823218338s remain**;
invocations**386/386**. Analysis245.423783159s/isolation250.22s
unchanged. Outcome: Component composition/counting validated; NO-GO for integration with the unchanged raw-view proof encoding. No further package started.
See [complete report](stage3_mldsa_full_forward_ntt_pilot.md).
Stages2–3/security obligations remain open; proof ledger2used/1unused.


## S3-COMPACT-AUTH-PROOF-PROFILE-REVIEW-1

| Requirement / source | Review evidence | Status |
| --- | --- | --- |
| V-B, VII-A.5/.6; R-010/020/023/024/029–037 | [Same-witness contract and cost inventory](stage3_compact_auth_proof_profile_review.md): exact hidden signature/message, holder opening, certified attributes/rid, path and complete E(X) preserved for all three candidates | Relation preserved as required target; no new full circuit/proof |
| VI-B4, VIII-C/D; R-043/045–047/050/051; OC-REL/EXT/PRIV/BUDGET | Claim/theorem matrix distinguishes original raw-view proof, CMS conditional QROM route and alternative implementation/application gaps | Complete knowledge/privacy and concrete hash modelling remain open |
| Existing KYC targets / ARITH-LOWER-001 | NTT host execution, logical composition and conditional2,568,395,104-byte projection separated; no universal lower bound or imported timings | Unchanged raw-view integration/optimisation paused |
| COMPACT-PROFILE-001 | Exactly three implementations/modes; new libiop wire/byte-accounting findings; one Aurora–BCS construction research decision and finite next contract | Proposed direction requires user input; no profile/installation/execution authorised |
| Preservation / ledgers | [Analysis evidence](data/s3_compact_auth_proof_profile_review_1/contract.json), prior201-file seal/53 assessed inputs verified; original baselines continued | Implementation41.823218338s and386/386 unchanged; closure below |

Stages 2–3 open; production security, component advantages at reduction budgets,
adaptive Delta_tail and complete proof feasibility remain unresolved. Isolation
safely stopped/unactivated with pending cases preserved; proof ledger two used/one unused.


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


## S3-AURORA-AUTH-CONSTRUCTION-CONTRACT-1

| Requirement / authority | Evidence and decision | Remaining obligation |
| --- | --- | --- |
| V-B, VII-A.5/.6; R-010/020/023/024/029–037 | [Same-witness constraint mapping](stage3_aurora_auth_construction_contract.md#same-witness-lowering-and-complete-acceptance): exact Mcred/ML-DSA, opening, full attributes/disclosure and same certified rid/path; public wrapper preserved | Complete bidirectional lowering, auxiliary/range/rejection constraints, full resource inventory |
| VII proof layer; COMPACT-PROFILE-001 | Proposed field/domain table, zero-grinding native-ZK Aurora, separate proof identity and bounded wire; no active profile change | AURORA-BRIDGE-001: pinned registration/query/mask and commitment/transformation bridge before prototype |
| VI-B4/C, VIII-A/C/D; R-043/045–047/050/051 | [Theorem matrix](stage3_aurora_auth_construction_contract.md#theorem-applicability-and-unresolved-application-arguments): Aurora9.2, BCS7.1, CMS proceedings3 with exact limits of source inspection | Round-by-round knowledge, finite constants, adaptive history/online simulation, concrete hash modelling; SEC-001..005 and OC obligations open |
| KYC targets / engineering admission | Full matrices/nnz/padding, live oracle/tree/mask memory and byte formula; published timing not imported | Complete authentication constraints, proof/verification time and provisional targets unmeasured |
| Preservation / resource separation | Prior62-file seal and53 assessed inputs verified; exact append-only docs and additive package evidence | Analysis only; implementation41.823218338s and386/386 unchanged; closure below |

No tests/builds/circuits/proofs/zkVM/activation/installations. Adaptive Delta_tail,
component advantages at actual reduction budgets and production-security obligations
remain open. Stages 2–3 open; isolation safely stopped/unactivated; proof ledger2used/1unused.


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

## S3-AURORA-TRANSCRIPT-BRIDGE-1

| Requirement / obligation | New source-only evidence | Boundary retained |
| --- | --- | --- |
| VII proof transcript; AURORA-BRIDGE-001 | [Pinned round/commitment/challenge map](stage3_aurora_transcript_bridge.md), 21 byte-sealed source texts; absorption ignores new digest, initial statement not bound | Decision 2; upstream code requires correction; no private prototype or profile adoption |
| R-002/R-045; VIII extraction/privacy | Exact symbolic coset/column/terminal disclosure accounting; source 2q+1 is a position bound; modified mask distributions identified | No joint simulator, restricted state-restoration or round-by-round knowledge claim; adaptive composition open |
| R-041/R-042 proof bytes/checking | Direct sums, terminal coefficients, roots, salts, paths and metadata mapped to bounded draft wire | Serializer contract only, no implementation or proof objects accepted |
| II–VIII auth relation / COMPACT-PROFILE-001 | Existing certified message, holder binding and same-identifier revocation linkage preserved | No relation, dependency, production code, active profile or RISC Zero evidence changed |

Recommend only inactive **S3-AURORA-TRANSCRIPT-CORRECTION-CONTRACT-1**, one bounded
source correction contract. Analysis opening 228.28910572698805 s; implementation
41.82321833795868 s and **386/386** invocations unchanged. No execution experiments.
Stages 2–3 remain open, raw-view integration/CPU proving paused, isolation safely
stopped/unactivated with 22 cases and 250.22 s retained; proof ledger two used/one unused.


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

## S3-AURORA-TRANSCRIPT-CORRECTION-CONTRACT-1

| Requirement / issue | Contract evidence | Remaining obligation |
| --- | --- | --- |
| VII transcript; AURORA-BRIDGE-001 TB-01/TB-02 | [Exact data flow and EXP2 pseudocode](stage3_aurora_transcript_correction_contract.md), atomic full-span absorption and trusted canonical E(X) initialisation | Proposed only; no implementation or validated correction |
| R-005/R-008/R-020/R-024 public/context meaning | Uses unchanged typed AuthenticationStatement, expected parameters and canonical encoder; no hidden witness fields | Hash binding does not replace primary-input algebraic checks or lifecycle freshness |
| R-041/R-042 proof boundary | Exact frame lengths/order, counters, empty inputs and rejection; independent trace recipe and 16 future cases | Public transcript regressions only; normal proof verifier remains fail-closed |
| VIII knowledge/privacy; AURORA-BRIDGE-001 | Separates local bug repair from new transcript encoding and BCS-style refinement | Joint masking/query, commitment, adaptive extraction/privacy and concrete-hash arguments open |

Recommend inactive **S3-AURORA-TRANSCRIPT-REGRESSION-1** without another general
review prerequisite: sixteen invocations proposed (386→402), at most 25 implementation
seconds with ten-second reserve. Current invocation count **386/386** and
implementation41.82321833795868 s unchanged; no tests, builds, hashes of proposed
transcripts or proofs executed. Stages 2–3 open, isolation safely stopped/unactivated,
CPU proving/raw-view work paused, proof ledger two used/one unused.


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


E501-only repair continuation: **stopped at storage admission**, no helper change,
static rerun, preparation or audit. Retained package usage 262,101/262,144 bytes
left 43 bytes; the existing helper requires 1,100 bytes reporting headroom before
new evidence. The report pointer leaves 262,142 bytes. Earlier failure archives
and all 16 passed cases are unchanged. See the [admission and closure record](status.md#repair-2-stop).
Five-second established bookkeeping charge: combined 23.762073883/35 s;
package 11.237926117 s remain including ten-second reserve; implementation
18.061144455 s remain. Tests 402/402; no new invocations. Full audit,
final inventory/reporting and E501 correction remain outstanding; no completion
claim or limit increase. Stages 2–3/AURORA-BRIDGE-001 remain open; proof ledger
2 used/1 unused; analysis/isolation unchanged, CPU proving paused, no activation.


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

Fourth-build admission → sealed runbook/request/policy and functional patch
verified; `build-4-admission-1/admission-result.json` records the 24 retained build
files/344,971 evidence bytes that defeat the approved reservation. Individual
SEM-01–SEM-08/TR-01–TR-16 outcomes are all not run in `native-case-outcomes.json`.
No native path executed; no semantic/correspondence claim. Builds 3/4, ledger
411/438; historical inputs and failures remain protected. Final preservation is
linked from the native report. Stages 2–3 and AURORA-BRIDGE-001 remain open.


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


### S3-AURORA-MASKING-CORRECTION-CONTRACT-1

| Requirement | Evidence | Status |
| --- | --- | --- |
| Exact distributions, direct messages and inactive source edits | [Contract](stage3_aurora_masking_correction_contract.md), SC-1–SC-4/LD-1–LD-2/FR-1/IO-1 | Proposed only; native/production sources and binaries preserved |
| Joint adaptive privacy and query projection | Same contract S0–S2; Aurora Protocols5.8/8.6, Theorem7.4; rank/conditional-translation argument | Perfect classical ideal algebraic view for admissible family; common positions distinct from scalar/direct disclosures |
| Full authentication relation and transformation gates | Same contract, relation and TB-01–TB-10 table | Relation unchanged; commitments, native/private correspondence, concrete hash and knowledge/privacy open |
| Preservation and unchanged ledgers | New package evidence under `docs/data/s3_aurora_masking_correction_contract_1` | Analysis only; invocation448/450, builds5/5, proof2used1unused; no functional execution |

Finalisation: complete audit exit0, 10,901 disjoint comparisons, inventory/reporting/readback passed; 3.894257s and 49,020,928 bytes cgroup peak under256MiB. One E501 static failure retained; formatting correction passed separately. Package charged18.392586s; analysis remains126.277380s. Native/implementation and448/450 invocations,5/5 builds unchanged. Contract complete, source proposals inactive and security obligations open; see [closure](data/s3_aurora_masking_correction_contract_1/validation-closure.json).


### OCT31-KYC-NATIVE-MILESTONE-1 — inactive execution plan

| Work | Concrete proposal and acceptance | Boundary |
| --- | --- | --- |
| Native masking | [Milestone N](october_implementation_milestone.md); SC/LD/FR/IO patch,24 new cases+16 TR, actual native callers | No private proof; retained EXP2 evidence separate |
| ML-DSA reference | Milestone B; issuer-bound persistent holder key, signed challenge/context, authenticated NR and durable A/B consume | Isolated new baseline format/contexts; full disclosure, no W3C/security-profile claim |
| Benchmarks | Milestone H; four scenarios,276 trials, JSONL/CSV/summary, unavailable-proof capability | Exclusive measurement; no incomplete PQ-DID/PQ-DAA overhead ratio |
| Execution/accounting | Shared600-slot/8-build proposal, one amended implementation pool, coordinator-owned records | Amendments require consolidated approval; no execution during preparation |

Preparation complete, awaiting one consolidated execution approval: static checks and full audit passed,10,901 disjoint comparisons, final inventory/reporting/readback complete. Audit3.506725s/41,791,488B cgroup peak; preparation charged19.222742s; analysis remains107.054637s. Implementation/native balances and448/450 invocations,5/5 builds unchanged. Proposed resource amendments remain inactive; see [closure](data/october_implementation_milestone_1/validation-closure.json).

## OCT31-KYC-NATIVE-MILESTONE-1 evidence

- Baseline fixed role/key/context frames and release/consumption contracts →
  [B01–B48 and report](stage2_mldsa_reference_baseline.md), actual bounded signatures.
- Native SC/LD/FR/IO corrections → [component report](stage3_aurora_masking_native.md),
  build2 N01–24; stronger build3 N04 and EXP2 matrix not yet executed.
- Measurement boundaries/provenance/null proof metrics →
  [H/C cases and276 measurements](kyc_milestone_benchmarks.md); C09 pending.
- Unchanged construction/parameters/manuscript/history → original preservation
  partitions plus [current evidence](data/oct31_kyc_native_milestone_1/).
- None of these rows establishes full authentication, W3C conformance or proof
  knowledge/privacy. Stages2–3/AURORA-BRIDGE-001 remain open; proof ledger2/1.

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


## Binius64 candidate mapping — no requirement closed

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

Coverage linkage: existing consolidation R-001–R-052 mapping is retained unchanged.
The new proposal maps PubOK/Ppub, Mcred/CredValid, holder binding, same-attribute
projection and same-rid non-revocation, enrolment, context/freshness and lifecycle
release/consumption to explicit candidate interfaces. It supplies no new implementation
evidence for these requirements. SHA3-384 exists upstream; bounded SHAKE128/256,
ML-DSA/private sampler, codecs, signed/range/overflow, policy/path and joint proof
integration still require implementation. Baseline measurements cannot fill private
proof fields; all such Binius measurements remain null.


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


## Binius64 G0 source/correspondence coverage

| Obligation | Evidence and result |
| --- | --- |
| B64-ZK-001 | [G0 trace](oct31_binius64_g0.md): pack_witness → ring-switch target → wrapper bypass → transcript → public outer equality. Unmasked witness-dependent value established by source; no native attack run. |
| B64-ZK-002 | Eight blob-verified source additions resolve encoder, query, RS representation and verifier paths. Original row unchanged; random companion row does not hide its opening. Cardinality-only support argument rejected. |
| Joint repair | Exact image/rank, support-annihilation, committed-key equality, joint simulation and affine-gamma conditions documented; no implementation-equivalence/privacy claim. |
| Native validation | All proposed gate checks unrun; no build, proof or functional invocation consumed. |
| Preservation | New package inherits all original comparisons, prefixes and retained repair inventories; closure records the full audit/readback outcome. |

Only manuscript Sections II–VIII and agreed clarifications remain authoritative.
No relation, BC-1, context, ML-DSA bound or accepted input set changed. Stage 2–3
completion and complete private authentication remain unestablished.

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

### KYC testbed continuation evidence

The [52-requirement delta](data/kyc_testbed_execution_1/coverage.json) retains the
consolidation index and all four evidence categories. W-01–W-24 plus promoted W-02
add atomic holder persistence, independent-head admission, fencing and interruption
checks to persistent state/UpdateWit obligations. F-01–F-14 add connected genuine
baseline issuer/holder/A/B-verifier/DID/revocation evidence (R-012–022, R-028–031).
M-01–M-10 validate only the approved local issuer/vocabulary/DID-key projections
(R-052), never a W3C securing mechanism. New T/R observations are disclosed-baseline
measurements; private metrics remain unavailable. R-1-4 is a retained setup failure;
R-1-8 and R-2-{1,4,8} are unrun. The earlier 21 full-relation checks remain unrun.
No complete scheme/security requirement is closed by these local component results.

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


## S3-BINIUS-COMMITTED-VIEW-CORRESPONDENCE-1

| Requirement or obligation | Evidence and status |
| --- | --- |
| Preserve full authentication relation and private/public boundary | New report sections 1–2 retain all reference checks; proposed decoder-transposed terminal rows, no adopted profile. |
| Both IntMul openings, correct point and shared outer object | Same native Y handle, equality then table; transparent suffix point; fixed distinct private slots in one OZ. Source map and construction-contract.json record the correspondence. |
| Commitments precede dependent challenges | Ordered O0/O1/O2/OZ/OL construction and lambda_J/Sigma/gamma order specified; roots-first simulation attempted, not established. |
| Original queries and full committed view | CV-RANK-1 conditional rank/entropy derivation; complete prefix and native lift/fold correspondence remain premises. Stronger-view saturation distinguished from actual disclosure. |
| Knowledge and privacy | CV-ONLINE-SAME-OBJECT-1 remains open; classical/FS/QROM/concrete-hash applicability separated in report section 6. |
| Preservation and resources | Existing guard/auditor, strict historical seals and three named append-only report prefixes; final closure in data/s3_binius_committed_view_correspondence_1. |

The component EC-01–EC-25 evidence is reused without reruns; native comparisons,
private authentication and the 21 previously unrun full-relation checks remain
unrun. The acquisition-memory observation, adaptive-tail and production-security
issues stay open. Comparison point v1 and all historical measurements remain
protected. No proof attempt is consumed; two used and one unused remain.


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
