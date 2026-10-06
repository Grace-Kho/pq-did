# S2-LIFECYCLE-REVIEW-1 — integration invariants and persistence requirements

19 September 2026. **The reference lifecycle is sufficiently consistent to proceed
to bounded recovery-admission work under its existing trusted-state assumptions. It
is not ready for restartable or replicated deployment.** All **28 new focused cases
and 50 selected existing regressions pass**. Two of the focused cases are explicitly
**unsafe-restart negative controls**: they reproduce identifier reuse and repeat
acceptance when stale state is deliberately imported in violation of those assumptions.
Their passing assertions demonstrate a recovery gap, not safe restart behaviour.

No functional source fix was warranted by the supported live-state tests. The new
[harness](../tests/unit/lifecycle_review_cases.py) and
[tests](../tests/unit/test_lifecycle_review.py) add deterministic integration evidence;
all existing production/reference source and test files remain unchanged. There is
no storage engine, checkpoint importer, real process-crash test, power-loss test,
network service, proof or zkVM execution in this package. CPU proving remains paused
at **two attempts used, one unused**. Stages 2–3 remain open.

## Authority and evidence reviewed

Checked [AGENTS.md](../AGENTS.md), the [implementation specification](implementation_spec.md),
the lifecycle modules and reports for [verification](stage2_verifier_state.md),
[witness updates](stage2_witness_updates.md), [revocation](stage2_revocation_state.md),
[issuance](stage2_issuance_enrolment.md) and [DID state](stage2_did_state.md), plus status,
traceability and issues. Only manuscript **Sections II–VIII** and the agreed
SPEC-001–004 clarifications are authoritative. Directly inspected III-B/D, IV-A–C,
VII-A.1–5/.7/.8 and the existing requirement mapping to VIII-E. Before review, the
selected manuscript digest was checked as
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
No excluded-section construction, prototype timing or claim is used.

The following evidence labels refer to existing immutable test files:

| Label | Test source / preserved report |
|---|---|
| D | [test_did_state.py](../tests/unit/test_did_state.py), S2-DID-STATE-1 |
| I | [test_issuance.py](../tests/unit/test_issuance.py), S2-ISSUE-ENROL-1 |
| V | [test_verifier_state.py](../tests/unit/test_verifier_state.py), S2-VERIFY-STATE-1 |
| R | [test_revocation_state.py](../tests/unit/test_revocation_state.py), S2-REVOKE-STATE-1 |
| W | [test_witness_updates.py](../tests/unit/test_witness_updates.py), S2-UPDATE-WIT-1 |
| F | [test_lifecycle_review.py](../tests/unit/test_lifecycle_review.py), this package |

Native helpers generate ephemeral synthetic keys and ordinary **uncapped test-only
signatures**. Existing bounded ML-DSA verification checks the resulting messages.
Enrolment/authentication relation evaluation stays holder-local in the harness;
the controlled proof adapter stores only exact public-statement/token pairs. These
tokens are not cryptographic proofs or receipts. No production signing/proving
guarantee follows from these tests.

## Lifecycle invariant and evidence matrix

The effective point is a local state transition or ordered read, not delivery of a
successful response. A delivery failure after that point cannot undo its effects.

| Boundary / requirement | Authoritative state and responsible component | Preconditions and committed output | Effective point; failure, retry and concurrent change | Evidence / remaining assumption |
|---|---|---|---|---|
| DID generation/publication, R-012–014 | Holder controller key/salt/reference/pending attempt; registry immutable history | Exact DID derivation; authenticated absence for genesis or current active predecessor; previous-key signature, validated new key for rotation | Registry locked append against absence/predecessor. Failed preparation leaves history; conflicting successor cannot overwrite. Controller retains pending bytes and possibly active keys before submit | D registration/concurrent successors; F simulated pending recovery. Bounded independent key/secret generation and durable pending storage open |
| DID resolution, R-015 | Pinned registry key/configuration and ordered registry snapshot | Exact DID/selector/nonce/signature/full chain; active endpoint gives minimal JSON and vD | Read linearises at locked snapshot; later overlapping update does not alter that answer. Historical active state is not current control. Invalid/unavailable/exhausted reads fail | D full-chain, nonce replay, overlap/history/deactivation; fresh ordered service remains a trust assumption |
| Issuer approval, R-019 | Authenticated issuer session, independently validated evidence/mapp and controller resolution | Expected pp; exact holder approval including DID/vD; external evidence/channel authority; initial authenticated issuance state | Session is reserved before dependencies; resolver/authorisation failure aborts it. No supplied controller field substitutes for the resolved key | I invalid requests/approval; D pending issuance changes. Confidential authenticated channel and real evidence policy remain dependencies |
| Permanent reservation, R-018/R-022 | Manager allocation prefix `[0,count)` | Expected current state, next rid below 2^20, zero path; increment count without changing epoch/root | Single manager snapshot assignment. Reservation survives issuer failure or lost reply; never recycled. New approved session obtains the next ID, not idempotent old success | I reservation loss; F `issuance_cut...` (reserved). Root does not authenticate count; trusted bootstrap/recovery required |
| Enrolment challenge and proof, R-020 | Issuer full approved challenge/controller/session and used nI set | Exact Xen, same B/mapp/rid/state/nI, real controller signature, exact VALID proof verdict | nI is retained before releasing pending challenge; one finish claims the session. Failed claimed call retires nonce/session; no same-session retry success | I substituted statement/proof/default adapters/concurrent finish. Actual proof verification and bounded signing remain open |
| Final issuance reads, R-019 | Independent DID registry and manager ordered reads | Same current DID version/key; registered zero leaf at the approved revocation reference | Each read fixes its own issuance reference. An earlier change rejects; a change after its read can coexist with certification at the old reference. There is no lock across DID, manager and issuer | D changes before final read; F changes after DID read and revocation during credential signing. No automatic migration or cross-service atomicity |
| Signing → logging → release, R-021/R-022 | Issuer certification tuple and terminal session record | Exact Mcred; bounded-valid credential signature; complete releasable credential/checkpoint prepared | Locked certification-log append and CERTIFIED phase precede return. Pre-log failure records no certification; post-log delivery failure retains it. Same begin/finish rejects, rather than returning an invented cached success | I pre/post-commit failures; F `issuance_cut...` (signed/logged). Durable transaction/outbound delivery still open |
| Holder acceptance, R-021 | Holder private intent/xH, approved attributes, accepted credential/checkpoint | Exact intended statement/binding/ID; bounded credential/state checks; zero path at issuance state | Locked assignment of one complete IssuedCredential. Pre-assignment interruption stores nothing; post-assignment reply loss retains both. Duplicate acceptance rejects | F holder interruption/concurrency and reconstruction; I wrong intent/revoked path. Acceptance at old state does not imply freshness |
| Presentation preparation, R-024–026 | Holder-approved request, original private credential/xH and matching witness/state | Request authentication/approval, matching instance/context and local relation; fresh real proof required | Current package harness constructs only a labelled reference token after local relation success. Witness maintenance changes no certified bytes | I/W full local relation composition; F outage/catch-up and mixed holder checkpoint. Real Present/approval UX and proof backend remain open |
| Challenge creation, R-016 | Verifier audience's complete context/state register and all nonce tombstones | Trusted pp/current state, approved policy, future expiry, unused nonce; sign exact E(ctx) | Register before request signing/release. Failed signing leaves nonce reserved. Replicas for one audience must share one atomic store | V request signing/collision/capacity tests; I/D exact instance checks. Durable store and trusted time/fresh randomness remain dependencies |
| Verification and freshness, R-017/R-027/R-028 | Expected registered ctx/session, public pp and public proof adapter; manager latest state | Exact statement, policy, proof, optional disclosed historical DID check; final ordered current reference must agree | Unavailable/changed state before final read rejects without consume. A revocation after that read does not invalidate the acceptance epoch. Expiry is still rechecked atomically at consume | V deterministic interleavings; F real-manager ordering and expiry. Public signatures cannot prove a dishonest/rolled-back service is latest |
| Challenge consumption, R-028 | Shared verifier pending/consumed store | Complete expected record/session and strict `now < texp` inside lock | Consumed-set insertion is acceptance. Two contenders get at most one ACCEPTED; lost return leaves tombstone. Ordinary repeated verify sees UNKNOWN; direct repeated consume is CONSUMED | V atomic races; F concurrent real services and lost returns. No exactly-once response delivery or application-side transaction claim |
| Revocation, R-030 | Manager tree, epoch, allocation prefix, consumed request nonces and full public history | Issuer authorisation, registered zero leaf, unused nonce/current reference; both new signatures validated | One snapshot commit includes tree/state/nonce/update record. Pre-commit failure changes nothing; commit survives notification/retrieval failure. Old request rejects. DID deactivation is independent | R preparation/concurrency/history; F committed revocation during retrieval/DID outage. External delivery service remains open |
| Witness update, R-031 | Holder's original credential and private `(rid,path,state)` | Authenticated complete ordered public batch and endpoint/path checks | Pure function returns one complete replacement or none; caller must persist new pair atomically. Missing history leaves old pair intact but unusable for a newer request | W mid-batch failures; F outage catch-up/mixed checkpoint. Retained public history and durable wallet installation required |

The matrix separates authority-local atomicity from independent service ordering.
Manager reservation is intentionally not rolled back when issuer processing fails.
Issuer and holder commits are separate: an issuer can retain a certification the
holder never receives or accepts. Revocation can commit independently of DID and
update-delivery availability. Verifier acceptance is fixed by the final ordered
manager read plus the local atomic consumption/expiry check, not a later global
transaction snapshot. No two-phase commit or compensating deletion is introduced.

## Deterministic fault and integration results

`Cut` injects exactly one exception immediately before or after a named call and
retains only a fixed label, hit count and completion flag. `Barrier(2)` synchronises
concurrent holder acceptance or verifier consumption; finite waits are failure
deadlines, not sleep-dependent race scheduling. At most two threads run inside the
single guarded execution worker. All fixtures are temporary in-memory objects;
no protected file is damaged to manufacture a failure.

| New test group (F function suffix) | Cases | Observed result and state assertion |
|---|---:|---|
| `issuance_cut_preserves_effects_and_new_session_never_reuses_id` | 3 | After reservation, pre-log signed response, or post-log lost response: FAILURE exposes no credential; counter remains 43. Only the post-log case retains certificate 42/CERTIFIED. Same session rejects; a separately approved session certifies 43 and advances count to 44 |
| `holder_interruption_retains_whole_pair_or_nothing` | 2 | Memory interruption after final path computation leaves no accepted object; explicit later acceptance succeeds. Delivery failure after acceptance retains exactly the original credential/checkpoint; duplicate rejects |
| `two_holder_acceptance_attempts_commit_one_complete_pair` | 1 | Two validated contenders produce exactly one ACCEPTED and one REPLAY; stored pair is intact |
| `revocation_committed_during_update_delivery_outage_then_explicit_catchup` | 1 | Lost revocation return leaves epoch 1/history/consumed nonce committed. Unavailable public retrieval does not undo it; old presentation fails STATE and wallet keeps old pair. Later explicit retrieval/local update permits a fresh request; old certificate bytes remain unchanged |
| `did_outage_does_not_prevent_independent_revocation_or_anonymous_verification` | 1 | DID publication is unavailable; independent revocation and holder-local update complete; anonymous verifier accepts without registry access |
| `did_change_after_issuance_read_has_no_cross_service_transaction` | 2 | Rotation/deactivation after the final DID read still permits certification against the read version; root/epoch remain unchanged. Existing D regression covers changes before that read rejecting |
| `revocation_after_final_issuance_read_does_not_roll_back_certification` | 1 | Revocation during signing occurs after the zero-leaf read. Original issuance checkpoint can be locally accepted at epoch 0; the committed epoch-1 update reports that credential revoked, without deleting certification |
| `real_manager_ordering_and_atomic_expiry` | 3 | Revocation before final read: STATE and pending challenge. Revocation after read: ACCEPTED at old logical epoch. Expiry exactly at texp after read: EXPIRED and pending challenge |
| `acceptance_followed_by_lost_response_cannot_consume_twice` | 2 | Connection/MemoryError in outer delivery after verify leaves the challenge consumed; repeat verify is UNKNOWN and direct consume is CONSUMED. No second acceptance in the same retained store |
| `concurrent_presentations_with_real_services_and_wrong_audience` | 1 | Wrong verifier/context fails MISMATCH without changing its challenge. Barrier-synchronised attempts yield one ACCEPTED/one CONSUMED; the second audience accepts its own correctly bound presentation |
| `simulated_missing_verifier_records_and_complete_retained_tombstone` | 1 | Missing challenge rejects UNKNOWN; reconstructed complete consumed record also rejects UNKNOWN. This does not authorise reuse of lost nonce history |
| `unsafe_restart_negative_control_stale_pending_snapshot_can_reaccept` | 1 | **Unsafe negative control:** a separate reconstructed store containing only the old pending record accepts again; native state signatures and a valid reference verdict do not recover the missing consumption tombstone |
| `simulated_manager_complete_counter_survives_but_old_history_is_unavailable` | 1 | Trusted current counter/nonce/root reconstruct consistently; next reservation is 43. Constructor omits pre-checkpoint history, so old-range retrieval is UNAVAILABLE and empty catch-up fails INVALID_HISTORY |
| `unsafe_restart_negative_control_signed_root_does_not_bind_allocation_counter` | 1 | **Unsafe negative control:** old count 42 and current count 43 have the identical signed root; deliberately bootstrapping count 42 reserves already-issued ID 42 again |
| `simulated_inconsistent_manager_checkpoint_fails_validation` | 1 | Root inconsistent with revoked set rejects INVALID_ARTEFACT; live manager state unchanged |
| `simulated_pending_did_recovery_needs_retained_attempt_and_key_handles` | 1 | Missing controller history cannot infer ownership/recover and conflicts on new genesis. Complete test-only pending-state/key-handle rehydration confirms committed rotation without resubmission, then can deactivate using retained rotated key |
| `simulated_incomplete_issuer_session_never_certifies` | 2 | Missing approved challenge fails and retires the claimed call; reconstructed CLAIMED phase cannot finish and abort is BUSY. Neither signs/releases or reuses allocation. Administrative recovery remains absent |
| `simulated_complete_certification_log_keeps_replay_rejection` | 1 | Complete test-only session/nonce/certification rehydration preserves both duplicate-begin and duplicate-finish rejection and the original log |
| `simulated_holder_missing_or_mixed_checkpoint_must_not_activate` | 1 | Missing response/mixed newer state and old pair reject. Original pair can be validated again, but a fresh epoch-1 challenge fails local relation/proof-token admission with the old witness |
| `public_verifier_boundary_and_default_dependencies` | 1 | Exact public interface; default proof and missing request signer fail closed; anonymous verification needs no DID call; private fields absent from adapter inputs/representations and captured diagnostics |
| **Total** | **28** | **26 supported/fail-closed integration cases + 2 explicit unsafe-reconstruction controls** |

The **50 selected existing cases** reuse the implementations and fixtures above:
issuer reservation/finish/signing/default/concurrency; verifier expiry/order,
record/session matching and dependency failures; DID rotation/deactivation and
pending recovery/conflicts/current-controller changes; manager bootstrap/preparation/
history corruption; and witness mid-batch, authenticated revocation and diagnostic
privacy. Exact test selectors and command lines are retained in the
[runner](data/s2_lifecycle_review_1/run_checks.py) and run records. Other prior
cryptographic, circuit and auditor evidence is reused unchanged rather than repeated.

## Findings, fixes and unsupported extensions

**REC-001 — allocation rollback is not detectable from the signed root.** Permanent
allocation leaves the root and epoch unchanged. The trusted manager constructor
checks the imported count's domain and consistency with revoked IDs, not completeness
of all historical reservations. The negative control shows the same authentic state
supports a stale lower counter and ID reuse. This is not a defect in the live atomic
reservation transition; it is a demonstrated unsafe use of an explicitly trusted
bootstrap interface. An old signed root must never be used to infer the next unused ID.

**REC-002 — consumption rollback is not detectable from a pending request.** A
registered/signed request does not authenticate future consumption. A separate stale
store can accept a formerly consumed challenge again. This violates the existing
shared atomic state assumption if deployed; it is not a failure of the tested live
store lock. Even complete local records can be rolled back consistently. Fresh manager
signatures cannot reconstruct lost audience tombstones.

**REC-003 — inspection snapshots are not complete restart images.** `IssuerSnapshot`
omits approved pending challenge/controller objects; `ControllerSnapshot` omits salt
and private signer handles; the manager checkpoint constructor does not import old
update history. A wallet's accepted response alone does not replace private xH,
trusted expected parameters or outstanding holder intent. No public recovery importer
claims otherwise. Partially reconstructed CLAIMED issuer sessions cannot be resumed
through ordinary finish/abort calls. Full recovery admission/retirement is unimplemented.

**REC-004 — delivery outcomes must not be confused with committed outcomes.** A
pre-commit validation failure has no commit; a lost post-commit return has an unknown
caller-observed delivery result and a retained server effect. Repeating a request
must keep the current rejection semantics. Neither response caching nor an idempotent
success-returning retry is added. In particular, the earlier statement that failed
verification does not consume refers to rejection before the consume point, not
failure of an outer delivery mechanism after a successful consumption.

**Demonstrated functional fixes: none.** Supported live-state transitions matched
R-013–R-022/R-028–R-031; no primitive, encoding, validation, signature, proof or
state-transition change is needed to obtain these results. The corrective deliverable
is explicit recovery requirements and a conditional deployment decision. The two
unsafe controls remain visible in the machine-readable
[review findings](data/s2_lifecycle_review_1/review-findings.json), rather than being
reported as passing production restart guarantees. No new cryptographic field,
checkpoint signature, current-control requirement, rollback authority or trust policy
is silently adopted.

Unsupported extensions remain: automatic credential migration after controller change;
deactivation as revocation; current controller possession for hidden-DID presentation;
global DID/manager/issuer atomic commit; replay returning the old successful response;
counter reconstruction from a Merkle root; eviction/recycling of nonce or allocation
history; arbitrary historical-key/schema reassignment; and automatic continuation from
unverified snapshots. Rotation, terminal deactivation, active historical resolution and
identical pending-publication recovery are supported exactly as already specified.

## Trust, privacy and failure boundaries

Issuance current-controller authorisation is separate from anonymous authentication
using xH. Controller keys are not issuer or manager keys, and the separate comparison
baseline's persistent holder authentication key is not inserted into this system.
Verification receives only the invoking session, echoed expected context, D/mD and
opaque proof; the full public X is reconstructed from pinned verifier state. No
holder secret, credential signature, hidden rid, path or controller key is a verifier
argument. Optional DID checks remain limited to both approved disclosed DID/vD fields
and the specified historical state. The tests prohibit registry access during a normal
anonymous verification and still complete it.

Issuer-private recovery data legitimately includes its approved attributes, certified
binding/ID, signature and retained initial response/checkpoint. This is not a public
presentation transcript or a public recovery log. Manager-private recovery includes
allocation/nonce state; public update records disclose only their already specified
revoked identifier/path. Holder secret, credentials and current private witness stay
holder-local except for information the issuance contract already permits authorities
to know. Update retrieval takes only namespace/from/to epochs, never private holder
rid/path. Controller private-key handles must not appear in registry records or
generic checkpoint diagnostics. In-memory test helpers inspect roles jointly only to
assert invariants; no such combined production API is introduced.

Fixed exceptions/status codes and suppressed private dataclass representations avoid
routine diagnostic exposure. The fault harness stores no arguments/results, the
captured diagnostic test is empty and saved XML contains case names/results rather
than private fixtures. This does not establish cryptographic zero knowledge, secure
secret erasure, side-channel protection, network unlinkability or production log safety.
Future persistence must preserve access-control and confidentiality boundaries.

Current-state and DID signatures authenticate response contents/nonce; ordered latest
state remains a service assumption. Clocks must remain trustworthy across restart;
turning the clock backwards is not an expiry recovery mechanism. An old valid wallet
pair is not current merely because local signature/path checks pass. Unavailable
authority/history must stop the dependent operation; it cannot justify a stale cache,
fresh-looking signature over rolled-back state or a weaker acceptance test.

## Required durable state and transaction boundaries

These are requirements for a future implementation, not a storage schema or new wire
format. No database, journal, disk synchronisation primitive or consensus mechanism is
implemented or selected. “Durable before release” means the recovery mechanism must
restore the same effective transition after a crash; these tests do not establish it.

| Owner | State that must survive or be securely reacquired | Required transaction/checkpoint and recovery rule |
|---|---|---|
| Setup/application trust | Exact pp, immutable issuer/key/schema/ns binding, registry γ/pkG, audience keys, authorised roles, resource policy and clock/freshness dependencies | Authenticate configuration independently of recovered messages before activating any role. Do not infer trust or key substitution from a DID/credential. Missing authority or mismatched instance blocks activation |
| Manager allocation | Permanent high-water count and any authority-local request/allocation correlation needed for recovery; all reservations including abandoned ones | Commit increment before returning allocation. Lost response can leave an orphan reservation; retain it. Never lower count to match surviving credentials or reuse an unacknowledged ID. Correlation records are local storage metadata, not new signed fields |
| Issuer sessions | Full approved mapp, pinned pp/state, resolved current controller/version at approval, registered Xen fields/rid/nI, phase, consumed/reserved nI set and authorised session context | Record pending challenge and nonce reservation before release. Atomically record certification/releasable response and terminal nonce/session state before release. An incomplete pending challenge cannot be rebuilt from untrusted holder input |
| Issuer certification/release | Original `(µ,mapp,rid,B)` certification log, exact credential/signature and complete retained response; terminal session outcome and delivery bookkeeping kept distinct | Signing alone is not certification/release. A fully validated but unlogged candidate may be abandoned while retaining allocation/nonce. A logged response survives loss; ordinary duplicate begin/finish still rejects. Any future retrieval API needs separate authorisation and an explicit contract |
| DID registry | Complete retained canonical signed histories, DID/version endpoint, terminal activity, pinned configuration, local ordering/append state and registry signing-key access | Atomically append record/version against predecessor; persist before acknowledging effective write. Retain all committed history. Fresh signed read must use authoritative recovered endpoint, not a merely authentic old prefix |
| Holder controller | DID, salt, retained version/current key ownership, exact pending signed record, predecessor and all possibly active old/new private-key handles | Persist pending bytes/key references before submission. On recovery, authenticate current full history first: exact occurrence confirms; unchanged predecessor allows one explicit identical resend; conflicting successor retires attempt. Timeout preserves possibly active keys. Missing secret handles cannot be derived from public records |
| Manager revocation | Exact state/epoch/root, revoked set/tree or equivalent reconstructable data, allocation counter, all consumed request nonces, base state and complete retained public updates | One durable commit covers tree/state, epoch, request nonce and retrievable record. Recompute/authenticate consistency. New checkpoint without old history cannot serve old-range updates; do not silently label a shortened page complete. Delivery outages do not roll back commit |
| Verifier per audience | Full pending contexts with pp/state/local DID-check flag/session, every reserved nonce including failed-signing requests, consumed tombstones and consistent session state | Persist registration before signed request release. Atomic durable full-record/session/expiry compare-and-consume before acceptance response. All replicas share this authority. Missing records reject old presentations, but absence is not permission to recycle old nonces or recreate pending records |
| Holder wallet | xH/private opening, immutable approved credential/intent/instance, accepted credential with matching private identifier/path/authenticated state, and any updated checkpoint | Atomically install a complete accepted pair. Update computes a new pair off to the side; persist both path and state together only on complete success. Preserve the old pair after failure. Revalidate and catch up before a new request; no latest-state claim from local acceptance alone |
| Signing/randomness providers | Authorised private-key access and correct role mapping; fresh approved randomness; bounded operation/resource controls | Fail closed if keys/RNG/signer unavailable. Never treat retained public key, signed reply or fixture token as proof of private-key availability. Do not resume transient MPC proof randomness from a checkpoint; real proving is outside this package |

An application action after verifier acceptance is another coordination boundary.
The protocol's one consumption does not itself atomically execute a remote business
action or guarantee response delivery. A future application needs an explicit local
transaction/outbound-action design tied to its authenticated consumption result;
this review does not invent that design or change the protocol response semantics.

### Recovery admission and ordering

1. **Quiesce/fence old writers and establish authoritative recovery state.** Before
   accepting calls, identify the fixed instance/role and obtain evidence of checkpoint
   completeness and freshness from an independently trusted recovery authority.
   A record's signature or a local digest is insufficient. Missing evidence means
   unavailable/quarantined, not a fresh empty instance under the same namespace.
2. Validate a complete role checkpoint within existing byte/count/work limits.
   Recompute tree/root and canonical histories, authenticate state/records and
   verify internal endpoint/phase/counter/nonce consistency. Consistency is necessary
   but does not establish freshness. No partial object becomes a serving authority.
3. Restore manager reservation high-water and nonce/history state, registry histories
   and verifier reserved/consumed state before serving their dependent reads/writes.
   Do not erase unknown reservations, log entries or tombstones to make stores agree.
4. Reconcile issuer incomplete operations against authoritative manager reservation
   evidence and retained issuer log. If logged, retain terminal certification regardless
   of receipt by the holder; if definitely unlogged, retain reservations/nonces and
   retire the abandoned attempt. If commit status is ambiguous or evidence missing,
   keep it unavailable. Reinterpreting a CLAIMED record as fresh PENDING is unsafe.
   Administrative retirement/reconciliation is currently an unimplemented interface.
5. Restore holder controller pending bytes and private-key handles, then perform the
   specified authenticated pending-publication resolution before new publication.
   Revalidate holder credential/checkpoint pairs; fetch complete public update ranges
   and request a fresh presentation context if the required state changed.
6. Admit service traffic only after each dependency's ordering, nonce, clock and
   same-audience consistency contract is satisfied. Expired/consumed contexts never
   become live by reconstruction. An independently created verifier store must not
   masquerade as a recovered replica of the same audience.

These steps are an engineering dependency ordering, not a new global transaction or
an adopted rollback protocol. The exact issuer administrative recovery states,
release-status retrieval, evidence format and cross-role reconciliation interfaces
need a concrete bounded design. No automatic retry, retry success or nonce recycling
is authorised by these requirements.

### Rollback detection remains an explicit trust decision

Local storage integrity and atomic transactions cannot by themselves distinguish a
complete old checkpoint from the latest committed one. This applies to allocation
count, verifier tombstones, issuer logs and DID/revocation histories. If the same keys
remain usable after rollback, new nonce-bound signatures can still attest stale state.
Signed public roots do not bind allocation progress; request signatures do not bind
subsequent consumption. Copies on the same rollback domain do not solve this.

A deployment must specify where an independently trusted monotonic commitment or
authoritative durable ordering survives (and how old writers are fenced), how its
identity is pinned, and what happens when it is unavailable or disagrees. Possible
classes include an external authoritative service or a separately protected monotonic
anchor; none is selected here. No security property of a particular product is assumed.
Ordinary fresh process memory, a local hash/checksum, an old signature, a wall-clock
timestamp or a caller-supplied “complete” flag is not an adequate freshness authority.
This is the concrete open trust question for the next package, not permission to
silently add a new trust assumption or protocol field.

## Validation envelope and preservation

The [configuration](data/s2_lifecycle_review_1/config.json) and runner preserve the
existing **256 MiB = 268,435,456-byte cgroup-v2 memory ceiling**, zero swap, one
guarded worker, two affined CPU cores, 60 s per command/55 s child stop, 300 s total,
100 selected cases, 10 GiB experimental disk/9 GiB early stop, 64 MiB diagnostic/
60 MiB early stop, 10 MiB package output, 60 KiB per-log stop and 1 MiB per-file limit.
WSL headroom must exceed the full memory allowance plus 2 GiB. Private networking
has no routes, and the project is read-only to workers except the evidence directory.
Fault barriers do not bypass worker/memory limits. No dependencies were installed.

Peak **cgroup charge** includes worker/descendant anonymous memory, file cache and
kernel memory. Sampled aggregate process-tree **RSS** is recorded separately; it
is neither the cgroup metric nor address-space usage. The outer launcher/monitor
does bookkeeping only; no protected comparisons are moved outside the guard.

| Guarded command through `docs/data/s2_lifecycle_review_1/run_checks.py` | Result | Outer wall time | Sampled tree RSS peak |
|---|---|---:|---:|
| `focused` | 28 passed, including the two labelled unsafe controls | 5.502026320 s | 74,850,304 bytes |
| `regression` | 50 passed | 2.665809177 s | 71,098,368 bytes |

[Focused record](data/s2_lifecycle_review_1/focused.json),
[regression record](data/s2_lifecycle_review_1/regression.json) and
[run ledger](data/s2_lifecycle_review_1/run-ledger.json) retain exact commands,
effective controls, headroom, events, exit codes, XML counts and timings. No functional
test failed or skipped. These are validation observations, not proving costs or
authentication latency/throughput/percentile claims.

The unchanged [corrected preservation auditor](../scripts/preservation_audit.py)
is reused by the [package audit](data/s2_lifecycle_review_1/audit.py). The
[scope](data/s2_lifecycle_review_1/scope.json) pins **five historical manifest identities**:
the original 8,759-entry baseline, manager (33), corrected auditor (40), issuance (48)
and DID (33) seals. No baseline is regenerated. The content partitions comprise
**8,759 primary + 140 supplementary = 8,899 distinct paths**, with zero overlap;
four additional distinct manifest-identity paths give **8,903 historical paths**.
Only three existing documentation files—status, traceability and issues—may change.
There is **no permitted existing source or test change**. All new test/report/evidence
names are individually listed; no directory exclusion is added.

Coverage includes all original crypto/circuit code, active parameters/encodings,
dependencies, original vectors, manuscript and historical evidence/STOPs. The original
manager ceiling failure and later passing audit results remain intact. The same
SHA-256 content algorithm, complete inventory, literal pre-existing cache-name list,
symlink/metadata handling, large-file coverage and report/guard acceptance rules are
preserved. The historical manager report's original prefix and latest sealed full
content are both retained. Existing auditor fixture tests are reused unchanged.

The completed sequence was guarded `focused`, `regression`, `quality`, `format`, then **one**
complete `full-audit`. Overall success requires [result.json](data/s2_lifecycle_review_1/result.json),
the clean [guard record](data/s2_lifecycle_review_1/full-audit.json), complete
[content/inventory report](data/s2_lifecycle_review_1/validation.json) and
[report-generation phase](data/s2_lifecycle_review_1/phases.json). Comparison alone
does not count as complete. The measured final result follows. Final
documentation and the [package seal](data/s2_lifecycle_review_1/manifest.json) are small
post-guard bookkeeping, not a second historical scan or replacement baseline.

### Completed final validation

**PASS**, one complete preservation attempt, exit **0**, no automatic retry or limit
increase. Exact command:
`.venv/bin/python docs/data/s2_lifecycle_review_1/run_checks.py full-audit`.
All content comparisons, inventory checks, report write/readback, worker exit and
outer resource guard completed successfully. Cgroup-v2 charged-memory peak was
**22,134,784 bytes (21.109375 MiB)** under the unchanged 256 MiB ceiling; separately
sampled aggregate process-tree RSS peaked at **40,595,456 bytes**. Outer wall time
was **2.049593098 s**. Memory-max/OOM/OOM-kill events and swap peak were all zero.
Package output at guard completion was **158,184 bytes**; temporary storage was
**zero bytes**. The monitor remained outside the charged worker tree as before.

Of the original 8,759 content entries, 8,756 are unchanged and precisely the three
permitted documentation files changed. All **140 supplementary content entries**
are unchanged. The distinct content/identity union covers **8,903 historical paths**;
the **525-entry name inventory** has no missing or unexpected name. The auditor
checked **287 local Markdown link paths** at that point. All five historical manifest
identities, the manuscript and proof ledger match. Existing source/test files,
cryptographic code, parameters, dependencies and historical results remain unchanged.

Final lint and formatting also pass, exit 0. All five guarded commands totalled
**10.396295292 s**; the largest cgroup peak was **63,238,144 bytes** in the focused
suite. The 78 selected tests comprise 28 focused and 50 reused regressions, with
no failures/skips; the two unsafe-restart negative controls retain their separate
meaning above. After the guard, only final result/obligation text in the four
permitted documentation files and the package seal are finalised. Small document
format/link and new-artifact checks are bookkeeping, not another complete audit.

## Integration decision and prioritised remaining gaps

**Proceed with reference recovery-admission design/validation, subject to the stated
trust boundary; do not deploy durable/replicated lifecycle services.** The positive
tests support local atomicity, correct read-point ordering and privacy-interface
separation with complete trusted state. The negative controls explicitly prevent a
claim of arbitrary-restart identifier uniqueness or at-most-once acceptance.

| Priority | Separate obligation | Disposition |
|---|---|---|
| P0 | Complete authenticated recovery admission, rollback protection and writer fencing; authoritative shared audience state | Blocking restart/replica deployment; no production importer/anchor chosen |
| P0 | Durable allocation/issuer certification+nonce/manager update/verifier consumption/wallet-pair transactions and role-private recovery | Requirements above; no engine or crash guarantee implemented |
| P1 | Authenticated confidential services, issuer evidence/approval, release/delivery and interrupted-session reconciliation | Existing trusted adapter boundaries remain; no idempotent-success extension |
| P1 | Bounded independent key generation/signing, signing-tail and DEP-001/002 evidence | Ordinary native fixtures do not satisfy this obligation |
| P1 | DID Core/VC representation and method interoperability/conformance | Existing dated mapping preserved; no new standardised ML-DSA type or conformance claim |
| P1 | Full authentication/BC-1, selective-disclosure/non-revocation proof integration, actual enrolment/authentication backend and security/privacy review | Separate Stage 3 work remains; CPU proving paused and no profile change |
| P2 | Real crash/power-loss/concurrent-replica fault tests, deployment operations and bounded retention strategy | Require an approved durable design first; no finite-store eviction/reuse inferred |

Recommend exactly one next bounded package: **S2-RECOVERY-ADMISSION-1**. Define typed
complete role checkpoints and pure bounded validation/activation interfaces, with a
default-unavailable, explicitly injected recovery-authority contract. Exercise the
missing/stale/incomplete cases above without a storage engine or new protocol bytes.
Before making a production freshness claim, present the concrete choice of independent
rollback authority, evidence binding and writer fencing for review; do not equate a
test oracle with that deployment authority. Preserve existing limits, duplicate/retry
semantics, private-role separation and the two-used/one-unused proof ledger. That
package has not started. Stages 2–3 are not complete.
