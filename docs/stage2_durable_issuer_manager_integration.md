# S2-DURABLE-ISSUER-MANAGER-INTEGRATION-1

25 September 2026. **24 new integration cases pass**, including two real process
crashes. The isolated path joins the existing durable manager and bounded issuer,
logs certification before recipient delivery and preserves atomic holder acceptance.
**Positive cases use explicitly injected synthetic proof acceptance.** They are
lifecycle evidence, not complete PQ-DAA, anonymous authentication, real enrolment
proof verification or end-to-end cryptographic security.

## Authority, baseline and allowance

The [attached task](data/s2_durable_issuer_manager_integration_1/task-specification.md),
manuscript **Sections II–VIII** and agreed SPEC-001–004 clarifications govern this
package. The [specification](implementation_spec.md), particularly R-018–021,
R-030 and R-033, is reused alongside the
[durable reconciliation design](stage2_durable_authority_pilot.md),
[signing adapters](stage2_bounded_signer_release_contract.md) and
[durable manager](stage2_bounded_manager_durable_release.md).

[Preflight](data/s2_durable_issuer_manager_integration_1/preflight-evidence.json)
verified the preceding seal
`ebd93639b6645eaa85813332c2a3a0351738bb3b47786402073605c9be128d17` and all its
58 entries, plus the 53 assessed source inputs. Manuscript identity remains
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
Historical source, failures, parameters, dependencies, proof results and seals are
preserved. No primitive/native harness or historical test suite is rerun.

The explicit amendment is **124 + 24 = 148 cumulative test invocations**. At entry,
121 were consumed and 27 available; this package adds 24, for **145 used / three
remaining**. Parameter values are individual rows below. No failed test, repeat or
automatic retry occurred. The two pytest selections are disjoint; deselection is
not execution.

The exact prior time ledger was **48.71412072714884/300 s charged**, leaving
**251.28587927285116 s**. Measured new commands and five bookkeeping seconds are
added, not reset. Admission retains ten seconds for cleanup/evidence in addition
to a full command reservation. Analysis **270.1814811680233 s** and isolation
**250.22 s**, including its ten-second emergency reserve, remain separate and
unchanged. Isolation is safely stopped/unactivated; its 100 historical invocations,
22 pending identity cases and retained resources/failures are unchanged. CPU proving
is paused; proof ledger **two used, one unused**.

## Transition, ownership and interruption matrix

The new [integration module](../src/pqdid/durable_issuance.py) supplies an owner-local
`ManagerIssuancePort`, `DurableIssuance` orchestrator and holder-side delivery decoder.
No existing implementation or storage schema changes. Manager and issuer use
**separate authority databases**. Each row below has its own effective point; there
is no ATTACH transaction, two-phase commit, rollback compensation or identifier
deallocation across stores.

| Transition / owner | Checks before advancing | Local durable/effective point | Interruption/recovery |
| --- | --- | --- | --- |
| Approved intent / issuer | Existing request domains, active current DID/version, authorisation decision, holder approval of exact canonical attributes, authenticated issuance state, trusted manager identity | Immutable issuer intent binds issue operation, session, recipient, approved challenge, manager service and state reference in its journal/head | INTENT with no reservation is conservatively retired; delayed already-authorised allocation can remain an orphan |
| Permanent reservation / manager | Active writer/expected head, exact state, unique issuer-service/issue-operation mapping, next registered zero leaf | Manager allocation prefix, reservation payload, operation outcome and head commit together | Allocation survives lost reply, attachment failure or later abort; lookup must use the same issue identity and reference |
| Attachment / issuer | Exact manager identity, reservation key/arguments/reference, unique rid association | Journal becomes RESERVED with the original reservation payload | Retire if no complete pending challenge; retain rid permanently |
| Pending / issuer | Existing bounded fresh-nonce selection and atomic instance-unused nonce check; original attributes/rid/state unchanged | PENDING checkpoint/session, nonce set, journal and head commit | Complete PENDING can be explicitly resumed with the same nonce/rid/challenge; no implicit new challenge |
| Signing claim / issuer | Existing sign-issue authorisation, active writer/head and PENDING journal phase | Single-use SIGNING marker binds the issuer generation and sequence | Uncertain SIGNING cannot be retried; explicit reconciliation retires it |
| Enrolment checks / issuer, ordered reads / DID and manager | Exact statement equals original challenge; bounded controller signature; required proof verdict; current controller; registered witness at the issuance reference | No new distributed commit: final ordered reads define issuance-time references | A preceding state/DID change rejects. Signed but unlogged material never becomes deliverable |
| Certification / issuer | Bounded credential signing/verification, unchanged binding/rid/attributes, expected signing ticket/generation, complete record admission | CERTIFIED session, certification log, exact response, journal and head commit in one issuer transaction | Before COMMIT, SIGNING remains and must retire. After COMMIT, retain exact outcome; do not sign/allocate again |
| Recipient delivery / issuer | Original committed recipient, authenticated local channel assumption, current issuer writer/generation and exact head | One nonblocking local SEQPACKET enqueue under issuer writer lock | Lost acknowledgement or failed enqueue does not revoke the committed result; separately authorised redelivery returns identical bytes |
| Holder acceptance / holder | Existing binding opening, intended attributes/rid/state, credential signature, state authenticity and zero-leaf path | Existing single pointer assignment of credential plus separate witness/checkpoint | Failure leaves the holder empty; repeated acceptance is REPLAY. This holder state is in memory, not a durable wallet |

The manager owns allocation, registration mapping, revocation state/history and its
own head/generation. The issuer owns approval, recipient/session/challenge/nonce,
single-use signing claim, certification and its own head/generation. The holder
alone holds its secret and intended statement. `ManagerIssuancePort.snapshot()`
exposes only the allocation count needed for issuer recovery; it does not export
the manager's private checkpoint/nonce set. Its witness method reconstructs an
already admitted **current** manager snapshot, not the reservation's earlier state.

The orchestrator derives local stage-operation identifiers with the existing local
digest/codec from both service identities, the issuance operation and stage.
Reconciliation additionally binds the current independently admitted issuer ticket,
so a later interrupted phase can be explicitly reconciled after a previous PENDING
resume. These are local journal identifiers, not changes to protocol messages or
signing formats. Ordinary repeated/conflicting `begin` does not allocate again;
recovery uses the journal rather than blindly rerunning it.

## Exact binding, signing and recovery admission

Trusted owner configuration pins each role, key reference, expected public identity,
service and complete public parameters. The integration constructor requires the
issuer's trusted dependency port to name the exact configured durable manager.
Existing default-deny storage policy, permits and expected tickets remain active.
Request inputs cannot select a different signer/context/role or inject an already
signed credential. Existing bounded adapters and all sampler/attempt caps are reused.

The immutable intent and manager mapping tie recipient/session/approved fields to
one issuance operation. The original enrolment statement binds attributes, rid,
binding, nonce and signed issuance state; the controller signature and test proof
verdict are checked against that exact statement. The credential remains the
existing `Mcred` signature over instance/binding/rid, with its existing canonical
attributes and empty opening material. No recipient or session is silently added
to the signed credential. Those associations are enforced by the journals and the
original recipient publication contract. Holder secret material is never sent to
the issuer or stored in either authority database.

Issuer commit/publication fencing stays in the existing SQLite transactions. The
manager's final registered-witness read requires its current permit/head as well.
Recovery opens existing stores only with explicitly supplied independently retained
heads and permits. Missing, conflicting or unavailable manager reservation evidence
prevents reconciliation; there is no guessed rid, extra allocation or certificate
reconstruction. Existing complete PENDING/CERTIFIED phases are preserved, while
incomplete INTENT/RESERVED/SIGNING phases retire as specified above.

Both after-commit crash tests use a **trusted test coordinator** that retains the
exact manager and issuer heads at the application barrier before killing the child.
The recorded heads are then supplied explicitly on reopen. This tests recovery with
that independent evidence available. It does not solve loss of both an acknowledgement
and all independent freshness evidence, or permit automatic admission from a merely
self-consistent database. The coordinator's barrier observations are test instrumentation,
not a new deployment protocol.

## Intervening revocation and proof boundary

R-019 and the existing issuer implementation place final ordered DID/state reads
immediately before certification. A revocation **before** the registered-witness
read changes the reference and aborts issuance, even if it revoked a different
allocated identifier. The pending challenge is not silently rewritten to the new
state. Revocation of the reserved rid also aborts. Both cases retain the permanent
allocation and consume no new identifier on retirement.

A revocation **after** the final ordered read can precede the separate issuer
certification COMMIT. The reference contract permits a credential with its original
issuance checkpoint in this ordering. The test deliberately revokes the newly
reserved rid during credential signing: holder acceptance of the original signed
checkpoint succeeds, while the actual manager state is already epoch 1 with that
rid revoked. This is **not current non-revocation or authentication**. Subsequent
witness/freshness checks must use the later state. This result preserves the existing
contract; demanding one current state across both service commits would be a new
cross-service ordering obligation, not an implicit property of this implementation.

Normal `Dependencies.proof_verifier=None` still selects the unchanged
`UnsupportedEnrolmentVerifier`. The integration module defines/imports no permissive
proof adapter and has no request/configuration switch selecting one. The negative
normal-default case fails certification. Positive tests explicitly provide the
existing **test-only** verifier through trusted fixture construction. It accepts
only an exact canonical enrolment statement/token pair whose holder relation was
locally evaluated in that fixture; a changed token is rejected. This does not execute
or verify a cryptographic proof. Test helpers are absent from ordinary source imports.

`accept_delivery` decodes the unchanged bounded local `IssuedRecord`, validates it
through the existing record checks and calls `HolderAcceptance.accept`. Acceptance
commits credential and witness together only after the original holder intent checks.
It provides neither crash-durable wallet state nor a current-state/anonymous-proof claim.

## Individual outcomes

[New tests](../tests/integration/test_durable_issuance.py) use
[isolated fixtures](../tests/integration/durable_issuance_cases.py), synthetic keys
and temporary 0700 store directories. Existing bounded DID/controller setup helpers
are reused, not their historical test invocations. Each fixture starts from a trusted
synthetic allocation prefix of one; its issuance reserves rid 1 and advances the
prefix to two. No expanded private keys are written to evidence or authority stores.

| # | Individual case / parameter | Result | Durable and release observation |
| --- | --- | --- | --- |
| 1 | Successful issuance and atomic holder acceptance | PASS | One certification, one new permanent reservation; holder accepts credential/witness together and repeated acceptance is REPLAY |
| 2 | Exception after reservation, before attachment | PASS | INTENT plus permanent reservation; reopen/reconcile retires with issuer floor 2, no certificate or extra allocation |
| 3 | Exception after certification COMMIT, before ack | PASS | Complete CERTIFIED survives; stale caller cannot deliver; explicit retained-head recovery redelivers exact bytes with no signature/allocation |
| 4 | Complete PENDING restart/resume | PASS | Same nonce, rid and statement retained; explicit finish certifies and holder accepts |
| 5 | Duplicate begin, identical inputs | PASS | Operation conflict; exact preceding durable state and allocation preserved |
| 6 | Conflicting operation reuse, different session | PASS | Operation conflict; no second reservation |
| 7 | Wrong recipient | PASS | Committed certificate remains; wrong recipient receives no bytes |
| 8 | Wrong instance in signing configuration | PASS | Integration admission rejects, both stores unchanged |
| 9 | Mismatched manager reservation mapping | PASS | Attachment rejects; manager reservation stays permanent, INTENT explicitly retires |
| 10 | Mismatched credential rid on delivery | PASS | Holder remains empty; original committed certificate unchanged |
| 11 | Stale issuer writer generation | PASS | Finish signs nothing; PENDING and permanent reservation remain, no certificate |
| 12 | Stale manager authority during issuer recovery | PASS | Issuer checkpoint admission denied; no delivery or automatic manager refresh |
| 13 | Missing cross-service reservation evidence | PASS | Reconciliation rejects with no state change or reconstruction |
| 14 | Reserved rid revoked before final read | PASS | Certification fails, SIGNING retires, prefix remains 2 and manager epoch 1 |
| 15 | Different rid revoked before final read | PASS | Reference mismatch still aborts; original challenge is not substituted |
| 16 | Reserved rid revoked after final ordered read | PASS | Original issuance checkpoint accepted, certification logged; manager already records the rid revoked at epoch 1; no current-eligibility claim |
| 17 | Normal unsupported proof adapter | PASS | No certificate/release; SIGNING explicitly retires |
| 18 | Injected synthetic verifier rejects changed token | PASS | Same fail-closed result, no certificate/release |
| 19 | Credential entropy-failure boundary | PASS | No certificate/release; retirement retains rid and nonce |
| 20 | Required certification commit failure | PASS | Rows roll back to SIGNING; no releasable outcome; explicit retirement retains reservation |
| 21 | Holder intended-state mismatch | PASS | Holder remains empty; committed historical credential unchanged |
| 22 | Enqueue succeeds but return is interrupted | PASS | Already queued bytes match subsequent redelivery; no signing/allocation; holder accepts once |
| 23 | Real SIGKILL after manager reservation COMMIT | PASS | Manager reservation and issuer INTENT recovered; explicit retirement preserves rid without certification |
| 24 | Real SIGKILL after issuer certification COMMIT | PASS | CERTIFIED preserved; exact stored response hash/bytes redelivered; holder accepts, no resigning/allocation |

All 24 are individually counted, including each parameter value. The two selections
are `-k "not test_real_process_crash"` (22 cases) and `-k test_real_process_crash`
(two cases). No hidden test loop or suite replay increases that count. JUnit:
[integration](data/s2_durable_issuer_manager_integration_1/focused.xml) and
[crashes](data/s2_durable_issuer_manager_integration_1/crashes.xml). Individual
resulting phases, head digests, allocation/floor/certification/nonce counts and fault
labels are in [integration state evidence](data/s2_durable_issuer_manager_integration_1/case-evidence-focused.json)
and [crash evidence](data/s2_durable_issuer_manager_integration_1/case-evidence-crashes.json).

The 22 cases took **24.72 s pytest / 25.011384103 s guarded wall time**; the two crash
cases took **3.47 s pytest / 3.710920457 s guarded wall time**. The
[worker](../tests/integration/durable_issuance_worker.py) was actually SIGKILLed and
reaped (PIDs **2409881**, **2409888**, exit **−9**). Test-only exceptions and core
error injection are separate from those crashes. The child adds an eight-second CPU
and twelve-second alarm bound, and the parent waits at most ten seconds for a barrier.
Only one owned child runs; it remains inside the capped worker cgroup and all pipes
are closed. Cleanup removes only the fixture's temporary directory.

Neither injected exceptions nor these application-barrier crashes establish
power-loss durability, SQLite-internal arbitrary crash coverage, storage-device
failure handling or coordinated whole-store rollback protection. Independent
authority freshness, trusted operator configuration and honest local storage remain
part of the stated reference model.

## Resources and preservation

[Configuration](data/s2_durable_issuer_manager_integration_1/config.json) records
the test amendment and carried time/output charges. The
[ledger](data/s2_durable_issuer_manager_integration_1/run-ledger.json) records every
expanded command and effective limits. The driver command is:

```sh
.venv/bin/python -I -B docs/data/s2_durable_issuer_manager_integration_1/run_checks.py NAME
```

Sequential names are `preflight`, `imports`, `source-format`, `focused`, `crashes`,
`final-source-format`, `quality`, `format`, `prepare`, `full-audit`; `close.py` then
does bounded write-once bookkeeping. These transient private-network validation
workers do not activate the isolation pilot or live authority services.

Ceilings are unchanged: one worker, two CPUs, four controlled processes (at most
worker + pytest + one owned child here), 256 MiB cgroup memory including descendants
and charged cache/kernel memory, zero swap, 60-second command / 55-second child,
8 MiB temporary data, cumulative 10 MiB output, 1 MiB per file, 60 KiB diagnostics,
existing 9 GiB experiment-storage stop and 2 GiB memory headroom reserve. Previous
output charge **1,114,487 bytes** carries forward. Sampled tree RSS is recorded
separately and may count shared pages more than once.

The corrected auditor is unchanged. It compares the original 8,759 paths and the
complete disjoint additive seal chain, checks inventory and preserved report
prefixes, and requires completed reporting plus the outer guard under the same
**256 MiB** ceiling. There is one complete audit, no baseline regeneration or
unmonitored helper scan. Final measured closure follows below.

New implementation is `src/pqdid/durable_issuance.py` plus three integration
test/helper files. This report and package evidence are new; status/traceability/issues
are append-only. The manuscript, active parameters, dependencies, original fixtures,
bounded core/adapters, manager/issuer storage implementation and all historical
evidence are preserved. No installation, host mutation/activation, estimator campaign,
circuit, proof generation or zkVM execution occurred.

## Disposition and next package

This package demonstrates **reference lifecycle integration with synthetic proof
acceptance** across the specified separate commits, conservative reconciliation,
exact recipient-bound stored redelivery and atomic in-memory holder acceptance.
It advances the specific issuer/manager release obligation; it does not complete
production signing or full lifecycle/security readiness.

Open obligations include real enrolment-proof verification, durable holder storage,
verifier integration, authenticated deployed transport and actual-ID isolation,
independent recovery freshness when evidence is lost, production key custody/entropy,
reliable erasure, side-channel/fault resistance, power-loss/rollback assurance,
DEP-001 adaptive `Delta_tail`, component reduction-budget advantages, SEC-001–005,
OC-REL/EXT/PRIV/BUDGET and complete proof knowledge/privacy. Stages **2–3 remain open**.

One bounded next recommendation: **S2-DURABLE-VERIFIER-LIFECYCLE-INTEGRATION-1**,
connect the existing durable verifier consumption contract to bounded request/current
adapters using synthetic public statements and an explicitly injected test verifier,
with normal proof verification still fail-closed. Plan against the three remaining
invocations or obtain an explicit amendment before exceeding them. No next package
is started. Isolation remains safely stopped/unactivated; proof ledger **two used,
one unused**.


## Measured validation closure

The single [complete preservation audit](data/s2_durable_issuer_manager_integration_1/result.json)
passed content/inventory comparison, report readback and its outer resource guard,
exit **0**. Coverage: 8,759 original and
1,050 supplementary paths,
**9,809 disjoint content paths**,
9,827 identity-inclusive paths.
No unexpected changes, additions or removals occurred. Three historical reports
have verified append-only prefixes; all pre-existing source/vectors/parameters,
manuscript, dependencies and original evidence are preserved. The only new source
is the separate integration module and three integration test/helper files.
Lint and formatting pass.

| Measurement | Result |
| --- | --- |
| Audit wall time | 2.369247573 s |
| Audit cgroup memory.peak | 23,175,168 bytes |
| Audit sampled process-tree RSS | 41,336,832 bytes |
| Maximum guarded-job cgroup memory.peak | 89,354,240 bytes, below 268,435,456 |
| Maximum observed guarded-job tree RSS | 113,537,024 bytes; separate metric |
| Guarded commands | 10, 31.887861752 s total; all checks completed successfully |
| Cumulative implementation charge | **85.601982479/300 s** |
| Remaining implementation allowance | **214.398017521 s**, **3/148 test invocations** |
| Test invocations | 121 previously charged + 22 integration + two crash cases = 145; no repeats |
| Functional failures/resource breaches | 0/0 in this package; all historical evidence retained |
| Temporary storage | 282,550 observed peak bytes; zero retained |
| Package bytes at outer audit completion | 361,715 |

The audit's unchanged **256 MiB** metric is cgroup-v2 memory.peak for the complete
worker/descendant tree, including charged file-cache/kernel memory; swap is zero.
The cumulative time includes 48.714120727 s previously charged and five new
bookkeeping seconds; analysis and isolation time were not borrowed.
The external RSS sample can count shared pages more than once. No execution/proving
cost inference is made. The final bookkeeping has a separate 256 MiB address-space,
CPU/alarm-five-second, two-CPU and 1 MiB-file bound, within the five-second charge.
It checks new outputs, exact names, links and report prefixes, then writes the
[closure](data/s2_durable_issuer_manager_integration_1/validation-closure.json) and
[new additive seal](data/s2_durable_issuer_manager_integration_1/manifest.json) once; it does
not repeat the protected content scan or regenerate a historical baseline.

Analysis **270.181481168 s** and isolation **250.22 s** remain untouched. Stages
2–3 remain open; DEP-001/002 production obligations, adaptive Delta_tail, side
channels/erasure and complete private-proof knowledge/privacy remain unresolved.
Isolation stays safely stopped/unactivated. No proof/zkVM/activation occurred;
proof ledger two used/one unused. Next recommendation remains the bounded
**S2-DURABLE-VERIFIER-LIFECYCLE-INTEGRATION-1**; it is not started.
