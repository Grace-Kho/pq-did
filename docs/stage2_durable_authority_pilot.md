# S2-DURABLE-AUTHORITY-PILOT-1 — bounded local durability pilot

19 September 2026. **The local SQLite storage, manager reservation, verifier
consumption and issuer reconciliation pilot is implemented.** There are **38 distinct
passing focused cases and 28 unchanged lifecycle regressions**, including both
original unsafe-restart controls. Eighteen recorded application-barrier SIGKILLs
terminate only fixture-owned children. This is application process-crash evidence,
not production recovery approval, host power-loss evidence or whole-store rollback
detection. Stages 2–3 remain open.

Read [AGENTS.md](../AGENTS.md), the [authority design](stage2_recovery_authority_design.md),
[admission contracts](stage2_recovery_admission.md), [lifecycle review](stage2_lifecycle_review.md),
source, status and issues. Only manuscript **Sections II–VIII** and SPEC-001–004 are
authoritative. The manuscript SHA-256 remains
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
No primitive, signed context, protocol encoding, parameter, dependency, manuscript,
original vector or historical experiment was changed. CPU proving stays paused:
**two attempts used, one unused; no proofs or zkVM executions**.

## Implementation and ownership

New implementation files are [local records](../src/pqdid/persistence/records.py),
[bounded codec](../src/pqdid/persistence/codec.py),
[SQLite store](../src/pqdid/persistence/sqlite_store.py) and
[durable facades](../src/pqdid/persistence/lifecycle.py), plus their package initializer.
The [tests](../tests/integration/test_durable_authority.py) and
[child worker](../tests/integration/durable_worker.py) are separate new files.
All pre-existing source and tests remain unchanged. The three existing documentation
change authorisations are exactly `docs/status.md`, `docs/traceability.md` and
`docs/spec_issues.md`; no directory exclusion or regenerated baseline is used.

Each database pins schema/codec version 1, role, service/authority IDs, complete
canonical parameters, namespace and verifier audience against independently supplied
`ServiceKey`. The pilot supports manager, issuer and verifier identities; the other
four durable roles reject. A/B use separate verifier files, challenges and audience
bindings. Manager rows receive opaque issuer/issue identities and reservation data,
not attributes, evidence or certificates. Issuer intents and certificates remain
issuer-local. Verifiers receive public statement/token fixtures only.

`SQLiteStore.initialise` requires explicit administrative authorisation, exclusive
new-file creation and a validated complete checkpoint. `mode=rw` recovery never
creates a missing file or migrates/reset an incompatible schema. Absolute canonical
paths, no symlink components, owner identity, private parent mode 0700, database
mode 0600, single hard-link identity and bounded expected sidecars are checked.
The guard uses umask 0077. Incomplete bootstrap storage remains quarantined.

There is **no default operator permission**: the default policy is `DenyAll`.
The fixture operator, recipient identities, provider and proof adapter are explicitly
TEST ONLY in the child helper. They are not production authorisation. The pilot
uses one shared WSL UID; separate files and policy checks do not establish hostile
cross-role OS isolation. Production role principals, private IPC endpoints, key
ownership and authenticated recipient channels remain deployment requirements.
The authorised owner inspection interface necessarily sees its own private state;
Python private members and raw SQLite/file access are not an adversarial sandbox.

## Runtime, bounds and enforcement

The [configuration](data/s2_durable_authority_pilot_1/config.json) was written before
pilot execution. The [runtime readback](data/s2_durable_authority_pilot_1/runtime-facts.json)
reports actual linked SQLite **3.46.1**, source ID
`2024-08-13 09:16:08 c9c2ab54ba1f5f46360f1b4f35d849cd3f080e6fc2b6c60e91b16c63f69aalt1`,
using the existing Python 3.14.4 environment. No install, upgrade or WAL experiment.
The design's installed distribution/library observations remain historical context;
the new evidence is actual connection readback, not a new vendor-patch claim.

Every relevant connection checks existing DELETE mode, applies and reads back:

```text
journal_mode=delete; synchronous=3 (EXTRA); locking_mode=normal
foreign_keys=1; read_uncommitted=0; busy_timeout=0; temp_store=2 (MEMORY)
mmap_size=0; cache_size=-2048; page_size=4096; max_page_count=128
```

Unexpected journal modes reject, rather than being converted. Private-cache URI
connections disable extensions and ATTACH. Explicit SQL BEGIN IMMEDIATE / COMMIT /
ROLLBACK is used with Python `autocommit=True`. Connection exit rolls back an active
transaction and closes it even after an exception. No automatic retry or lock wait.
A database error or uncertain COMMIT yields unavailable, never assumed success;
recovery must explicitly inspect/reconcile the durable state.

| Resource | Unchanged admission/enforcement |
|---|---|
| Entire worker tree | 256 MiB cgroup-v2 MemoryMax, swap 0; supplementary sampled aggregate VmRSS ceiling 256 MiB; monitor outside cgroup |
| Work/concurrency | One guarded command via file lock; two CPUs/200% quota; one pytest worker and at most two owned children concurrently, within the four-controlled-process design allowance |
| Time/cases | 60 s command, 55 s command-child deadline, 300 s aggregate; child barriers have finite 10/12 s deadlines; 100 selected-case ceiling |
| Disk/output | Experiment 10 GiB / stop 9 GiB; diagnostics 64 MiB / stop 60 MiB; new package 10 MiB; command log stop 60 KiB; inherited RLIMIT_FSIZE 1 MiB |
| Local storage | SQLite file 512 KiB, 4096-byte pages × 128; sidecar checked at 512 KiB; encoded container/response ≤64 KiB; ≤128 operations and role entries; retained heads/checkpoints; no eviction or GC |
| Temporary storage | Aggregate 8 MiB monitored, including fixture databases and journals; fixtures cleaned between cases; temp_store=MEMORY; no unmonitored helper work |
| SQL | Length 256 KiB for row overhead, SQL text 16 KiB, 64 parameters, ATTACH 0; connection progress callback interrupts at 100,000 VM steps; busy timeout 0 |
| Environment | ≥256 MiB + 2 GiB MemAvailable admission; PrivateNetwork with no routes; no remote service, proof backend or zkVM |

These are lower pilot storage admissions within the inherited envelope, not support
for every maximum-size reference checkpoint. Combined local containers can reach the
64 KiB limit before individual fields do. SQLite FULL, row exhaustion or VM interruption
ends that operation without advancing the head. The isolated negative tests deliberately
exercise these application limits; no outer resource guard fired or was increased.
SQL progress cannot interrupt an arbitrary filesystem flush; the external deadline
remains necessary.

## Commit, admission, fencing and publication

The schema uses a singleton service binding, content-addressed complete checkpoints,
immutable ordered heads, unique 32-byte operations with exact requests and outcomes,
and unique role-entry keys. Foreign keys, exact schema comparison, quick_check,
head-chain commitments, current checkpoint digest and entry commitments are checked.
Role uniqueness is enforced by typed transitions and the unchanged recovery validators:
permanent manager prefix plus issuer/issue map, issuer session/nonce/certification
associations, and verifier nonce tombstones. No caller-supplied SQL or generic public
mutation interface is exposed.

The non-executable local binary codec whitelists existing frozen recovery types,
uses explicit framing and bounded byte/node/depth counts, rejects truncation/trailing
bytes, then invokes the existing typed recovery admission and bounded cryptographic
checks. The embedded protocol encodings remain unchanged. Recovery loads the complete
checkpoint from the authority transaction; it does not accept a substituted stale
service image. An expected `HeadTicket` includes sequence, head/checkpoint digests
and generation, including authority-only changes.

| Operation | Durable/effective point and failure behaviour |
|---|---|
| Initialise | One schema/service/checkpoint/head transaction commits before returning the initial ticket; failed or missing recovery storage cannot select this branch |
| Acquire/replace writer | Authorised expected-head transaction inserts the immutable grant operation/outcome, increments the positive signed-63-bit generation and advances the head; lost grant response retains the consumed generation |
| Manager reserve | Validate expected authenticated state, derive the next zero-leaf allocation, then commit full incremented checkpoint, immutable issuer/issue reservation, outcome and head before ALLOCATED; failure before COMMIT preserves the previous prefix |
| Verifier register | Commit complete context/state/nonce reservation before REGISTERED; no nonce recycling; this pilot does not expose a new request-signing service |
| Verifier consume | Existing public ReferenceVerifier performs its checks; private durable store rechecks full context/session/audience and current strict expiry inside the transaction; tombstone/checkpoint/outcome/head commit is the single acceptance point |
| Issuer intent/attach/pending/claim | Each phase has its own durable operation and checkpoint/head/journal transaction; approved intent/outbox commits before manager contact; signing-attempt generation/sequence is pinned before accepting a signing result |
| Issuer certification | Bounded validation of exact issued credential/witness and associations; complete certification log, CERTIFIED session/journal, exact response and head commit before any credential publication |
| Credential publication | Separately authorised original recipient; current writer and exact head rechecked under BEGIN IMMEDIATE, then one nonblocking AF_UNIX SEQPACKET send while the writer lock excludes replacement; enqueue is the publication point, transaction rolls back its read-only work on exit |

Each mutation checks active principal/generation and expected head inside its actual
write transaction. Superseded writers fail even with a previously open facade.
An exact manager operation retry with its original full request/prior ticket returns
ALREADY_COMMITTED and the existing reservation without a second allocation. Changed
operation contents conflict. Exact grant retry can recover the still-current grant
without incrementing it. There is no timed takeover or counter reset.

The durable facades privately reuse existing validation/pure candidate work, rather
than exposing a recovered mutable reference service to callers. Unsupported manager
revocation/current-signing, verifier request-signing and full issuer begin/finish APIs
are absent from these durable facades. Their legacy constructors remain trusted live
reference interfaces and are not covered by the pilot's durability claim.

Verifier replay follows the existing contract: after durable consumption, ordinary
verify returns UNKNOWN, not another ACCEPTED; internal repeated consumption cannot
produce a second acceptance. Outcome metadata is not an application business action.
The generic publication path permits only CERTIFIED issuer outcomes, never verifier
acceptance redelivery.

Signing generation/sequence and the caller's signing ticket must match the actual
current head. A delayed result is not relabelled onto a replacement generation.
There is no automatic signing invocation or retry in the journal API. Publication
rejects a stale permit/head or wrong recipient, and nonblocking queue failure leaves
the already committed credential intact. A packet enqueued before replacement can
arrive afterwards; replacement cannot recall those bytes. Local retrieval returns
REDELIVERY with exact stored bytes, not a new credential or fresh protocol success.

## Issuer reconciliation across separate databases

The issuer journal is an owner-private pilot adapter, not a second implementation
of the enrolment protocol. The configured issuer policy must supply approved intent
and authorise the one signing attempt after required protocol checks. Tests reuse
an existing valid certificate and explicitly labelled public proof tokens; they do
not install a permissive production signing/proof path. Production bounded signing,
real proof verification and end-to-end durable begin/finish integration remain open.

| Persisted interruption state | Explicit recovery action |
|---|---|
| Intent committed, manager confirms no reservation | Retire session conservatively; retain intent/outbox identity. A delayed already-authorised reservation can become a permanently spent manager orphan |
| Manager reservation committed, issuer attachment absent | Look up the exact issuer/issue/ref mapping, attach its rid to retirement metadata; retain manager allocation; never substitute a new rid |
| Attachment committed, no complete pending challenge | Retire the session and retain rid; no new challenge/signing retry |
| Complete PENDING | Preserve PENDING and retained nonce/challenge; a separately authorised explicit finish/claim may proceed |
| SIGNING with no committed certification | Retire the session, nonce and rid; an unlogged signature is discarded; never sign automatically again |
| Certification transaction interrupted before COMMIT | SQLite restores the old SIGNING state; reconcile to retirement |
| Certification COMMIT completed, response/release lost | Preserve CERTIFIED and exact bytes; ordinary finish/log rejects; separately authenticated original recipient can retrieve the committed result |
| Missing/unavailable/conflicting manager authority | Reject/quarantine; no reservation reconstruction, certificate recreation or cross-store compensation |

Checkpoint PENDING may coexist with an authority-only SIGNING marker. The durable
journal facade uses that marker to prevent another claim; it is not passed off as
an ordinary recovered issuer ready to finish. Reconciliation produces a valid
ABORTED checkpoint or preserves PENDING/CERTIFIED. The complete journal is covered
by the head, even when the old checkpoint digest itself has not changed.
Manager and issuer databases are deliberately separate transactions. The tests
exercise the gap between their commits, including a late orphan; there is no ATTACH,
two-phase commit, cross-store atomicity claim or reservation deallocation.

## Validation and recorded failures

Commands are preserved exactly in the [run ledger](data/s2_durable_authority_pilot_1/run-ledger.json)
and individual service records. They use `.venv/bin/python .../run_checks.py NAME`;
pytest disables plugin autoload and cache/bytecode writing. Native fixture signing is
ordinary **test-only, uncapped signing**, reused solely to make valid synthetic inputs.
All credential/state validations still use existing bounded verifiers. Controlled
proof tokens are not proofs or receipts.

| Focused cases | Count | Observed outcome |
|---|---:|---|
| Manager SIGKILL before BEGIN, after BEGIN, after row writes, after COMMIT/before acknowledgement | 4 | Fresh process sees exactly old prefix/head or complete next allocation |
| Runtime/default-deny/binding/codec; lost response/conflict/stale same-root checkpoint | 2 | Settings read back; invalid import denied; same reservation recovered once; stale admission refused |
| Two contenders for transition or replacement; paused old writer and BUSY | 3 | One new allocation/grant, bounded BUSY/conflict or exact prior grant; superseded process cannot commit |
| Verifier pre/post-consume crash across A/B; register/audience/final expiry/fence | 3 | Only committed consumption survives; A replay UNKNOWN, B independently accepts once; expiry/audience/fence reject |
| Issuer intent, manager reservation, attachment, pending, signing, pre/post-log and pre/post-enqueue cuts | 9 | Fresh-process journal reconciliation follows the table above; retained rid, nonce and certificate counts checked |
| Delayed certificate and exact-recipient publication | 2 | Old generation/signing ticket rejected; same committed certificate only; already queued pre-replacement packet remains valid |
| Missing, malformed, missing checkpoint/outcome, wrong schema, symlink | 6 | Recovery unavailable; no empty bootstrap or successful effect |
| SQL VM, real SQLITE_FULL and 128-operation cap | 1 | Each bounded failure preserves the previous head; no limit increase |
| Independently started old process delayed at signature, release or proof result | 3 | Replacement fences certification, publication and consumption at their actual effect boundaries |
| Writer-grant pre/post-commit kills | 2 | Old or complete new generation; a committed unused grant remains consumed |
| Late orphan/missing cross-store authority; saturated publication; strict counters/overflow preflight | 3 | No rebinding/recreation, no partial publication success and no head advancement on exhaustion |
| **Focused total** | **38** | **All distinct cases pass** |
| Original lifecycle regressions, including two unchanged unsafe controls | **28** | **Pass with their original meanings** |

There were **69 executed case instances**: 66 distinct successful cases and three
failed development invocations, each subsequently resolved. Completed unaffected
cases were reused, rather than rerunning entire suites. Failures remain in their
original XML/logs, STOP records and [correction 1](data/s2_durable_authority_pilot_1/correction1.json),
[correction 2](data/s2_durable_authority_pilot_1/correction2.json),
[correction 3](data/s2_durable_authority_pilot_1/correction3.json):

1. Two contender processes could overlap admission before the intended race barrier.
   The harness now admits/pauses the first before starting the second, then releases
   both to race the transition. Six completed cases were retained.
2. The new verifier wrapper supplied positional arguments to a keyword-only existing
   constructor. Corrected the API call and preserved the final EXPIRED decision;
   added explicit signing-generation binding and delayed-process checks. Three more
   completed cases were retained.
3. A synthetic socket buffer was smaller than the credential packet, producing
   EMSGSIZE rather than EAGAIN. Publication already failed closed. The corrected
   bounded fixture fills an individually adequate buffer to test queue saturation;
   three more completed cases were retained.

A separate pre-finalisation lint-edit invocation reported four E501 lines in the new
audit driver. Its log and [formatting correction](data/s2_durable_authority_pilot_1/correction4.json)
are also retained; this was not an additional test case or functional failure.

No failure was a memory/time/storage guard failure. Resource events are checked
before admitting the explicitly documented corrections; command names/evidence are
not overwritten. All work shares the same 300-second budget.

Per-case evidence is in [initial cases](data/s2_durable_authority_pilot_1/case-evidence.json),
[corrected contenders](data/s2_durable_authority_pilot_1/case-evidence-focused-corrected.json),
[remaining cases](data/s2_durable_authority_pilot_1/case-evidence-focused-final.json),
[additional boundaries](data/s2_durable_authority_pilot_1/case-evidence-scoped.json) and
[final boundary checks](data/s2_durable_authority_pilot_1/case-evidence-scoped-final.json).
Records include commands, PIDs, named barriers, owned-child SIGKILL/exit status,
checkpoint/head/generation observations, allocation/consumption/certification counts,
child wait4 peak RSS and CPU time, case wall time and sampled temporary bytes.
Failed early harness cases have partial child observations and retain their full
command-level guard/log evidence; they are not claimed as complete crash results.

The largest test-command cgroup `memory.peak` was **95,236,096 bytes (90.82421875 MiB)**;
largest supplementary sampled aggregate VmRSS was **147,095,552 bytes (140.28125 MiB)**.
The former includes charged anonymous memory, file cache and kernel memory for the
worker and descendants. RSS can count shared mappings more than once. These metrics
are deliberately separate. No memory-max, OOM or swap event occurred. The largest
focused command was **21.526897728 s**, below 60 s. Through regression, all ten
commands totalled **35.821951919 s**; final tooling/audit costs are appended below.

The largest recorded per-case temporary-file observation was **308,578 bytes**,
including journals visible at barriers. This is a sampled observation, not an exact
transient disk peak: parent-only SQL-pressure cases can grow and roll back between
observations. The outer guard independently sums all temporary files against 8 MiB;
SQLite page/file limits and the bounded store count also limit pressure. No hidden
helper or unmonitored content comparison was used. Fixture directories are removed
before the preservation audit. Parent `ru_maxrss` values are cumulative process
high-water marks, not incremental per-case allocations.

## Preservation and remaining obligations

Final lint/format and the single complete preservation audit passed; their final
measurements are recorded below. The audit reuses the corrected streaming/cache-bounded engine
under **256 MiB**, eight original pinned baseline identities and exact authorisations.
Content, inventory, report readback and final guard success are all required. A
comparison alone is insufficient. Original manager ceiling failure, later corrected
audit, experiment results, unsafe controls and two-used/one-unused ledger remain
protected. No baseline is regenerated from the workspace.

REC-001/002 now have real file-backed process-crash and intact-authority stale-cache
evidence for allocation and one-time consumption. REC-003/004/006/007 gain bounded
journal transactions, commit/publication fencing, log-before-release and explicit
conservative reconciliation evidence in these three pilot roles. STORAGE-001 gains
DELETE/EXTRA readback and application-crash tests on the installed runtime.

Still open: production role/admin/recipient authentication and OS/IPC isolation;
real issuer signing/approval/proof integration and durable operations outside this
pilot; registry/resolver/controller/wallet persistence; durable retention/backup and
capacity policy; host/WSL/power-loss/flush qualification; recovery after ambiguous
external business effects; whole-authority rollback (REC-005). An internally
consistent rolled-back DB can roll back its own heads, generations, allocations and
tombstones; matching its own checkpoint/head cannot detect that event. No external
non-rollbackable witness was introduced.

Bounded production key generation/signing, DEP-001/002, interoperability, full private
authentication/BC-1, selective-disclosure/non-revocation proof integration, CredValid
proof feasibility and privacy/security review remain open. An execution or local
process test is not proof/security evidence. **Recommended next bounded package:
S2-AUTHORITY-OWNER-BOUNDARY-1**, define and test the role-owned IPC/admin/recipient
boundary and recovery-grant handoff under the same envelope, with explicit test
principals and no proving. Production deployment remains blocked until that boundary
and the stated storage/rollback assumptions are resolved.


## Final preservation result

[One complete audit](data/s2_durable_authority_pilot_1/result.json) **passes**, exit 0,
with content/inventory comparison, report generation/readback and the outer resource
guard all complete. Wall time **2.111892061 s**; cgroup-v2 memory.peak
**24,236,032 bytes (23.11328125 MiB)**; supplementary sampled aggregate VmRSS
**41,484,288 bytes**; zero memory-limit/OOM/swap events. Temporary storage at completion
was **0 bytes**, and new package evidence occupied **447,835 bytes**
at guard finalisation, before this final report append and seal.

All **9,016 historical paths** are accounted for: 8,759 primary comparisons (8,756
unchanged and the exact three allowed documents), 250 unchanged supplementary paths,
and seven additional pinned manifest identities. Partitions are disjoint. The
**690-entry inventory** has no missing or unexpected names. All pre-existing source,
cryptographic code, tests, dependencies, manuscript and historical results remain
unchanged. Final lint/format pass. All **15 guarded commands**, including retained
non-resource failures, total **38.300096529 s** within the original 300 s allowance.
The final [manifest](data/s2_durable_authority_pilot_1/manifest.json) seals new files and
the exact three allowed documents; it does not regenerate any original baseline.
Post-guard work is limited to these result appends, local-link checks and the small
new-file seal; the complete historical content scan is not repeated.

The pilot package is complete. Deployment recovery and Stages 2–3 remain open for
the obligations above. No proofs or zkVM executions; ledger unchanged at two used,
one unused, with CPU proving paused. Next recommendation remains the bounded
S2-AUTHORITY-OWNER-BOUNDARY-1 package; no further implementation is started here.
