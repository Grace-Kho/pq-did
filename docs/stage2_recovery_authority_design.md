# S2-RECOVERY-AUTHORITY-DESIGN-1 — authority, fencing and interrupted issuance

19 September 2026. **Recommend a role-owned local authority broker and one SQLite
database per role/service instance, using `journal_mode=DELETE` and
`synchronous=EXTRA`.** Store the complete private checkpoint, authority head,
operation journal and committed outcomes in the same role transaction. Fence every
protected commit and publication with an authorised writer generation and expected
prior head. Coordinate manager and issuer through durable operation identities and
explicit reconciliation, without a transaction across their stores.

This is a **design**, not implemented protection. It targets process termination,
competing reference writers and stale service-checkpoint restoration while the role
authority store remains intact. A local database cannot detect restoration of its
own older, internally consistent contents. Simultaneous rollback of service and
authority storage remains outside the first implementation's guarantees. Production
recovery, Stages 2–3 and the proof/security obligations remain open.

## Scope, inputs and evidence

Read [AGENTS.md](../AGENTS.md), the [recovery implementation](../src/pqdid/recovery.py),
[typed records](../src/pqdid/recovery_records.py),
[admission report](stage2_recovery_admission.md),
[lifecycle review and persistence requirements](stage2_lifecycle_review.md), existing
manager/issuer/verifier/DID commit and publication paths, status, traceability and
issues. Only manuscript **Sections II–VIII** and SPEC-001–004 are authoritative.
The manuscript SHA-256 was checked as
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
Local authority records and retry metadata below are engineering proposals; no
protocol signed context, suite, parameter or cryptographic encoding changes.

No production/reference source, test, dependency, manuscript or historical evidence
was changed. No software was installed, persistent SQLite database opened/created,
WAL enabled, crash experiment, functional test, proof or zkVM execution run.
CPU proving stays paused at **two attempts used, one unused**. Existing functional
evidence is reused with its original scope and labels, including the 50 + 8 + 1
admission checks and 28 lifecycle cases; the original two unsafe controls remain
unsafe controls.

New evidence: [environment facts](data/s2_recovery_authority_design_1/sqlite-environment.json),
[filesystem/package facts](data/s2_recovery_authority_design_1/filesystem-package-facts.json),
[primary source register](data/s2_recovery_authority_design_1/sources.json),
[machine-readable design](data/s2_recovery_authority_design_1/design.json),
[runner](data/s2_recovery_authority_design_1/run_checks.py) and
[preservation scope](data/s2_recovery_authority_design_1/scope.json).

## 1. Authority, ownership and failure model

The authority is a **role-local broker under the existing role owner's control**,
with its own database and independently supplied configuration/authorisation policy.
It is authoritative relative to service memory and exported checkpoint copies.
It is not independent of that database's own rollback domain. A generic implementation
may be reused by roles; no shared superuser process or database receives everyone's
private checkpoints. Backups, logs and crash dumps require the same role isolation.

For a production deployment, each role broker owns its private directory, database,
SQLite journal and IPC endpoint under an appropriate OS principal. Workers get only
typed authorised IPC operations, not a database connection or pathname capability.
The initial local pilot uses explicitly labelled test principals; the current shared
WSL user and project directory mode 0755 do not establish cross-role access isolation.
Provisioning those principals, key access and recovery-admin credentials remains open.
Proposed runtime layout is each owner's private state root followed by
`pqdid-authority/<role>/<service_id>/authority.sqlite3`, with service checkpoint copies
outside that authority directory. The pilot uses disposable equivalents under its
new guarded evidence `tmp/` directory. Neither location is provisioned here. Separate
paths prevent a service-copy restore from implicitly replacing authority, but do not
create a different host/VHD rollback domain.

| Role / authority owner | Who authorises recovery and replacement | Latest committed state and freshness facts | Private boundary | If unavailable |
|---|---|---|---|---|
| Manager | Revocation/allocation operator, with a separately configured recovery-admin permission | Manager DB head and full allocation prefix, operation-to-rid map including orphans, revoked set, consumed request nonces and retained update history | Issuer identity and opaque operation correlations; no holder secret, attributes or credential log | No allocation, revoke, registered witness, current signature or authoritative update service |
| Issuer | Issuer operator and its recovery-admin policy | Issuer DB head, full approved sessions, manager reservation references, nonce reservations, signing-attempt markers, certifications and releasable outcomes | Evidence, attributes, controller binding, channel/recipient authorisation and credential results remain issuer-local | No new approval, finish, signing or release; existing private records remain inaccessible through service APIs |
| Verifier | Each audience's operator independently: A cannot grant authority for B | Separate DB per audience/service ID; all challenge reservations, full context/state, local DID-policy flag, consumed decision and operation outcome | Public statement/proof inputs only; private audience/session and consumption metadata never shared with the other verifier | No new challenge or acceptance; no empty-store fallback |
| DID registry | Registry operator | Registry DB head, all canonical genesis-to-tip chains, append outcomes, publication records and pinned registry configuration | Registry key handles stay with its broker/vault; public chains do not grant access to controller secrets | No authoritative append/current or historical signed reply |
| DID resolver | Resolver owner in its configured trust domain | Resolver DB head, configuration and every reserved read nonce, including failed requests | Query/nonce associations stay within that resolver; anonymous verification still performs no hidden-DID lookup | No trusted resolution; never reset read-nonce history |
| Holder controller | Holder's local controller owner, via independently authenticated local recovery permission | Controller DB head, confirmed reference, exact pending publication and possibly-active key-handle associations | Salt, private key handles and publication intents stay holder-local; vault contents are not exported to another role | No publication or pending reconciliation; preserve both possible keys |
| Holder wallet | Holder's wallet owner | Wallet DB head, original approved intent, accepted credential and complete current witness/state association | xH, credential, rid, path and intent stay holder-local, including recovery validation | No acceptance/presentation preparation from the recovered wallet; no reconstruction from issuer/public data |

Mapping to prior trust: the manager/registry already promise ordered authoritative
reads, the verifier assumes one atomic audience store, and issuer/holder state is
trusted and private. The proposal makes those local stores durable. **Stronger
assumptions** are a trusted non-Byzantine broker, secure recovery-admin provisioning,
exclusive ownership of all write/publication paths, reliable local SQLite locking
and storage flushes, and an authority DB that is not restored with stale service
copies. Root or the role-store owner can bypass these assumptions; hashes and SQLite
constraints do not protect against that administrator. No external rollback witness
is silently introduced or claimed to exist.

| Failure ID | Event | First implementation contract |
|---|---|---|
| F01 | Worker or broker process terminates, including SIGKILL around commit | Targeted: fresh process opens the same intact authority DB and recovers old or complete new transaction; lost response is reconciled from durable operation outcome |
| F02 | Host/WSL restart without storage rollback | Conditional design: same database and necessary journals survive, supported locking/fsync/VHD stack behaves correctly, and a new authorised generation is acquired. No WSL-restart/power-loss evidence is produced here or promised by process-kill tests |
| F03 | Missing/corrupt file, storage failure, I/O error or unavailable checkpoint/outcome | Detected inconsistency means quarantine/unavailable. Never initialise the same namespace empty or fall back to an older head; coherent undetected corruption is outside the assumed storage integrity model |
| F04 | Old service checkpoint restored while authority DB is current | Targeted: exact head/ticket/digest comparison rejects it, even when signed revocation root/epoch is unchanged |
| F05 | Service and authority database restored together, or authority alone restored consistently | Outside guarantee: generations, reservations and tombstones can all roll back consistently. The database cannot detect its own older valid contents; known/suspected restoration is quarantined, but undetected rollback is not guaranteed to fail closed |
| F06 | Old writer resumes or two replacements compete | Targeted: current generation, expected head and operation content checks at each protected boundary; old connections and PIDs confer no authority |
| F07 | Power loss, faulty host flush, damaged VHD or storage controller | Outside pilot evidence. Recommended SQLite settings are prerequisites, not a validation of the actual host/storage stack |
| F08 | Malicious role owner, raw SQL/file access or direct signer/publication bypass | Outside guarantee until access paths are closed and trusted ownership holds; ordinary SQLite does not enforce an application fencing policy against arbitrary writers |

Detecting F05 requires a separately administered, non-rollbackable witness or equivalent
external authority whose progress cannot be restored with these files. Its protocol,
privacy, availability, backup and operator trust policy is unresolved. An adjacent
signed manifest, timestamp, hash chain or second database in the same rollback domain
does not solve it. The initial pilot must state this assumption at admission.

## 2. Observed SQLite and selected storage contract

Read-only observation on 19 September 2026:

| Fact | Observed value / limit of observation |
|---|---|
| Existing interpreter | Python **3.14.4**, `.venv/bin/python`; no replacement |
| Actually linked SQLite | **3.46.1**, `/usr/lib/x86_64-linux-gnu/libsqlite3.so.0`; distribution package **3.46.1-9ubuntu0.3** |
| SQLite source ID | `2024-08-13 09:16:08 c9c2ab54ba1f5f46360f1b4f35d849cd3f080e6fc2b6c60e91b16c63f69aalt1` |
| Kernel | `6.18.33.2-microsoft-standard-WSL2` |
| Project filesystem | ext4 on `/dev/sdd`, observed `rw,nosuid,nodev,relatime,discard,errors=remount-ro,data=ordered` outside the guard; the guard deliberately presents a read-only bind mount |
| Block size / free bytes at guarded inspection | 4,096 / 1,014,231,744,512; neither measures truthful persistence to the physical host |
| Compile/runtime metadata | THREADSAFE=1, Python threadsafety=3, default synchronous=2, page size 4096, default mmap=0; full options retained in evidence |
| Query-only in-memory connection | journal `memory`, synchronous 2, foreign_keys 0, timeout 0. These are observation defaults for `:memory:`, not persistent DB settings or durability evidence |

SQLite's current documentation identifies the WAL-reset issue in upstream 3.7.0
through 3.51.2, with fixes in 3.51.3 and listed backports 3.44.6/3.50.7. It concerns
overlapping writers/checkpointers on multiple connections. The linked 3.46.1 is in
that upstream interval. The installed 7,091-byte distribution changelog has no
WAL/checkpoint/reset match; this does **not** prove the absence of a vendor patch.
WAL is unqualified here and is not selected. No dependency upgrade is performed.
[SQLite WAL-reset documentation](https://www.sqlite.org/wal.html#walreset).

WAL commits at its commit record; copying committed pages back to the database is
a separate checkpoint operation. A transaction spanning ATTACHed WAL databases is
not atomic across those files, and the WAL sidecar is part of persistent state.
Even a fixed WAL version would not make manager/issuer commits one transaction.
[SQLite WAL transaction and file rules](https://www.sqlite.org/wal.html).

Choose rollback `DELETE` with `EXTRA`: the latter adds directory synchronisation
after journal deletion, beyond `FULL`. SQLite warns that rollback `FULL` durability
near power loss depends on the filesystem. This conservative choice also avoids the
unqualified WAL path and suits the bounded single-writer pilot. It is a design
choice, not a performance result. [SQLite synchronous settings](https://www.sqlite.org/pragma.html#pragma_synchronous).

Proposed connection settings, applied and read back by the future owner before use:

```text
journal_mode=DELETE; synchronous=EXTRA; locking_mode=NORMAL
foreign_keys=ON; read_uncommitted=OFF; busy_timeout=0
temp_store=MEMORY; mmap_size=0; cache_size=-2048
```

Use private caches, no ATTACH, extensions, caller SQL, automatic migrations or journal
mode conversion on recovery. Reject an unexpected existing mode/configuration rather
than silently changing it. Missing existing storage is an error (`mode=rw`), not
creation. Trusted initial bootstrap alone creates a new identity/database using an
exclusive administrative operation, secure directory and pinned schema/configuration.
Private paths require canonical identity, no symlink substitution, mode 0700 directory,
0600 database/journal and umask 077; no shared-drive, `/mnt/c`, network or synchronised
folder is selected. Preserve hot journals: never copy just a live database file or
delete sidecars as cleanup. [SQLite corruption hazards](https://www.sqlite.org/howtocorrupt.html).

Use Python `autocommit=True`, explicit SQL `BEGIN IMMEDIATE`, `COMMIT` and `ROLLBACK`;
do not rely on `Connection.commit()`/`rollback()` in this mode, or infer a transaction
from a Python context manager. Parameters are bound, not interpolated. The Python
documentation consulted is current 3.14 documentation; the observed runtime remains
3.14.4. [Python transaction control](https://docs.python.org/3.14/library/sqlite3.html#transaction-control).

`BEGIN IMMEDIATE` acquires the write transaction up front and may report BUSY. A
failed COMMIT may leave a transaction active. On BUSY, rollback/close and return a
bounded unavailable outcome; do not loop. I/O/FULL/NOMEM/interrupt or an uncertain
COMMIT result closes the connection and requires a fresh operation lookup before
any further side effect. [SQLite transactions](https://www.sqlite.org/lang_transaction.html).
Separate connections serialise writes; no shared-cache/read-uncommitted escape is
permitted. [SQLite isolation](https://www.sqlite.org/isolation.html).

The durability contract requires correct locking, complete journal handling and
truthful flushes through Linux, WSL's virtual disk, the host filesystem and storage
device. Current read-only checks cannot establish those guarantees. A successful
SQLite COMMIT is the application's local effective point under these assumptions;
faulty storage can invalidate that assumption. [SQLite atomic-commit assumptions](https://www.sqlite.org/atomiccommit.html).

## 3. Records, uniqueness and atomic state availability

One database contains **one role and service identity**, with independently pinned
suite/pp/namespace and audience or registry identity as applicable. Multiple verifier
replicas for A must use A's authority; B uses a distinct authority and database.
No holder secrets are included in either verifier store. The following are proposed
local records, not new protocol formats or an already installed schema.

| Table / record | Proposed key and contents | Required constraints |
|---|---|---|
| `service` | Singleton role, service_id, authority/store ID, pp digest, namespace, optional audience/registry, schema version, active generation and head sequence | Exact match to independent trusted configuration; fixed byte lengths; no implicit create/migrate; one identity per file |
| `checkpoints` | Content ID, codec version, complete bounded typed checkpoint bytes, existing checkpoint digest and length | PK content ID; bytes re-decode to exact role record; digest/length checked; never external-only blobs |
| `heads` | Sequence, previous-head digest, checkpoint FK, journal/outcome commitment and writer generation | PK positive signed-63-bit sequence; complete referenced checkpoint exists in same transaction; one service tip; immutable committed heads |
| `operations` | 32-byte operation ID, kind, canonical local arguments/digest, authorised principal/recipient, expected prior head, origin generation, phase and outcome FK | PK operation ID within service; same ID with different kind/arguments/principal/expected prior head is CONFLICT; immutable request binding |
| `outcomes` | Operation ID, terminal decision, exact response bytes/reference, related reservation/certificate/challenge IDs | UNIQUE operation ID; complete result before success; private result bound to original authorised recipient; no regenerating missing responses |
| `writer_grants` | Administrative replacement ID, authorised new worker identity, expected old generation, new generation, supporting head/ticket | UNIQUE replacement ID and generation; request contents pinned; generation never reused, even for lost reply or unused grant |
| `events` / outbox | Ordered transition/phase event and immutable owner-authorised external request or publication intent | FK operation; unique operation/phase; no deleting uncertain or orphan effects; delivery observation is separate from protocol effect |

Role indexes add: manager `reservations(rid UNIQUE, issuer_service, issue_op UNIQUE,
manager_op UNIQUE, original_request_ref)` and permanent prefix; issuer session/nonce
uniqueness and one certification per reserved rid/session; verifier nonce PK with
monotonic consumed state; registry unique `(did,index)` and version/predecessor;
resolver nonce uniqueness; controller exact pending bytes/key references; holder
intent, accepted credential and complete witness pair. Keys and every byte/string/
tuple count are bounded before SQL or crypto. SQL NOT NULL, length/range checks,
foreign keys and uniqueness support the typed transition validator; constraints do
not replace authenticity or independent freshness.

`heads` must cover **authority-only** changes too: writer grants, signing-attempt
markers and delivery/coordination records may change while the existing checkpoint
digest remains identical. A new `HeadTicket(sequence, head_digest, checkpoint_digest,
expected_generation)` is local metadata. Existing `RecoveryBinding` remains unchanged,
but the concrete authority adapter pins this additional trusted ticket and checks it
at its final comparison. Comparing only the old three-field binding would miss such
transitions. The head commitment is an integrity link, not proof against F05.

Each protected transaction validates one permitted transition, inserts its complete
checkpoint and relevant journal/index/outcome/outbox rows, and advances the head
and writer metadata atomically. No head is durable before its checkpoint bytes.
Keep every referenced checkpoint/outcome within the finite store; first pilot has
**no garbage collection or eviction**. If storage admission cannot retain all required
data, reject the next transition before publishing it. A broken FK, missing blob,
digest mismatch or incomplete head on recovery quarantines the role; do not skip to
an older complete checkpoint. Authoritative and inspection caches are distinct.

The same-role DB transaction eliminates a service-state/authority dual-write window.
An exported checkpoint is only a copy: loss or staleness does not change the head.
The service must use the stored current contents, not rewrite authority to match a
supplied copy. Current data and journals remain private to the role owner. Cross-role
messages contain the minimum operation identity/result required by the existing
interface, never another role's whole checkpoint.

## 4. Writer acquisition, commits and publication fencing

Use positive **63-bit writer generations**, zero reserved for uninitialised state,
maximum 9,223,372,036,854,775,807. This is local metadata, not a protocol epoch.
No timed lease expiry or automatic takeover is selected; replacement requires
explicit authenticated owner/admin permission. At maximum generation or head/event
sequence, refuse advancement and require a separately reviewed migration. Never wrap,
reset or reopen under the same namespace as a fresh store.

Acquisition/replacement is a bounded `acquire(RecoveryAuthorisation, replacement_id,
expected_generation, HeadTicket)` call. The caller cannot authorise itself with a
checkpoint. The owner checks role/identity and admin policy, enters BEGIN IMMEDIATE,
compares both generation and full head ticket, and commits the unique next generation
and grant outcome. Competing replacements from the same predecessor cannot both win.
An exact replacement retry retrieves the recorded grant only if it is still current
and its authenticated worker identity is unchanged; it never increments again.
Different contents conflict. A later replacement invalidates the old grant even if
the old process still has a connection, checkpoint, token or signing result.

Proposed protected mutation contract:

```text
commit_transition(WriterPermit, operation_id, expected_head, typed_transition)
  preflight sizes and permitted role operation
  prepare/validate candidate without publishing or mutating the live service
  BEGIN IMMEDIATE
  check permit identity/principal AND active generation
  look up operation: different complete request => CONFLICT
  if exact committed operation: return an existing-outcome reference, no new effect
  otherwise check current head == expected_head and legal current phase
  write checkpoint + indexes + outcome + required outbox + next head
  explicit COMMIT; only then make the result available for publication
```

An already committed retry has the original expected predecessor, even though the
current head has advanced; authenticate its current permitted caller, compare its
original request exactly and retrieve the prior outcome before applying the new-work
head check. A pending operation may be continued only by its documented next phase
with a fresh expected head; it is not silently replayed as a new request. Phase
transitions have their own unique operation/phase key and immutable inputs.

Every allocation, nonce reservation, certification, consumption, DID append,
pending-key change and holder-pair installation uses this boundary. Prepare work
does not call an old mutating reference method and persist afterwards: that would
leave an unfenced effect. Signatures computed outside the transaction carry the
origin generation/head/operation/phase; bounded verification and a final fence precede
commit. A delayed signature from a superseded generation is discarded internally,
with no logging as a certification and no release. No automatic re-signing follows.

Publication needs fencing too. The owner broker is the sole protocol response path
and signer dispatcher; raw signed results are not returned to workers for arbitrary
later transmission. After preparing a reply, the broker acquires a short write
transaction, checks active generation and the required current head/operation, then
performs at most one nonblocking enqueue to its owned local transport while replacement
is excluded by that transaction. Failure/EAGAIN produces unavailable; no wait loop.
The enqueue is the logical publication point, followed by explicit ROLLBACK to
release this read/publication-only transaction.
No new state transition is hidden in this read/publication lock. State-changing
results and their outbox were already committed. Delivery acknowledgement can be
recorded separately and cannot undo or repeat the effect.

A reply queued before replacement may arrive afterwards: it linearised before the
replacement and is not a promise that the network receiver sees the latest state at
delivery. A reply not yet queued must pass the new fence. Signed current replies
must retain nonce binding and recheck the captured head after signing, as the manager
already does with its in-memory snapshot. Historical lookup still requires a current
writer permission, though its data reference is intentionally historical. No fence
can recall bytes already delivered or constrain a malicious actor holding a raw
signing key. Key access and all publication paths must obey the broker contract.

Within the existing `RecoveryAuthority.exclusive` interface, the candidate is first
validated off to the side. The concrete adapter starts the final transaction,
compares current `HeadTicket` and checkpoint, then prepares the writer grant while
the recovered facade is inaccessible. It yields the existing `RecoveryEvidence`,
and commits on successful context exit. A failed exit leaves admission rejected;
a durable but unused grant after a lost response is safely consumed. The writer
permit is kept privately by the durable facade, not added to a signed context.

**Current bypass remains explicit:** `RecoveredService.__getattr__` presently checks
only local admission and calls ordinary in-memory methods. Its authority context
does not intercept later commits or publication. The manager/issuer/verifier/DID
constructors, private assignments, direct signer calls and direct SQL/file access
would bypass durable fencing. Therefore injecting a SQLite `exclusive()` adapter
alone must not enable durable service traffic. The next implementation needs dedicated
durable role adapters and must test their actual commit/publication paths. Until
that integration exists for a role, durable admission for it stays unsupported.

All database attempts use timeout zero and **zero automatic retries**. A caller may
make one explicit outcome lookup or explicitly authorised continuation per invocation;
loops are not part of the API. Resource and operation deadlines bound preparation,
SQL work and IPC. SQLite progress limits cannot interrupt every kernel fsync, so
the enclosing process-tree wall deadline remains necessary. Connection-local cached
generations/heads never authorise later operations without a new transaction check.

## 5. Interrupted issuance and separate manager/issuer commits

The issuer first durably records an approved immutable intent, recipient/session
authorisation and a fresh opaque 32-byte `issue_op` with a manager-request outbox.
Its operation ID is drawn from the existing trusted randomness dependency with at
most eight collision attempts, then durably reserved; exhaustion stops. The manager
receives only the authenticated issuer service ID, opaque `issue_op`, expected
manager reference and exact allocation command. Attributes/evidence/controller
approval remain in the issuer's private intent; no low-entropy attribute hash is
exported as a new cross-role identifier.

The manager transaction binds `(issuer_service, issue_op)` once to the next rid,
increments the permanent prefix and stores the exact allocation outcome. The issuer
then attaches that outcome to **the same** approved intent in its own transaction.
An exact lookup can recover the allocation after a lost response even if the manager
head later advances. The manager never uses surviving certifications to reduce its
prefix, and neither side rebinds the rid/operation to different request contents.
Different contents under one operation ID conflict; an obsolete reference for an
uncommitted reserve returns conflict, not a silent new reference/approval.

There is no cross-store transaction or compensating deallocation. A committed manager
reservation without issuer attachment is an orphan that remains permanently spent.
An already durable issuer outbox authorises that exact manager operation once; it
may complete after the issuer worker is replaced. This is completion of a prior
authorised operation, not permission for the old worker to create a new one. All
new outbound requests require the issuer's current fence. Reconciliation queries
the manager by opaque operation identity; it does not expose issuer records or
pretend a remote generation check is atomic with a local commit.

The durable issuer journal adds intent, coordination and signing-attempt facts that
the current `IssuerRecord` does not carry. They belong to the authority head. After
reconciliation, it produces a complete supported PENDING, ABORTED or CERTIFIED
checkpoint for existing validation. PREPARING/CLAIMED are never changed merely to
make the current validator pass. Ambiguous outcomes remain quarantined until the
required durable records can be read consistently.

| Interruption | Durable evidence required | Allowed next action | Quarantine/refusal condition |
|---|---|---|---|
| Intent committed; manager call not known to complete | Exact approved intent/outbox and manager lookup for the same operation | One explicit lookup. If manager committed, attach its original rid; if absent, conservatively retire the intent. A delayed previously authorised reserve can still become a permanently retained orphan | Manager unavailable, mismatched operation contents or missing issuer intent. Absence alone must not cancel an in-flight authorised reserve |
| After permanent reservation, before issuer attachment | Manager operation-to-rid/outcome plus matching issuer intent | Attach exact outcome and retain rid; retire if no complete released challenge is durably present. New approval requires a new operation/rid | Unknown manager outcome, conflicting rid/session/intent, or impossible claimed completion without allocation evidence |
| Complete pending challenge durably recorded | Full approved attributes/controller/state, rid, nonce and exact PENDING record | Existing explicit finish may proceed after normal current-controller/state/proof checks and a new fenced claim | Incomplete approval/challenge, changed required current checks or missing nonce history |
| CLAIMED or SIGNING, during signing | Durable claim/one-attempt marker, immutable input and reservation, authoritative absence/presence of certification | If no committed certification, conservatively retire; retain rid/nonce/session. Never infer that an absent response permits another signing call | Journal/authority unavailable or contradictory commit records; signer can publish outside the controlled channel |
| Signature exists, before certification logging | Signature alone is insufficient; query authoritative certification/outcome | Unlogged result is discarded and the operation retired. A delayed result from an old generation cannot commit or release | Any uncertainty about whether certification committed or required prior records are missing |
| Certification transaction interrupted before COMMIT | Complete old head or complete new certification transaction after SQLite recovery | Old head: retire attempted signing. New head: retain CERTIFIED and exact releasable response | Partial/mismatching head/checkpoint/log/outcome; never select individual surviving fields |
| After certification log COMMIT, before release | Same transaction contains CERTIFIED, nonce/session effects, original credential, issuance witness and authorised delivery/outcome | Publish or retrieve the exact stored result through the fenced authorised delivery path; no allocation or signature generation | Missing original result/recipient authorisation, inconsistent certificate/witness, or unqualified recovery of issuer authority |
| Response lost, delivery acknowledgement absent | Committed outcome and original authenticated recipient/session; delivery status may be unknown | Separate authenticated `retrieve_committed_issue` can redeliver identical bytes with local REDELIVERY status. Ordinary begin/finish still return REPLAY; no second certification | Recipient cannot reauthenticate, conflicting operation contents or missing committed result |
| Issuer claims certification but manager has no matching committed reservation | Consistent current evidence from both stores | None; quarantine and investigate storage rollback/inconsistency | Never recreate a reservation from the credential, rewind the manager or select a different rid |

The policy is deliberately conservative before certification: interruption after a
signing attempt can abandon a valid but unlogged signature. This costs an ID and
nonce but preserves the finite signing bound and release-after-log rule. A wholly
recorded PENDING operation remains resumable under existing checks; a potentially
attempted SIGNING/CLAIMED operation does not. Retirement is an explicit durable
reconciliation transition under current writer/admin authority, not an automatic
replay of `finish` or recovery from a holder-supplied statement.

Post-commit retrieval is an **additional proposed local delivery API**, not changed
behaviour for ordinary issuer finish or verifier verify. It returns the existing
credential/checkpoint, even if subsequent revocation/DID changes make it unsuitable
for a fresh presentation; no new validity or freshness promise accompanies delivery.
The proposed rule is reauthentication as the original approved recipient over a
confidential channel. How that identity survives lost client sessions, key rotation
or account recovery is a precise unresolved production policy. Until configured,
retrieval fails closed; a new current DID controller is not automatically that recipient.

Verifier retry handling differs: an operation lookup may report that consumption
already committed, but ordinary verify must never emit a second fresh ACCEPTED or
re-execute an application effect. Existing UNKNOWN/CONSUMED behaviour remains.
An external business action is outside the local consume transaction and needs its
own separately scoped coordination design. Strict `now < texp` uses the current
trusted clock inside the fenced consumption transaction; recovery never restores time.

## 6. Next bounded implementation package

Recommend **S2-DURABLE-AUTHORITY-PILOT-1**, limited to a local persistence core,
manager permanent allocation, verifier registration/consumption for separate A/B
stores, and issuer private-journal reconciliation/exact-result retrieval. No production
deployment, dependency upgrade, remote authority, power-loss experiment, real proof
or zkVM execution. Remaining registry/resolver/controller/wallet durable adapters
stay unadmitted until their own commits and publication paths are integrated.

Proposed files and interfaces (not created in this design package):

| File | Concrete responsibility |
|---|---|
| `src/pqdid/persistence/records.py` | Strict versioned local `ServiceKey`, `HeadTicket`, `WriterPermit`, `RecoveryAuthorisation`, `OperationIntent`, `CommittedOutcome`; no protocol codec changes |
| `src/pqdid/persistence/codec.py` | Bounded non-executable checkpoint/journal encoding into bytes; no pickle/import callbacks; reuse existing canonical embedded encodings and typed validator |
| `src/pqdid/persistence/sqlite_store.py` | Pinned schema/settings, bootstrap versus open-existing, `load_current`, `acquire`, `commit_transition`, `lookup_outcome`, bounded owned publication; no arbitrary caller SQL |
| `src/pqdid/persistence/recovery_adapter.py` | Head-ticket-aware `RecoveryAuthority.exclusive`, default-deny authorisation and permit handoff only to durable facades |
| `src/pqdid/persistence/durable_manager.py` | Allocation and retained reservation outcomes using the protected commit; unsupported durable operations fail closed |
| `src/pqdid/persistence/durable_verifier.py` | Challenge reservation and atomic consume/current expiry using the protected store, preserving public-only proof boundary and A/B separation |
| `src/pqdid/persistence/issuer_reconciliation.py` | Durable intent/reservation attachment/claim/certification/outcome records; conservative interrupted-signing retirement and separately authorised exact-result lookup |
| `tests/integration/test_durable_authority.py` plus child-worker helper | Fresh subprocesses, finite barriers and named kill points; labelled synthetic authorisation/signing/proof fixtures, no proof backend |
| `docs/stage2_durable_authority_pilot.md` and new exact evidence namespace | Commands, versions, original controls, process-crash labels, resource and preservation evidence |

The implementation must expose actual durable operations, not merely a validator
in front of an unfenced reference object. Existing pure cryptographic helpers and
validation evidence are reused. If a source hook is needed, propose its exact file/
commit boundary and preservation allowance within that implementation package;
no broad source-directory exemption is authorised by this design.

Proposed pilot envelope: unchanged **256 MiB for the complete worker process tree**,
zero swap, one test worker, two CPU threads, at most four controlled descendants
(owner/coordinator and competing clients), 60 s command/55 s child deadline,
300 s aggregate, at most 100 selected cases, no automatic retries. Preserve 10 GiB
experiment budget/9 GiB stop, 64 MiB diagnostics/60 MiB stop, 10 MiB new package
output, 60 KiB per-command log stop and **1 MiB per-file RLIMIT_FSIZE**. The latter
rules out casually proposing multi-megabyte test DBs under the existing runner.

Therefore the first pilot lowers local storage admission: **512 KiB per SQLite
file**, page_size 4096 and max_page_count 128; **64 KiB per encoded checkpoint**;
at most 128 operation rows per fixture store and **8 MiB aggregate temporary data**
including rollback journals. Required historical rows remain retained; any earlier
space limit stops the next transition. This is a bounded pilot subset, not support
for every maximum-size role image in one file. SQL text ≤16 KiB, ≤64 bound parameters,
no ATTACH, and a 100,000-VM-step progress budget are proposed; set connection length
limits with room for bounded row overhead, at most 256 KiB, while enforcing the
64 KiB blob limit independently. Keep transaction/connection lifetimes bounded and
close all cursors. These are lower local limits, not suite parameter changes.
[SQLite limit controls](https://www.sqlite.org/limits.html).

Future acceptance groups, **not run here**:

| ID | Required future observation |
|---|---|
| T01 | Actual SIGKILL before/after BEGIN, row writes and COMMIT; a newly started process recovers exactly the old or complete new state, never a partial head |
| T02 | Kill after COMMIT before reply; same operation lookup retrieves the exact committed outcome with no duplicate mutation |
| T03 | Restore stale service copies against intact authority, including same signed root with lower allocation count; recovered interface refuses |
| T04 | Two processes compete for replacement from one expected generation, and separately for different mutations from the same head; at most one grant/first-head commit, bounded BUSY/conflict for the other |
| T05 | Pause old process, replace, resume it; old allocation, consumption, certification and publication attempts are fenced at their actual boundaries |
| T06 | Same operation/same full contents retrieves outcome; changed request/phase/principal conflicts; no second verifier acceptance |
| T07 | Kill across issuer-intent, manager-reserve and issuer-attachment commits; correlate exact operation, preserve orphan rid and never rebind |
| T08 | Interrupt signing or deliver a signature after replacement; authoritative absence of certification retires, with no automatic signing retry |
| T09 | Kill before/after certification COMMIT and release; only exact committed bytes can be retrieved by the original authorised recipient |
| T10 | Authority unavailable, DB missing, missing checkpoint/outcome, digest mismatch, BUSY/FULL/I/O errors: no admission, empty initialisation or partial success |
| T11 | Preserve the original identifier-reuse and repeat-acceptance unsafe controls; separately demonstrate their rejection through durable recovered interfaces |
| T12 | Current trusted clock still rejects expired challenges at consume; verifier A/B and role-private checkpoint access remain separate |
| T13 | Exhaust bytes/pages/records/SQL work/wall budgets without advancing authority or reporting incomplete success |
| T14 | Generation/head sequence exhaustion rejects without wrap or implicit new namespace |
| T15 | Delay signing/publication, advance head or replace writer; final publication fence rejects; already queued pre-replacement replies retain their earlier ordering |
| T16 | Fail activation COMMIT or context exit, including suppression of an exception; no facade becomes available; unused durable grant remains consumed if committed |

Use disposable synthetic stores only and named IPC barriers with finite deadlines,
not timing sleeps. SIGKILL applies to explicitly created children, not WSL or the
host. Test two clients within the single guarded worker's tree, not unmonitored
helpers. These are **process-crash tests**, not storage-power-loss or whole-store-
rollback proofs. T03 assumes intact authority; no test may relabel an inability to
detect F05 as successful rollback protection. Native signing and proof adapters
remain labelled fixtures; bounded production signing is a separate open obligation.

## 7. Decisions, blockers and validation

Selected: separate role-owned SQLite stores, DELETE/EXTRA, complete same-role atomic
state/head/outcomes, current-head tickets, per-boundary writer fencing, no automatic
retry, conservative pre-certification retirement, and exact committed-result retrieval
only through separately authorised delivery. Not selected: WAL, a shared private-data
authority, cross-role transactions, timed automatic takeover, allocation recycling,
or trusting a local DB to detect its own rollback.

Open before production: independent authority for whole-store rollback; administrator/
OS principal and key-broker isolation; actual WSL/host flush guarantees; recipient
reauthentication for delivery; complete durable role integration and retention;
bounded signing/key generation and DEP-001/002; interoperability; full private
authentication/BC-1, selective-disclosure/non-revocation proof integration, actual
proofs and privacy/security review. The pilot addresses a narrower failure model,
and cannot close the deployment recovery blocker by passing fixture/process tests.

Documentation/data consistency, local links, primary-source/configuration mappings,
planned test IDs and preservation are checked in this package. Read-only inspection
used the guarded existing interpreter and no persistent DB. The first facts filename
collided with the runner's command-result filename; that successful guard/log remains
preserved. A second bounded read-only inspection saved facts under a distinct name.
Neither changed the environment or retried a resource failure. Functional tests and
crash/storage experiments are not rerun. Initial lint reported one E501 overlong descriptive string in the new validation
script. The original failed guard/log/STOP is retained; a formatting-only fix is
checked in `final_checks`, sharing the original aggregate time/output limits.
The corrected preservation engine remains
unchanged under the original 256 MiB guard; final audit measurements follow below.

## Final documentation and preservation result

[Static design validation](data/s2_recovery_authority_design_1/design-validation.json)
passes: seven roles, eight failure classes, sixteen planned acceptance groups, eight
primary sources and observed-environment/design consistency. This is not functional,
process-crash, power-loss or persistence evidence. Final lint/format pass for all four
new package scripts. The initial E501 lint failure and STOP remain intact; the fix
changed string formatting, and finalisation retained the original aggregate budget.

The [complete preservation result](data/s2_recovery_authority_design_1/final_checks/result.json),
[content/inventory report](data/s2_recovery_authority_design_1/final_checks/validation.json),
[phase record](data/s2_recovery_authority_design_1/final_checks/phases.json) and
[outer guard](data/s2_recovery_authority_design_1/final_checks/full-audit.json) all pass.
Exact command:

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python docs/data/s2_recovery_authority_design_1/run_checks.py --final full-audit
```

**One complete audit, exit 0, 2.057240563 s**. The unchanged **256 MiB** cgroup ceiling
covers the complete worker and descendants plus charged anonymous/file-cache/kernel
memory; peak **21,516,288 bytes (20.51953125 MiB)**. The separately sampled aggregate
process-tree VmRSS peaks at **39,796,736 bytes (37.953125 MiB)** and retains its original
256 MiB stop; shared pages can be counted more than once in that metric. The
bookkeeping monitor remains outside the cgroup, as in preceding packages. No memory-
max, OOM or swap events. Comparison, inventory, report serialisation/readback and final
worker/outer guard completion are all required and all succeeded.

Seven original pinned manifests cover **8,975 historical paths**: 8,759 primary content
comparisons (8,756 unchanged; only the exact three permitted existing documents
changed), 210 unchanged supplementary comparisons, and six additional manifest
identities. Content partitions are disjoint; no baseline was regenerated. The
**607-entry inventory** has no unexpected or missing paths. All production/reference
source, tests, parameters, dependencies, manuscript, historical failures/results and
the two-used/one-unused proof ledger are preserved. Original unsafe controls remain
unchanged. Only this design/evidence and status/traceability/issues are new or edited.

| Guarded command | Exit | Wall seconds | Cgroup memory.peak bytes | Sampled tree RSS bytes |
|---|---:|---:|---:|---:|
| environment | 0 | 0.110387378 | 17,530,880 | 29,732,864 |
| inspection | 0 | 0.108913831 | 15,310,848 | 29,511,680 |
| consistency | 0 | 0.109730780 | 16,064,512 | 28,557,312 |
| quality | 1 | 0.088800521 | 10,330,112 | 13,955,072 |
| final/quality | 0 | 0.089175852 | 10,166,272 | 14,016,512 |
| final/format | 0 | 0.091644784 | 10,932,224 | 14,077,952 |
| final/full-audit | 0 | 2.057240563 | 21,516,288 | 39,796,736 |

All seven guarded invocations, including the retained lint failure and corrected
check, total **2.655893709 s**, below the unchanged 300 s aggregate limit. WSL memory
headroom was checked before each run; worker count, CPU, wall, disk and diagnostic
limits were unchanged. Temporary storage at final completion: **0 bytes**; evidence
size at guard completion: **202,864 bytes**. No install, persistent database change,
functional-test rerun, crash experiment, proof or zkVM execution occurred.

After the guard only these authorised documents were finalised with measurements.
Small document/link checks and the [new artefact seal](data/s2_recovery_authority_design_1/manifest.json)
record final bytes; they do not repeat the historical content audit or regenerate
an original baseline. The selected design remains unimplemented. Proceed only on a
separate instruction for **S2-DURABLE-AUTHORITY-PILOT-1** within its stated failure
model. Whole-store rollback protection, production recovery and Stages 2–3 stay open.
