# S2-AUTHORITY-OWNER-BOUNDARY-1 — bounded authenticated local owners

19 September 2026. The existing durable manager, issuer and verifier pilot now has
an explicit local owner interface, authenticated caller permissions and immutable
issuance-recipient checks. Owners retain the existing generation/head fences at
commit and publication. This is a same-UID local pilot: **a hostile process with
the owner's filesystem/process access can bypass it**. Production authorisation,
OS isolation and the remaining lifecycle/proof/security obligations stay open.

Read [repository instructions](../AGENTS.md), the
[authority design](stage2_recovery_authority_design.md),
[durable pilot](stage2_durable_authority_pilot.md),
[lifecycle contracts](stage2_lifecycle_review.md), implementation, status and issues.
Only manuscript Sections **II–VIII** and SPEC-001–004 remain authoritative.
The manuscript identity is
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The IPC envelope, capabilities and local request metadata below are engineering
choices; no PQ-DAA authentication or cryptographic protocol encoding is changed.

## Permission and ownership boundary

Implementation: [policy](../src/pqdid/persistence/owner_auth.py),
[transport/client](../src/pqdid/persistence/owner_ipc.py) and
[owner/adapter](../src/pqdid/persistence/owner_service.py). Each `Owner` receives
exactly one trusted `ServiceKey`, store, internal writer ID, endpoint and policy.
The key binds role, instance/service ID, authority namespace, parameters and the
existing audience/registry identity. Request arguments cannot select another key,
database, SQL statement, executable, file path or writer identity. Other service
roles remain outside this pilot.

The authority design requires independently authenticated administrative and worker
permissions but leaves credential provisioning open. This package uses explicit
**pilot-only 32-byte random bearer capabilities**, each mapped by trusted owner
configuration to a logical principal, permission set, expected kernel UID/GID and,
where applicable, fixed issuer-service or delivery-recipient identity. Capabilities
are compared with `hmac.compare_digest`. The scope digest covers the complete local
service identity; a capability from another scope is refused. An empty grant table
denies all IPC callers. PID is diagnostic evidence, never permission. Permissions
are checked after authentication and before store inspection or privileged effects.

| Configured principal | Named operations | Constraints |
|---|---|---|
| Recovery administrator | `status`, `admit`, `replace` | Exact expected head and existing generation/grant rules; replacement chooses only the owner's configured writer; no empty recovery, deletion, counter reset or credential retrieval |
| Manager service writer | `status`, `reserve`, `reservation`, `allocation-count` | Issuer-service identity comes from its grant; lookup cannot substitute another issuer |
| Verifier service writer | `status`, `register`, `verify` | Fixed verifier instance/audience/store; existing public evaluation, freshness and durable one-time consumption |
| Issuer service writer | `status`, `intent`, `attach`, `pending`, `claim`, `certify`, `reconcile` | Existing phase/signing/head invariants; fixed manager interface and trusted approved-session recipient mapping; certification reply contains no credential |
| Operational observer | `status` | Scope, authority ticket and bounded counts only |
| Issuance recipient | `retrieve` | Exactly the recipient attached to the immutable committed certification; no operational status or mutation permission |

There is no general privileged client. Internal owner-writer identities are disjoint
from client principal names. Administrative replacement still calls the unchanged
store transition and cannot recycle an allocation, erase consumption, bypass an
expected head or publish an unlogged credential. Trusted bootstrap remains a distinct
offline internal operation, not an IPC method.

Actual owners and clients run as **UID 1000 / GID 1000**. Kernel `SO_PEERCRED`
values are checked and recorded by independent owner/client processes; forged PID,
UID, role, recipient, instance and namespace arguments do not authenticate anyone.
Private pathname sockets are mode 0600 in canonical, non-symlink, owner-controlled
0700 directories. Database and socket directories are separate so the unchanged
SQLite sidecar inventory remains strict. Clients also check the endpoint and the
server's kernel UID/GID. These checks assume trusted ownership of the path ancestry;
they do not defeat a malicious owner renaming its own files.

The test supervisor provisions all synthetic capabilities in temporary 0600 files,
and can select a principal for each independent client. This is privileged fixture
provisioning, **not** proof that same-UID clients cannot read one another's grants.
Current 0700/0600 checks intentionally support the same-UID pilot only. Separate
sockets are not separate OS principals. No accounts, groups, deployment permissions,
public network service, package dependencies or host configuration were changed.

## IPC contract and bounds

Linux pathname `AF_UNIX/SOCK_SEQPACKET` carries one complete request per connection:

```text
PQL1((1, configured_scope_digest, capability32, operation_bytes, argument_tuple))
```

The unchanged local codec permits only its fixed typed record whitelist, bounded
tuples, bytes, unsigned integers and booleans; no pickle or dynamic type import.
The protocol uses version 1, strict operation arities, existing typed/canonical
decoders and fixed role membership. Authentication is distinct from an argument
claim. Extra recipient/role/path/SQL fields reject. Message truncation, trailing
bytes, ancillary data, unsupported versions/types and incomplete packets reject.
No fragment accumulation occurs. A client that sends nothing is closed at the idle
deadline; each connection serves at most one request.

| Operations | Arguments after the authenticated envelope |
|---|---|
| `status`, `allocation-count` | none |
| `admit`; `replace` | expected ticket; operation ID and expected ticket |
| `reserve`; `reservation` | operation ID, prior ticket, issue ID, canonical state; issue ID |
| `register` | operation ID, prior ticket, unconsumed typed challenge |
| `verify` | existing session, canonical context, disclosed index tuple, disclosure bytes, proof bytes |
| `intent` | operation ID, prior ticket, preapproved session, approved challenge, canonical state |
| `attach`, `claim`, `reconcile` | operation ID, prior ticket, issue ID |
| `pending` | operation ID, prior ticket, issue ID, nonce32 |
| `certify` | operation ID, prior ticket, issue ID, typed issued record, signing ticket |
| `retrieve` | certification operation ID only |

Responses are bounded typed records or fixed tagged tuples. A successful retrieval
is the exact existing encoded `IssuedRecord`; it is not a proof receipt. Failure
labels come from a fixed whitelist and disclose no private SQL/request payload.
Status never includes sessions, nonces, attributes, certificates or capability
secrets. Test logs store response digests/lengths or fixed error labels; the actual
test response travels only through a private pipe. Capability bytes are checked
absent from fixture databases and JSON event logs. Test fixtures use the existing
TEST-ONLY signer and labelled public proof adapter, not production cryptography.

| Resource | Admission/enforcement |
|---|---|
| Frame / reply | 65,536 bytes; one `recvmsg(CAP+1)` with truncation checks; codec depth 16 and 8,192 nodes; single bounded nonblocking response enqueue |
| Connections/work | Four active connections per owner, fixed listen backlog 4, at most 64 accepted connections per owner; one serial request handler; at most eight configured principals |
| IPC time | Idle 0.5 s; processing 1 s; client call socket timeout 2 s; owner lifetime 20 s; no automatic retries |
| Whole check | One guarded command/pytest worker; at most four controlled child processes; two CPUs/200% quota; 60 s command, 55 s child, 300 s aggregate, at most 100 selected test-case instances |
| Memory | Unchanged 256 MiB cgroup-v2 `memory.max`, swap 0; supplementary sampled aggregate tree VmRSS ceiling 256 MiB; at least 256 MiB + 2 GiB MemAvailable before admission |
| Storage/output | Original 10 GiB experiment budget / stop 9 GiB, diagnostic 64 MiB / stop 60 MiB, package 10 MiB; aggregate temporary storage 8 MiB; per-file RLIMIT_FSIZE 1 MiB; command log stop 60 KiB |
| Database | Unchanged DELETE/EXTRA, 512 KiB database/sidecar admissions, 128 operations, 64 KiB checkpoints, bounded SQL/VM steps, no ATTACH or lock wait |
| Locality | Private network namespace with no routes; no remote service, proof generation or zkVM execution |

The processing timer runs in the dedicated owner's main thread and raises a private
`BaseException` so the reference verifier's exception-to-rejection handler cannot
mislabel timeout as a credential decision. It unwinds open transactions; a
monotonic check also precedes normal response publication and credential retrieval.
This is a bounded application deadline, not a guarantee of interrupting arbitrary
C/filesystem calls immediately. Existing SQLite VM limits and the outer process
deadline remain backstops. A deadline after a commit or socket enqueue cannot undo
that effect: callers must explicitly inspect/reconcile rather than infer rollback.
All limits are fixed in the pre-execution
[configuration](data/s2_authority_owner_boundary_1/config.json).

## Durability, replacement and recipient delivery

`ContextStore` reuses the unchanged SQLite format, transitions and local codec. It
adds `(IPC1, scope, authenticated logical principal)` to local operation arguments,
without storing the capability; the existing recipient argument stays last.
An explicit prior ticket remains part of mutation identity. Same operation/contents
can recover its committed outcome; changed contents or principal under that ID
conflict. No timestamp or request-supplied role substitutes for authority.

Owners start inactive. Only authenticated administration admits an existing exact
ticket or acquires the next writer generation. Each business request loads the
current head but retains its admitted writer permit; it cannot adopt a replacement
generation automatically. The old commit fences remain authoritative. Normal
success publication additionally acquires `BEGIN IMMEDIATE`, checks the writer
generation and exact current head, then enqueues the response while holding the
lock. Credential delivery uses the unchanged core recipient/head/generation check
at the actual socket enqueue. A previously connected client to a superseded owner
receives `fenced-writer`, despite holding a valid capability. Read-only `status`
may still report the current head from an inactive/superseded owner; it grants no
mutation or publication authority.

The issuer's manager dependency is a configured `ManagerClient` over IPC, with a
public service-identity adapter and no manager database handle. Reservations and
allocation counts come from that owner under its configured issuer-service grant.
No transaction across manager and issuer databases is introduced.

For issuance, trusted configuration maps an approved session to its recipient
before `intent`; the resulting intent is immutable. `certify` derives the recipient
from that intent, validates the existing signing ticket/record and logs certification
before returning a credential-free acknowledgement. `retrieve` takes only the
certification operation ID. The authenticated grant supplies the recipient and the
core checks it against the immutable committed record. Another recipient with the
same operation ID is refused; an extra substituted recipient field is invalid.
Administration, writer and observer capabilities confer no retrieval permission.
Knowing a rid, DID, operation ID or socket path alone confers no delivery access.

After an unobserved response, the original recipient can retrieve the **same**
logged record, without re-signing, reallocation or another certificate. Manager
retry uses its durable outcome. Verifier retry uses the current consumption state:
it returns `unknown-challenge`, not a second `reference-model-accepted`, even if the
first acceptance committed before the owner died. A changed internal writer ID
does not magically replay another writer's operation; current owners use explicit
lookup/reconciliation and existing operation conflicts remain binding.

Recipient authorisation applies only to issuance/recovery delivery. A verifier
service authenticates its own IPC calls; anonymous presentations retain their
existing inputs and gain no persistent holder identity or wallet authentication key.

## Validation and retained development evidence

[Tests](../tests/integration/test_owner_boundary.py) use
[independent process helpers](../tests/integration/owner_worker.py). The
[run ledger](data/s2_authority_owner_boundary_1/run-ledger.json) records exact commands,
headroom, cgroup settings, wall time, output paths and resource results. Per-case
records retain child command/PID, exit/owned SIGKILL, CPU/max-RSS, kernel peer
identity, socket mode, response digest, connection metrics and temporary storage.
Private fixture credentials, authentication secrets and databases are removed.

| Selected group | Successful cases | Evidence / exercised boundary |
|---|---|---|
| Access | 20 | Permission matrix; missing/invalid/wrong-scope/wrong-kernel-identity/empty-policy authentication; forged role, recipient, instance, namespace, UID, PID, path and SQL; malformed/trailing/oversized/version/partial/idle frames |
| Lifecycle | 7 | Exact retry/conflict; live replacement with already connected old client; concurrent consume and separate verifier audiences; all issuer phases, manager reads via IPC and recipient binding; two targeted owner SIGKILLs after commit before response; unavailable owner; lost recipient reply after socket enqueue |
| Bounds | 1 | Four active connections and refusal of the fifth; deliberate 1 s processing timeout before commit, unchanged head/allocation |
| Unchanged lifecycle regression | 28 | Existing `tests/unit/test_lifecycle_review.py` suite |

The previous **38 durable-pilot cases and 18 owned crash injections** remain valid
for unchanged persistence code and inputs, and are reused without rerunning the
old crash matrix. New fault hooks are confined to fixture child processes; no
production hook implementation or old test evidence was modified.

Three non-resource development failures are preserved: the initial fixture placed
a socket in the database directory (correctly refused by existing sidecar checks);
the next reused one operation ID for administration and allocation (correctly
conflicted); Ruff reported long comments and intentional pytest fixture shadowing.
Corrections use separate socket directories, distinct operation IDs and local style
fixes. No guard failure, coverage reduction or limit increase was used to continue.
The 20 access successes are repeated once after adding the request timer; final
coverage remains **56 distinct successful cases**, with **78 executed case
instances** including the two failed fixture attempts and that targeted repeat.
Final lint, formatting and complete preservation results are recorded below.

For the lifecycle test command, measured wall time is **14.805856586 s**, cgroup
`memory.peak` **119,558,144 bytes (114.01953125 MiB)**, supplementary sampled aggregate
VmRSS **182,030,336 bytes (173.59765625 MiB)** and observed temporary storage peak
**381,371 bytes**. Cgroup memory charges include anonymous, file-cache and kernel
memory for the entire guarded worker and descendants; the monitor is outside it.
Summed VmRSS double-counts shared resident mappings and is a different metric.
Sampling is not an exact disk/RSS high-water mark. These synthetic process timings
are not throughput, percentile, production latency or proving-cost measurements.

## Preservation and remaining obligations

The corrected [streaming auditor](../scripts/preservation_audit.py) is reused
unchanged. [Scope](data/s2_authority_owner_boundary_1/scope.json) pins the original
8,759-entry baseline and all subsequent immutable seals, including the preceding
durable pilot. Original baselines are not regenerated. Only existing
`docs/status.md`, `docs/traceability.md` and `docs/spec_issues.md` may change; new
implementation, tests, report and evidence paths are individually enumerated.
There are no broad new directory exclusions. The final content comparison, complete
inventory, report readback and outer resource guard must all pass to claim success.

Existing `SQLiteStore`, durable facade, recovery and in-memory reference interfaces
remain directly importable for trusted internal/test use. Python private members
are not a sandbox. A same-UID process or administrator with raw database, capability,
signer or publication access can bypass the IPC boundary. This package does not
close those deployment paths or retrofit every reference entry point.

Keep separately open: production application approval and admin/recipient capability
provisioning/rotation/revocation; separate OS identities and exclusive database/key
ownership; full durable begin/finish and other role integration; bounded production
signing; resource/retention and backup policy; host flush/power-loss qualification;
whole-authority rollback protection (REC-005); full authentication/BC-1,
selective-disclosure/non-revocation integration, actual CredValid proofs, DEP-001/002
and privacy/ZK/quantum-security/Section VIII review. The existing same-rollback-domain
head cannot detect rollback of its own complete database.

Recommend one next bounded package, **S2-AUTHORITY-ISOLATION-PLAN-1**: specify and
review the role/account, endpoint, capability lifecycle, recovery-administrator and
recipient provisioning matrix, including elimination of raw-store and signer
bypasses, before any deployment changes. No host-account changes or new execution
are authorised by that recommendation. **Stages 2–3 remain open; CPU proving is
paused, two proof attempts used and one unused.** No proofs or zkVM executions
were launched in this package.


## Final preservation and resource result

The single [complete preservation audit](data/s2_authority_owner_boundary_1/result.json)
passes with exit **0**, wall time **2.134272240 s**, cgroup peak **24,907,776 bytes
(23.75390625 MiB)** and supplementary sampled aggregate VmRSS **41,394,176 bytes
(39.4765625 MiB)**. The original 8,759-entry comparison permits only the exact three
existing documentation changes; **332 supplemental protected files** are unchanged.
The disjoint content partitions cover **9,091 files**, and verified baseline identities
bring coverage to **9,099 historical paths**. The **773-entry name inventory** has
no missing or unexpected files. Content, inventory, report generation/readback and
the outer resource guard all complete. Temporary storage at completion is **0**.

All **16 guarded commands** together took **55.803938689 s** within the unchanged
300 s package budget. No command produced a memory-limit, OOM or swap event; the
largest cgroup peak was the lifecycle test's **119,558,144 bytes (114.01953125 MiB)**,
with sampled tree VmRSS **182,030,336 bytes (173.59765625 MiB)**. The 28 final IPC
cases, 28 unchanged regressions, final Ruff lint and formatting pass. All 78 test
case instances and the three resolved non-resource development command failures
remain recorded. The prior audit ceiling failure and all old manifests/history
remain untouched.

After the complete audit, only this result text, the authorised status/traceability/
issues appendices and small package finalisation/seal metadata are written. No
implementation change or repeated historical content scan follows. The new
[seal](data/s2_authority_owner_boundary_1/manifest.json) records final file digests;
[finalisation](data/s2_authority_owner_boundary_1/finalisation.json) records the narrow
post-guard documentation checks. This is not a regenerated original baseline.

The package stops here. Same-UID/direct-store bypasses and trusted capability/session
provisioning assumptions remain explicit. Next recommendation:
**S2-AUTHORITY-ISOLATION-PLAN-1** only. Stages 2–3 stay open; CPU proving paused,
ledger **two attempts used, one unused**; no proofs or zkVM executions.
