# S2-AUTHORITY-ISOLATION-PLAN-1 — proposed local identity isolation

19 September 2026. **Select dedicated Linux owner identities, distinct IPC client
identities, per-owner transport groups and a root-protected runtime/configuration
tree for one synthetic isolation pilot.** The staged artefacts are uninstalled.
No account, host setting, existing store permission, dependency or production code
was changed. No deployment protection is claimed from this plan or its static checks.

Inputs: [instructions](../AGENTS.md),
[owner implementation](../src/pqdid/persistence/owner_service.py),
[transport](../src/pqdid/persistence/owner_ipc.py),
[caller policy](../src/pqdid/persistence/owner_auth.py),
[owner-boundary report](stage2_authority_owner_boundary.md),
[authority design](stage2_recovery_authority_design.md),
[durable pilot](stage2_durable_authority_pilot.md),
[lifecycle contracts](stage2_lifecycle_review.md), status and issues.
Only manuscript **Sections II–VIII** and SPEC-001–004 are authoritative; its SHA-256
was rechecked as
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
This is a deployment engineering design, not a new protocol requirement.

## Observed constraints and the boundary that is missing

[Host metadata](data/s2_authority_isolation_plan_1/host-metadata.json) is a small
read-only inspection outside the tool's UID/filesystem remapping.
[Guarded runtime/library metadata](data/s2_authority_isolation_plan_1/environment-facts.json)
and the [view correction](data/s2_authority_isolation_plan_1/inspection-view-note.json)
retain the distinct observations. No private checkpoint, credential, process
environment or secret was inspected. The guard also remaps root and some groups;
its original descriptive view label is corrected by the separate note. Do not use
mapped `nobody` ownership as the host access-control design.

| Actual constraint | Consequence for the selected design |
|---|---|
| Host identity Grace, UID/GID 1000; groups `adm`, `cdrom`, `sudo`, `dip`, `plugdev`, `users`, `grace` | Grace is a trusted deployment operator in this model, not an untrusted isolated client; proposed accounts receive none of these extra groups |
| `/home/grace` 0750; project, source and environment owned by Grace, normally 0755 | Do not grant new clients access by relaxing the home directory; do not run trusted owners from the writable project |
| Host `/`, `/usr`, interpreter and system libraries root-managed; original `.venv/bin/python` links to `/usr/bin/python3.14` | Retain the inspected base interpreter, but create a fresh environment at the protected release path |
| Python 3.14.4; SQLite 3.46.1 from `/usr/lib/x86_64-linux-gnu/libsqlite3.so.0`; native liboqs 0.16.0 local install tree | Preserve versions and native bytes; require actual import/linkage verification after staging |
| `_pqdid.pth` points at `/home/grace/projects/pq-did/src`; `_virtualenv.pth` executes the old environment hook | Copying/moving the old environment alone would retain mutable or inaccessible startup paths; explicitly assemble a new runtime |
| liboqs shared object links to root-managed libc/loader; SQLite also to libm | Keep exact loaded library paths under the protected release or approved root-managed system roots; reject home-directory loader overrides |
| systemd 259.5-0ubuntu3.4, WSL; system and user manager queries available; cgroup v2 memory/cpu/pids available | Use root **system** units to assign distinct service users; retain the existing non-root guard only for this package's checks |
| Project filesystem ext4 on `/dev/sdd`, host `rw,nosuid,nodev,...,data=ordered`; guard bind mount is read-only | Use Linux filesystem paths, not `/mnt/c`; this says nothing about physical flush or WSL power-loss durability |
| Previous sockets were temporary `role-ipc/s` or `t`, with cleanup complete | There is no persistent endpoint to migrate; proposed `/run/pqiso/ROLE/owner.sock` is new and separate from stores |
| Proposed account names absent in inspection | Activation must recheck all account/group/path collisions; this observation does not reserve names or numeric IDs |

The original same-UID pilot still passes its historical 28 IPC + 28 lifecycle
checks; the prior 38-case durable matrix/18 owned crash injections is reused.
Those tests do not establish separation between hostile OS identities.

| Demonstrated bypass / gap | Required protection, still unimplemented |
|---|---|
| Same UID can read/write raw SQLite and journals, bypassing the owner API | Distinct owner/client UIDs; owner-only 0700 store parent and 0600 files; no owner-private group membership for clients |
| A client can read other grants or change trusted provisioning in a shared account | Root-controlled policies/vault; only the unit's scoped credentials delivered read-only; actual UID/GID binding plus capability ACL |
| Writable parent, source, `.pth`, executable or native library can replace the enforcement code | Root-controlled ancestors and immutable release inventory; clean isolated Python startup; no hard-links/symlinks back to mutable source |
| A writable socket parent permits unlink/substitution regardless of socket mode | Owner-only directory write, transport-group traverse/connect only; client verifies server credentials and pinned endpoint metadata |
| Privileged handles survive a change of identity or exec | Clean service launch/descriptor allowlist, no socket activation/FD store or owner-handle inheritance; reject ancillary descriptors |
| Shared verifier identity could read both audience stores | Separate owner and writer identities, stores, groups, scopes and paths for verifier A/B |
| Claimed recipient field could replace real approval if trusted fixtures became production provisioning | Host-provisioned immutable recipient mapping from independently authenticated approval; no recipient selection by a request field |

## Selected identities and ownership

Use **13 nologin accounts** with private primary groups: owners `pqiso-o-m`,
`pqiso-o-i`, `pqiso-o-va`, `pqiso-o-vb`; corresponding writers `pqiso-w-m`,
`pqiso-w-i`, `pqiso-w-va`, `pqiso-w-vb`; `pqiso-admin`, `pqiso-observer`,
`pqiso-rec-a`, `pqiso-rec-b`, and negative-test-only `pqiso-denied`.
`m/i/va/vb` denote manager, issuer, verifier A/B. Numeric IDs are allocated once,
recorded and pinned at future provisioning; they are not guessed in this plan.
Four supplementary transport groups are `pqiso-ipc-m/i/va/vb`.

Each owner and its writer join only the matching transport group. The issuer owner
also joins the manager transport group for its existing manager-reader dependency;
that grants no filesystem access to the manager store. Admin/observer join all four
transport groups, with separate per-scope capabilities. Recipients join only issuer
transport. The denied account joins none. Nobody except the respective account
joins an owner's private primary group. No interactive shell, sudo, adm, journal,
container-control or broad deployment group is assigned.

The application admin is a trusted recovery client for all four scopes but has no
root credential-vault or raw-store rights. The host administrator is a stronger,
explicitly trusted authority: it can replace code/configuration, impersonate users
and read stores. Owner processes are trusted, non-Byzantine enforcement processes;
isolation protects against their untrusted clients, not a malicious owner or root.
No extra per-role superuser broker sees every private checkpoint.

In the matrix, O is the corresponding owner, C an authorised IPC client; other
owners/clients have no private-state access unless a row explicitly says otherwise.

| Resource / proposed path | Owner and mode | O | C / other principals | Host administrator |
|---|---|---|---|---|
| `/var/lib/pqiso`, `stores`, `clients` ancestors | root:root 0755 | Traverse only | Traverse only; cannot replace role subdirectories | Create/administer |
| `stores/ROLE` | O:O-private 0700 | Read/write/traverse | No read/write/traverse | Trusted administration |
| DB, rollback journal, checkpoint content | O:O-private 0600; checkpoints remain inside DB | Read/write through unchanged store invariants | No direct file access, including application admin | Can bypass; trusted |
| `/run/pqiso` | root:root 0755 | Traverse, no parent replacement | Same | Create/administer |
| `/run/pqiso/ROLE` | O:transport-group 2750 | Bind/unlink owned socket; no group directory write | Transport members traverse/list only; others denied | Create/administer |
| `owner.sock` | O:transport-group 0660 | Serve | Transport members may connect; application ACL still required | Trusted override |
| `/etc/pqiso/owners/ROLE` and role policy | root:O-private 0750 / 0640 | Read only | No access | Sole writer |
| `/etc/pqiso/clients/ACCOUNT` and client policy | root:C-private 0750 / 0640 | Only own additional configured client material | Each client reads only its own policy | Sole writer |
| `/etc/pqiso/credentials` and source bundles | root:root 0700 / 0400 | No direct vault access | No direct vault access | Generate/replace/revoke |
| systemd unit credentials | Read-only unit-local credential projection | Only its owner grants and configured bridge credential | Only its own scoped token(s); no all-principal fixture bundle | Trusted service-manager delivery |
| `/opt/pqiso/r1` code/environment/native tree and ancestors | root:root; dirs 0755, files 0644, executable files 0755 | Read/execute, no write | Read/execute, no write | Reviewed promotion only |
| System interpreter/stdlib/ELF dependencies | Root-managed approved `/usr` and `/lib` paths | Read/execute | Read/execute | Updates require runtime requalification |
| `clients/pqiso-rec-a` and `...rec-b` synthetic wallet state | Corresponding recipient private 0700 / 0600 | No issuer/verifier access | Only that recipient; no shared holder group | Trusted host access |
| Other client synthetic scratch | Corresponding client private 0700 / 0600 | No implied access | Its own files only, never owner DB handles | Trusted host access |
| Service journal diagnostics | Root/journald-controlled, fixed redacted fields | Submit only its diagnostics | No journal groups; observer gets typed status via IPC | Read/administer |
| `/var/lib/pqiso/evidence` | root:root 0700; files 0600 | No general private evidence access | No general access | Bounded coordinator/monitor output only |

An owner can mutate its own socket directory and store: that is the declared trust
boundary. Clients cannot replace a leaf by modifying an ancestor. Preflight checks
all ancestors, resolved symlink targets, hard-link count, extended ACL grants and
actual supplementary groups. Setgid 2750 makes newly bound sockets inherit the
transport group without making that group directory-writable. Owner code must set
0660 before reporting readiness; umask remains 0077. Database permissions and
strict sidecar checks remain unchanged at 0700/0600.

## IPC compatibility and application authorisation

The current `owner_ipc.endpoint_path()` requires the socket parent/socket to belong
to `os.getuid()` at 0700/0600, and `Owner.serve()` sets 0600. **It will reject the
selected cross-UID layout.** A follow-up must add an explicit configured endpoint
policy to both client and server, validating expected owner UID, transport GID,
2750/0660 modes and safe ancestry. Keep the old same-UID policy for existing callers;
do not relax checks based on a failed access attempt. No such production code
change is made here.

Preserve the existing versioned bounded framing, named operations, authentication
before permission checks, fixed ServiceKey/store/scope, strict argument arity,
generation/head fences at commit and actual publication, exact operation retry/
conflict and no second acceptance after consumption. OS group access only lets a
client reach the socket. The owner then matches kernel `SO_PEERCRED` UID and
**primary** GID plus its scoped capability to an immutable configured principal;
payload PID/UID/role/recipient/namespace fields and socket names are not authority.
The client checks kernel server UID/GID against its independent configuration.

[Principal mappings](proposals/s2_authority_isolation_plan_1/principals.json) preserve
admin `admit/replace/status`, each role writer's existing mutation/read set,
observer `status`, and recipients `retrieve` only. The issuer-to-manager bridge is
restricted to reservation/count reads and a fixed issuer-service binding. Every
scope has at most eight grants. The only mapping from approved session to immutable
recipient comes from trusted provisioning, not client arguments.

Capability possession alone is insufficient without the configured kernel identity.
Tokens remain pilot application credentials, not PQ-DAA protocol authentication.
An authorised client may legitimately invoke its granted business operations;
this plan does not defend against misuse of powers deliberately granted to it.
The issuer writer still receives no retrieval permission; the original recipient
can recover exact logged certification bytes after a lost response. A capability
rotation keeps the same logical recipient only after independently authorised
identity continuity; it must not reassign old records to a stranger.

Anonymous presentations are unchanged. The verifier service writer authenticates
to its owner; the presenting wallet does not join a verifier group or supply a
persistent wallet capability. Holder-private files stay with the holder identity;
there is no cross-verifier holder identifier introduced by this deployment plan.

## Provisioning, startup and revocation

Only the trusted host provisioner may create, replace or revoke credentials and
numeric identity mappings. Policies contain pinned identity/scope/head references;
capabilities are random 32-byte secrets generated during future provisioning, never
embedded in repository files, command lines, environment variables or reports.
Root-only bundles are delivered by `LoadCredential`; unit arguments carry only
the credential directory path. Separate client/owner bundles avoid giving a writer
or recipient the owner's complete grant table. The operator who approves enrolment
must establish the recipient before immutable intent creation; production business
approval remains outside the synthetic fixture pilot.

Start after namespace/account/permission/runtime/credential validation, initially
inactive. Admit the manager with independently approved exact head information;
only then start its dependent issuer channel. Start verifier A/B independently.
Type=exec is not readiness: require a bounded authenticated status handshake.
Only explicit admin admission/replacement activates a writer. Missing store,
incompatible policy, wrong UID/GID, unsafe ancestry or inaccessible runtime means
unavailable; no permissive fallback or automatic empty bootstrap.

Stop-and-restart rotation is selected because current owner policies are immutable
in memory. Quiesce/stop all affected owners and clients, including stale owners,
close old connections, replace both token bundles and mapping versions atomically,
restart inactive and re-admit explicitly. Test old-token/old-connection refusal.
Editing a file while an old process serves is not revocation. Do not reuse numeric
UIDs while retained records/grants could name them. Already queued/delivered bytes
cannot be recalled; delivery revocation is distinct from protocol revocation.

No listener/database/credential FD may pass to a client. Launch with null stdin,
bounded diagnostic stdout/stderr, close-on-exec internal handles and no passed FDs.
Disable FD store/socket activation; reject ancillary rights; inspect descriptors
under actual IDs and deny cross-UID `/proc` access. Service hardening supplements
DAC but cannot fix a leaked already-open descriptor or a malicious trusted owner.

## Concrete artefacts and privileged actions

All artefacts are in the clearly marked
[proposal directory](proposals/s2_authority_isolation_plan_1/README.md).
The [activation runbook](proposals/s2_authority_isolation_plan_1/activation.md) gives
ordered preflight/install/start/verification/revocation/rollback steps. Templates
cover sysusers accounts/groups, exact tmpfiles ownership, owner/client system units,
aggregate cgroup slice and placeholder credential/configuration contracts. They
contain no live credentials, no install targets and no boot enablement.

The [runtime layout](proposals/s2_authority_isolation_plan_1/runtime-layout.json)
creates a fresh `/opt/pqiso/r1/.venv` using pinned `/usr/bin/python3.14 -m venv
--without-pip`. It stages only verified pqdid source, the exact installed liboqs
Python package/metadata, native library tree and future reviewed launchers; a single
path-only `.pth` targets the protected source. It neither relocates the old venv
nor executes root build hooks. All inactive dependency markers/extras are checked;
unexpected active dependencies stop staging. The unchanged backend's source-relative
native prefix then resolves within the release. The existing native SHA-256 is
`36a8ca7ac0827079ca0436dfaa69f166d691468aacffc95bb5e8d004e522c25d`.
Actual import/linkage/version checks under the new users are still mandatory;
copying individual approved files does not establish runtime compatibility by itself.

| Future privileged action | Why required / restriction |
|---|---|
| Create 13 nologin accounts/private groups and four transport groups | Establish real UID separation; fail on any pre-existing name; no privileged memberships |
| Create new root/owner-controlled trees and apply exact modes | Prevent client ancestor/file substitution; never alter the project or existing store permissions |
| Promote reviewed runtime and root-owned launch/preflight tools | Prevent mutable code/import/native/config bypass; no source hooks run as root |
| Resolve identities and provision root-only mappings/capability bundles | Independently establish authority; application admin cannot self-provision |
| Install selected system units, reload system manager, create approved marker | Only system manager/root can assign all proposed UIDs and aggregate cgroup controls; no enable-at-boot |
| Coordinate bounded actual-ID tests and read aggregate resource evidence | Use only synthetic newly created resources, one worker, exact recorded unit set; no unrestricted root shell given to a client |
| Stop/revoke/quarantine pilot resources | Preserve all databases/history; removal only by exact creation ledger, no recursive/wildcard cleanup or automatic UID reuse |

These actions are **not performed or authorised for execution by this package**.
Required cross-UID endpoint, release/provisioning/preflight launchers and the bounded
system-manager coordinator are implementation blockers. Templates referencing them
are concrete contracts, not deployable working services today. Static unit syntax
validation cannot establish their existence or behaviour.

## Bounded subsequent pilot and acceptance

[Acceptance plan](proposals/s2_authority_isolation_plan_1/acceptance.json): **22 selected
cases**, at most 32 case instances including any reviewed development corrections,
one worker and at most four controlled processes concurrently. Cases cover protected
runtime loading; each role's authorised operations and denied direct store/config/
parent/socket access; both verifier cross-access directions; recipient binding and
lost-response delivery; denied transport and application permissions; superseded
owner plus already-connected client; credential rotation; holder-private data;
inherited FDs; four misconfigurations; all four role restarts.

Tests must run as the proposed actual Linux identities. The controller records real
process and kernel peer UID/GID, denied syscall errno and exact scope/store/head
outcomes. Mock UIDs, owner-run permission checks, unit configuration inspection and
ordinary same-UID tests do not count. Negative file operations use only new synthetic
fixtures; unexpected read access fails immediately without logging private bytes.

Retain **256 MiB total** cgroup memory, swap zero, supplementary sampled aggregate
RSS ceiling 256 MiB, two CPUs/200% quota, one 60 s command (55 s child), aggregate
300 s, temporary storage 8 MiB, output 10 MiB, per-file 1 MiB, per-log 60 KiB and
original 10 GiB/9 GiB experiment and 64 MiB/60 MiB diagnostic thresholds. Newly
staged release/store/evidence bytes must count towards aggregate storage admission;
placing files outside `experiments/` must not evade it. The common `pqiso.slice`
contains the test coordinator, owners and clients; per-service caps alone are not
the required aggregate cap. The small monitor stays outside, matching the existing
scope. No automatic retries or compensating limit increase.

Preserve existing 64 KiB request/reply, 4 active connections, 64 accepted connections,
8 principals, 0.5 s idle, 1 s processing, 2 s socket timeout and 20 s owner lifetime.
Database/sidecar 512 KiB, 128 operations, DELETE/EXTRA, SQL/progress limits and zero
lock-wait remain unchanged. No proof or zkVM execution. Stop on a resource failure,
retain evidence and report incomplete; do not relabel timeout as successful denial.
The current 1 s Python processing timer still cannot promise immediate interruption
of arbitrary C/filesystem calls; retain the outer deadline.

Accept only complete actual-ID cases, runtime/provisioning checks, resource records,
lint/static checks and preservation comparison/report/outer guard. Safe restart
retains DB/journals and explicitly re-admits; it does not reset consumed challenges,
allocations, certification or generations. Whole-store rollback (REC-005), malicious
host administrators and WSL power-loss/flush guarantees remain outside this pilot.

## Planning-package validation and preservation

Functional source and inputs are unchanged, so the previous functional evidence is
reused without rerunning tests. Only metadata inspection, non-privileged static
checks and documentation/data validation are executed here. The original inspection
used an output filename also used by its guard; its command record is retained and
one bounded read-only repeat wrote a distinct facts file. Guard-view remapping is
also retained with an explicit host-view supplement; no false identity-isolation
result is inferred from either inspection.

The unchanged [corrected preservation auditor](../scripts/preservation_audit.py)
is reused under the same 256 MiB guard. The
[scope](data/s2_authority_isolation_plan_1/scope.json) pins the original 8,759-entry
baseline and every historical supplement, including the owner-boundary seal.
Only existing status, traceability and issues documentation may change; exact new
report/proposal/evidence files are enumerated individually. No original baseline
is regenerated and no directory-level exclusion is broadened. A content comparison
alone is not completion: inventory, report readback and outer guard must also pass.
Final results are appended below.

Recommend one next package: **S2-AUTHORITY-ISOLATION-PILOT-1**, first implementing the
specified endpoint/startup/provisioning gaps, then running the approved 22-case
actual-identity pilot under the exact privileged-action and resource bounds above.
Do not activate these templates against the current code. Production application
approval, full lifecycle integration, bounded signing/DEP-001/002, BC-1/full
authentication, disclosure/non-revocation integration, proof feasibility and
privacy/security review remain separately open. **Stages 2–3 remain incomplete;
CPU proving paused; ledger two attempts used, one unused.** No proofs or zkVM
executions, host accounts, deployments or existing-store permission changes here.


## Final validation result

[Final static consistency](data/s2_authority_isolation_plan_1/static-accepted-validation.json)
and [systemd syntax validation](data/s2_authority_isolation_plan_1/static-accepted-unit-syntax.json)
pass; the final four unit templates produce no parser warnings. The installed
systemd parser identified obsolete `CPUAccounting`; that proposal directive was
removed while keeping quota, two-CPU affinity and aggregate memory controls. Earlier
static records and the compatibility note remain preserved. Final Ruff lint and
formatting pass. No functional or actual-identity test was run; none of the proposed
accounts, credential bundles, runtime trees or units was installed/activated.

The single [complete preservation audit](data/s2_authority_isolation_plan_1/result.json)
passes, exit **0**, wall time **2.066424324 s**, cgroup `memory.peak`
**21,860,352 bytes (20.84765625 MiB)** and supplementary sampled aggregate VmRSS
**39,747,584 bytes (37.90625 MiB)**. Cgroup accounting covers the entire worker and
descendants, including charged anonymous/file-cache/kernel memory; the monitor is
outside the cgroup. VmRSS is a separate sampled metric and can count shared pages
more than once. The **256 MiB ceiling** and all inherited enforcement remain unchanged.

The original **8,759-file** comparison has **8,756 unchanged files** and only the
three explicitly permitted documentation changes; all **415 supplementary files**
are unchanged. Disjoint content coverage is **9,174 files**, with original-manifest
identity checks bringing the union to **9,183 historical paths**. The **851-entry
inventory** has no missing or unexpected names. Content, inventory, report generation,
readback and outer resource guard all completed. Temporary storage is zero at audit
completion. Original manuscript, dependency/runtime files, production source/tests,
proof ledger, old audit ceiling failure and historical results remain protected.

All **13 guarded invocations** total **3.629145615 s**; maximum cgroup peak is
**75,464,704 bytes (71.96875 MiB)** during metadata inspection. All guard memory-limit,
OOM and swap counters are zero. The separate small host-view metadata read took
0.019080024 s; it is labelled metadata-only, not an audit/workload measurement or
actual-identity test. Repeated static checks correspond to explicit template changes;
existing functional evidence was reused without rerun.

Post-guard work only appends these results to the report and the authorised
status/traceability/issues documents, then records final metadata and a
[new-package seal](data/s2_authority_isolation_plan_1/manifest.json). No source/template
change or repeated historical scan follows. The original baseline is not regenerated.
The [finalisation record](data/s2_authority_isolation_plan_1/finalisation.json) covers
only those narrow documentation/output checks.

The planning package is complete and stops here. **Isolation remains unimplemented**
until the specified endpoint/launch/provisioning gates and actual-ID tests succeed.
Recommend **S2-AUTHORITY-ISOLATION-PILOT-1** under separately approved privileged
scope, preserving the fixed resource envelope. Full lifecycle integration, bounded
signing and proof feasibility remain separate blockers. Stages 2–3 stay open;
CPU proving paused, **two attempts used, one unused**, no proofs or zkVM executions.
