# S2-AUTHORITY-ISOLATION-PILOT-1

## Outcome and authority boundary

Cross-UID endpoint support and the staged provisioning/launch/test tools are
implemented. **Activation is not authorised or performed. All 22 actual-identity
cases remain pending. No OS isolation success is claimed.** The user's instruction
§5 explicitly reserves approval until this implementation, unprivileged validation,
concrete runbook and preservation audit are reviewable. Earlier planning was not
activation approval. No accounts, ownership changes, installed units, protected
runtime, real-identity clients or authority stores have been created on the host.
The final preservation result is appended below after its one guarded run.

Read: repository instructions, current status, the
[durable-authority report](stage2_durable_authority_pilot.md),
[owner-boundary report](stage2_authority_owner_boundary.md),
[selected isolation plan](stage2_authority_isolation_plan.md), its
[proposal](proposals/s2_authority_isolation_plan_1/README.md), templates, 22-case
contract, source and previous evidence. Only manuscript Sections II–VIII remain
authoritative. This package makes no new cryptographic or manuscript interpretation.
SPEC-001–004, the active profile, dependencies, original vectors and manuscript are
preserved. CPU proving remains paused: **two attempts used, one unused**. No proofs
or zkVM executions.

## Implemented changes and preserved contracts

The previous endpoint check required the current process to own a 0700 parent and
0600 socket, so distinct clients could not use the proposed transport group. The
new [EndpointPolicy](../src/pqdid/persistence/endpoint_policy.py) explicitly pins
owner UID, owner primary GID and a different transport GID. It requires a canonical
Unix pathname, owner:transport 2750 parent, root-owned non-writable higher ancestry,
no unexpected ACLs, and owner:transport 0660 socket. Bind checks require the actual
owner UID/primary GID and transport membership. Symlink/metadata/path failures
remain failures, with no chmod repair of existing endpoints.

Only two pre-existing source files change:
[owner_ipc.py](../src/pqdid/persistence/owner_ipc.py) accepts an explicit endpoint
policy and checks its owner against the kernel-peer expectation;
[owner_service.py](../src/pqdid/persistence/owner_service.py) uses that policy when
binding and validates the resulting socket. The existing same-UID path remains
available without an explicit policy. Framing, limits, authentication/ACLs,
SO_PEERCRED UID/primary-GID checks, fences, SQL transitions, atomic consumption and
recipient-bound redelivery are unchanged. The new code adds no identity field to
anonymous presentation requests. Each verifier retains separate scope, audience,
store, capability and OS role; the local service writer is not a holder identity.

The [staged runbook](proposals/s2_authority_isolation_pilot_1/README.md) lists exact
privileged commands, all accounts/groups/paths/modes, shutdown/verification/rollback,
resource limits and the 22 ordered real-ID cases. The new
[tools directory](../scripts/isolation_pilot/pilotctl.py) contains:

| File | Purpose |
| --- | --- |
| `layout.py`, `runtime.py` | Fixed paths/identity mapping, bounded file I/O, closed runtime inventory/digests, protected permissions/ancestry/ACLs, exact credential and service bindings |
| `provision.py`, `configure.py` | Fresh-only collision checks, sealed source/input copying, fresh venv, exact root policy/credential construction and creation ledger |
| `preflight.py`, `owner_entry.py` | System-interpreter checks before project imports, real owner identity, fresh-only bootstrap, SQL/checkpoint integrity before listening, inactive start |
| `client_entry.py`, `control.py` | Fixed non-root client units, private bounded requests/results, public identity observations, no direct-store fallback, explicit head/admission handling |
| `activation_guard.py`, `cases.py` | Serial common-slice resource guard and 22 prospective actual-identity cases; nonzero exit or incomplete reporting never passes |
| `fixture_factory.py`, `isolation_pytest.py` | Unprivileged synthetic inputs and new-package test evidence routing; excluded from the installed runtime |

The new bootstrap unit is a bounded implementation detail for the plan's explicit
owner-UID bootstrap, not another authority role. Four owner client directories
support real-owner cross-role probes. Neither change grants a client owner-private
membership. Root promotion copies sealed source and the pinned binding/native tree
into a fresh system-Python venv; no existing environment relocation, dependency
install, network service or package build is involved. Runtime compatibility under
those actual identities still awaits activation. New root roles/configurations are
synthetic pilot resources only.

Trusted owners and the host administrator remain inside the trust boundary. Root
creation/recovery records are not an independent whole-store rollback oracle.
Neither static checks nor SIGKILL tests establish WSL power-loss durability.

## Completed unprivileged validation

All commands use [run_checks.py](data/s2_authority_isolation_pilot_1/run_checks.py)
and the inherited [configuration](data/s2_authority_isolation_pilot_1/config.json).
There is one validation worker, private networking, two CPUs and zero proving.

| Validation | Result and scope |
| --- | --- |
| Initial endpoint/provisioning fixtures | 20 passed; mocked metadata/NSS identities and temporary files, not OS isolation |
| Final focused prerequisites | 28 passed in 0.631661292 s guard wall; adds four-role/13-client/17-bundle configuration, capability plus UID, read-only issuer bridge, recipient/verifier separation, rollback-scope and hardlink checks |
| Unchanged owner-boundary regression tests | 28 passed in 29.798034902 s guard wall; current endpoint integration preserves existing authenticated IPC/lifecycle contracts |
| Existing lifecycle regression evidence | Reuse the prior 28 passed cases; core lifecycle/signing/SQL code and original test inputs unchanged |
| Fresh synthetic fixture preparation | Completed unprivileged; same unchanged fixture factory, no signing keys or live IPC capabilities exported |
| Dry run | Passed; exact proposed resources printed, no host mutation |
| Staged unit parser | Passed, parser exit 0 and empty stderr; executable/working-directory substitutions explicitly recorded |
| Final lint/format and preservation | Final results appended below |

Twenty initial plus 28 final focused invocations plus 28 owner regressions total
**76** test invocations; 22 proposed actual cases would bring the 100-case envelope
to 98. Test identities in isolated fixtures are models, never substituted for real
UID evidence. Real IDs/group memberships are deliberately null in the
[22 pending outcome records](data/s2_authority_isolation_pilot_1/actual-identity-cases.json).

The largest completed unprivileged command cgroup peak so far is **113,946,624
bytes (108.66796875 MiB)**, from owner regressions. Supplementary sampled tree RSS
peaked at **184,143,872 bytes**. These differ because summing per-process resident
sets counts shared mappings repeatedly; the unchanged primary enforcement metric
is cgroup-v2 charged memory, including anonymous memory, file cache and kernel
memory for the complete worker subtree. The small monitoring process is outside
that cgroup, as previously. The fixed ceiling is **268,435,456 bytes**, swap zero.
No memory `max`, OOM or swap event occurred. Temporary fixture storage peaked at
**3,809,055 bytes**, below 8 MiB, then was cleared within the guard. Original evidence
was not altered to manufacture negative cases.

Failures are preserved, not rewritten as passes. Initial lint found unused imports,
ambiguous names, import order and long lines. Three source-only correction records
explain those failures. The first static helper requested user-manager parsing for
system units and did not preserve the precise parser diagnostic; that uncertainty
is recorded. Corrected system-mode parsing then exposed an ignored `RuntimeMaxSec`
on the new oneshot bootstrap. It was removed; effective `TimeoutStartSec=5`
remains. The strict final parser has no warnings. Five original failed commands,
logs and [correction records](data/s2_authority_isolation_pilot_1/correction-static-system.json)
remain in the ledger. Each failure was reviewed before the corrected check;
none was a resource failure or a limit increase.

## Preservation scope and remaining obligations

The full audit uses the corrected streaming auditor against the original 8,759-
entry revocation baseline and ten historical supplementary seals, including the
80-path isolation-plan seal. It never regenerates the original baseline from this
workspace. The permitted old-file changes are exactly the two IPC files above and
`docs/status.md`, `docs/traceability.md`, `docs/spec_issues.md`. New sources, tests,
staged templates, fixtures and evidence are enumerated individually; no directory
exclusion is widened. Original manager resource-failure evidence, manuscript,
dependencies, vectors and proof ledger remain protected.

Activation and every actual-ID test are pending approval, including real runtime
linkage/import safety, DAC/ACL enforcement, descriptor handling, preconnected-client
timing, restart boundaries and final resource/reporting results. Prospective code
is not evidence that those executions will pass. Any unexpected access, timeout,
resource event or harness/report failure stops the actual pilot without retries.
The 0.5 s idle/0.4 s test barrier is intentionally not lengthened for system-manager
overhead; failure to meet it is a harness failure, not a successful fencing test.

Next step: approve only the concrete guarded activation/runbook so the 22 cases can
supply the missing evidence. **Only after the isolation pilot passes**, recommend a
bounded full lifecycle integration package using these durable components. Bounded
production signing/DEP-001/002, complete privacy-preserving proof feasibility,
selective-disclosure/non-revocation integration and security/privacy review remain
open. Stages 2–3 are not complete.


## Final validation and activation decision

[One complete preservation audit](data/s2_authority_isolation_pilot_1/result.json)
**passed**, exit 0, in **2.163518033 s**, cgroup `memory.peak`
**22,597,632 bytes (21.55078125 MiB)** under the unchanged 256 MiB ceiling.
Supplementary tree RSS was 40,488,960 bytes. The content, inventory, report write/
readback and final outer guard all completed; no memory-limit/OOM/swap event.
Coverage: **9,251 content paths**, no overlapping partitions, plus baseline
identities for **9,261 unique historical paths**; **974 inventory entries**, no
missing or unexpected names. The original partition has 8,756 unchanged files and
exactly three allowed documentation changes; the supplementary partition has
490 unchanged files and exactly the two authorised IPC source changes.

Final lint (`quality-closure`) and formatting (`format-closure`) pass. Twenty-one
guarded commands, including five retained reviewed failures, total
**35.443476731 s**. Maximum command cgroup peak is 113,946,624 bytes; maximum
observed temporary storage is 3,809,055 bytes, with zero retained temporary data.
No protected content scan was repeated. Post-guard work is limited to recording
these final results and sealing the package's new/authorised files.

The [authorisation seal](proposals/s2_authority_isolation_pilot_1/source-manifest.json)
contains 96 runtime source inputs, with the two unprivileged-only helpers excluded.
The parser's earlier informational count was 98; the final source seal is the
installation inventory. The templates validated by that parser are unchanged.
The original preceding plan seal is
`c81853d60f250593ce08986347a181b81517da9eb336901e6151b39228582481`.

**Decision: implementation and unprivileged validation ready for review; activation
awaits the user's section 5 approval.** The 22 actual-identity cases are pending.
The next action is the exact privileged runbook, not a claim of deployment safety.
All Stage 2–3, bounded signing and complete private-proof obligations remain open;
CPU proving stays paused with two attempts used/one unused and zero new proofs or
zkVM executions.

## Conditional activation approval — preflight stopped, 19 September 2026

The user approved the exact staged activation **subject to passing preflight**,
and explicitly required stopping if corrections change privileged commands or
effects. That approval is recorded; another request for the same approval is not
the blocker. **No privileged command was executed.** Provisioning, verification,
all 22 cases, shutdown and rollback were not run. No pilot account, group, unit,
credential, store, runtime or root-owned activation directory was created.
The preceding readiness decision above remains historical evidence; the targeted
review found launcher defects that the earlier mocked/static checks did not cover.

### Identity and source review

[Preflight evidence](data/s2_authority_isolation_pilot_1/activation-preflight/result.json)
and [individual comparisons](data/s2_authority_isolation_pilot_1/activation-preflight/inspection.json)
record **96/96 runtime source inputs, 8/8 synthetic inputs and exact inventories**
matching the existing authorisation manifest. Its SHA-256 is
`7fd9f0e1bcedf7ed7756b4f25bdde6458e06650cdece62841100c0f636e09086`.
All **126 preceding package entries** also matched before this authorised
documentation append. That historical package manifest retains SHA-256
`daf88fd67840b059fe0e27da351a073a1a67bb037871c399fee2082f6ac1cc17`.
Neither seal was regenerated. This was a targeted input check, not a repeat of the
completed 9,261-path preservation audit or functional test suites.

Review covered `pilotctl`, `provision`, `configure`, `runtime`, `preflight`,
`owner_entry`, `client_entry`, `control`, `cases`, `layout`, `activation_guard`,
and all seven templates: accounts, directories, slice, owner, client, replacement
manager and bootstrap. The account template names only the 13 new principals and
their 13 private/four transport groups. Directory and unit writes target the
documented pilot namespaces. Source copying, runtime permissions, negative-case
permission changes and credential rotation target fresh pilot resources; there is
no project chown, existing account membership change, boot enablement, unrelated
service stop, package install, proof or zkVM launch.

[Host observations](data/s2_authority_isolation_pilot_1/activation-preflight/host-observations.json)
were made as real host UID/GID 1000, with the identity UID map, not a remapped test
UID. All 13 names, 17 group names and proposed installation paths are collision-free
under the sealed NSS/path check. Python 3.14 and the required systemd executables
are present; existing interpreter evidence is reused. Installed systemd is
259.5-0ubuntu3.4. The memory/cpu/cpuset/pids controllers and kernel `cgroup.kill`
facility are present. Existing parents are root-owned 0755 except for the **absent
`/etc/sysusers.d`**. Project, `src`, `docs` and `.venv` remain UID/GID 1000, 0755.
The composite manager-query probe did not retain its individual command outputs
before an assertion; live system-manager query verification is therefore incomplete,
not a demonstrated facility failure. Its failure is retained separately.

### Blocking discrepancies and required corrections

1. **The approved launcher cannot read its existing ledger.**
   [activation_guard.py](../scripts/isolation_pilot/activation_guard.py#L132) calls
   `read_json` with the default **65,536-byte** limit on the **155,989-byte** historical
   ledger. A read-only diagnostic reproduced `PilotError: input-size`.
   `OUT.mkdir` and the lock precede this read, so the approved provision command
   would first create root-owned project evidence, then fail before provisioning.
   Correct the ledger reader/admission ordering using bounded processing of every
   historical record, preserving the 65,536-byte IPC limit, all failures, time
   accounting and the 256 MiB ceiling. Include this preflight's additional accounting;
   do not truncate the ledger or regenerate it from successful runs only.
2. **A required installation parent is missing.**
   [provision.py](../scripts/isolation_pilot/provision.py#L85) requires
   `/etc/sysusers.d` to exist and pass `protected(..., directory=True)` before
   creating pilot configuration. The current host reports ENOENT. Creating that
   parent is an additional privileged effect absent from the existing command's
   implementation. Its exact creation/ownership and rollback-retention treatment
   must be specified and reviewed; no directory was created during this check.
3. **Complete stop and shutdown are not established.** The installed
   [systemd binary inspection](data/s2_authority_isolation_pilot_1/activation-preflight/installed-systemd-inspection.json)
   supports recursive cgroup killing for a slice: the slice vtable supplies cgroup
   context, and `unit_kill` reaches `cg_kill_kernel_sigkill` with recursive fallback.
   The installed `systemctl(1)` documents default `--kill-whom=all`. This is static
   implementation evidence, not a live termination test. All role templates and
   non-provision coordinator units select `pqiso.slice`; **provisioning omits that
   Slice property** and runs separately under the service's own 256 MiB guard.
   Consequently the runbook's sole slice emergency command does not reach an
   in-progress provisioner. The outer monitor also intentionally sits outside the
   measured worker cgroup. The guard ignores kill-command return codes and does
   not establish that all descendants have exited. Case exceptions skip the
   success-path shutdown. The documented follow-up shutdown itself ignores stop/
   show errors and accepts empty MainPID output, without checking descendant
   cgroups. Correct failure cleanup and emergency coverage for both provisioning
   and the common slice, check command results and bounded quiescence, and retain
   failure reports even when child/reporting timeouts occur. Never signal unrelated
   slices or treat a failed/empty systemd query as evidence of an empty workload.

The intended common slice sets `MemoryMax=268435456`, swap zero, CPU quota 200%,
CPUs 0–1 and TasksMax 128. Its hierarchy would charge coordinator, owners, clients
and descendants, including file cache and kernel memory. That configuration is
consistent with the proposed metric; **effective actual-pilot containment is
unmeasured** because activation did not occur. The stop discrepancies above prevent
signing off the complete enforcement claim. No live signals were sent to test it.

### Rollback review

[rollback()](../scripts/isolation_pilot/provision.py#L242) first calls shutdown,
then validates the full recorded removal list against the five fixed unit paths
and two fixed sysusers/tmpfiles files, checking ownership/mode and all recorded
digests before unlinking any of them. It separately checks the approval marker's
owner/mode before removal. The marker has no digest entry in `created_files`;
do not describe it as digest-verified. Changed control files cause refusal.
There is no recursive removal of accounts, runtime, credentials, stores, journals,
history or evidence. Those retention boundaries match the runbook.

Operational rollback still depends on correcting shutdown. The runbook's installed
controller path also cannot be used if provisioning fails before that controller
has been copied. Any proposed early-failure configuration rollback must identify
an exact trusted guarded entry point and preserve the creation ledger, absent-path
handling and retained resources. That fallback was not added or executed here.

### Measurements, retained failures and decision

The one guarded seal/ledger diagnostic completed with exit **0**, report readback
complete, in **0.133094973 s**. Cgroup-v2 `memory.peak` was **21,561,344 bytes
(20.5625 MiB)**; supplementary sampled tree RSS was **43,057,152 bytes**. The
metric covers the complete diagnostic worker subtree and charged anonymous/file/
kernel memory; the small external monitor is excluded as before. Memory max/OOM
events and swap peak were zero. Temporary data peak was zero. Admission observed
4,740,952,064 bytes MemAvailable and 7,618,673,412 experiment bytes, below the
unchanged storage stop. **Diagnostic completion is not activation-preflight success.**

New-script lint and formatting checks also pass under the same guard. Three new
guarded commands total **0.335257243 s**; with the preceding 21 commands the
guarded total is **35.778733974 s**, not a reset of the 300 s budget. The effective
limits remain 256 MiB, zero swap, one worker, two CPUs, 60 s command/55 s child,
8 MiB temporary data, 10 MiB package output, 1 MiB/file and 60 KiB command log,
with the existing 9 GiB storage stop. No resource ceiling was raised.

Two small operator metadata probes failed before writing their own JSON: one at
a composite command-status assertion (individual statuses unavailable), one on
the missing sysusers parent. Their commands/failure details are retained in
[operator-probes.json](data/s2_authority_isolation_pilot_1/activation-preflight/operator-probes.json).
A subsequent read-only metadata observer recorded absent paths explicitly and
completed. These operator observations were outside the measured diagnostic
worker; their memory was not measured and is not claimed as actual-pilot evidence.
No original selected case, test suite or preservation audit was repeated.

**Decision: conditional approval received; activation stopped before privileged
mutation under the user's discrepancy rule.** All 22 individual outcomes are
`not-run-preflight-blocked`, with actual IDs null. There are no new host resources
to shut down or quarantine, so shutdown/rollback were unnecessary and not invoked.
Only this report, status, traceability, issues and newly enumerated preflight
evidence changed; the runbook, templates, source seal, runtime/cryptographic code,
parameters, dependencies, manuscript and original evidence remain unchanged.

Next: correct and review the concrete launcher, prerequisite and stop/rollback
discrepancies within the existing scope and budgets before reconsidering activation.
Do not silently replace the reviewed seal. Recommend bounded full lifecycle
integration only after all 22 actual-identity cases and their outer guards pass.
Stages 2–3 stay open. Production bounded signing and complete private-proof
feasibility remain unresolved; CPU proving is paused, two attempts used/one unused,
with no proofs or zkVM executions in this continuation. Only manuscript Sections
II–VIII remain authoritative; no new manuscript-derived requirement was introduced.

## Targeted correction pass — version 2, no activation

The user authorised implementation/validation of the three preflight corrections,
with **24 additional focused invocations and a 124 cumulative ceiling**. The prior
76 invocations are not reset. Original-scope activation approval remains recorded;
only the additional commands/effects in the
[version-2 runbook](proposals/s2_authority_isolation_pilot_1/v2/README.md) require a
new decision. No privileged host action or actual-identity case ran in this pass.

The original 11 runtime tools, seven templates, source seal, runbook, fixtures,
failed preflight and historical validation remain untouched. Corrected tools are
in `scripts/isolation_pilot_v2`; corrected templates/runbook are in the nested
`v2` proposal directory. The [candidate seal](proposals/s2_authority_isolation_pilot_1/v2/candidate-manifest.json)
explains every changed/copied input and references original seal SHA-256
`7fd9f0e1bcedf7ed7756b4f25bdde6458e06650cdece62841100c0f636e09086`.
The final corrected seal is issued after the complete audit and final guard result;
its digest and cumulative measurements are appended below.

### Implemented corrections

**Ledger admission.** The failing document is exactly
`docs/data/s2_authority_isolation_pilot_1/run-ledger.json` (155,989 bytes, 21 rows,
including five failed commands). The old guard's `main()` was the direct caller
that sent it through `layout.read_json()`'s 65,536-byte default. All other ordinary
reader calls remain at that limit; source-manifest reads retain their existing
explicit bound. Historical `run_checks.py`, audit/preparation and the preflight
wrapper are retained, not rewritten as though they had used this correction.

Version 2's `ledger.read_ledger()` has a purpose-specific 1 MiB ceiling, maximum
128 records, 16 KiB canonical bytes per record, bounded structure/depth and unique
names. It validates outcomes and finite non-negative elapsed times, preserving
failed rows. Incomplete records are refused for activation; only an explicitly
in-flight validation audit can charge one as its full 60 s reservation. Oversize,
truncated, duplicate-key, malformed and non-finite documents fail without a fallback.
The new guard and correction runner use this reader for the original ledger,
preflight ledger and correction ledger. Final admission pins those control inputs
against the corrected seal before any new root evidence directory is created.
Started activation records reserve 60 s and block case retries if final reporting
is lost. A conservative merged representation demonstrates capacity for the
remaining 22 case summaries and four lifecycle commands; detailed activation
records remain separate bounded files. No IPC limit was enlarged.

**Shared parent.** `shared_parent.ensure_parent()` validates `/etc` and the exact
`/etc/sysusers.d` path. An existing safe root:root directory is accepted without
changing its metadata. A missing directory is created exclusively, assigned
root:root/0755 and fsynced. Creation intent, previous existence and the final
`created_by_pilot` result are recorded in the new creation ledger; a partial intent
is preserved on failure. Files, symlinks and unsafe parent/ACL conditions are
rejected. Rollback retains the shared parent and unrelated contents. No real parent
was created or chmod/chowned during this correction pass.

**Stop, shutdown and rollback.** `termination.py` centrally gates start requests;
`/run/pqiso-launch.lock` and the persistent `/run/pqiso-stop` inhibitor are proposed
root:root 0600 resources. Four templates add the matching negative start condition.
The stop-only source-tree `emergency_stop.py` requires neither the installed runtime
nor the normal guard/ledger. It explicitly enumerates 49 pilot units, covering
separate provisioning/maintenance cgroups, the common slice, every fixed owner,
bootstrap/client, replacement manager and original case coordinator. It does not
match process names, stop unrelated units or launch cleanup workloads.

The [installed-interface observation](data/s2_authority_isolation_pilot_1/correction-v2/installed-interface.json)
records complete successful `not-found`/inactive service responses from systemd
259, rather than treating failed queries as absence. Strict property parsing checks
identity, jobs, state, both service PIDs and the exact permitted cgroup. Cgroup
`populated` includes descendants. Missing/malformed properties, nonzero status,
stderr, bus errors, timeouts, occupied cgroups and uncertain lock acquisition all
prevent completion. MainPID zero alone is insufficient. Emergency SIGKILL and
irreversible stop requests target only the fixed identified units.

A failed worker triggers the independent stop and remains a failed command even
if teardown succeeds. Stop/report failures remain incomplete. Stop evidence is
bounded and appended to the inhibitor file; earlier failures are retained. Normal
shutdown/rollback use the source guard, first finish independent teardown, then
admit their separately capped maintenance worker. Thus partial provisioning does
not require an already installed controller. Rollback checks an explicit complete
shutdown result before validating/removing the seven recorded configuration paths
and marker. It retains accounts, runtime, credentials, stores, history, evidence,
shared parent and inhibitor/lock files. Missing creation data or stale sockets
require review, never automatic adoption or unlinking.

The small external emergency monitor remains outside the original workload
cgroup scope and adds address-space/CPU/alarm/output bounds of its own; these do
not replace the primary 256 MiB charged-memory metric. Ordinary admission retains
a ten-second emergency reserve. The outer guard stops new work by 55 s to leave
teardown time within the original 60 s ceiling. Stop remains available when ordinary
admission fails; configuration rollback still requires valid evidence and headroom.
The trusted host root/operator boundary remains unchanged.

### Focused validation and retained failures

**24/24 focused invocations passed**: the initial 20 tests plus four distinct
admission/failure-report closure tests. This consumes the additional allowance;
there are **100 cumulative executed invocations**, 22 original actual-ID cases
still pending, and two unallocated slots within the 124 total ceiling. Those two
slots are not permission for further focused tests or identity retries. The
[invocation log](data/s2_authority_isolation_pilot_1/correction-v2/test-invocations.jsonl)
counts starts, including failures/repeats. No earlier suite was rerun.

Tests use temporary fixtures and explicit ownership/systemd models, never actual
root identities. Oversize admission is tested through an oversized stat observation,
without writing a file larger than the unchanged per-file ceiling. Coverage includes
legitimate/future ledger representation, all invalid-input classes, missing/existing/
unsafe parents, partial-provision stop scope, launch inhibition, failed queries,
surviving descendants, bounded incomplete termination, rollback refusal/retention,
sealed-control mutation, failed-worker cleanup and failed stop reporting.

Static parsing passes without warnings; it substitutes only absent executable and
working-directory paths, preserving the security/identity directives. The 22 case
IDs/assertions and fixtures are unchanged. Native/functional/cryptographic evidence
is reused. Three lint commands failed on overlong documentation strings;
import-order fixes and literal splitting are recorded, with original failed logs
retained. None was a resource failure. Three intervening check requests were refused
before a worker started while the final lint failure awaited review. Final quality and full preservation
results follow below; no failure is overwritten or counted as an isolation pass.

Only the four existing report/status/traceability/issues files receive append-only
updates. All new versioned paths are individually inventoried for the corrected
preservation audit against the original 8,759-entry baseline and historical seals,
including the completed preflight evidence. No directory exclusion is widened.

Stages 2–3 remain open. Bounded production signing and complete private-proof
feasibility remain unresolved, as do full lifecycle integration and privacy/security
review. CPU proving stays paused; two attempts used/one unused, no proofs or zkVM
executions. Only manuscript Sections II–VIII are authoritative; the manuscript,
cryptographic implementation, parameters, dependencies and original vectors are
unchanged. Bounded full lifecycle integration is recommended only after actual
isolation validation passes, not on these temporary/model tests alone.

### Version-2 final closure and concrete activation decision

[One corrected complete audit](data/s2_authority_isolation_pilot_1/correction-v2/result.json)
**passed**, exit 0, in **2.206143964 s**, cgroup `memory.peak`
**33,054,720 bytes (31.5234375 MiB)**. Supplementary sampled tree RSS was
46,301,184 bytes. Content comparison, inventory, report write/readback and final
outer guard all completed. No memory-max, OOM or swap event occurred. Coverage is
**9,391 content paths**, zero overlapping partitions, **9,403 identity-inclusive
historical paths** and **1,084 inventory entries**, with no missing/unexpected names.
The original baseline, seals, original runbook/tools/templates, previous failed
preflight, dependencies, manuscript, vectors and proof ledger remain preserved.
All four prior report prefixes also match, and the audit permits only their
explicit append-only updates. This is one additional requested correction audit;
the original complete audit is retained, not replaced or recounted as this run.

Final lint (`v2-lint-closure`), formatting (`v2-format`), template parsing and all
24 focused invocations pass. Three reviewed lint failures and three pre-worker
admission refusals remain in the evidence. No resource failure, identity case,
proof, zkVM execution or host provisioning occurred. New source behaviour was
validated with fixtures/models; actual OS isolation remains untested.

The correction's largest worker cgroup peak was **39,866,368 bytes
(38.01953125 MiB)** and maximum supplementary tree RSS was 64,286,720 bytes.
Temporary data peaked at **478,128 bytes**, then was cleared; retained temporary
data is zero. The unchanged primary ceiling is 268,435,456 bytes, with zero swap.
Package output was 1,403,586 bytes before the audit report, well below 10 MiB.

Fourteen new guarded commands, including the retained failures, consumed
**3.996667133 s**. Total guarded time is **39.775401107 s**; adding the explicit
five-second operator charge gives **44.775401107 s charged** and
**255.224598893 s remaining** of the original 300 s. Of that, 10 s is reserved for
emergency stopping, leaving **245.224598893 s** before that reserve. No time budget
was reset. The final capacity calculation accounts for 38 existing command records
and 26 remaining result summaries at a conservative **722,338 bytes**, below the
1,048,576-byte per-file ceiling and 128-record bound.

The final [corrected source/control manifest](proposals/s2_authority_isolation_pilot_1/v2/source-manifest.json)
SHA-256 is:

```text
994327b3b0d32d22b6ce9aa09a5125ec798d509ebbdcfa79819bf2225f1a6c32
```

It pins the same 100 runtime inputs as the tested/audited candidate, all eight
unchanged fixtures, the version-2 runbook, resource amendment, original/preflight/
correction ledgers, case plan and final validation closure. Thirteen input deltas
are explained: five changed versioned tools, four new helpers and four service
start conditions. The final seal references both the original digest and the
candidate digest; it does not replace either. Final post-guard work is limited to
validation bookkeeping, unchanged-input sealing and these result appends. Frozen
admission inputs must not be edited to record a later approval or activation run;
those future records belong to separate activation evidence.

**Decision: correction implementation and focused/static/preservation validation
complete; no known remaining correction blocker. Activation is withheld.** The
additional 24-test allowance is fully consumed; cumulative executions are 100,
with the original 22 actual-ID cases pending and two unallocated total slots.
The original-scope approval remains valid. Request approval only for the exact
version-2 command/effect delta in the revised runbook: absent-only shared-parent
creation, root launch-lock/inhibitor/evidence files, template inhibition and
independent stop/source-tree maintenance. The four changed command forms are
printed there and in the user-facing decision. No second approval for the 13
accounts, 17 groups or original 22 cases is requested.

Emergency stop remains independent of installed/normal controllers and ordinary
ledger admission. Unknown termination or reporting still blocks rollback; data,
accounts, credentials, runtime, shared parent and stop/lock files remain retained.
After approval, repeat only the required live preflight, then follow the fixed
22-case sequence and stop rule. Recommend bounded full lifecycle integration only
if all actual cases and outer guards pass. Production bounded signing and complete
private-proof feasibility remain unresolved, Stages 2–3 open, CPU proving paused,
and the proof ledger remains two attempts used/one unused.


## Version-2 approval and live preflight — authentication pending

The user's subsequent approval explicitly binds the version-2 command and host-effect
delta to SHA-256
`994327b3b0d32d22b6ce9aa09a5125ec798d509ebbdcfa79819bf2225f1a6c32`.
The original pilot scope remains authorised. No further approval of that scope is
needed. The [sealed version-2 runbook](proposals/s2_authority_isolation_pilot_1/v2/README.md)
is retained byte-for-byte, including its historical pending-approval wording; this
append records the later approval without changing a frozen admission input.

The [live preflight](data/s2_authority_isolation_pilot_1/activation-v2-session/seal-preflight.json)
verified the exact approved manifest, all 100 runtime inputs, eight frozen control
inputs and eight synthetic fixtures, including exact inventories. No mismatch or
resealing occurred. Real-host NSS/path checks found no pilot collisions and no
loaded pilot units. `/etc/sysusers.d` was absent; the six required existing parents
were root:root 0755. `/run/pqiso-launch.lock`, `/run/pqiso-stop` and the privileged
activation evidence directory were absent at this observation. The host interpreter
is Python 3.14.4; systemd is 259.5-0ubuntu3.4, with the required cgroup-v2 memory,
CPU, cpuset and pids controllers available. Effective worker limits must still be
confirmed by the activation guard after a real launch; availability alone is not
resource-enforcement or actual-identity evidence.

Available memory was 4,893,945,856 bytes; experiment storage was 7,618,673,833 bytes
and package output was 1,448,944 bytes before the new observation records. The live
read-only check took 1.432155590 s and recorded 22,781,952 bytes process peak RSS.
That RSS is an operator-observation metric, not a pilot workload cgroup peak. This
bounded observer used a 256 MiB address-space bound, two-CPU affinity, five-second
CPU bound and ten-second alarm. It did not replace or modify the pilot's primary
256 MiB cgroup charged-memory ceiling, zero-swap limit or any other guard setting.

An earlier sandbox-namespace ownership observation stopped with `unsafe-owner`;
it was not evidence about real-host ownership. The subsequent real-host read-only
observation above passed. `sudo -n true` then reported that interactive
authentication is required (exit 1). These are retained operator observations,
not focused tests or identity-case failures. No privileged workload was launched
by the assistant. The operator has been asked to run the one already-approved
provisioning command in their WSL terminal and return its final JSON. Verification
and cases remain withheld pending inspection of that result; no retry is requested.

[Session accounting and observations](data/s2_authority_isolation_pilot_1/activation-v2-session/session.json)
retain the prior 44.775401107 s charge. An additional conservative five-second
operator charge reduces the user's rounded 255.22 s starting remainder to
**250.22 s**, including the unchanged **10 s emergency reserve**. Thus 240.22 s
remains before that reserve, before any activation command. Later guarded command
and recorded stop times must also be deducted; no ledger or aggregate budget is
reset. Stop admitting ordinary work if its maximum allowance and the required
shutdown cannot both fit. Incomplete activation records retain their full
60-second reservation. The existing 24 correction tests and historical suites were
not repeated. Cumulative test invocations remain **100**; the unchanged 22 cases
remain pending, with no additional cases or retries authorised.

| Order | Identity case | Current evidence |
| --- | --- | --- |
| 1 | ISO-RUNTIME | Pending; not invoked by this session |
| 2 | ISO-ROLE-m | Pending; not invoked by this session |
| 3 | ISO-ROLE-i | Pending; not invoked by this session |
| 4 | ISO-ROLE-va | Pending; not invoked by this session |
| 5 | ISO-ROLE-vb | Pending; not invoked by this session |
| 6 | ISO-CROSS-va | Pending; not invoked by this session |
| 7 | ISO-CROSS-vb | Pending; not invoked by this session |
| 8 | ISO-RECIPIENT | Pending; not invoked by this session |
| 9 | ISO-DAC-DENIED | Pending; not invoked by this session |
| 10 | ISO-ACL-DENIED | Pending; not invoked by this session |
| 11 | ISO-FENCING | Pending; not invoked by this session |
| 12 | ISO-ROTATION | Pending; not invoked by this session |
| 13 | ISO-HOLDER | Pending; not invoked by this session |
| 14 | ISO-FD | Pending; not invoked by this session |
| 15 | ISO-MISCONFIG-peer-identity | Pending; not invoked by this session |
| 16 | ISO-MISCONFIG-socket-mode | Pending; not invoked by this session |
| 17 | ISO-MISCONFIG-writable-parent | Pending; not invoked by this session |
| 18 | ISO-MISCONFIG-mutable-runtime | Pending; not invoked by this session |
| 19 | ISO-RESTART-m | Pending; not invoked by this session |
| 20 | ISO-RESTART-i | Pending; not invoked by this session |
| 21 | ISO-RESTART-va | Pending; not invoked by this session |
| 22 | ISO-RESTART-vb | Pending; not invoked by this session |

No actual pilot UIDs/GIDs, case measurements or isolation outcomes are available
from this observation. At the last real-host check no pilot resources existed, so
there was no workload requiring shutdown or configuration requiring rollback.
This is not a shutdown result for a future or operator-started provision. After
provisioning begins, the documented strict shutdown and, where required,
configuration rollback remain mandatory; failed queries or incomplete reporting
must never be converted into a successful termination claim.

**Current disposition: activation authorised, awaiting an authenticated operator
provisioning result; isolation validation remains incomplete.** The user has
specified **S2-CONCRETE-SECURITY-ASSESSMENT-1** as the next package after this attempt
completes or is safely stopped, before further lifecycle integration. This later
instruction supersedes the earlier conditional lifecycle recommendation; wait for
the user's assessment task. Stages 2–3 remain open. Bounded production signing and
complete private-proof feasibility remain unresolved. Only manuscript Sections
II–VIII are authoritative. No proofs or zkVM executions occurred; CPU proving
remains paused and the proof ledger remains two attempts used, one unused.


## Security-assessment prerequisite — 24 September 2026

The separate S2-CONCRETE-SECURITY-ASSESSMENT-1 task permits analysis after a safely
settled stopped state. [Fresh strict read-only host evidence](data/s2_concrete_security_assessment_1/host-closure.json)
confirmed no jobs/workloads/descendants in the fixed version-2 pilot units/cgroups
and no proposed pilot resources. The attempt is safely stopped **unactivated**;
this does not pass any of the 22 pending actual-identity cases. The previously
recorded privileged-authentication blocker and every failure remain unchanged.
No shutdown, rollback, activation or host mutation was needed or performed.
Original/version-2 approvals remain valid, cumulative test count 100 and separately
charged remaining time 250.22 seconds (including ten-second reserve) remain intact.
The analysis uses a separate guard/accounting envelope and does not consume this
pilot budget. See the [security assessment](stage2_concrete_security_assessment.md)
for its own conclusions and resource closure. Stages 2–3, production signing,
recovery/isolation and complete private-proof feasibility remain open; no proofs
or zkVM executions, proof ledger two used/one unused.


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
