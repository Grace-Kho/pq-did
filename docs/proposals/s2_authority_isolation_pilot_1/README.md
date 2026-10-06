# S2-AUTHORITY-ISOLATION-PILOT-1 staged activation runbook

**Not activated. Explicit user approval is required before any command in the
privileged block.** The user's pilot instruction §5 is the approval boundary;
the preceding planning package did not authorise these mutations. This runbook
covers only fresh synthetic pilot resources, never production authority stores.

## Reviewable inputs and non-mutating commands

From `/home/grace/projects/pq-did`, the guarded commands recorded in
[the package ledger](../../data/s2_authority_isolation_pilot_1/run-ledger.json)
validate the endpoint, configuration models, existing authority contracts and staged
units. The public CLI dry run is:

```sh
.venv/bin/python -I -B scripts/isolation_pilot/pilotctl.py dry-run
.venv/bin/python -I -B scripts/isolation_pilot/pilotctl.py static
```

Dry run prints all 13 account names, their private primary groups, the four
transport groups, exact directory modes/owners, credential modes and complete unit
texts. NSS/path collision checks are repeated as real host root before provisioning;
no existing account/path is adopted. Current namespace observations are not real-ID
isolation evidence. Static parsing substitutes only absent executable/working paths
with `/usr/bin/true` and `/`, retaining all security/identity directives. No unit is
installed or started by these checks.

[Source/input authorisation seal](source-manifest.json) pins the reviewed Python
source, tools, seven templates, liboqs binding distribution/native library and eight
fresh synthetic fixture inputs. This is a new package seal, not a replacement for
any historical preservation baseline. No live deployment capability or signing key
is committed. Capabilities are generated privately only during approved provisioning.

## Exact privileged scope and effects

- Create nologin accounts/private groups `pqiso-o-{m,i,va,vb}`,
  `pqiso-w-{m,i,va,vb}`, `pqiso-admin`, `pqiso-observer`, `pqiso-rec-a`,
  `pqiso-rec-b`, `pqiso-denied`; four groups `pqiso-ipc-{m,i,va,vb}`.
  No existing account memberships or privileged groups change.
- Create `/etc/pqiso`, `/var/lib/pqiso`, `/run/pqiso`, `/opt/pqiso/r1` with the
  exact [directory table](directories.tmpfiles.conf.in). Four additional owner
  client directories let the real owner UIDs exercise cross-role negative probes.
- Install only `/etc/sysusers.d/pqiso.conf`, `/etc/tmpfiles.d/pqiso.conf`, and
  `/etc/systemd/system/{pqiso.slice,pqiso-owner@.service,pqiso-client@.service,
  pqiso-replacement-m.service,pqiso-bootstrap@.service}`. Reload the system manager;
  enable nothing at boot. No unrelated service is altered.
- Root creates a **fresh** `python3.14 -I -B -m venv --without-pip` runtime,
  copies only sealed source/pinned binding/native files, creates one fixed source
  `.pth`, and seals its exact inventory. No existing venv is relocated, no package
  build hooks run as root, and no download/install/upgrade occurs. The redundant
  new `lib64 -> lib` alias is removed before sealing; canonical `lib` is used.
- Root writes policies (0640/private group), the root-only credential vault
  (0700/0400), a creation ledger and explicit activation marker. The fresh-only
  bootstrap helper runs as each **owner UID**, with a one-use root marker and
  absent database requirement. Subsequent starts cannot bootstrap automatically.
- Start only the selected synthetic cases. They deliberately alter permissions or
  identity fields on **new pilot resources** for four negative startup cases and
  restore those exact fields. Credential rotation quiesces the affected units,
  replaces only synthetic bundles, retains the database and requires admission.
- Root-owned activation guard output is newly created only in
  `docs/data/s2_authority_isolation_pilot_1/activation` (0700). Its temporary child
  directory is bounded at 8 MiB. Other runtime evidence is root-private in
  `/var/lib/pqiso/evidence`. Project ownership and existing file permissions stay
  unchanged. Privileged tools are standard-library-only until the release has been
  verified. The reviewed installer runs directly from this trusted operator's
  source tree; no `/root/pqiso-approved` staging directory is required.

Root is needed for account/group creation, protected ownership, private credential
provisioning and system-manager UID switching. The root coordinator is trusted;
all test-client actions run in fixed `User=` units as the selected non-root IDs.

## Privileged commands — only after explicit approval

The first command runs the reviewed installer under the 256 MiB guard. It is
fresh-only and refuses existing resources. All following commands use the newly
protected controller. Each case is separate, sequential and stops on failure.

```sh
sudo /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /usr/bin/python3.14 -I -B /home/grace/projects/pq-did/scripts/isolation_pilot/activation_guard.py provision
sudo /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /usr/bin/python3.14 -I -B /opt/pqiso/r1/activation_guard.py verify
```

Then, for each ID in the exact order below, execute this command with `CASE_ID`
replaced by that literal ID, stopping immediately on nonzero exit. This is the
complete permitted test list, not an open-ended wildcard or retry loop.

```sh
sudo /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /usr/bin/python3.14 -I -B /opt/pqiso/r1/activation_guard.py case CASE_ID
```

| Order | Literal case ID | Required observation |
| --- | --- | --- |
| 1 | ISO-RUNTIME | All 13 actual IDs load only the protected pinned runtime/native library; runtime writes denied |
| 2 | ISO-ROLE-m | Fresh owner bootstrap, explicit admission, authenticated allocation; protected-path and ACL denials |
| 3 | ISO-ROLE-i | Manager IPC bridge, intent through certification; no private issuer result to writer/admin/observer |
| 4 | ISO-ROLE-va | First verifier acceptance exactly once, independent scope/store, bounded client permissions |
| 5 | ISO-ROLE-vb | Second verifier acceptance exactly once, independent scope/store, bounded client permissions |
| 6 | ISO-CROSS-va | va owner/writer denied vb store/config/socket access |
| 7 | ISO-CROSS-vb | Reverse denial |
| 8 | ISO-RECIPIENT | Wrong recipient/field substitution denied; A exact retrieval after deliberately unobserved reply |
| 9 | ISO-DAC-DENIED | Non-member cannot connect or replace protected paths |
| 10 | ISO-ACL-DENIED | Invalid token and admin token used from wrong actual UID denied |
| 11 | ISO-FENCING | Replacement manager writer fences old live owner and already connected client |
| 12 | ISO-ROTATION | Quiesced old connections, old token denied, new token retrieves exact retained outcome |
| 13 | ISO-HOLDER | A denied B wallet; both verifier owner/writer identities denied private wallets |
| 14 | ISO-FD | No inherited sensitive descriptors; SCM_RIGHTS refused; cross-UID /proc/fd denied |
| 15 | ISO-MISCONFIG-peer-identity | Wrong pinned identity aborts startup |
| 16 | ISO-MISCONFIG-socket-mode | Wrong mode on owned synthetic socket aborts startup |
| 17 | ISO-MISCONFIG-writable-parent | Writable endpoint ancestry aborts startup |
| 18 | ISO-MISCONFIG-mutable-runtime | Writable runtime aborts before project imports |
| 19 | ISO-RESTART-m | Retained independent head, inactive restart, explicit admission, allocation count preserved |
| 20 | ISO-RESTART-i | Retained head/certification/recipient delivery and boundaries |
| 21 | ISO-RESTART-va | Retained consumption; no second acceptance; boundaries persist |
| 22 | ISO-RESTART-vb | Same for independent verifier |

The driver retains expected heads outside owner stores following explicit bootstrap
or successful authorised mutations. Restarts compare against those retained tickets;
no automatic admission from merely self-consistent database contents. The synthetic
verifier adapter recognises the unchanged fixture's previously evaluated public
statement/token. It is labelled **reference evidence, never a cryptographic proof**.
Lost-reply coverage means the client deliberately did not observe a response; it
makes no claim that bytes had already been enqueued before the disconnect.

## Resource enforcement and stop rule

The same aggregate 256 MiB cgroup-v2 `memory.peak` scope includes coordinator,
owners, clients and charged file-cache/kernel memory; swap is zero. A small external
monitor also samples aggregate tree RSS. The provisioner is separately guarded
before the common slice exists. One worker, two CPUs, at most four controlled
owner/client processes, 60 s command/55 s child, aggregate 300 s including the
completed unprivileged checks, 8 MiB temporary data, 10 MiB package output,
1 MiB per file, 60 KiB diagnostic stop, and the existing 9 GiB storage stop remain.
Fixed service processing/idle/owner/client limits remain 1 s/0.5 s/20 s/2 s;
bootstrap has an effective five-second start deadline. No automatic restart/retry.

No original selected case is repeated. Seventy-six unprivileged test invocations
already consumed the shared 100-case envelope; 22 proposed cases bring it to 98.
The 32 actual-case ceiling is therefore not permission for 32 additional cases.
No additional case/correction is automatic. A resource breach ends the run; inspect
retained evidence and never raise another limit to compensate. Failed harness,
startup, resource or reporting phases cannot become a successful isolation result.

## Shutdown, verification and rollback

```sh
sudo /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /usr/bin/python3.14 -I -B /opt/pqiso/r1/activation_guard.py shutdown
sudo /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /usr/bin/python3.14 -I -B /opt/pqiso/r1/activation_guard.py rollback
```

The controller stops only its fixed owned units and confirms no surviving main
process/listener. Rollback validates **every installed-file hash and exact pathname**
against the creation ledger before removing configuration files or the approval
marker. It reloads the manager. New accounts remain locked/reserved; stores, journals,
allocation/consumption history, runtime, credentials and evidence remain quarantined.
No database deletion, recursive rollback of data, UID recycling, sidecar cleanup or
unrelated file removal occurs. A changed file, stale socket or partial failure is
retained for review; there is no repair-by-chmod or automatic adoption of a partial
installation. A setup failure can leave protected pilot resources; the ledger is
updated after each installed control file.

Emergency stop after exhaustion (no new workload; no data deletion):

```sh
sudo /usr/bin/systemctl kill --signal=KILL pqiso.slice
```

A stale socket after emergency termination intentionally requires inode/owner/dead-
unit review before a separately authorised cleanup. Guarded verification/rollback
also require remaining resource headroom; exhaustion never licences an unbounded
cleanup workload. Full lifecycle integration is the next recommendation **only
once all actual-identity cases and their outer guards pass**. Bounded production
signing and complete private-proof feasibility remain unresolved.
