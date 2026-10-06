# Proposed activation and verification runbook — DO NOT EXECUTE IN THIS PACKAGE

Scope: one separately authorised **S2-AUTHORITY-ISOLATION-PILOT-1**, using new
synthetic stores and the fixed `pqiso` names below. This is not production deployment
or permission to change host accounts. The present planning package performs none
of the privileged steps. Record exact installed file hashes, newly allocated IDs,
paths, unit names and inodes in a root-owned creation ledger. Never use a wildcard
cleanup, recursive chmod/chown on the project, or a pre-existing runtime/store path.

## Gate 0 — required implementation and approval

Before installation, a reviewed follow-up must supply:

1. A strict cross-UID endpoint policy: configured owner UID/IPC GID, socket 0660,
   parent 2750, approved root-owned ancestry, no group/other directory write, no
   symlink substitution. Both client and server use it. Preserve the original
   0700/0600 same-UID mode explicitly for old tests; no automatic relaxation.
2. Root-protected `preflight.py`, `owner_entry.py`, `client_entry.py` and bounded
   `isolation_coordinator.py` with the exact CLI contracts in the unit templates.
   They parse bounded typed configuration/credential inputs, validate numeric
   UID/primary-GID maps, enforce the existing operation ACLs and fail closed.
   Owner startup is inactive; bootstrap is a distinct explicit synthetic-fixture
   operation. No launcher imports the test-only all-grants provisioning helper.
3. A reviewed release/provisioning helper that copies a strict manifest of public
   runtime files, generates per-scope 32-byte capabilities without logging them,
   and writes bounded root-only credential bundles. It rejects existing targets,
   duplicate/reused accounts, unknown scopes, unresolved placeholders and unsafe
   ownership. A root-owned approved session record establishes each recipient;
   a claimed recipient field does not enrol it.
4. An explicit approval for the listed privileged actions, actual-identity test
   budget and synthetic fixture-only paths. No approval is implied by this plan.

These files/interfaces are requirements, **not existing executable commands**.
The units deliberately reference unavailable launchers. Installing only the
templates must fail; do not replace failed preflight with `true` or omit it.

## Gate 1 — read-only host admission

From the real host view, not a UID-remapped tool/user namespace, record:

```sh
id
systemctl show --property=Version,Virtualization
systemctl --user show --property=Version,ControlGroup
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
namei -l /usr/bin/python3.14
namei -l /home/grace/projects/pq-did/.venv/bin/python
findmnt -T /home/grace/projects/pq-did -o TARGET,SOURCE,FSTYPE,OPTIONS
getent passwd pqiso-o-m pqiso-o-i pqiso-o-va pqiso-o-vb
getent passwd pqiso-w-m pqiso-w-i pqiso-w-va pqiso-w-vb
getent passwd pqiso-admin pqiso-observer pqiso-rec-a pqiso-rec-b pqiso-denied
getent group pqiso-ipc-m pqiso-ipc-i pqiso-ipc-va pqiso-ipc-vb
```

All proposed account, private-group and IPC-group names must be absent. Check each
name individually so mixed `getent` success cannot hide a collision. Check absence
of `/opt/pqiso`, `/etc/pqiso`, `/var/lib/pqiso`, `/run/pqiso`, proposed unit/template
paths and sysusers/tmpfiles files. Also require absent group names corresponding to
all 13 private primary groups. Stop on any collision; do not adopt or repair another
package's objects. Verify cgroup-v2 memory/cpu/pids support and root system-manager
access and CPU IDs 0 and 1 in the effective cpuset; templates pin those two
observed CPUs and do not silently choose an unbounded mask. The existing user manager cannot confer arbitrary service identities.

Admission: MemAvailable at least 256 MiB + 2 GiB, unchanged available-disk/output
thresholds, no concurrent pilot/other proof worker, and original preservation seals
intact. Verify the source/runtime manifest and pinned system Python/native/library
versions. A root-managed OS upgrade invalidates the observed runtime identity and
requires requalification, not an automatic dependency change.

## Gate 2 — privileged account and directory provisioning

Only a trusted host administrator performs these steps after approval. Commands
below use staged files copied to a separately verified root-owned input directory,
shown as `/root/pqiso-approved`; never run privileged code from the writable repo.

```sh
sudo install -m 0644 /root/pqiso-approved/accounts.sysusers.conf.in /etc/sysusers.d/pqiso.conf
sudo systemd-sysusers /etc/sysusers.d/pqiso.conf
sudo install -m 0644 /root/pqiso-approved/directories.tmpfiles.conf.in /etc/tmpfiles.d/pqiso.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/pqiso.conf
```

Account creation and system configuration need root because they change the host
identity/ownership boundary. These commands require the prior exclusive-path check;
`install` or tmpfiles must not overwrite unrelated resources. Record all actual
numeric UIDs/GIDs; pin them in both owner and client policies. Recheck `getent`,
`id ACCOUNT` and `stat` against the complete matrix, including absence of privileged
and owner-private supplementary groups on clients. Logins are disabled, homes are
`/nonexistent`, no sudo/adm/journal/docker membership or credentials are added. Do not enable
linger, user managers or polkit service-management permissions for runtime accounts.
The child units have no cgroup delegation and cannot modify cgroup control files.

## Gate 3 — protected runtime at its final path

The runtime is `/opt/pqiso/r1`, owned by root; each ancestor is root-controlled and
not group/other writable. Current `/home/grace` permissions stay unchanged. The
existing `.venv` is **not copied or moved**. Create a fresh standard environment:

```sh
sudo install -d -m 0755 -o root -g root /opt/pqiso /opt/pqiso/r1
sudo /usr/bin/python3.14 -I -m venv --without-pip /opt/pqiso/r1/.venv
```

The reviewed release helper then copies only approved public files into that exact
release tree, using private new files, bounded chunks and pre/post digest comparison:

- `src/pqdid` without caches into `/opt/pqiso/r1/src/pqdid`.
- The exact installed `oqs` package and `liboqs_python-0.16.0.dist-info` without
  bytecode into the new environment's `lib/python3.14/site-packages`. Preserve
  distribution metadata and file identities; verify RECORD-listed files and an
  explicit complete inventory. No dev/lint extras are needed. The sole runtime
  conditional dependency `tomli` applies only below Python 3.11, so is inactive
  on the pinned 3.14.4. Reject a changed dependency graph instead of guessing.
- The exact pinned `native/.deps/install/lib` under the same relative release
  location, with internal versioned liboqs symlinks. Do not rebuild liboqs.
- The reviewed launcher/preflight/test-coordinator files from Gate 0, separately
  identified from preserved protocol code.
- One path-only `_pqdid.pth` containing `/opt/pqiso/r1/src` and a newline; no
  original editable `.pth`, `_virtualenv` startup hook, activation script, tool
  cache, project secrets, historical evidence or old store is imported.

Use root:root, directories 0755, files 0644 and executable files 0755. Do not
hard-link to the mutable workspace. Permit only documented interpreter links to
`/usr/bin/python3.14` and internal native-library links; walk their resolved parents
as well. The system interpreter, stdlib, SQLite, libc, libm and dynamic loader stay
under root-managed `/usr`/`lib`; do not redirect to a home-directory library.

This is a specifically assembled fresh environment, not a claim that arbitrary
virtualenv relocation works. New site layout/import/ABI compatibility is a mandatory
actual-identity gate. Run `-I -B` with the clean environment in the unit template;
inspect `sys.prefix`, `sys.base_prefix`, `sys.path`, module origins, distribution
version, actual loaded library path and `/proc/self/maps`. Call the existing guarded
backend loader for its version/context-API/path checks; do not directly `import oqs`
with its auto-download path. No signing, proving, network installation or dependency
upgrade is part of that runtime check. Expected pqdid source resolves under
`/opt/pqiso/r1/src`; unchanged `backend.ROOT` therefore finds the staged native tree.

Root promotion is privileged to keep code/configuration immutable to runtime
identities. Do not execute project build hooks as root. No wheel build or network
cache is required by this selected assembly. All release files count towards the
pilot's aggregate storage budget; temporary copy/verification data stays within
8 MiB. Stop if the closed file manifest cannot be staged within the fixed limits.

## Gate 4 — private provisioning, policies and synthetic stores

The trusted host provisioner resolves the placeholders in `principals.json` against
actual `getent` identities, independently approved ServiceKeys/scopes and expected
head tickets. It writes root-owned role/client policies mode 0640, group equal to
the respective private primary group, in the new 0750 configuration directories.
Capabilities are generated in memory (32 random bytes per principal/scope), stored
only in `/etc/pqiso/credentials` (root:root 0700, files 0400), and delivered by
`LoadCredential`. No token in JSON committed to the repo, command arguments,
environment variables, shell history or logs. `%d` passes a directory path, not a
secret. The owner-i bundle also contains its separately scoped manager-reader token.

The application administrator may admit/replace writers; it cannot edit policies,
provision its own extra permissions or read the root credential vault. Only the
trusted host provisioner can add, rotate or revoke a mapping. Preserve stable
logical principal/recipient bindings for recovery; do not silently reassign an
existing recipient to another account. Pin actual peer UID **and primary GID**;
socket access groups are supplementary and are not SO_PEERCRED primary-GID claims.

Bootstrap only new synthetic fixture stores, running under their owner UIDs via
the reviewed bounded helper in the aggregate slice. Database/parent must be absent
before first bootstrap; restart uses the existing file with the unchanged strict
0700/0600 checks, DELETE/EXTRA readback and configured service identity. No existing
database permissions, manifests, checkpoint bytes or real holder records change.
Approval/recipient fixture bindings remain labelled synthetic, not a completed
production business-enrolment protocol.

## Gate 5 — install units, preflight and bounded activation

After all previous gates, install only the exact reviewed files:

```sh
sudo install -m 0644 /root/pqiso-approved/pqiso.slice.in /etc/systemd/system/pqiso.slice
sudo install -m 0644 /root/pqiso-approved/pqiso-owner@.service.in /etc/systemd/system/pqiso-owner@.service
sudo install -m 0644 /root/pqiso-approved/pqiso-client@.service.in /etc/systemd/system/pqiso-client@.service
sudo install -m 0644 /root/pqiso-approved/pqiso-replacement-m.service.in /etc/systemd/system/pqiso-replacement-m.service
sudo systemd-analyze verify /etc/systemd/system/pqiso-replacement-m.service /etc/systemd/system/pqiso.slice /etc/systemd/system/pqiso-owner@.service /etc/systemd/system/pqiso-client@.service
sudo systemctl daemon-reload
```

The root-owned approval marker may now be created with mode 0600, recording the
approved release/creation-ledger identity. Do not enable units at boot. The reviewed
coordinator starts only cases/units authorised in `acceptance.json`, under
`pqiso.slice` and one 60 s case command at a time (55 s child deadline, total 300 s).
Its own process belongs to the same capped slice; only the small resource monitor
is outside, as in the existing envelope. Starting per-unit 256 MiB limits without
the common slice does not satisfy the aggregate ceiling. The coordinator/monitor
implementation is a Gate 0 blocker, not an existing runnable helper.

For each case: start only the required manager owner, verify ready/inactive status,
then explicitly admit/replace using the approved head via the admin client. Start
issuer only after the configured manager channel is ready. Verifiers use separate
stores/identities/audiences. Sequential groups use at most four controlled processes;
never start all role units together merely to shorten the run. For ISO-FENCING only,
use the dedicated `pqiso-replacement-m.service` under the same trusted manager owner
UID and store. Its root-configured `replacement` slot uses a distinct writer ID and
`/run/pqiso/m/replacement.sock`; the primary owner keeps its old permit/socket.
The authenticated admin replaces through the second endpoint while a client remains
connected to the first. Slot selection is trusted launcher configuration, never an
IPC argument or a client-selected database path. Both processes share the aggregate
slice and the four-process ceiling. Systemd Type=exec
confirms exec, not application readiness; require the authenticated bounded status
handshake before proceeding. Missing data/config/credentials or bad permissions mean
unavailable and stop, never automatic chmod, bootstrap, default ACL or direct-store
fallback. `Restart=no`; owner lifetime remains 20 s, client unit 5 s, IPC bounds
unchanged. Application processing timeout is 1 s, client socket timeout 2 s.

Before any listener, preflight must check every source/runtime/config path and
resolved target, account/group allowlist, namespace/cgroup membership, key/scope
identity, SQL settings and store/head integrity. Reject unexpected ACL grants,
capabilities, setuid files, writable ancestry and unsafe log destinations. Expect
exact source hashes/ownership; a mode table alone cannot prove import safety.

Inherited-descriptor rule: no socket activation or FD store; stdin null, stdout and
stderr only the private diagnostic channel; no database/credential/listener handles
passed to clients, `close_fds=True`, no `pass_fds`, close-on-exec on internal handles.
Allow only documented runtime-internal FDs after startup. Reject ancillary rights
on IPC. Capture a bounded descriptor inventory under the actual identities; `/proc`
cross-UID protection and `ProtectProc=invisible` supplement, not replace, this rule.

## Verification and restart/revocation

Use the template-instantiated names for the selected case (example manager):

```sh
systemctl show pqiso.slice -p MemoryMax -p MemorySwapMax -p CPUQuotaPerSecUSec -p TasksMax -p ControlGroup
systemctl show pqiso-owner@m.service -p User -p Group -p MainPID -p ControlGroup -p ActiveState -p Result
id pqiso-o-m
id pqiso-w-m
namei -l /var/lib/pqiso/stores/m/authority.sqlite3
namei -l /run/pqiso/m/owner.sock
stat -c '%u %g %a %n' /var/lib/pqiso/stores/m /run/pqiso/m /run/pqiso/m/owner.sock
```

The actual test clients must additionally execute open/write/unlink/rename/connect
attempts under their real IDs. Report only success/errno, never private bytes;
unexpected read success closes immediately and fails the case. Use only the new
synthetic fixtures. Test both verifier directions, wrong recipient/field substitution,
invalid capability with transport access, valid synthetic token from a wrong UID,
stale connected writers, inherited FDs, four explicit misconfigurations and all
four role restarts. The coordinator verifies real process UID/GID and kernel peer
observations, rather than trusting client output alone. Capture cgroup memory peak,
events/swap, sampled tree RSS, time/storage, exact commands and completed outcomes.

Restart: stop only the owned case units, confirm empty cgroups/no surviving
listeners, retain DB/journals, remove a stale socket only after checking the owned
unit is dead and exact path/inode/type/UID matches its creation record. Never delete
SQLite sidecars. Recreate the volatile `/run` directory from the approved template
if needed, revalidate all ownership and mappings, reopen inactive, and require the
independently approved exact ticket/new writer admission. No auto restart or ticket
derived merely from a self-consistent rolled-back store.

Credential revocation/rotation: quiesce affected owner instances (including stale
ones) and clients; stop units and close already connected sockets; retain committed
DB state. Atomically replace the bounded owner/client bundles and identity maps
under host-provisioner authority, then repeat startup/preflight and explicit
admission. Verify old token and old connection refusal. Immutable loaded policies
are not live-revoked just by editing a file. Never reuse a numeric UID while a
retained grant/store could name it. Bytes already delivered/enqueued cannot be
recalled; credential-delivery access revocation is not PQ credential revocation.

## Rollback limited to newly created pilot resources

For this planning package, there are **no installed resources to roll back**.
For the subsequent approved pilot, use its root creation ledger, not name matching:

1. Stop its recorded client and owner units, then its coordinator and slice; confirm
   all owned cgroups are empty. Remove only its approval marker after identity check.
2. Revoke the pilot mappings and retain credentials root-only for the approved
   handling policy. No automatic secure-erasure or already-delivered-byte claim.
3. Remove only unit/sysusers/tmpfiles configuration files whose installed hashes
   match that ledger, then `systemctl daemon-reload`. Restore no unrelated file.
4. Leave new stores, journals, release, logs and evidence quarantined under their
   protected ownership. Do not automatically delete databases or roll them back.
   No recursive deletion, project chmod, copying over original stores or WAL cleanup.
5. Leave newly created nologin accounts locked/reserved until their grants and data
   are retired under a separate decision. Do not recycle UIDs or change pre-existing
   memberships. Removal of retained data/accounts requires separate explicit scope.

Passing static checks in the planning package is not permission to execute this
runbook, nor evidence of actual OS isolation, whole-store rollback detection or
WSL host/power-loss durability.
