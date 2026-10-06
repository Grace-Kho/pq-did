# S2-AUTHORITY-ISOLATION-PILOT-1 corrected activation runbook — version 2

**Not activated. Original-scope approval remains recorded. Only the changed host
commands/effects below require approval before activation.** This correction pass
performs no provisioning, host permission changes, unit launches or actual-ID cases.
The [original runbook](../README.md), original templates and original seal remain
historical, unchanged. Use this version only after approval of its concrete delta.

The [corrected seal](source-manifest.json) records predecessor SHA-256
`7fd9f0e1bcedf7ed7756b4f25bdde6458e06650cdece62841100c0f636e09086`, exact source
and template changes, unchanged synthetic inputs, and frozen admission controls.
Its final digest and validation outcome are in the [implementation report](../../../stage2_authority_isolation_pilot.md).
The final seal is issued after guarded validation and audit; the earlier
`candidate-manifest.json` pins the source actually validated. No unexplained input
change is permitted between candidate and final seal.

## Approval delta: exact changed commands and effects

Run from `/home/grace/projects/pq-did`. These are proposed privileged commands;
none is executed in the correction pass.

```sh
sudo /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /usr/bin/python3.14 -I -B /home/grace/projects/pq-did/scripts/isolation_pilot_v2/activation_guard.py provision
```

This uses the separately reviewed version-2 installer and installs it into the
originally approved, still fresh `/opt/pqiso/r1`. It creates `/etc/sysusers.d` **only
when absent**, through `shared_parent.ensure_parent()` (`mkdirat`, new-directory
`fchown(0,0)` and `fchmod(0755)`, with directory fsync). It validates an existing
root-owned, root-group, non-writable-by-others directory without chown/chmod.
Files, symlinks, writable ancestry and unsafe ACLs are refused. The creation ledger
records prior existence, creation intent and whether this pilot created the parent;
a crash before finalisation leaves the intent for review. Rollback **always retains
this shared parent and unrelated contents**.

The correction adds `/run/pqiso-launch.lock` (root:root 0600), and on final shutdown
or failure `/run/pqiso-stop` (root:root 0600). The latter is a persistent launch
inhibitor and bounded append-only stop-evidence file (at most 1 MiB). Neither file
is automatically removed. Four service templates add
`ConditionPathExists=!/run/pqiso-stop`; no account, group, cryptographic parameter,
role, acceptance assertion, fixture or actual-identity case is added.

Manager start requests hold the launch lock until the request completes. The
coordinator holds it until systemd observes its queued unit. Final teardown writes
the inhibitor before acquiring that lock. Pending/new starts then fail closed;
only the explicit shutdown/rollback maintenance action is admitted afterwards.
The lock is an operational admission serialiser, not a defence against trusted
host root deliberately bypassing the approved controller.

The corrected guard validates bounded local ledger inputs and the final source/
control seal **before creating root-owned project evidence**. It retains started
reservations if a command/report is incomplete, rejects retries and enforces the
original 22-case order. Its purpose-specific reader admits at most 1 MiB, 128
records, 16 KiB canonical bytes/record and bounded nesting/nodes; duplicate,
malformed, truncated, non-finite and incomplete records are rejected. No IPC or
other ordinary 65,536-byte reader is enlarged. Remaining result capacity is
recorded in the validation closure. Raw activation diagnostics remain separate
bounded files; no historical record is truncated or skipped.

Verification and all 22 case command forms remain unchanged after provisioning:

```sh
sudo /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /usr/bin/python3.14 -I -B /opt/pqiso/r1/activation_guard.py verify
sudo /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /usr/bin/python3.14 -I -B /opt/pqiso/r1/activation_guard.py case CASE_ID
```

Replace `CASE_ID` by each literal below, exactly once in order. Stop on a nonzero
exit, unexpected access, resource breach or incomplete reporting. No automatic
case retry or additional case is authorised.

1. ISO-RUNTIME
2. ISO-ROLE-m
3. ISO-ROLE-i
4. ISO-ROLE-va
5. ISO-ROLE-vb
6. ISO-CROSS-va
7. ISO-CROSS-vb
8. ISO-RECIPIENT
9. ISO-DAC-DENIED
10. ISO-ACL-DENIED
11. ISO-FENCING
12. ISO-ROTATION
13. ISO-HOLDER
14. ISO-FD
15. ISO-MISCONFIG-peer-identity
16. ISO-MISCONFIG-socket-mode
17. ISO-MISCONFIG-writable-parent
18. ISO-MISCONFIG-mutable-runtime
19. ISO-RESTART-m
20. ISO-RESTART-i
21. ISO-RESTART-va
22. ISO-RESTART-vb

The assertions and detailed effects are exactly those in the original runbook;
this list is not a new test allocation. Reference fixture verdicts remain reference
evidence, never cryptographic proofs.

## Independent emergency stop — before installation or after partial failure

The exact new command uses only reviewed standard-library source from the trusted
operator tree, independent of `/opt/pqiso/r1`, the normal guard and its ledgers:

```sh
sudo /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /usr/bin/python3.14 -I -B /home/grace/projects/pq-did/scripts/isolation_pilot_v2/emergency_stop.py
```

This is a stop-only external monitor: no workload, proof, installation or data
cleanup is launched. It first persists the inhibitor, then serialises with start
admission. `termination.ALL_UNITS` enumerates all four owners, four bootstraps,
13 fixed clients, replacement manager, provision/verify/22-case/shutdown/rollback
coordinator units and `pqiso.slice`. The provision and maintenance coordinators
have explicit `/system.slice/pqiso-guard-*.service` cgroups; other units belong to
`/pqiso.slice`. No wildcard process matching or unrelated service is used.

The installed systemd 259 interface is queried with explicit `Id`, `LoadState`,
`ActiveState`, `SubState`, `Job`, `ControlGroup` and service `MainPID`/`ControlPID`
properties. Complete, successful `not-found`/inactive responses are distinguished
from bus/query failures. Nonzero status, stderr, timeout, malformed/missing
properties or an unexpected cgroup is **unknown shutdown**, never evidence of
absence. Loaded active services receive explicit `kill --kill-whom=all
--signal=KILL`; fixed loaded units receive `stop --no-block
--job-mode=replace-irreversibly`. Required cgroups must be absent or report
`cgroup.events: populated 0`, which covers descendants. Jobs and service states
must also be inactive/failed and quiescent. An empty/missing main PID is insufficient.
A query/stop/report failure is retained and returns nonzero; no rollback is licensed
by an uncertain result. A lock timeout likewise leaves shutdown incomplete.

The existing charged-memory scope remains the workload cgroup/common slice and
its descendants; the small external monitor remains outside it. The fallback
adds its own 256 MiB address-space, two-CPU affinity, five-second CPU and ten-second
alarm bounds, with a five-second teardown deadline and 60 KiB report cap. These
additional monitor bounds do not substitute address space for workload cgroup
memory or constitute an enlarged workload budget. No new execution workload is
admitted to perform emergency cleanup. Root stop reports are appended to
`/run/pqiso-stop`; output/report failure cannot be reported as a successful stop.
The previous slice-only emergency command is insufficient for provisioning and
is superseded by this exact stop-only command.

## Changed shutdown and configuration rollback commands

These use the reviewed source guard even if the installed controller is absent:

```sh
sudo /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /usr/bin/python3.14 -I -B /home/grace/projects/pq-did/scripts/isolation_pilot_v2/activation_guard.py shutdown
sudo /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /usr/bin/python3.14 -I -B /home/grace/projects/pq-did/scripts/isolation_pilot_v2/activation_guard.py rollback
```

The guard completes the independent stop before admitting a maintenance worker,
so a separately capped maintenance worker does not overlap surviving pilot
workloads. It then rechecks termination, excluding only its own maintenance unit.
A stale socket requires review and is never automatically unlinked. There must be
remaining time/memory/storage headroom for guarded configuration rollback; only
stop remains available when normal admission or the installed runtime is unavailable.

Rollback requires a valid creation ledger, confirmed shutdown, an exact subset of
the seven recorded configuration paths, ownership/mode checks and matching recorded
file digests before any removal. The approval marker retains its explicit owner/
mode check, not an invented historical digest guarantee. A missing creation ledger,
unknown shutdown, altered control file or partial reporting failure prevents a
completion claim. The only deletions are those fixed matching configuration files
and the approval marker. It never removes the shared sysusers parent, accounts,
runtime, credentials, stores, history, evidence or stop/lock files. No production
store adoption, data rollback, UID recycling or broad repair-by-chmod occurs.

## Resource and invocation accounting

The existing 256 MiB cgroup-v2 `memory.peak` ceiling (including charged file cache
and kernel memory), zero swap, one worker, two CPUs, 60 s command/55 s child,
300 s aggregate, 8 MiB temporary data, 10 MiB output, 1 MiB/file, 60 KiB command
log and 9 GiB storage stop are unchanged. Owner/client processing/idle/lifetime
bounds and all cryptographic parameters remain unchanged. The outer guard stops
work by 55 s to retain up to five seconds for teardown within the 60 s ceiling.
A ten-second emergency reserve is required at ordinary command admission.

Historical guarded time is 35.778733974 s. New correction runs are added, including
failed lint and audit outcomes; a conservative five-second charge covers the small
operator observations in addition to measured guarded time. Started-but-incomplete
activation commands cost their full 60 s reservation. Stop-record time is added
conservatively, even if already included in a failed command's wall time. No ledger
is reset. Failure evidence remains present; no resource failure permits escalation.

The explicit invocation amendment is **up to 24 additional focused invocations,
including repeats, maximum 124 cumulative**. Historical consumption is 76; the
original 22 actual-ID cases remain pending and unchanged. Tests are counted when
started, including failure. The final closure records actual consumption and
remaining allowance. Earlier native/functional/audit results are reused where
unaffected. Stages 2–3 remain open; production bounded signing and complete private-
proof feasibility are unresolved. CPU proving stays paused, ledger two attempts
used/one unused, and no proofs or zkVM executions are authorised here.
