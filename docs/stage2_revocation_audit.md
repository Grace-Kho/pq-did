# S2-REVOKE-AUDIT-1 — preservation within the unchanged 256 MiB ceiling

19 September 2026. Audit implementation, temporary-fixture tests and evidence only.
No cryptographic code, protocol behaviour, parameter, dependency or manuscript change.
Only manuscript Sections II–VIII remain authoritative; this package changes no
specification. CPU proving stays paused: **two attempts used, one unused**;
**zero proofs and zero zkVM executions**. Stages 2–3 remain open.

## What failed previously

The exact previous child command was:

```sh
.venv/bin/python docs/data/s2_revoke_state_1/audit.py
```

Its launcher was `.venv/bin/python docs/data/s2_revoke_state_1/run_checks.py final-audit`.
The full systemd command, properties and environment are retained in the original
[guard record](data/s2_revoke_state_1/final-audit.json), with its
[service measurements](data/s2_revoke_state_1/final-audit.service.json),
[log](data/s2_revoke_state_1/final-audit.log),
[content result](data/s2_revoke_state_1/validation.json) and
[STOP](data/s2_revoke_state_1/STOP.json).

All 8,759 original content comparisons completed: 8,756 unchanged and the exact
three permitted documentation changes, no missing files. The child also completed
manuscript/ledger identities, existing test/resource evidence, syntax, lint/format,
JSON and 235 local-link checks, and wrote its report before exiting zero. That was
**not successful completion of the guarded audit**: the worker then observed
387 `memory.events:max` events, with `memory.peak = 268435456`, and returned **125**.
Guarded wall time was **1.402033682 s** (child **1.327564731 s**). There were no OOM,
OOM-kill or swap events. Sampled aggregate process RSS peaked at **39,108,608 bytes**.
The failure was detected during post-child resource inspection; the original logs
cannot locate the first ceiling event within hashing, validation or reporting.

The ceiling is cgroup-v2 **charged memory for the worker and every descendant**:
anonymous memory, charged file cache and kernel memory. It is not a Python-heap,
RSS-only or address-space limit. The outer systemd launcher/monitor is outside the
worker group, as before; no content work runs there. The additional sampled sum of
member-process `VmRSS` is recorded and checked separately. Neither metric substitutes
for the other. The original report's content success and failed guard remain intact.

## Cause supported by source and bounded diagnostic

The original SHA-256 helper already used `hashlib.file_digest`; the installed
Python 3.14 implementation reuses a **256 KiB** buffer. There was no whole-file
Python allocation for the large protected binaries. The original baseline parser
retained its 1,581,536-byte JSON text/map, and later JSON validation could create a
second map. The result/list/log structures and serialisation were small relative
to the ceiling, although avoiding duplicate structures improves the bound.

The single [diagnostic](data/s2_revoke_audit_1/diagnosis.json) was explicitly **not a
complete preservation check**. It loaded the existing manifests, inventoried sizes
without rebaselining content and read one existing 23,967,968-byte protected Ruff
binary twice, capped at 64 MiB per read and 20 s internally, inside the original
resource guard. Two baseline dictionaries reached **24,309,760 charged bytes**.
A buffered read retaining consumed pages raised measured charged file memory from
**2,428,928 to 9,007,104 bytes**, with highest sampled current **30,064,640 bytes**.
After discarding consumed pages, the second read reached **22,872,064 current bytes**
and retained **2,428,928 file bytes**. Both reads produced exactly the same SHA-256.
The guard passed with zero memory-max/OOM events. These were not independent cold-cache
trials; mapped/shared pages and existing cache ownership affect the charge.

This supports **avoidable buffered file-cache retention** as the mechanism corrected.
The original protected files totalled **293,614,566 bytes** at diagnostic inspection,
including a **108,165,720-byte** executor binary. The original run did not capture
memory categories, so its exact anonymous/file/kernel split and peak phase remain
unknown. The evidence does not support blaming a whole-file hash allocation or
claiming a precise retrospective attribution. Instrumentation itself remains in the
same worker and is included in the new peak.

## Correction and exact scope

The new [audit engine](../scripts/preservation_audit.py) reads SHA-256 input through
one 256 KiB buffer. Linux `POSIX_FADV_RANDOM` avoids unnecessary readahead;
`POSIX_FADV_DONTNEED` releases consumed clean pages in bounded chunks. These are
cache hints, not edits, exclusion rules or a substitute for the cgroup ceiling.
Errors in cache advice or I/O fail the audit. Every file is hashed to EOF, including
the largest binary. No work moves into unmonitored helpers.

A strict incremental UTF-8/JSON parser processes the original flat manifest in 8 KiB
reads, validates final EOF, and rejects malformed/truncated input and duplicate or
invalid lexical paths. It retains path membership needed for completeness and
inventory checks, not multiple full digest maps. Admission is 10,000 entries,
4,096 characters per path and bounded tokens; the pinned original baseline fits.
Reports are streamed to a new temporary file, flushed/fsynced, atomically renamed
and read back. Partial comparison, resource, I/O or reporting failure cannot produce
an authoritative success. In-process telemetry retains only bounded phase records
and the highest observed sample, not accumulated per-file output.

[Scope and permitted changes](data/s2_revoke_audit_1/scope.json) explicitly pin:

- Original `preservation-before.json`: **8,759 entries**,
  SHA-256 `ca7230bf0529444da2da75d10b7925baac5dd98f5b33b2170cdff0c4a38f8a31`.
  The only original permitted content changes remain `docs/status.md`,
  `docs/traceability.md` and `docs/spec_issues.md`. Deletions are not permitted.
- Historical final `manifest.json`: **33 entries**,
  SHA-256 `518a614ad09c26c61f197f284385d570aa1d68c1e7339deae310014c71e272fc`.
  Its three overlapping documentation names are assigned to the original partition;
  the remaining **30** are checked separately, making **8,789 distinct comparisons**,
  with no missing or duplicated partition. The final manifest's own identity is
  checked separately. Neither historical manifest is regenerated or edited.
- One newly authorised existing-file change: **append only** to
  `docs/stage2_revocation_state.md`. Its original **25,818-byte** prefix must still
  hash to `c0e7ac7a9d34ed64dba8199871295cf6c66db516227a399028590b9956ed7df6`.
  The full current report is also hashed as a permitted supplementary change.
- New engine, fixture tests, this report and exact package evidence filenames are
  listed individually. **No historical audit file is edited.** No directory-level
  exclusion is added, and no protected-content baseline is derived from current files.

The original audit checked the named baseline's membership/count and removals; it
had no global workspace additions scan. This package additionally enumerates every
non-directory entry under `src`, `tests`, `scripts`, `configs` and `docs`, comparing
exact names against historical names, expressly authorised additions and **93**
pre-existing cache filenames observed before correction. Those literal cache names
are inventory-only, outside the original content baseline; they have no newly
blessed content digests. Unexpected additions and required removals fail. No suffix
or directory is skipped. This does not claim global additions coverage for cache,
native build or experimental trees outside those five added inventory roots.
Original content protection outside them is unchanged.

Lexical manifest path identities stay distinct even when two paths resolve to one
inode. Regular-file symlinks follow their targets as previously; directory symlinks
are not traversed by the additional inventory. Original checks do not compare mode
or timestamps to a metadata baseline. The new before/after `fstat` detects concurrent
mutation during a read; it does not replace content hashing with metadata checks.

## Validation and complete-audit envelope

[Temporary-fixture tests](../tests/unit/test_preservation_audit.py) cover unchanged
sets, same-size protected mutations, permitted changes versus deletions, additions,
removals, directory symlinks, five positions at/around chunk boundaries, strict
malformed/truncated/duplicate/UTF-8 manifests, final-EOF failure after yielding entries,
incomplete/duplicate comparisons, read/traversal/advice/memory failures, report
write/fsync/rename failure, legacy report fields, file-symlink identities, unchanged
metadata semantics, append-prefix preservation and concurrent mutation. Separate
cases require the complete clean guard even when the content report says success.
All negative cases use temporary fixtures, not protected project files.

The existing manager **73 focused + 25 regression passes** are reused; its module,
helper and tests remain under historical digest protection. New audit source is
linted/formatted, and syntax, JSON, Markdown/link and resource-record checks run in
the complete audit. Earlier `validation.json` content fields retain their meaning;
the new [validation report](data/s2_revoke_audit_1/final_checks/validation.json) likewise states
that the outer guard is pending. Only the completed
[package result](data/s2_revoke_audit_1/final_checks/result.json), which requires content, report
readback and a clean guard, establishes this audit's final success.

Commands (one invocation per evidence namespace; no complete-audit retry):

```sh
.venv/bin/python docs/data/s2_revoke_audit_1/run_checks.py diagnostic
.venv/bin/python docs/data/s2_revoke_audit_1/run_checks.py focused
.venv/bin/python docs/data/s2_revoke_audit_1/run_checks.py quality
.venv/bin/python docs/data/s2_revoke_audit_1/run_checks.py quality --final-checks
.venv/bin/python docs/data/s2_revoke_audit_1/run_checks.py format --final-checks
.venv/bin/python docs/data/s2_revoke_audit_1/run_checks.py full-audit --final-checks
```

All **44 fixture cases passed**, with no skips. Initial lint found one B007 unused
loop-variable name in the diagnostic. The **failed lint record and STOP are retained**;
the queued initial-format command was denied at admission and did not execute.
The variable was renamed `dirs` to `_dirs`, without changing diagnostic behaviour or
repeating the diagnostic/tests. The [correction record](data/s2_revoke_audit_1/lint-correction.json)
identifies a fixed fresh `final_checks` namespace for corrected-source lint, formatting
and the single complete audit. Original run names/STOP are not overwritten. A failure
or STOP in the final namespace prohibits another check. This is a source correction
after a lint finding, not a retry of the complete audit or a resource failure.
Both namespaces share the original 300 s aggregate budget, 10 MiB output budget and
one-worker lock. No measurement/enforcement scope or numerical limit is raised.

Exact child/systemd commands, environment, controls and headroom are saved in the
[initial run ledger](data/s2_revoke_audit_1/run-ledger.json) and
[final run ledger](data/s2_revoke_audit_1/final_checks/run-ledger.json). The
[configuration](data/s2_revoke_audit_1/config.json) and
[guard](data/s2_revoke_audit_1/run_checks.py) retain **256 MiB cgroup memory, no swap,
one worker/two affined cores, 60 s per command / 300 s aggregate**, 55 s child kill,
10 GiB experiment storage / 9 GiB early stop, 64 MiB diagnostic budget / 60 MiB early
stop, 10 MiB new package output, the inherited stricter 60 KiB individual-log stop
and 1 MiB individual-file limit, and at most 100 new collected fixture cases.
WSL admission requires the full memory allowance plus 2 GiB available headroom.
A lock enforces serial workers; private networking has no routes; project files
are read-only to the service except this new evidence directory. Nothing installs,
proves or executes a zkVM. If the single complete audit fails, evidence is retained
and this package stops without retry or escalation.

## Outcome

**PASS — the single complete audit and its resource guard both exited zero.**
The authoritative [result](data/s2_revoke_audit_1/final_checks/result.json),
[guard command/measurements](data/s2_revoke_audit_1/final_checks/full-audit.json),
[service counters](data/s2_revoke_audit_1/final_checks/full-audit.service.json),
[phase record](data/s2_revoke_audit_1/final_checks/phases.json) and
[completed content report](data/s2_revoke_audit_1/final_checks/validation.json)
are retained. No complete audit was retried.

| Complete-audit measurement | Result |
|---|---:|
| Guarded wall time | 1.053191021 s |
| Cgroup `memory.peak`, whole service and descendants | 21,823,488 bytes (20.8125 MiB) |
| Margin below unchanged 256 MiB ceiling | 246,611,968 bytes (235.1875 MiB) |
| Separately sampled aggregate process `VmRSS` peak | 39,415,808 bytes |
| `memory.events:max`, `oom`, `oom_kill`; swap peak | All zero |
| WSL available memory at admission | 4,821,327,872 bytes |
| Existing experiment storage at admission | 7,618,673,412 bytes |
| New package output at guard completion, before result bookkeeping | 184,264 bytes |
| Temporary fixture/comparison storage remaining at completion | 0 bytes |
| Final exit / timeout / output stop | 0 / none / none |

The precise memory metric is the cgroup kernel high-water counter sampled by the
worker after the audit child exits, retaining the previous measurement scope. It
includes content checks, inventories, telemetry and completed child reporting. The
separate summed RSS sample can exceed charged memory because the metrics account
for shared/resident pages differently. `memory.stat` phase categories are kernel
samples with batched updates, not an exact synchronous decomposition of every byte
at the high-water instant. The service log independently reports a 20.8M peak and
zero swap. These are audit-command measurements, not proof costs or throughput.

The original partition completed **8,759/8,759** comparisons: **8,756 unchanged**,
exactly the three permitted documentation edits, **zero unauthorised changes and
zero missing files**. SHA-256 input in that partition totalled **293,617,360 bytes**;
the difference from diagnostic metadata size reflects the expressly permitted
subsequent documentation edits. The supplementary partition completed **30/30**:
**29 unchanged**, the one append-only manager report, no missing/unauthorised files,
**1,735,079 bytes**. Its original report prefix passed. All **8,789 distinct paths**
were accounted for once across those partitions, with zero overlap; the pinned
historical final-manifest identity was additionally checked. Coverage fingerprints
are recorded for each partition. Both original baselines remain byte-for-byte intact.

The additional name inventory checked **418 entries**, with zero unexpected or
missing names. It includes exact authorised files already present at that phase;
subsequent result/guard/seal files are individually authorised in the scope list.
**261 local Markdown link paths** and **36 JSON files** were checked, plus syntax
and unchanged historical validation evidence. The baseline parser consumed final
EOF, rather than stopping after the expected entry count.

The original content phase completed at **0.883984120 s**, supplementary/prefix at
**0.889041664 s**, syntax/JSON/docs at **0.930504261 s**, inventory/output checks at
**0.937449714 s**, and report write/readback at **0.940375019 s**, relative to the
child's measurement start. The cgroup peak through original comparison was
21,073,920 bytes; final reporting completed at a peak of 21,823,488 bytes. The outer guard
then passed. This resolves resource acceptance for this audit; it does not revise
the previous failure or identify its previously unmeasured peak phase.

| Validation command | Outcome | Guarded seconds | Cgroup peak, bytes |
|---|---|---:|---:|
| Bounded diagnostic | Pass; diagnostic only | 0.253010 | 30,064,640 |
| Isolated fixtures | 44 passed, zero skipped | 0.355148 | 42,352,640 |
| Initial lint | B007; failure/STOP preserved | 0.088475 | 10,588,160 |
| Corrected-source lint, fresh namespace | Pass | 0.068927 | 11,100,160 |
| Final formatting | Pass | 0.088658 | 10,592,256 |
| Complete audit, one run | Pass | 1.053191 | 21,823,488 |

All six executed commands used **1.907409014 guarded seconds** in aggregate, including
the initial lint failure. No command reached a resource limit. The denied initial
format command did not execute and consumed no service attempt. The 98 manager
functional tests were not rerun. The correction's 44 fixture cases and completed
audit add no credential or proof-performance result.

The new [evidence manifest](data/s2_revoke_audit_1/manifest.json) seals only this
package's artefacts and final expressly permitted documentation. After the guard,
only factual outcome documentation, the final result and that seal were written;
there was no second protected-content scan, baseline regeneration or code change.
Historical manager failure/STOP/result and earlier experiment/proof evidence remain
unchanged. Changes are limited to the new audit engine, its tests, three package
scripts/configuration/evidence, this report, appended manager-report validation and
status/traceability/issue documentation.

Recommend using this validated audit implementation and the same resource envelope
for the next separately scoped reference-lifecycle package. Resolve the next
allocation/issuance/release boundary explicitly before implementation; this audit
authorises no additional protocol work or proving.

## Remaining obligations

Stages 2–3 remain open: bounded production keygen/signing and DEP-001/002;
allocation/issuance/certification-release integration; persistent/distributed
manager/wallet/verifier/DID services; full authentication circuits, selective-disclosure/
non-revocation proof integration, BC-1, actual CredValid/authentication proofs and
privacy/ZK/quantum-security/Section VIII review. Resolving an audit resource issue
adds no protocol correctness or security claim. Proving remains paused.
