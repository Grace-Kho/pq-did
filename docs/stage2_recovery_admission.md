# S2-RECOVERY-ADMISSION-1 — bounded recovery admission

19 September 2026. **Typed checkpoint validation and gated recovery of the seven
reference roles are implemented.** Fifty focused cases passed, followed by eight
cases for an additional strict field-schema check and one faulty-adapter case; all
28 unchanged lifecycle-review
cases passed. These include the two original labelled unsafe-restart controls. Their
passing assertions still demonstrate unsafe use of the old trusted constructors.
The new recovered interfaces refuse those stale imports when independent evidence
disagrees or is unavailable. **Deployment recovery remains blocked.**

Implementation: [records](../src/pqdid/recovery_records.py),
[admission and facades](../src/pqdid/recovery.py),
[tests](../tests/unit/test_recovery.py),
[explicit fixture authority](../tests/unit/recovery_cases.py).
No existing source, test, cryptographic primitive, parameter, protocol encoding,
dependency, vector, manuscript or historical result was edited. No proof or zkVM
execution occurred. CPU proving stays paused: **two attempts used, one unused**.
Stages 2–3 remain open.

## Authority and scope

Read [AGENTS.md](../AGENTS.md), the [lifecycle review](stage2_lifecycle_review.md),
its persistence requirements and REC-001–004 findings, the existing manager,
issuer, DID, holder and verifier contracts, status, traceability and issues.
The checked manuscript SHA-256 remains
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
Only Sections **II–VIII** and agreed SPEC-001–004 are authoritative. This package's
local recovery containers, admission policy and bounds are engineering choices
authorised by the user, not additional manuscript wire fields or protocol claims.

Existing constructors remain explicitly trusted initial/live reference interfaces.
They cannot be used to recover an existing service merely because its files are
missing. Recovery uses a new `RecoveredService`, initially QUARANTINED, and a
complete `Checkpoint`. Missing state cannot select an empty constructor branch.
An actually empty checkpoint is admissible only if independent authority confirms
that complete empty state for the expected existing service. Trusted initial setup
is a different administrative event and must not be inferred from loss of storage.
Direct private Python access or use of legacy trusted constructors is outside the
facade contract; the module is not a sandbox against its own trusted caller.

## Five distinct checks

| Check | What establishes it | What it does not establish |
|---|---|---|
| Structure | Exact frozen record and field types, version, immutable byte/tuple leaves, canonical embedded decoders, count/byte/depth/work bounds | Authenticity or completeness |
| Internal/cross-component consistency | Relationships below; exact expected pp; issuer allocation floor checked against the trusted manager; DID configuration/key handles checked against trusted dependencies | That a consistent old image is current |
| Authenticity/provenance | Existing bounded signature/path/chain checks for protocol objects; independently trusted complete-role evidence for local reservations, approval/session logs, nonce sets and consumed flags | A native signature alone cannot authenticate later local effects |
| Authoritative freshness | Independent authority compares the digest of the complete role checkpoint against its own latest authoritative state, including failed-reply effects | Candidate generation, signature, hash or adjacent local manifest is not evidence |
| Permission to resume | Final exclusive authority lease and one local gated activation; all preceding checks succeed | Durable commit, rollback protection, distributed fencing or application-side exactly-once delivery |

## Version 1 checkpoint schema

`Checkpoint(version=1, role, service_id, parameters, state)` pins the expected role,
32-byte service instance ID and exact canonical `E(pp)` supplied independently by
the caller. This checks suite, issuer/key/schema/namespace bindings in addition to
the service ID. Registry ID/key and verifier audience/request key must also agree
with trusted dependencies. No recovered value can replace those expectations.

The container is a local typed API, separate from cryptographic protocol formats.
Embedded parameters, credentials, contexts, states, enrolment statements, DID
records and public updates use the unchanged canonical encodings. The local digest
uses SHA-256 with a recovery-specific domain and explicit type/count/length framing;
it is an identity for an authority comparison, never a protocol signature or a
self-certifying freshness claim. No on-disk codec, database or general file importer
is supplied. A future storage adapter must bound parsing before constructing these
objects as well as invoking their validation.

All record dataclasses are frozen and suppress field representations. The recursive
preflight checks the actual type of every annotated field, including empty tuples
and optional records. Frozen annotations alone would not enforce those types.
It rejects mutable leaves, unknown records, wrong types, excessive depth and oversized
graphs before hashing payloads. A second bounded pass streams the local identity,
without retaining a serialised copy. The candidate service is reconstructed privately;
no live service is overwritten. Protocol decoders produce immutable values and
mutable service collections are newly owned, never aliases into a supplied container.

| Role / local state | Required contents, order and validation | Operations withheld before admission |
|---|---|---|
| Manager: `ManagerRecord` | Permanent allocation prefix `[0, allocated_count)` including orphaned/abandoned reservations; original base state/revoked/nonce sets; current state/revoked/consumed nonces; complete retained ordered public update bytes. Sorted unique sets, count ≤2^20, revoked IDs below count, both sparse roots, exact consecutive history/endpoints, old zero paths and new roots, bounded state/update signatures. Each post-base update adds one distinct consumed nonce | Allocation, registered witnesses, revoke, signed current reads, update pages, provider instance/current/resolve and local snapshot |
| Issuer: `IssuerRecord` | Allocation floor, sorted full session records, sorted used nonce set, original certification commit-order log with session links and exact releasable credential/witness. Every ID distinct and below the floor; trusted manager count ≥floor; nonces exactly cover session reservations. PENDING/CERTIFIED require approved attributes/state and resolved controller DID/version/key. Attributes match those fields; certification matches ID/attributes/state and valid issuer signature/zero path; exactly one log item for each CERTIFIED session | begin, finish, abort, snapshot |
| Registry: `RegistryRecord` | Pinned registry ID/key, DID-sorted nonempty complete genesis histories in predecessor order. Every record uses existing derivation, new-key, previous-controller signature, index, predecessor, activity and terminal-state checks. Total records bounded across all DIDs | read, append, snapshot and configuration accessor |
| Resolver: `ResolverRecord` | Pinned registry ID/key and sorted complete retained resolver read-nonce reservations. Existing nonces remain reserved, including failed reads. Fresh transport and randomness dependency retained | resolve and configuration accessor |
| Controller: `ControllerRecord` | Pinned registry, genesis public key/salt, complete locally confirmed chain, exact optional pending record, current and possibly-active successor key-handle IDs. Derive original DID, validate chain/pending successor, match independent vault handles to public keys. No private signer is deserialised | publish, explicit pending recover, snapshot |
| Verifier: `VerifierRecord` | Pinned audience/request key; all registered contexts/states sorted by nonce, including unsigned reservations after failed request signing, exact local DID-policy flag and consumed bit for every record. Canonical context/state/audience agreement, DID disclosure prerequisites, bounded state authentication; no saved clock | create_challenge, verify |
| Holder: `HolderRecord` | Private secret and original enrolment intent, optional complete original accepted credential/issuance witness, optional current matching witness/state. Existing HolderAcceptance validates the intent, opening, signature and original pair. Current witness has the same ID, authentic zero path and no earlier epoch; same-epoch roots agree. Accepted record and current pair must both exist or both be absent | accept, private snapshot, private checkpoint |

The manager's prefix compactly represents every permanent reservation in the
existing allocation model. It is **not inferred from credentials or the tree**.
A valid root and plausible count cannot prove prefix completeness; independently
trusted evidence must cover all increments, including those with lost replies.
Public update bytes do not contain request nonces. The validator checks set growth
and complete history/root consistency; independent local provenance must establish
the correspondence of those nonces with effective revocations. Original base
contents and the retained-history boundary also require that provenance.

Issuer approval provenance and certification log order are local authority facts;
protocol signatures alone cannot reconstruct them. Aborted sessions retain any
completed ID/nonce reservations. **PREPARING and CLAIMED sessions are rejected**,
not silently retried, deleted or changed to PENDING. Their durable intent/outcome
reconciliation is a remaining obligation. Missing records cannot be repaired from
an untrusted holder submission. A certified session preserves duplicate rejection
even if its response was lost. Complete PENDING recovery can use existing finish,
which repeats its normal current-controller/manager checks.

The recovered controller with a pending attempt continues to reject new publication
until explicit `recover()` applies the existing fresh authenticated occurrence/
predecessor/conflict rules. The holder's accepted response remains at issuance state;
the separately validated current witness may be later. Local holder admission is
not a claim that this state is the manager's latest state or suitable for a new
presentation. Normal request freshness and witness catch-up remain necessary.

## Bounds and failure behaviour

| Admission | Ceiling |
|---|---:|
| Aggregate byte leaves / single blob | 2,097,152 / 65,536 bytes |
| Recursive nodes / dataclass records / depth | 8,192 / 512 / 16 |
| Conservative validation work units | 1,024 |
| Manager retained updates / revoked IDs / request nonces | 32 / 64 / 64 |
| Issuer sessions / nonce records / certifications | 64 / 64 / 64 |
| Verifier retained challenge records | 100; configured capacity may be lower |
| DID records across a registry, or controller history plus pending | 32 |
| Resolver retained nonces / controller private-key handles | 64 / 2 |

Recovery limits may only be lowered. Role cardinalities and conservative work cost
are checked before expensive reconstruction. Work units upper-bound signature/key
checks and sparse-tree work, each with existing fixed bounded suite operations; they
are not measured CPU cycles. Trees reconstruct from at most 64 revoked IDs, without
scanning 2^20 leaves. Existing lower manager/issuer/DID limits and verifier proof/nonce
limits remain trusted runtime configuration. No uncapped verification fallback or
new signer/proof implementation is introduced. The byte ceiling counts payload
leaves; bounded framing, nodes and Python overhead additionally remain subject to the
unchanged whole-worker resource ceiling.

Malformed structure, cryptographic failure, unavailable dependency, insufficient
evidence and resource/I/O failures reject the entire candidate. Exceptions during
validation or authority context exit clear the private candidate; interruption also
leaves REJECTED before propagating when appropriate. A rejected facade cannot be
retried or overwritten. A second `admit` on an already admitted facade is refused
without modifying its service. No incomplete snapshot is served as current state.

## Independent authority, activation and expiry

`RecoveryAuthority.exclusive(RecoveryBinding(role, service_id, checkpoint_digest))`
is a trusted context-manager interface. It yields an exact `RecoveryEvidence` for
the separately pinned 32-byte authority identity and requested binding, or no
evidence. Its default implementation yields none. The checkpoint does not contain
an authority object. Injecting an adapter is an explicit trust decision; a malicious
adapter that simply echoes the candidate violates this contract and cannot be made
trustworthy by adding another local signature check.

The authority must independently retain the complete latest role state or an
equivalent trusted transition commitment, compare that state, retire old writers and
grant permission to activate. Its evidence covers allocation increments, failed
issuance reservations, certifications, registry/pending state, resolver nonces,
challenge registration and consumption, and wallet associations as applicable.
Revocation epoch alone is insufficient. Availability failure blocks the affected
operations. The authority's state, administrative decisions and key/configuration
bindings must not be rollbackable with the recovered checkpoint. Selecting such
infrastructure and its trust/availability policy remains open.

Transition: **QUARANTINED → VALIDATING → ADMITTED or REJECTED**. A nonblocking local
gate excludes all role calls throughout admission. Validation prepares a private
candidate; the authority compares freshness again under its exclusive lease at the
end. The assignment of that candidate inside the lease is the local activation
point. An authoritative change before that point must disagree or be serialised
after it. No call can enter until the authority context exits successfully. Context
exit failure clears the candidate before releasing the gate. Tests inject both a
new authoritative reservation during validation and authority entry/exit failures.

This is a local consistency model, not a distributed lock implementation. Production
authority adapters must enforce writer fencing and maintain their independent state
across **subsequent** operations before granting another recovery. The facade does
not durably journal runtime effects or refresh a recovery commitment after every
operation. A live reference dependency supplied to the constructor is trusted; an
unadmitted recovered dependency cannot supply authoritative methods/configuration.
Private administrative snapshots are not public verifier inputs. The authority sees
only a binding, not holder secrets or a private witness, but even that digest belongs
to the authorised recovery channel and is not a public presentation field.

The verifier retains all records and consumed bits and uses its newly supplied
**current trusted clock**. An expired challenge stays expired at verification and
atomic consume; no timestamp is imported. As before, the clock itself must satisfy
the trusted-time contract. This package does **not** support discard-pending as an
alternative recovery policy. Retiring all old challenges could prevent old acceptance
under the existing wire contract, but fresh-challenge operation would still need
complete permanent nonce reservations, same-audience coordination and authoritative
writer retirement. Missing state cannot safely initialise an empty store. No new
wire epoch, nonce reset, context change or allocation-history reset is justified.

## Validation and preserved evidence

The [runner](data/s2_recovery_admission_1/run_checks.py) retains exact commands and
[limits](data/s2_recovery_admission_1/config.json). All commands use one execution
worker, two CPU threads/200% quota, cgroup-v2 `MemoryMax=268435456`, zero swap,
60 s per command (55 s child deadline), 300 s aggregate, original storage/output
ceilings, private network with no routes, and a read-only project except this new
evidence directory. Admission checks WSL MemAvailable ≥256 MiB +2 GiB reserve.
Sampled aggregate process-tree VmRSS has the same 256 MiB stop. The authoritative
`memory.peak` metric includes worker and descendants plus charged file cache/kernel
memory; the bookkeeping launcher/monitor remains outside, as before.

| Evidence | Cases | Scope |
|---|---:|---|
| [focused](data/s2_recovery_admission_1/focused.json) | 50 | Stale allocation/consumption blocked through actual facades; independent evidence failures; wrong role/instance/ns/suite/pp; bounds/incomplete/corrupt histories; all current roles; original duplicate semantics; current-clock expiry; authority change/I/O/memory/lease-exit faults; pending issuer/controller and holder consistency |
| [structural](data/s2_recovery_admission_1/structural.json) | 8 | After source review tightened recursive field types: all seven valid role admissions plus invalid empty-field types, and total-byte rejection before reconstruction |
| [lease](data/s2_recovery_admission_1/lease.json) | 1 | Final source review: a faulty authority context suppressing a validation exception still yields REJECTED, never an incomplete admission |
| [regression](data/s2_recovery_admission_1/regression.json) | 28 | Original unmodified lifecycle review, including both named unsafe-restart controls |

The first 50 cases preceded the additional strict schema check. The eight scoped
cases verify that addition for every role, and the unchanged core evidence is reused;
no claim is made that the first run used later source bytes. A final completion check was added and verified in one case after source review
found that a faulty authority context could suppress validation exceptions. This
case preserves the rejected outcome even for that adapter error. Total executed cases:
**87**, within the 100-case allowance. All four test commands exited 0 without resource
events. No resource failure or automatic retry occurred. Native test signatures use
the existing ephemeral test-only signer; reference proof tokens remain explicitly
labelled and are not cryptographic proofs. Tests use in-memory deterministic fault
and authority decisions, not process crashes, storage recovery or power loss.

The original unsafe controls remain named
`test_unsafe_restart_negative_control_signed_root_does_not_bind_allocation_counter`
and `test_unsafe_restart_negative_control_stale_pending_snapshot_can_reaccept`.
They still reproduce the underlying gap through deliberately trusted stale
constructors. New tests exercise the distinct recovered facade and show refusal of
those same stale effects. The good verifier restores a consumption tombstone,
rejects the old presentation, and separately creates/accepts a fresh challenge.
This is full-history recovery, not discard-pending.

Preservation uses the **unchanged corrected auditor**, its previous 44 fixture tests,
six original pinned manifests and exact [scope](data/s2_recovery_admission_1/scope.json).
No original baseline is regenerated. Expected coverage: 8,759 primary content paths
and 170 disjoint supplementary content paths, plus five additional manifest identities:
**8,934 historical paths**. Only `docs/status.md`, `docs/traceability.md` and
`docs/spec_issues.md` may change among those originals. New recovery source/tests,
this report and individually listed evidence files are explicit additions. No
directory exclusion is broadened. The original manager ceiling failure, earlier
failures/STOPs, all historical reports and proof ledger remain protected.

The complete comparison, inventory, report write/readback and outer resource guard
must all pass; a comparison alone cannot establish success. The single complete audit passed; final measurements are recorded below. Relevant machine-readable
claims are in [admission-findings.json](data/s2_recovery_admission_1/admission-findings.json).

## Remaining decision and next package

REC-001/002 have guarded reference recovery paths, conditional on independent
complete/fresh evidence and exclusive writer permission. REC-003 now has explicit
typed containers, consistency checks and gates, but interrupted issuer reconciliation
is unsupported. REC-004 retains original commit-versus-delivery and duplicate rules.
None closes the deployment recovery blocker. Durable atomic state, rollback-resistant
authority, leases/fencing across crashes/replicas, bounded storage decoding, retention,
confidential authorised recovery channels, real crash tests, bounded signing/keygen,
interoperability and full private authentication/proof/security work remain open.

Recommend one bounded next package: **S2-RECOVERY-AUTHORITY-DESIGN-1**, a design review
of a concrete independent transition authority and writer-fencing policy. Specify
who can advance/check it, atomic reservation/consumption coupling, stale-writer
rejection, lease loss, rollback scope, availability and uncertain issuer outcomes,
with a finite failure matrix and a deployment decision for review. Do not implement
storage, grant production recovery approval or resume proving in that package.

## Final validation and preservation result

[Final result](data/s2_recovery_admission_1/result.json),
[guard record](data/s2_recovery_admission_1/full-audit.json),
[content/inventory report](data/s2_recovery_admission_1/validation.json) and
[phase evidence](data/s2_recovery_admission_1/phases.json) all complete successfully.
Exact audit command:

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python docs/data/s2_recovery_admission_1/run_checks.py full-audit
```

Exit **0**; one full audit, no retry. All **8,934 historical paths** are accounted
for: 8,759 primary comparisons (8,756 unchanged and the exact three permitted
existing documentation changes), 170 unchanged supplementary comparisons, and five
additional manifest identities. The content partitions are disjoint. The **566-entry
inventory** has no missing or unexpected paths. Original baselines, historical
failures, source/test files, manuscript and the proof ledger are preserved.

The audit's entire worker cgroup peaks at **21,762,048 bytes (20.75390625 MiB)**,
including charged anonymous/file-cache/kernel memory and descendants. Independently
sampled aggregate process-tree VmRSS peaks at **40,341,504 bytes (38.47265625 MiB)**;
this distinct metric can count shared pages more than once. Both retain the original
268,435,456-byte ceiling and scope. Wall time: **2.072833665 s**. Content comparison,
name inventory, report serialisation/readback, final worker exit and outer guard all
pass. Memory-max/OOM/swap events: **zero**. Temporary storage at completion: **0 bytes**;
new package evidence at guard completion: **183,917 bytes**.

| Guarded command | Exit | Wall seconds | Cgroup memory.peak bytes | Sampled process-tree RSS bytes |
|---|---:|---:|---:|---:|
| focused | 0 | 5.715896213 | 55,652,352 | 62,636,032 |
| structural | 0 | 1.459567229 | 55,947,264 | 65,892,352 |
| regression | 0 | 5.435435172 | 45,604,864 | 68,050,944 |
| lease | 0 | 0.524531408 | 63,156,224 | 66,850,816 |
| quality | 0 | 0.071546221 | 11,128,832 | 14,012,416 |
| format | 0 | 0.088429899 | 11,653,120 | 28,680,192 |
| full-audit | 0 | 2.072833665 | 21,762,048 | 40,341,504 |

All seven guarded commands total **15.368239807 s**, within the unchanged 300 s
aggregate envelope. Final lint and formatting pass for all six new Python files.
No guarded failure, retry, skipped case, new dependency, proof or zkVM execution.
The corrected auditor's existing 44 fixture tests and unchanged cryptographic/native
validation are reused. The report distinguishes the initial 50 cases from the eight
strict-schema cases and one completion-guard case added after source inspection;
these scoped follow-ups did not repeat or conceal a failed run.

After the guard, only the authorised current package report and three status/issue/
traceability documents were finalised with these results. Small local document/link
checks and a [new artefact seal](data/s2_recovery_admission_1/manifest.json) record
those final bytes; this is bookkeeping, not a second historical content audit.
Production recovery approval remains **false**, the deployment recovery blocker
remains open, and Stages 2–3 remain incomplete. Stop after this package.
