# KYC-MANAGER-INCREMENTAL-STORAGE-1

The isolated manager-v2 persistence, bounded public retrieval and affected holder
catch-up integration passed their scoped validation. **47 distinct cases passed
across 49 invocations**, with two failed invocations preserved and corrected. Both
previously unrun eight-record scaling cases completed. The largest history actually
validated is **eight updates**; larger capacity is not established. This is not
complete private authentication and does not close Stages 2–3 or the full programme.

Only manuscript Sections II–VIII and SPEC-001–004 are authoritative. Opening
verification covered 131 direct predecessor seals, the prior completed audit/closure
and the unchanged manuscript hash. The [execution plan](data/kyc_manager_incremental_storage_1/execution-plan.json)
was recorded before affected tests, with bounded additions before their invocation.
No new resource amendment was used: opening balances were 2,069.981 overall seconds,
1,702.753 workstream seconds, 55 invocations, 10,248,259 shared evidence bytes and
10,696,938 cumulative evidence bytes. The protected reserves remain 300 seconds and
2 MiB. There were no builds, installations, proofs, zkVM runs or host activation.

## Boundaries and exact preserved semantics

The old `SQLiteStore._write` encoded the entire typed checkpoint into one PQL1 value
and retained a new full copy at each head. `ManagerRecord.history` grew by an
11,162-byte signed update per revocation. Eight raw updates require **89,296 bytes**,
before tuple/checkpoint framing, exceeding **65,536**. S-22 retains this encoding
failure as a regression, using an explicitly invalid repeated-history fixture; DAG
roundtrip works, but unchanged semantic admission still rejects that false history.
No invalid fixture is used to claim a valid eight-update chain. Genuine chains are
used separately in H-01/H-15/H-16/H-17 and R-1-8/R-2-8.

The other boundaries are now explicit:

| Operation | Previous materialisation | Current bounded handling |
| --- | --- | --- |
| Persistence | Whole checkpoint and aggregate entry encoding | Immutable components ≤65,536 bytes, shared by typed checkpoint roots; bounded entry-root structure |
| Recovery | Whole latest checkpoint and all operation metadata | Reconstruct bounded typed objects from verified components; all retained checkpoint digests checked; existing recovery validator reused |
| Manager mutation | Full in-memory bounded history for replay/signing | Unchanged, capped at existing 32-history reference limit; no claim of unbounded or constant-memory history |
| Public retrieval | `updates()` returned a Python page, without a complete transport encoder | New explicitly local frame ≤65,536 bytes; at most four current-size records, also respecting caller's lower record/byte limits |
| Catch-up | Baseline required one complete page | Public pages collected at one signed target; ≤16 records/178,592 record bytes total; unchanged full-batch validation, then one wallet replacement |

`SQLiteStore.inspect/_load`, `BoundedDurableManager.snapshot/_candidate`, recovery
`_manager`, and the public page adapter still materialise bounded history. That is
permitted by the unchanged reference limits; it is not hidden streaming or a claim
that a larger complete workload fits. Individual signatures, state/update records,
PQL1 cap, ML-DSA sampler/signing caps, parameters and signed contexts are unchanged.
The new DAG and page tags are **local research storage/transport conventions**,
not W3C cryptosuites or protocol-signing formats.

## Incremental manager storage and migration

`experiments/kyc_manager_incremental_storage_1/store.py:ManagerStore` is an opt-in
manager-only subclass of the unchanged authority store. Version 2 has exact-schema
`nodes`, `service`, `checkpoints`, `operations`, `heads`, and `entries` tables.
An immutable node is an atom (existing PQL1 leaf), ordered tuple of child digests,
or whitelisted record type plus ordered field digests. Its SHA-256 covers the local
v2 domain, kind, explicit byte length and canonical bounded payload. Types, canonical
encodings, child order and field arity are checked. No arbitrary class construction,
pickle, missing-node fallback or timestamp-based content check is used.

The existing **typed `Checkpoint` and `checkpoint_digest` remain identical** after
reconstruction. Checkpoint roots share unchanged attributes, states and histories;
new transitions insert only missing immutable nodes and new root references. Entry
values remain permanent: deleting or rebinding an old allocation entry is rejected.
Operation request/decision/response bytes stay exact and bounded. V2 heads bind the
checkpoint digest, entry root, operation component references, sequence, predecessor,
generation, writer and service identity. Legacy heads retain their original formulas.
All node hashes, retained checkpoint digests, head continuity, operations, membership,
metadata and expected writer/head are checked before the existing recovery admission.

Limits remain: 128 operations/entries, counters as before, bounded node depth 16,
collections at most 128, and a 4,096-node implementation admission bound. The latter
is a bound, not a promised capacity; the unchanged 512-KiB SQLite database ceiling
can stop work earlier. The original path ownership/mode/symlink checks, 128-page cap,
100,000-step SQL progress guard, settings and 512-KiB journal/1-MiB store checks are
reused. Public frames and operation bytes retain the independent 65,536-byte cap.
No quota was raised or large file excluded from evidence accounting.

A manager mutation still uses the existing bounded signer. Signing candidates are
private; the unchanged manager revalidates its captured checkpoint, expected head,
authorisation and fencing under BEGIN IMMEDIATE. Nodes, allocation entries, signed
history/state, consumed nonce set, operation outcome and authoritative head become
durable in **one SQLite COMMIT**. A failed transaction exposes no public response;
a committed lost response is retrieved from exact stored bytes without resigning.
The independent issuer journal keeps certification/recipient binding. There is no
cross-store ACID claim: permanent manager reservation precedes issuer certification
and remains reserved after issuer failure. Manager history is public, whereas issuer
credential redelivery remains recipient-bound; neither API is substituted for the other.

Migration is only on fresh synthetic stores or isolated copies. `migration_plan`
requires admin policy, an independently retained expected v1 head and valid writer
permit, and predicts the generation-incremented v2 successor. `migrate` revalidates
under the writer lock, imports **every retained checkpoint, operation/outcome, entry
and legacy head**, switches schema/version and records its migration head atomically.
No allocation, certification outcome, consumed nonce or trusted freshness counter is
reset. The trusted operator must keep the proposed successor outside the store before
mutation. Before-commit interruption recovers exactly v1; after-commit interruption
recovers v2 under that retained successor. Old schema/writer objects remain fenced.
Missing external freshness is never repaired by trusting the database's own head.

S-02–05 and S-08–11 distinguish injected exceptions from actual child-process
`os._exit(73)`. S-25/26 exercise actual exits around a **signed revocation**, checking
state, history, nonce consumption, public outcome and exact recovery/redelivery.
Parent-retained tickets model independent operator evidence; this is not durable
production ticket custody, power-loss assurance or whole-store rollback protection.

## Public paging and atomic catch-up

`history.page` accepts only **public namespace, after-epoch and signed target state**,
plus lowerable limits. It exports neither holder identifier/path nor private authority
allocation head. The target must occur in the admitted signed history. Pages contain
an explicit local type/version tag, namespace, exact requested target, starting state,
endpoint and ordered update records. Count is derived from the complete encoded frame,
including state/framing overhead; a caller limit cannot be enlarged to obtain progress.
A new random signature or target token is not created during retrieval.

`history.collect` bounds input before decoding and checks canonical framing, fixed
target, namespace, contiguous epochs, signed states, progress, record sizes and total
batch limits. Missing, duplicate, reordered, truncated, oversized or inconsistent
pages fail without returning a replacement wallet. Logical state-reference equality
is used where the reference relation permits different valid signatures; transported
signatures are still authenticated. H-17 covers this explicitly. The final unchanged
`update_witness`/private-wallet transition verifies **all** update signatures, Merkle
transitions, identifier linkage and target consistency before any wallet publication.

The baseline adapter calls `Holder.apply` once after complete collection, preserving
its existing atomic file replacement. The private reference adapter calls
`Wallet.prepare_update` and `commit` once, preserving its expected-head recheck and
atomic credential/witness/state update. It does not commit page-by-page. Catch-up to
a historical signed state is not a fresh eligibility assertion; the existing
nonce-bound verifier current-state check remains required for authentication.

The private reference-wallet integration uses the existing genuinely signed one-update
fixture through an explicitly synthetic public transport. The genuine manager/issuer/
DID/two-verifier eight-update path is the **fully disclosed ML-DSA baseline**. It is
not eight-update private-proof authentication. H-13 preserves stale-wallet rejection;
H-11 confirms that revocation returns no replacement and retains old wallet bytes.
No anonymous-flow stable holder identifier or authentication key is added.

## Validation and retained corrections

Two failures are retained. H-15 initially encountered the v1 schema because the
verifier provider captured the old manager at construction. The isolated wiring now
recreates both trusted providers for the new manager, retaining consumer identity,
keys and policy. Only affected H-15 was rerun; H-16 then ran for the first time.
H-17 initially lacked a fixture import. Static-5 reported it, but dispatch occurred
before that result was inspected; the failed invocation is fully charged. Static-6
and the explicit targeted H-17 rerun passed without changing expectations. Both fresh
failed fixtures were archived losslessly with per-file hashes/readback before cleanup.
Original historical stores and archives were never touched.

The final reference-equality correction preserves valid differently signed logical
states; it does not replace state authentication with unsigned metadata. H-17 and all
four subsequent measurement cases exercise final paging code. Unaffected negative
checks still use the same namespace, epoch, size, ordering, canonical and signature
guards; their evidence is reused. Full source identities and correction records are
retained. Primitive/native ABI, prior wallet tests, original 276 measurements and the
19 plus issuer-v2 three observations were not rerun or overwritten.

| Invocation | Case | Outcome | Purpose | Seconds |
| --- | --- | --- | --- | ---: |
| KYCM1-0001 | S-01 | pass | populated migration and repeated recovery | 1.953946 |
| KYCM1-0002 | S-02 | pass | migration before COMMIT exception | 0.165211 |
| KYCM1-0003 | S-03 | pass | migration after COMMIT exception | 0.198382 |
| KYCM1-0004 | S-04 | pass | actual process exit before migration COMMIT | 0.171600 |
| KYCM1-0005 | S-05 | pass | actual process exit after migration COMMIT | 0.199417 |
| KYCM1-0006 | S-06 | pass | stale migration plan | 0.121462 |
| KYCM1-0007 | S-07 | pass | old writer fenced | 0.174663 |
| KYCM1-0008 | S-08 | pass | commit before COMMIT exception | 0.506883 |
| KYCM1-0009 | S-09 | pass | commit after COMMIT lost acknowledgement | 0.483608 |
| KYCM1-0010 | S-10 | pass | actual process exit before commit | 0.450492 |
| KYCM1-0011 | S-11 | pass | actual process exit after commit | 0.493775 |
| KYCM1-0012 | S-12 | pass | concurrent/stale prepared manager commit | 0.444506 |
| KYCM1-0013 | S-13 | pass | missing history node | 0.182673 |
| KYCM1-0014 | S-14 | pass | duplicate history entry/incorrect checkpoint | 0.179989 |
| KYCM1-0015 | S-15 | pass | altered head | 0.179713 |
| KYCM1-0016 | S-16 | pass | malformed node | 0.175958 |
| KYCM1-0017 | S-17 | pass | missing operation | 0.183179 |
| KYCM1-0018 | S-18 | pass | wrong instance or missing external freshness | 0.180991 |
| KYCM1-0019 | S-19 | pass | exact committed public redelivery without signing | 0.432710 |
| KYCM1-0020 | S-20 | pass | recipient-bound issuer redelivery retained | 0.176570 |
| KYCM1-0021 | S-21 | pass | nonce replay and permanent allocations | 0.255360 |
| KYCM1-0022 | S-22 | pass | historical eight-record encoding failure preserved | 0.184931 |
| KYCM1-0023 | S-23 | pass | bounded node codec and structural limits | 0.173402 |
| KYCM1-0024 | S-24 | pass | migration preserves prior checkpoint and outcomes | 0.197930 |
| KYCM1-0025 | H-01 | pass | complete eight-record paging and atomic baseline catch-up | 12.994437 |
| KYCM1-0026 | H-02 | pass | missing last page leaves wallet unchanged | 0.464158 |
| KYCM1-0027 | H-03 | pass | duplicate page leaves wallet unchanged | 0.467169 |
| KYCM1-0028 | H-04 | pass | reordered updates rejected | 0.329930 |
| KYCM1-0029 | H-05 | pass | wrong target state rejected | 0.318719 |
| KYCM1-0030 | H-06 | pass | wrong namespace rejected | 0.318928 |
| KYCM1-0031 | H-07 | pass | oversized complete response rejected | 0.317807 |
| KYCM1-0032 | H-08 | pass | truncated response rejected | 0.324218 |
| KYCM1-0033 | H-09 | pass | changed history endpoint rejected | 0.321651 |
| KYCM1-0034 | H-10 | pass | zero progress rejected | 0.317068 |
| KYCM1-0035 | H-11 | pass | revoked holder retains old wallet | 0.607034 |
| KYCM1-0036 | H-12 | pass | private reference wallet paged catch-up | 0.427683 |
| KYCM1-0037 | H-13 | pass | stale private wallet commit blocked | 0.232343 |
| KYCM1-0038 | H-14 | pass | per-call lower bounds enforced | 0.454621 |
| KYCM1-0039 | H-15 | failed | independent verifiers after v2 catch-up | 0.632788 |
| KYCM1-0040 | H-15 | pass | independent verifiers after v2 catch-up | 15.281698 |
| KYCM1-0041 | H-16 | pass | Second independent verifier after v2 paged catch-up | 3.038056 |
| KYCM1-0042 | S-25 | pass | Actual exit before signed revocation COMMIT | 1.982375 |
| KYCM1-0043 | S-26 | pass | Actual exit after signed revocation COMMIT and exact redelivery | 0.822293 |
| KYCM1-0044 | H-17 | failed | Alternate valid state signatures preserve logical-reference catch-up semantics | 12.609185 |
| KYCM1-0045 | H-17 | pass | Alternate valid state signatures preserve logical-reference catch-up semantics | 12.616371 |
| KYCM1-0046 | R-v2-1 | pass | Affected scaling; v2 manager/issuer; genuine baseline | 1.649073 |
| KYCM1-0047 | R-v2-4 | pass | Affected scaling; v2 manager/issuer; genuine baseline | 4.852144 |
| KYCM1-0048 | R-1-8 | pass | Affected scaling; v2 manager/issuer; genuine baseline | 12.629056 |
| KYCM1-0049 | R-2-8 | pass | Affected scaling; v2 manager/issuer; genuine baseline | 12.470240 |

## Separate manager-v2 measurement series

| Case | Updates / issued sessions | Setup ms | Catch-up ms | Encoded response bytes | Manager DB bytes | Issuer DB bytes |
| --- | ---: | ---: | ---: | --- | ---: | ---: |
| R-v2-1 | 1 / 2 | 1536.245 | 82.515 | 21540 | 122880 | 77824 |
| R-v2-4 | 4 / 5 | 4591.373 | 183.166 | 55041 | 266240 | 147456 |
| R-1-8 | 8 / 9 | 12023.892 | 463.532 | 55041 + 55041 | 450560 | 229376 |
| R-2-8 | 8 / 9 | 11867.580 | 462.443 | 55041 + 55041 | 450560 | 229376 |

Setup includes fresh synthetic keys, DID bootstrap, store migrations, issuance and
revocation. Catch-up times include bounded page collection, full reference checking
and the single holder wallet replacement; retrieving the explicitly selected target
from the trusted local manager is outside that timed interval. All clocks, exact
commands, source/fixture hashes, message sizes and storage at every setup step are
in the case records. Fresh entropy is intentional. These are serial local operations,
not network latency, steady-state throughput or percentile estimates.

Eight updates have 89,296 raw record bytes but travel in **two 55,041-byte responses**;
no combined over-cap response is constructed. Manager DB growth at 0–8 revocations
is 81,920; 122,880; 167,936; 212,992; 266,240; 311,296; 356,352; 401,408;
450,560 bytes. The final value leaves 73,728 bytes below its database cap, **not a
promise of any further number of records**. Retained checkpoint metadata, outcomes
and node/table overhead still grow. Transient journal peak was not separately retained;
the existing store/SQLite and guarded temporary limits remain enforced. Final temporary
usage is recorded after cleanup. No storage/memory limit was increased.

Each record remains 11,162 bytes; credential 11,012, enrolment body 7,720, ML-DSA
signature 3,309, signed state 3,427 and witness path 960 bytes. Per-case exact values
are retained. The original series and new series must not be pooled into privacy
cost, PQ-DAA throughput or unsupported speedup claims. Genuine private-proof message,
proof-generation and verification measurements remain unavailable.

## Reproduction, accounting and Preservation

Use the exact guarded command lines in `jobs/*.input.json`, for example:

```sh
.venv/bin/python -I -B experiments/kyc_manager_incremental_storage_1/run.py job manager-cases python 240 -- /home/grace/projects/pq-did/.venv/bin/python -I -B /home/grace/projects/pq-did/experiments/kyc_manager_incremental_storage_1/dispatch.py focused S 1 24
.venv/bin/python -I -B experiments/kyc_manager_incremental_storage_1/run.py job scaling-R-1-8 python 150 -- /home/grace/projects/pq-did/.venv/bin/python -I -B /home/grace/projects/pq-did/experiments/kyc_manager_incremental_storage_1/dispatch.py measure R-1-8
```

These are historical commands, not authority for uncounted repeats. New reproduction
requires a fresh admitted ledger linked to this checkpoint. Existing jobs reject
reuse; failures remain separate records. Worker memory is 256 MiB cgroup-v2 (including
descendants/cache/kernel), one serial worker, two CPUs, zero swap, inherited command,
process/storage limits and protected completion reserves. No circuit rows/gates were
emitted. Both time balances charge guarded elapsed time plus explicit conservative
implementation/bookkeeping charges. Analysis/isolation budgets are unchanged.
Final measured accounting is in `resource-closure.json` and `validation-closure.json`.

All 47 planned distinct cases now have passing outcomes, with **49 total invocations**
and cumulative **1,140/1,146**. Builds remain **10/13**. No scaling case is still
unrun in this matrix; the earlier 21 full-authentication relation checks remain unrun.
A single inherited complete preservation audit, final inventory, readback and workload
shutdown are recorded below on completion. Original baselines/seals are not regenerated.

KYC-TESTBED-SCALE-001's demonstrated four/eight-record obstruction is resolved for
this isolated version. Larger-history capacity, production external freshness custody,
power-loss/whole-store rollback, encryption/erasure/side channels and deployment
isolation remain unestablished. Standards-level securing/key/private-status mappings,
adaptive Delta_tail, component/reduction budgets, QROM knowledge/extraction,
commitment/privacy/hash composition, finite parameters and complete private-proof
construction remain open. Binius64 remains paused after G0 NO-GO; no backend is
adopted. Private verification stays fail-closed. CPU proving and isolation remain
paused; the proof ledger remains **two used, one unused**.

The full PQ-DID/KYC/benchmarking scope and 31 October target are unchanged; current
evidence still does not support committing to full completion by that date.


Preservation checkpoint: the single full audit **passed**, exit 0, with
10,901 disjoint historical comparisons and
10,936 identity-inclusive paths; no changed/missing
protected content or inventory discrepancy. Guard time 4.878s; worker
`memory.peak` 49,483,776 bytes (47.191 MiB), including descendants
and charged cache/kernel, below 256 MiB with no resource breach. Final inventory,
report readback, terminated workload and actual balances are recorded in
`docs/data/kyc_manager_incremental_storage_1/validation-closure.json` and
`resource-closure.json`. Historical failures remain failures; two eight-record
measurements remain unrun, and no missing private-authentication result is supplied.


Final-readback correction: the initial readback rejected a line break inside its
required literal qualification. The earlier wording remains intact above. This is
not complete private authentication. No implementation, case expectation or audit
comparison changed. The failed readback and pre-correction inventory/seal are
retained under `jobs/final-readback.*` and `readback-correction/`. Only the affected
readback is repeated as `final-readback-corrected`; the full audit is not repeated.

The corrected readback then detected the inventory amendment still referenced by
its preceding seal. This was the explicitly authorised new-output inventory, not
a protected historical input. Both versions and both failed readback records are
retained. Its dependent package seal is now updated explicitly, and every complete
manifest input is checked before the final readback. No baseline comparison or
original expected digest has been changed; the full audit remains a single run.
