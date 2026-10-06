# KYC-ISSUER-INCREMENTAL-STORAGE-1
The isolated issuer storage correction and its admitted validation succeeded. **46
individual cases passed**, including 35 storage/recovery cases, eight genuine
ML-DSA application checks and three separate baseline scaling observations. Two
eight-record scaling cases remain **unrun**, blocked by the unchanged manager
checkpoint representation. This is not complete private authentication and does
not close the KYC workstream or Stages 2–3.

Only manuscript Sections II–VIII and SPEC-001–004 are authoritative. The manuscript
identity and all 223 directly inherited checkpoint seals were checked before work.
The explicit resource amendment is in `data/kyc_issuer_incremental_storage_1/amendment.json`.
Original policies, failures, Binius64 G0 NO-GO and the closed Aurora experiments
remain historical evidence. No G1–G3, builds, installations, proofs, zkVM execution,
private-profile adoption or host isolation activation occurred.

## Exact failure and unchanged boundary

`baseline/storage.py:IssuerJournal.transition` encoded the entire sorted set of
`(operation, encode(session))` into one PQL1 head preimage. Certification of the fourth
session exceeded PQL1's **65,536-byte aggregate-object cap**. It was neither an
oversized individual credential nor a transport-frame failure. The sealed failure
contains three 18,517-byte CERTIFIED records and one 7,498-byte SIGNING record.
S-01 reuses an isolated copy of that sealed store and observes the original
`payload-cap` rejection before writes; permanent IDs 0–3 and the SIGNING phase
remain intact. S-02 migrates a separate copy and completes a **synthetic storage
record only**, with aggregate payload 74,075 bytes. It makes no cryptographic claim.
The genuine end-to-end five-session/four-revocation runs provide the separate
cryptographic application evidence.

The original archive, inventory and their hashes are unchanged. Its SHA-256 is
`9428963121f0fc9d12c0b2b9ffc33f11e89345e57ac757ccd438b933e51674d3`.
The test's recovery ticket is derived from independently sealed historical evidence,
not adopted from an arbitrary self-consistent live database. No protected store is
migrated, and no baseline is regenerated.

## Version-2 contract and integrity

The implementation is `experiments/kyc_issuer_incremental_storage_1/journal.py`;
`integration.upgrade` connects it to the unchanged baseline issuer by its existing
journal interface. This is an isolated, trusted-local reference implementation.
It does not enable live signing or replace comparison point v1.

SQLite `user_version=2` has five exact-schema tables: `v2_meta` (identity, expected
head/generation and migration origin), `v2_records` (operation, bounded PQL1 current
outcome, leaf digest), `v2_base` (migration leaf set), `v2_events` (one digest event
per transition/fence), and `v2_legacy_heads` (unchanged v1 sequence/digest history).
Every read checks schema/settings, SQLite integrity, independent expected ticket,
legacy chain length/anchor, event continuity/generations, roots, current row hashes
and exact membership. No missing or duplicate session, nonce or reserved identifier
is accepted. Operation = SHA-256(`baseline-issue` || session) stays unchanged.

Local SHA-256 leaf framing is `pqdid/local-issuer-v2/leaf\0 || operation32 ||
lengthBE32 || PQL1-record`. The root streams domain, countBE32 and sorted
`operation32 || leaf32`; it never encodes aggregate payloads. Each head hashes a
bounded canonical tuple containing identity, migration origin, sequence, predecessor,
generation, operation, phase, old/new digest, root and count, with a distinct local
head tag. The exact formula is in the source; these are **local storage commitments**,
not new credential/signature formats or proof commitments.

There are at most 64 session records and 512 v2 events, explicitly checked. Each
record remains capped at 65,536 bytes; no record is truncated. Session pages return
at most four records; digest-history pages at most 16 events, ordered at one fixed
expected head with validated cursors. They are local APIs, not permission to send
an oversized IPC object. Compatibility `snapshot()` and integrity replay may scan
the bounded store; this is bounded persistence, not unlimited constant-time history.
The active testbed shape retains ML-DSA-65 keys (1,952 bytes), its 1,024-byte
attributes, identifier range, 960-byte path and 3,427-byte state. Typed canonical
and cryptographic checks remain in the existing issuer/holder modules.

The database and its journal remain separately capped at 512 KiB, with 128 SQLite
pages, private 0700/0600 paths, DELETE/EXTRA transaction settings, disabled extensions,
bounded SQL/VM work and no unmonitored helpers. A capacity failure remains a failure;
no larger file/transport or memory ceiling was introduced. Retaining digest events
avoids rewriting growing payload histories but does not guarantee 64 fully certified
sessions fit the fixed database cap.

## Transaction, migration and release ordering

`prepare` computes an exact single-record plan against a validated expected head.
`commit` takes BEGIN IMMEDIATE, revalidates the head/generation and complete prepared
binding, and atomically updates **one outcome row, one history event and metadata
head**. A competing or fenced writer cannot commit. Uncommitted signature bytes are
not retrievable via `BaselineIssuer.retrieve`. Certification is committed before
release; exact redelivery reads stored bytes without resigning and checks recipient.
INTENT → RESERVED → SIGNING → CERTIFIED, immutable reservation fields, consumed
signing nonce and unique identifier checks remain enforced.

The manager reservation and issuer are separate stores. There is no cross-store
atomicity claim: a permanent manager allocation precedes certification and is never
reclaimed when signing/commit fails. SIGNING is a conservative consumed, non-releasable
state; it is not automatically retried or resigned. Existing trusted role/key/instance,
DID admission and state-supersession checks are reused unchanged.

Migration is explicit and fresh-copy-only in this workstream. `migration_plan`
validates v1 against the external expected ticket, checks each record and retained
heads, and predicts an origin-bound successor head with generation incremented.
The trusted operator must retain that plan **outside the store before mutation**.
`migrate` rechecks it under BEGIN IMMEDIATE, copies bounded rows/legacy heads, creates
the new digest structures and changes schema/version in one transaction. Missing,
stale or changed plans fail; old writers cannot use v1 on v2. Before-commit interruption
recovers exactly v1. After-commit lost response recovers exactly v2 using the already
retained successor ticket. Repeated recovery is read-only and does not reset IDs,
consumed nonces or freshness. Related store contents are never rewritten by migration.

Tests distinguish Python-injected failures from actual forked child `os._exit(73)`
before/after SQLite COMMIT. The parent retains the independent plan during those
process interruptions. Neither establishes power-loss durability, durable external
operator-ticket custody, hostile-owner isolation, reliable erasure or protection from
whole-store plus trusted-ticket rollback. Test-only module fault hooks are inert in
ordinary APIs; no request/container field enables them.

## Individual validation and measured scaling

The plan was recorded before affected tests. Three bounded history/schema checks
were added before their execution, within the existing invocation allocation.
Completed primitive/native ABI, wallet, mappings and unaffected lifecycle tests were
reused. No regression case was retried. Static-1 found two style-only diagnostics;
the retained static-2 and final static-3 checks passed. One final complete audit,
inventory, readback and shutdown follow below.

| Case | Outcome | Purpose | Seconds |
| --- | --- | --- | ---: |
| S-01 | pass | sealed v1 four-record aggregate rejection | 0.017779 |
| S-02 | pass | sealed failure copy migrates and accepts bounded fourth record | 0.020205 |
| S-03 | pass | empty migration | 0.009773 |
| S-04 | pass | simulated migration before commit | 0.011142 |
| S-05 | pass | simulated lost migration response | 0.013701 |
| S-06 | pass | actual migration exit before commit | 0.016820 |
| S-07 | pass | actual migration exit after commit | 0.016524 |
| S-08 | pass | stale migration plan | 0.013002 |
| S-09 | pass | repeat recovery without mutation | 0.014865 |
| S-10 | pass | v1 writer rejected after migration | 0.014353 |
| S-11 | pass | fencing rejects old writer | 0.017699 |
| S-12 | pass | simulated commit failure before commit | 0.016139 |
| S-13 | pass | simulated lost commit response | 0.017593 |
| S-14 | pass | actual process exit before commit | 0.017843 |
| S-15 | pass | actual process exit after commit | 0.021670 |
| S-16 | pass | prepared result fenced at commit | 0.020342 |
| S-17 | pass | competing prepared writers | 0.017926 |
| S-18 | pass | tampered auxiliary prepared plan | 0.013830 |
| S-19 | pass | missing session | 0.015639 |
| S-20 | pass | duplicate primary key | 0.012391 |
| S-21 | pass | malformed row | 0.016171 |
| S-22 | pass | missing event | 0.014813 |
| S-23 | pass | inconsistent event root | 0.015352 |
| S-24 | pass | inconsistent head | 0.015785 |
| S-25 | pass | missing legacy head | 0.015143 |
| S-26 | pass | duplicate nonce | 0.019280 |
| S-27 | pass | bounded page coverage | 0.032880 |
| S-28 | pass | head change between pages | 0.022104 |
| S-29 | pass | five sessions exceed old aggregate limit | 0.112253 |
| S-30 | pass | invalid phase and removal | 0.015830 |
| S-31 | pass | stale ticket and wrong instance | 0.013325 |
| S-32 | pass | oversized record unchanged cap | 0.013613 |
| I-01 | pass | real populated migration exact recipient redelivery without signing | 0.709353 |
| I-02 | pass | verifier A acceptance and replay | 0.554457 |
| I-03 | pass | independent verifier B acceptance and replay | 0.604998 |
| I-04 | pass | failed certification commit blocks release | 0.193553 |
| I-05 | pass | committed certification lost response exact redelivery | 0.259380 |
| I-06 | pass | signing failure preserves reservation and consumes nonce | 0.165854 |
| I-07 | pass | fencing after real signature blocks certification | 0.271464 |
| I-08 | pass | old certified nonce cannot certify again | 0.111960 |
| S-33 | pass | Bounded authenticated event history pages with exact coverage | 0.059016 |
| S-34 | pass | Duplicate permanently reserved identifier rejected | 0.036866 |
| S-35 | pass | Unexpected stored schema rejected | 0.014980 |
| R-1-4 | pass | Affected regression | 4.673390 |
| R-2-1 | pass | Previously unrun scaling case | 1.386962 |
| R-2-4 | pass | Previously unrun scaling case | 4.837578 |

| Scaling case | Update records / issuer sessions | Setup ms | Catch-up ms | Update payload bytes | Issuer DB bytes | Manager DB bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| R-1-4 | 4 / 5 | 4372.835 | 297.747 | 44648 | 147456 | 475136 |
| R-2-1 | 1 / 2 | 1274.709 | 110.309 | 11162 | 77824 | 143360 |
| R-2-4 | 4 / 5 | 4531.884 | 302.795 | 44648 | 147456 | 475136 |

Setup includes fresh synthetic key generation, DID bootstrap, manager/issuer stores,
explicit empty-store migration, issuance and revocation. Migration took 12.979–13.510
ms in these runs. Catch-up includes public history retrieval/verification and atomic
holder witness update. Individual outcomes retain exact clocks, fixture identities,
command arguments, message sizes and storage at every growth point. Credential
11,012 bytes; enrolment body 7,720 bytes; enrolment signature 3,309 bytes; state 3,427
bytes; path 960 bytes. Each update payload is 11,162 bytes. No private proof appears.

Issuer database growth at 0/1/2/3/4 revocations is
53,248 / 77,824 / 98,304 / 118,784 / 147,456 bytes. The manager grows
81,920 / 143,360 / 233,472 / 344,064 / 475,136 bytes. The latter already approaches
512 KiB. These are observed database sizes, not projected asymptotic costs.
All three new observations are in `measurements-v2.json`, separate from the original
276 and subsequent 19. They provide no percentile, sustained throughput, privacy
overhead or speedup claim. Unaffected existing throughput results were not rerun.

**R-1-8 and R-2-8 remain explicitly unrun.** Source inspection proves that eight
required manager update payloads alone require 8 × 11,162 = **89,296 bytes**, before
local framing and other checkpoint fields, versus the unchanged 65,536-byte PQL1
checkpoint cap. Earlier 89,328-byte analysis included additional framing; both
bounds exceed admission. Changing only issuer storage cannot remove that obstruction.
No eight-record test, resource-limit failure or substitute measurement was launched.

## Reproduction, remaining work and Preservation

Use the retained exact commands in `jobs/*.input.json`. For example (a historical
command, not permission for an uncounted rerun):

```sh
.venv/bin/python -I -B experiments/kyc_issuer_incremental_storage_1/run.py job storage-cases python 100 -- /home/grace/projects/pq-did/.venv/bin/python -I -B /home/grace/projects/pq-did/experiments/kyc_issuer_incremental_storage_1/dispatch.py focused S 1 32
.venv/bin/python -I -B experiments/kyc_issuer_incremental_storage_1/run.py job scaling-R-1-4 python 95 -- /home/grace/projects/pq-did/.venv/bin/python -I -B /home/grace/projects/pq-did/experiments/kyc_issuer_incremental_storage_1/dispatch.py measure R-1-4
```

Reproduction needs a fresh admitted evidence ledger linked to this checkpoint;
existing jobs/positive cases reject reuse. Fresh entropy is intentional; matching
behaviour/conditions does not imply identical random keys or signatures. Python3.14,
SQLite versions, CPU, worker affinities and resource measurements are recorded.
Successful disposable stores were removed after assertions, with inventories retained.
Original failure archives and every earlier diagnostic remain protected.

The opening amendment was applied once: 2,840.340 implementation seconds and
2,473.113 workstream seconds, 101 invocations, cumulative evidence 40 MiB, shared
headroom 10,627,889 bytes. The separate 448,679-byte unallocated headroom and all
300-second/2-MiB completion reserves remained intact. Guarded job durations and
explicit conservative source/bookkeeping charges consume both time balances;
analysis/isolation allowances are untouched. Final balances, storage and resource
metrics are in the new resource/validation closures, not reset historical records.

The concrete remaining storage decision is a separately scoped **incremental manager
checkpoint/history/outcome design**, with atomic trusted-head transitions and bounded
retrieval, before the two eight-record measurements. It must address both the PQL1
aggregate cap and retained checkpoint duplication approaching the 512-KiB database
cap; raising only the issuer cap or rerunning eight records cannot solve it.
This issuer-only package does not silently adopt a manager architectural change.

Local W3C mappings remain experimental; externally standard securing/key/private
status mechanisms remain unresolved. Binius64 stays paused after G0 NO-GO; the
assessed Aurora route stays closed. The 21 complete-relation checks remain unrun.
Private verification stays fail-closed. Adaptive Delta_tail, component/reduction
budgets, QROM knowledge/extraction, privacy/commitment/hash composition, finite
parameters, production custody/entropy/erasure/side channels and isolation remain
open. Full PQ-DID, KYC and benchmarking scope and the 31 October target remain
unchanged; the evidence does not support committing to full completion by that date.
Proof ledger: two used, one unused. CPU proving and isolation remain paused.

Preservation result will be appended after the complete guarded workflow succeeds.


Preservation checkpoint: the single full audit **passed**, exit 0, with
10,901 disjoint historical comparisons and
10,936 identity-inclusive paths; no changed/missing
protected content or inventory discrepancy. Guard time 4.840s; worker
`memory.peak` 48,730,112 bytes (46.473 MiB), including descendants
and charged cache/kernel, below 256 MiB with no resource breach. Final inventory,
report readback, terminated workload and actual balances are recorded in
`docs/data/kyc_issuer_incremental_storage_1/validation-closure.json` and
`resource-closure.json`. Historical failures remain failures; two eight-record
measurements remain unrun, and no missing private-authentication result is supplied.
