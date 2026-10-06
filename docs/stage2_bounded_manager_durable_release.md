# S2-BOUNDED-MANAGER-DURABLE-RELEASE-1

25 September 2026. **24 individually counted manager integration cases passed**:
22 ordinary/application-fault cases and two real child-process SIGKILL cases.
This is an opt-in reference facade using synthetic keys and temporary authority
stores. No live service, pilot activation or production signing is enabled.

## Authority, baseline and carried budget

Only manuscript **Sections II–VIII** and agreed SPEC-001–004 clarifications are
authoritative. R-030 requires atomic tree/epoch/nonce/public-record commit and
retrievability despite delivery failure; R-033 requires bounded validation of every
signature before release. See [the specification](implementation_spec.md),
[manager state report](stage2_revocation_state.md),
[durable authority report](stage2_durable_authority_pilot.md),
[owner boundary](stage2_authority_owner_boundary.md) and
[completed signer release report](stage2_bounded_signer_release_contract.md).
Original primitive/native and adapter validation is reused, not rerun.

[Preflight](data/s2_bounded_manager_durable_release_1/preflight-evidence.json)
checked every input in the previous seal
`06fc22d4d4f4c9ca27d762fcdb672b815189563c5a50bb311e77e8dd481c44bf`, the assessed
source inventory and manuscript digest
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
No historical baseline, seal, failure record, active parameter or dependency changed.

The user expressly raised the cumulative test ceiling from **100 to 124** by adding
24 invocations. At admission, **97** had already been consumed, leaving **27**;
this package uses **24**, for **121/124 total and three remaining**. Parameterised
cases are listed separately below. Deselected tests in the two disjoint pytest
selections were not run; there were no failed/repeated test invocations.

The previous ledger records **30.539082388975658/300 seconds charged** and
**269.46091761102434 seconds remaining**. New guarded command times plus five
bookkeeping seconds are added to that same implementation ledger. Admission reserves
another ten seconds for cleanup/evidence in addition to each 60-second command
reservation. Analysis **270.1814811680233 seconds** and isolation **250.22 seconds**
(including its ten-second emergency reserve) are unchanged, never borrowed.
Isolation stays safely stopped/unactivated with 100 historical invocations and
22 actual-identity cases pending. No new host query or activation is needed to reuse
the existing sealed closure evidence. Proof ledger: **two used, one unused**;
CPU proving remains paused.

## Exact transaction boundary

[The new facade](../src/pqdid/bounded_manager.py), `BoundedDurableManager`, composes
the existing `DurableManager`, `SQLiteStore`, recovery validator and bounded
`ManagerSigningAdapter`. No pre-existing implementation file is modified.
The existing storage design already provides the required **single-database**
transaction; no cross-store atomicity, schema change or new authority mechanism is
introduced. Issuer intent/reservation remains a separate journalled contract.

| Durable object | What commits together for a revocation |
| --- | --- |
| Manager checkpoint | Existing `ManagerRecord`: encoded new signed state, complete revoked set, consumed revocation-request nonce set and retained signed update history |
| Preserved checkpoint metadata | Permanent allocation prefix, base signed state, base revoked/nonces and complete instance/role/service binding |
| Sparse tree | Reconstructed from the committed base/revoked set and authenticated history by the existing recovery validator; no second independently committed tree store |
| Signed public records | Existing `encode_state` bytes and complete `rupdate` bytes, including both signed endpoints and update signature; unchanged SPEC-001 sibling-path framing |
| Operation outcome | Existing operations table binds operation ID, kind, writer principal, expected ticket, exact issuer request message/signature, decision and exact public response bytes |
| Checkpoint/head | Checkpoint digest, previous head, operation commitment, generation and entries commitment bind the next head; service tip advances in the same transaction |
| Authority entries | Existing allocation entries retained unchanged by revocation; not lost or rewritten from another store |

`read_current(operation, nonce)` stores the exact nonce-bound current signature in
an operation outcome and advances the head in the same database. Its manager
checkpoint is unchanged. The `current` nonce is not a revocation-request nonce and
does not change the consumed-revocation-nonce set. Allocation still uses the existing
permanent reservation transaction and its authorised issuer interface.

The existing database bounds remain: 64 KiB local containers/response/checkpoint,
128 operations/entries, 512 KiB database and at most 1 MiB database plus journal.
The original manager history/revocation/nonce limits remain, as do SQLite DELETE
journalling, synchronous EXTRA, zero busy timeout, schema/foreign-key/quick checks
and bounded SQL progress. Capacity failure fails closed; this work adds no eviction,
compaction, retry or limit increase.

## Signing, commit and release sequence

1. Construction requires an explicit writer permit and **independently retained
   expected head ticket**. The existing recovery admission checks role/instance,
   service identity, generation, exact head, checkpoint consistency and signatures.
   A trusted `TrustedSigningKey` must match manager role, service, full parameters
   and `pp.revocation_public_key`; bounded key-import/public-identity checks are reused.
   Callers cannot supply a key, context, signer, finished record or alternative role
   through a mutation request. The existing write-authorisation policy stays decisive.
2. Capture an admitted immutable checkpoint/head under the database writer lock.
   Reject an already committed operation before signing; explicit retrieval is the
   only redelivery path. The facade admits one operation at a time locally, while
   SQLite and generation/head checks coordinate independent facades/processes.
3. Reconstruct a private reference manager and sign outside the transaction. The
   original request checks enforce issuer signature, allocation, unused nonce,
   non-revocation and exact current state. Existing message constructors and contexts
   remain `build_state_message` / `PQ-DID/state/v1`, `build_update_message` /
   `PQ-DID/update/v1` and `build_current_message` / `PQ-DID/current/v1`.
   The bounded adapter validates write authority and the **same captured ticket**
   before and after each signature. Its completed core verifies before returning;
   the reference manager additionally performs its existing artefact validation.
4. Acquire `BEGIN IMMEDIATE` again and revalidate writer policy, exact expected head,
   writer generation/principal, previous checkpoint and absence of the operation.
   The unchanged `_write` validates the complete candidate checkpoint, writes all
   rows and executes **one COMMIT**. The lock excludes another admitted database
   writer through that commit. A concurrent allocation also invalidates the expected
   head even when the public root/epoch has not changed.
5. Return only a credential-free/redacted outcome (`response == b""`) and its committed
   head. Public bytes come exclusively from the committed store through retrieval.
   A commit exception never returns the private candidate or silently refreshes the
   caller's expected recovery ticket. No automatic re-signing or retry occurs.

All four primitive caps remain **1026 / 512 / 256 bytes and 1024 signing attempts**.
Entropy failure, exhausted signing, verification rejection, authority withdrawal
or failed commit release nothing. Internally signed but uncommitted messages and
repeated bounded import/verification work still count in security workload budgets;
failure is not a claim that no signing work occurred or that memory was erased.

## Public retrieval, ordering and recovery

`updates(namespace, after_epoch, target_epoch, limits=...)` delegates to the existing
bounded page semantics after admission, under the same database lock. It returns
only public signed endpoints/update records and continuation state. It takes no
holder identifier, witness, recipient or credential. This owner-local read linearises
at its locked snapshot; a later commit does not undo that historical read.

`retrieve_committed(operation, transport)` enqueues one exact committed result on
a nonblocking local AF_UNIX/SOCK_SEQPACKET channel **while holding the database
writer/fencing lock**. The owner must still be authorised and current. Revocation
outcomes must match retained checkpoint history and their new signed endpoint.
They remain valid historical public data after later revocations. A stored `CURRENT`
outcome can be delivered only while its encoded state still matches the committed
current state; after a revocation it fails `superseded-current`. An old generation
cannot commit or enqueue after replacement. Successful enqueue is an ordered
publication, not a promise that the receiver observes bytes before any future commit.

Response containers use the **existing bounded local PQL1 codec**: revocation is
`(encoded_state, encoded_update)`, current is `(nonce, encoded_state, signature)`.
These are local outcome/transport containers, not new signed messages or a deployed
network protocol. There is deliberately no issuer-style recipient binding: the
revocation records are public. Existing private credential `CERTIFIED` delivery,
its original-recipient checks and verifier acceptance rules are unchanged.

Before-commit failure leaves the original checkpoint, head, history and nonce set.
The identifier remains permanently allocated; the failed revocation nonce is not
consumed. There is no committed success outcome. Signed material remains private
and is discarded. Explicit future resubmission would be new work; it is not an
automatic recovery action in this facade.

After COMMIT but before acknowledgement, the complete new state/outcome may exist
although the facade still holds its old ticket. Old-ticket admission fails. Recovery
requires explicit reconciliation and an independently retained expected head, then
retrieves exact stored bytes without calling the signer. In both after-commit tests,
the **trusted test coordinator explicitly captures the committed head at the test
barrier**, before exception/termination. This is not automatic refresh from a
self-consistent database, nor a general solution if both the acknowledgement and
all independent head evidence are lost. Existing recovery-authority freshness and
generation contracts remain prerequisites.

Missing/inconsistent checkpoints fail admission. Semantic-corruption tests deliberately
rehash the malformed fixture head and supply that synthetic false anchor to show
that complete-history and nonce invariants are still checked. They do not establish
protection against coordinated whole-store rollback, malicious owner code or a
compromised independent authority.

## Individual test outcomes

[Integration tests](../tests/integration/test_bounded_manager.py) use only
[synthetic helpers](../tests/integration/bounded_manager_cases.py), two public seed
constants and isolated temporary databases. Expanded secret keys are not written
to stores/evidence. Initial allocation count two is an explicit trusted synthetic
bootstrap; no production record is adopted. Rare errors are injected at existing
test-only boundaries, never via ordinary facade inputs. The prior native ABI and
core cap tests were not repeated.

Each row below is **one pytest invocation**, including every parameter value.
Fixture construction and assertions about the resulting state are prerequisites
and observations of that row, not undisclosed extra scenarios.

| # | Case / parameter | Outcome | Resulting durable/public state |
| --- | --- | --- | --- |
| 1 | Revocation, restart, public history and exact redelivery | PASS | Epoch 1; one update, revoked ID 0 and one consumed nonce; allocation stays 2; exact bytes delivered twice, no new signatures |
| 2 | Current read, restart and exact redelivery | PASS | Head advances, epoch/history unchanged; exact nonce/state/signature retained; only original current signature generated |
| 3 | Simulated rows-before-commit exception | PASS | Both signatures generated privately; no new head/state/history/nonce/outcome; retrieval sends no bytes |
| 4 | Simulated commit-before-ack exception | PASS | Complete epoch-1 outcome retained; old ticket denied; explicit retained-head recovery and exact redelivery, no resigning |
| 5 | Stale head before signing | PASS | Competing allocation alone survives (count 3); stale operation signs zero times |
| 6 | Replacement writer during signing | PASS | Generation 2 wins; private state signature discarded; epoch/history/nonces unchanged; old publication denied |
| 7 | Concurrent allocation before commit | PASS | Both signatures remain private; exact-head recheck fails; allocation 3 alone survives |
| 8 | Concurrent replacement before commit | PASS | Both signatures remain private; generation recheck fails; generation 2 alone survives |
| 9 | Invalid issuer authorisation signature | PASS | No manager signing, state change or public outcome |
| 10 | Withdrawn write authority | PASS | Signing/publication denied; original durable state remains, no bytes enqueued |
| 11 | State entropy-error boundary | PASS | Signing failure; original state/head retained and no outcome |
| 12 | Update attempt-exhaustion boundary | PASS | Real first state signature stays private; resource-exhausted outcome, original state/head retained |
| 13 | Current post-verification-error boundary | PASS | No durable current outcome or public reply; original head retained |
| 14 | Wrong configured service identity | PASS | Constructor rejected, store unchanged |
| 15 | Wrong configured manager role | PASS | Constructor rejected, store unchanged |
| 16 | Wrong configured instance | PASS | Constructor rejected, store unchanged |
| 17 | Incomplete recovered history | PASS | `checkpoint-admission` denied, no admitted facade |
| 18 | Incomplete recovered consumed-nonce set | PASS | `checkpoint-admission` denied, no admitted facade |
| 19 | Missing checkpoint row | PASS | `missing-reference` denied, no admitted facade |
| 20 | Current result superseded by revocation | PASS | Revocation remains committed; old current reply sends no bytes and does not resign |
| 21 | Old writer attempting stored publication | PASS | Replacement generation retained; old writer sends no bytes and does not resign |
| 22 | Repeated mutation operation ID | PASS | Explicit retrieval required before any signing; committed state unchanged |
| 23 | Actual SIGKILL at rows-before-commit | PASS | Reopen recovers original sequence 2 / epoch 0 / empty history and nonce set; no public result |
| 24 | Actual SIGKILL at commit-before-ack | PASS | Reopen admits retained sequence 3 / epoch 1 head; exact response digest and bytes match; repeated retrieval signs zero times |

JUnit evidence: [22 integration cases](data/s2_bounded_manager_durable_release_1/focused.xml)
and [two crash cases](data/s2_bounded_manager_durable_release_1/crashes.xml).
Individual resulting heads/counts and fault labels:
[integration state evidence](data/s2_bounded_manager_durable_release_1/case-evidence-focused.json)
and [crash evidence](data/s2_bounded_manager_durable_release_1/case-evidence-crashes.json).
The two selections are disjoint: `-k "not test_real_process_crash"` and
`-k test_real_process_crash`. Tests passed in 8.12 s and 1.43 s pytest time;
guarded command wall times were **8.388047651 s** and **1.651576432 s**.

The [crash worker](../tests/integration/bounded_manager_worker.py) was actually killed
and reaped at each barrier (exit **−9**, PIDs **2402693** and **2402694**). It has an
additional five-second CPU/ten-second alarm bound. The parent admits one child,
waits at most eight seconds for the application barrier, kills only that owned PID
and closes all pipes; fixture cleanup removes only its temporary directory.
The worker, pytest process and child remain inside the same capped cgroup. These
two outcomes establish the exercised **application-process crash** recovery with
intact honest storage. They do not establish power-loss durability, storage-device
failure behaviour, interruption inside SQLite itself or universal crash coverage.

## Validation envelope and preservation

The [configuration](data/s2_bounded_manager_durable_release_1/config.json) explicitly
records the **100 → 124** test amendment and prior time/output charges.
The [run ledger](data/s2_bounded_manager_durable_release_1/run-ledger.json) contains
every exact expanded command and measured guard result. Commands use:

```sh
.venv/bin/python -I -B docs/data/s2_bounded_manager_durable_release_1/run_checks.py NAME
```

Names, in order: `preflight`, `imports`, `source-format`, `focused`, `crashes`,
`final-source-format`, `quality`, `format`, `prepare`, `full-audit`. `close.py`
then performs the existing bounded write-once reporting/sealing step. Import/format
commands apply only to new package files. No historical suite, native harness or
test failure is automatically repeated.

All existing ceilings are retained: one sequential worker, two CPUs, 256 MiB cgroup
memory including descendants and charged cache/kernel memory, zero swap, 60-second
command/55-second child, 8 MiB temporary data, cumulative 10 MiB package output,
1 MiB files, 60 KiB per-command diagnostics, existing 9 GiB experiment-storage stop,
2 GiB memory headroom reserve and 300 cumulative implementation seconds. The earlier
755,567 output bytes are carried forward. Source controls at most one extra test
child (worker + pytest + child, within four controlled processes); the existing
systemd TasksMax=128 remains unchanged. Separate sampled tree RSS may count shared
pages more than once and is not substituted for the cgroup metric.

The corrected preservation auditor remains unchanged and receives the original
8,759-file baseline plus the additive historical seal chain. It checks complete
disjoint content coverage, name inventory, sealed code/parameters/dependencies,
historical evidence and append-only report prefixes under the unchanged **256 MiB**
guard. A full pass requires comparison, report readback and successful outer resource
completion. No failed/partial audit counts as preservation success; no baseline is
regenerated. Final measured closure is recorded below.

New implementation files are `src/pqdid/bounded_manager.py` and the three integration
test/helper files linked above. This report and its package evidence are added;
status, traceability and issues are append-only. Existing signing adapters, bounded
core, lifecycle/storage implementation, manuscript, active parameters and dependencies
are preserved. No installation, activation, estimator campaign, circuit generation,
proof or zkVM execution occurred.

## Disposition and next implementation

This package satisfies the tested **reference durable manager publication** subtask:
one-store checkpoint/history/nonce/outcome/head commit, commit-before-release,
explicit stale/concurrent-writer rejection, public stored retrieval without signing,
current-result supersession checks and complete/incomplete recovery admission.
It adds real process-crash evidence at two application boundaries, with the exact
independent-head prerequisite stated above. It does not complete DEP-002 production
release readiness or all-role lifecycle integration.

Still open: complete issuer/manager/verifier/holder integration, actual-ID isolation,
production custody and entropy assurance, reliable erasure, side-channel/fault
resistance, capacity/deployment policy, unavailable independent freshness evidence,
power-loss testing and whole-store rollback protection. DEP-001/adaptive `Delta_tail`,
component advantages at reduction budgets, SEC-001–005, OC-REL/EXT/PRIV/BUDGET and
complete proof knowledge/privacy remain unresolved. The manuscript construction,
reference components and experimental proof-backend results remain separate.

One next recommendation: **S2-DURABLE-ISSUER-MANAGER-INTEGRATION-1**, an isolated
synthetic integration of the two completed bounded facades through the existing
intent/reservation/reconciliation contracts. Check permanent allocation, issuance
release, later revocation and recovery without asserting a transaction across the
separate authority stores. Scope its test plan against the three remaining
invocations or request a concrete allowance amendment before exceeding them.
No next package is started. Stages **2–3 remain open**, isolation safely stopped and
unactivated, proof ledger **two used / one unused**.


## Measured validation closure

The single [complete preservation audit](data/s2_bounded_manager_durable_release_1/result.json)
passed content/inventory comparison, report readback and its outer resource guard,
exit **0**. Coverage: 8,759 original and
995 supplementary paths,
**9,754 disjoint content paths**,
9,771 identity-inclusive paths.
No unexpected changes, additions or removals occurred. Three historical reports
have verified append-only prefixes; all pre-existing source/vectors/parameters,
manuscript, dependencies and original evidence are preserved. The only new source
is the separate manager facade and three integration test/helper files.
Lint and formatting pass.

| Measurement | Result |
| --- | --- |
| Audit wall time | 2.347716602 s |
| Audit cgroup memory.peak | 23,076,864 bytes |
| Audit sampled process-tree RSS | 40,865,792 bytes |
| Maximum guarded-job cgroup memory.peak | 59,478,016 bytes, below 268,435,456 |
| Maximum observed guarded-job tree RSS | 96,493,568 bytes; separate metric |
| Guarded commands | 10, 13.175038338 s total; all checks completed successfully |
| Cumulative implementation charge | **48.714120727/300 s** |
| Remaining implementation allowance | **251.285879273 s**, **3/124 test invocations** |
| Test invocations | 97 previously charged + 22 integration + two crash cases = 121; no repeats |
| Functional failures/resource breaches | 0/0 in this package; all historical evidence retained |
| Temporary storage | 146,720 observed peak bytes; zero retained |
| Package bytes at outer audit completion | 347,184 |

The audit's unchanged **256 MiB** metric is cgroup-v2 memory.peak for the complete
worker/descendant tree, including charged file-cache/kernel memory; swap is zero.
The cumulative time includes 30.539082389 s previously charged and five new
bookkeeping seconds; analysis and isolation time were not borrowed.
The external RSS sample can count shared pages more than once. No execution/proving
cost inference is made. The final bookkeeping has a separate 256 MiB address-space,
CPU/alarm-five-second, two-CPU and 1 MiB-file bound, within the five-second charge.
It checks new outputs, exact names, links and report prefixes, then writes the
[closure](data/s2_bounded_manager_durable_release_1/validation-closure.json) and
[new additive seal](data/s2_bounded_manager_durable_release_1/manifest.json) once; it does
not repeat the protected content scan or regenerate a historical baseline.

Analysis **270.181481168 s** and isolation **250.22 s** remain untouched. Stages
2–3 remain open; DEP-001/002 production obligations, adaptive Delta_tail, side
channels/erasure and complete private-proof knowledge/privacy remain unresolved.
Isolation stays safely stopped/unactivated. No proof/zkVM/activation occurred;
proof ledger two used/one unused. Next recommendation remains the bounded
**S2-DURABLE-ISSUER-MANAGER-INTEGRATION-1**; it is not started.
