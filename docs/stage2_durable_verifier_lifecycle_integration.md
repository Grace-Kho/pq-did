# S2-DURABLE-VERIFIER-LIFECYCLE-INTEGRATION-1

Completed isolated reference lifecycle integration for **two independent verifiers**,
with bounded request/current signing and separate durable stores. All **24 distinct
cases pass** after three individually recorded test-assertion corrections. There
were **27 invocations**, including those failures and repeats; cumulative use is
**172/172**, with none remaining. These are **synthetic proof-acceptance outcomes**,
not evidence of credential authenticity, holder knowledge or private non-revocation.

## Authority, baseline and carried allowances

The [task specification](data/s2_durable_verifier_lifecycle_integration_1/task-specification.md)
amends the implementation ceiling from 148 to 172, without resetting the 145
previously consumed invocations. The starting implementation charge was
**85.60198247910012/300 seconds**, leaving **214.39801752089988 seconds**.
Analysis **270.1814811680233 seconds** and isolation **250.22 seconds**, including
its emergency reserve, are separate and untouched. New measured command time and
five seconds for bookkeeping are charged to the implementation allowance.

[Preflight](data/s2_durable_verifier_lifecycle_integration_1/preflight-evidence.json)
verified all 59 inputs of the preceding additive seal,
`5894e21ed0f815cb4f393fb21b266ec7fa1253f1fe523fa0d61c537ee1db3954`, and the
53 assessed source inputs. The unchanged manuscript SHA-256 is
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
Only Sections **II–VIII**, SPEC-001–004 and the agreed contracts are authoritative.
Relevant obligations are R-016/R-017/R-027/R-028 in the
[current specification](implementation_spec.md): IV-A/B, V-C, VII-A.7 and VIII-E.
The existing [verifier model](stage2_verifier_state.md),
[durable authority contract](stage2_durable_authority_pilot.md),
[bounded adapters](stage2_bounded_signer_release_contract.md) and
[durable manager](stage2_bounded_manager_durable_release.md) are reused.

Sealed host-closure evidence still records isolation safely stopped and unactivated,
100 historical invocations and 22 actual-identity cases pending. No pilot resources,
permissions, credentials or services were activated or changed. The two-used,
one-unused proof ledger and paused CPU proving are preserved.

## Configuration and integrated sequence

The new [integration module](../src/pqdid/durable_verification.py) exposes only
`BoundedDurableVerifier.create_challenge/verify/snapshot` and the public
`ManagerVerificationProvider` interface. Existing lifecycle, storage, signing,
canonical codecs, public policy and recovery implementations are unchanged.

| Configuration | Verifier A | Verifier B |
| --- | --- | --- |
| Audience | `audience-A` | `audience-B` |
| Service/authority identity | synthetic `A` repeated 32 bytes | synthetic `B` repeated 32 bytes |
| Request signing identity | independent synthetic public key, role VERIFIER, reference A | independent synthetic public key, role VERIFIER, reference B |
| Store | isolated `verifier0/authority.sqlite3` | isolated `verifier1/authority.sqlite3` |
| Challenges | own persistent nonce namespace and tombstones | own persistent nonce namespace and tombstones |
| Trusted dependencies | pinned pp, clock, current provider, policy, nonce source, exact expected head/writer | independently configured equivalent dependencies |

The shared manager has its own database, identity, head/generation and bounded key.
Equal nonce bytes in A and B are permitted: audiences/stores differ. Replicas of
**one** audience must share its atomic authority store. Synthetic seeds 11–14 and
counter nonces are confined to test fixtures; keys are not written to evidence or
installed. The normal nonce-source contract remains fresh uniform randomness.

| Step | Ownership and checks | Transaction/release boundary |
| --- | --- | --- |
| Explicit admission | Verifier store binds role, service/authority IDs, pp, audience, request public key, expected head and writer generation; configured signing key binds role/service/instance/public identity | No automatic expectation refresh from a self-consistent database |
| Request current read | Provider pins the whole instance; sends only a fresh nonce through the admitted manager | Bounded manager `read_current` commits the exact signed reply and head, then existing public retrieval fences and refuses superseded replies |
| Authenticate reply | Existing verifier checks nonce, `PQ-DID/current/v1` signature and independent `StateAuth` | Malformed, unavailable or unauthenticated reply prevents request/acceptance |
| Register challenge | Existing canonical ctx binds suite, audience, invoking session, 32-byte nonce, public policy, issuer instance, state reference and strict expiry; complete signed state and disclosed-DID flag retained | Durable `REGISTERED` checkpoint/outcome/head precedes request signing; nonce collision resampling retains the existing cap |
| Sign request | Trusted `RequestSigningAdapter` reconstructs canonical `E(ctx)`, fixed `PQ-DID/request/v1`; owner admission rechecked before/after bounded signing | Only verified signature is returned. Failed signing retains the unused pending nonce reservation; no retry/resign/redelivery endpoint added |
| Presentation admission | Match supplied context against the stored context and invoking session; strict initial expiry; trusted instance; canonical D/mD, PubOK and public policy | Rejection leaves the verifier challenge pending |
| Proof boundary | Reconstruct X from stored pp/ctx/state and supplied canonical disclosures; opaque proof passed to configured verifier | Missing normal backend returns UNSUPPORTED; a synthetic positive verdict is test evidence only |
| Optional DID check | Existing model permits only disclosed certified DID **and** version, resolved at the specified state | No hidden-holder-DID lookup and no persistent holder authentication key |
| Final current read | Authenticate a new nonce-bound manager read and compare its full reference with the stored challenge | Mismatch rejects; it never substitutes a new root into the existing X |
| Atomic consumption | Existing `BEGIN IMMEDIATE` transaction rechecks principal/generation, expected head, full challenge/state/flag, session/audience and strict expiry | Checkpoint tombstone, unique consume outcome and new head commit together. **SQLite COMMIT is the acceptance point**, preceding ACCEPTED return |
| Restart/replay | Explicit independently retained head and writer permit required; consumed flag survives | Ordinary replay returns UNKNOWN, not another acceptance. Exact concurrent consume-operation replay returns CONSUMED |

Manager reply retrieval uses a bounded local nonblocking SEQPACKET pair, the
unchanged 65,536-byte local codec ceiling and explicit truncation checks. Both
ends close on success/failure. Local operation identifiers domain-separate consumer
service and nonce; they do not change the protocol message/signature format. The
verifier never receives the manager's private checkpoint and sends no holder rid.
These are in-process reference interfaces, not a deployed authenticated transport.

Request signing uses the existing bounded core and verification-before-return;
all attempt/sampler caps and failure propagation are preserved. Authority inputs,
proof dependency, clock and nonce source are trusted configuration, not a sandbox
against arbitrary mutation of Python private attributes. Ordinary request arguments
cannot select a role, key, context, proof implementation or alternate instance.

## Freshness and acceptance interpretation

R-017 defines the verification epoch by the **final ordered current-state read**.
The provider obtains a committed reply and retrieves it only while its state remains
current. An update before that final read is reflected and rejects a challenge
bound to the previous reference. An update after successful ordered retrieval may
commit before verifier consumption without retrospectively invalidating the read.
The test explicitly places a revocation there and observes the prescribed acceptance.
It does not establish that the credential is unrevoked at the later verifier COMMIT.

The verifier's final expiry sample remains strict `now < texp`, under its local
transaction. Clock reaching 100 for `texp=100` after the read rejects without
consumption. There is **no globally atomic manager/verifier transaction** and no
invented freshness window. Signature authentication alone cannot prove latest-state
honesty; the configured service ordering/trust and nonce assumptions still apply.

## Proof, recovery and release boundaries

Positive fixtures explicitly inject the existing test-only `ControlledProofAdapter`
from the verifier test harness. Its allow-set is exact canonical public X plus an
opaque synthetic token. The new implementation does not import that class or expose
a configuration selector for it. The default `Dependencies.proof_verifier=None`
remains `UnsupportedProofVerifier`; this is tested through a reopened durable owner.
The two-instance tests use public disclosure fields from preserved synthetic relation
fixtures under fresh test keys/states. They do not certify those credentials under
the fresh keys or evaluate the private authentication relation. **No new local
relation evaluation or remote proof verification was performed.** Earlier local
revoked/surviving-relation evidence remains separate and is not reclassified here.

Before consumption COMMIT, injected storage failure rolls back rows and leaves the
original pending challenge and expected head intact. After COMMIT but before the
acknowledgement, an injected exception returns FAILURE while consumption remains
committed. That failure means no acknowledgement was delivered, not that no
acceptance occurred. The old expected head then fails admission. Recovery with the
explicit retained committed head preserves the tombstone and replay returns UNKNOWN.
The test captures the committed head at a private test hook; it does not establish a
production rollback-resistant freshness service or recover a lost independent head.

The existing generic `SQLiteStore.publish` permits only issuer CERTIFIED results.
A verifier CONSUMED outcome is **not releasable**, even to an otherwise authorised
recipient: this refusal and absence of queued bytes are tested. No acceptance
redelivery endpoint was invented. Retained outcome metadata is not a new acceptance
or application business action. Exactly-once KYC downstream side effects remain a
separate application contract; loss of an acceptance response is not solved by
replaying the challenge.

## Individual validation and preserved corrections

[Tests](../tests/integration/test_durable_verification.py) use
[isolated fixtures](../tests/integration/durable_verification_cases.py). Both verifier
stores and the manager store are temporary; each directory is 0700 and each SQLite
file follows the existing 0600 storage contract. No protected project file is altered
for negative tests. An individual parameter value counts as one invocation.

| # | Case | Final result and durable observation |
| --- | --- | --- |
| 1 | Verifier A success | PASS; signature checked, consumed `[1,0]`; no hidden-DID resolver call |
| 2 | Verifier B success | PASS; independent request key/nonce namespace, consumed `[0,1]` |
| 3 | A context at B | PASS; MISMATCH, both pending |
| 4 | A synthetic presentation reused at B | PASS; PROOF under B's exact X/token allow-set, both pending |
| 5 | Invoking/stored session mismatch | PASS; MISMATCH, both pending |
| 6 | Canonical policy mismatch | PASS; MISMATCH, both pending |
| 7 | Altered issuer-instance reference | PASS after assertion correction; PUBLIC at exact-instance encoding admission, both pending |
| 8 | Initial `now=texp` | PASS; EXPIRED, both pending |
| 9 | `now=texp` after final read | PASS; final transaction returns EXPIRED, both pending |
| 10 | Noncanonical disclosed attributes | PASS; PUBLIC, both pending |
| 11 | Normal missing proof backend | PASS; UNSUPPORTED after reopening owner, both pending |
| 12 | Explicit invalid proof verdict | PASS; PROOF, both pending |
| 13 | Unauthenticated current reply | PASS; STATE, both pending |
| 14 | Valid current signature over invalid state signature | PASS; independent StateAuth rejects, both pending |
| 15 | Revocation ordered before final read | PASS; STATE for stale reference, epoch advances but both challenges pending |
| 16 | Revocation after final read, before consumption | PASS; ACCEPTED under read-point semantics, epoch 1 and consumed `[1,0]`; no private-NR claim |
| 17 | Restart, replay and independent B | PASS; A replay UNKNOWN, B independently accepts, consumed `[1,1]` |
| 18 | Concurrent same challenge, two admitted facades | PASS after assertion correction; exactly one ACCEPTED and one CONSUMED; one tombstone |
| 19 | Rows before consumption COMMIT exception | PASS; FAILURE, rollback leaves pending head; restart preserves pending |
| 20 | Consumption COMMIT before ack exception | PASS; FAILURE with committed tombstone; stale head refuses; retained-head restart gives UNKNOWN; outcome publication refused |
| 21 | Writer replacement during proof callback | PASS; FAILURE, generation 2, no consumption |
| 22 | Inconsistent head/audience recovery | PASS after assertion correction; stale/inconsistent ticket or service-binding refusal; original stores unchanged |
| 23 | Request-signing entropy failure | PASS; no request returned; new registration remains pending, nonce not recycled |
| 24 | Stale manager writer | PASS; FAILURE, both verifier challenges pending |

The concurrency barrier places both submissions after their initial pending checks;
only test-side ordered manager reads are serialised. Both use the same durable
verifier store and original ticket; exact operation replay returns CONSUMED to the
loser. Two threads finish and no background worker remains.

Three retained failures concern assertions about **existing rejection labels**,
not weakened checks or changed production behaviour:

1. [Correction 1](data/s2_durable_verifier_lifecycle_integration_1/correction1.json):
   issuer-reference mismatch fails canonical instance admission with PUBLIC, before
   stored-context MISMATCH. Six passed, one failed, five not invoked.
2. [Correction 2](data/s2_durable_verifier_lifecycle_integration_1/correction2.json):
   exact concurrent operation replay returns CONSUMED, not generic FAILURE.
   Five passed, one failed, six not invoked.
3. [Correction 3](data/s2_durable_verifier_lifecycle_integration_1/correction3.json):
   altered trusted audience changes the ServiceKey and rejects at service-binding,
   before checkpoint-admission. Four passed, one failed, two not invoked.

Each correction retains original test source, guard/configuration versions, hashes,
JUnit/log/state evidence and stop marker. Only the failed case is repeated; uninvoked
cases run subsequently. No previously passing case is repeated. No implementation
source change was needed for these corrections. A separate retained
[lint correction](data/s2_durable_verifier_lifecycle_integration_1/correction4.json)
splits one 102-character report-generator line; its rerun invokes no functional tests. No automatic retries or relaxed
resource/validation limits were used.

| Guarded test command | Invocations | Pass/fail | Guarded wall seconds |
| --- | --- | --- | --- |
| `focused` | 7 | 6 / 1 | 4.920395287 |
| `focused-remainder` | 6 | 6 / 0 | 4.395957400 |
| `boundaries` | 6 | 5 / 1 | 6.480458323 |
| `boundaries-remainder` | 5 | 4 / 1 | 4.494901894 |
| `final-boundaries` | 3 | 3 / 0 | 2.497331402 |
| Total | **27** | **24 pass / 3 retained assertion failures** | **22.789044306** |

The five XML files and `case-evidence-*.json` records in the
[evidence directory](data/s2_durable_verifier_lifecycle_integration_1/) record every
individual outcome, resulting heads, generations, pending/consumed counts and
manager epoch. The final unique-case union contains 24 successes; the three earlier
failures remain counted. The [configuration](data/s2_durable_verifier_lifecycle_integration_1/config.json)
records released reservations for tests not invoked after `-x` stops, reconciled
against the actual JUnit entries, not a reset of historical counts.

New persistence-boundary tests use **injected exceptions**, not SIGKILL. The original
[verifier pre/post-consume crash tests](../tests/integration/test_durable_authority.py)
and their completed [pilot evidence](stage2_durable_authority_pilot.md) already cover
this unchanged SQLite consumption transaction across A/B restarts; they were reused,
not rerun. Neither these tests nor that evidence establishes power-loss durability,
storage-device failure tolerance or coordinated whole-store rollback resistance.

## Resources, preservation and disposition

The [run ledger](data/s2_durable_verifier_lifecycle_integration_1/run-ledger.json)
records expanded commands, returned status and guard measurements. The command is:

```sh
.venv/bin/python -I -B docs/data/s2_durable_verifier_lifecycle_integration_1/run_checks.py NAME
```

Recorded names are `preflight`, `imports`, `source-format`, the five test commands
above, `final-source-format`, `quality`, `quality-final`, `format`, `prepare`, `full-audit`, followed
by bounded write-once `close.py`. The final three tests exhaust the case budget;
lint/format/preservation do not launch additional functional tests.

Unchanged limits: one worker, two CPUs, four controlled processes; 256 MiB cgroup-v2
memory for the complete worker/descendant tree including charged cache/kernel,
swap zero, separate aggregate RSS stop; 60-second command / 55-second child,
8 MiB temporary data, cumulative 10 MiB package output, 1 MiB per file, 60 KiB
command diagnostics, 9 GiB experiment-storage stop and 2 GiB memory headroom.
Prior cumulative output charge **1,488,267 bytes** is retained. Admission reserves
ten seconds for cleanup/evidence beyond the next command reservation. Guarded
private-network validation jobs do not activate live authority services.

Only the new integration module, its two test/helper files, this report and package
evidence are added. Status/traceability/issues are append-only. Original source,
vectors, active parameters, dependencies, manuscript, historical failures, isolation
approvals and proof results remain unchanged. The corrected preservation auditor
retains original scope/digest/inventory semantics, streams content under its unchanged
256 MiB guard, and requires complete report generation plus outer-guard success.
The final measured closure below records the single complete audit and remaining time.

Stages **2–3 remain open**. Outstanding obligations include real enrolment/authentication
proof verification; production signing custody, entropy assurance, reliable erasure,
side-channel/fault resistance; DEP-001 adaptive Delta_tail; component advantages at
reduction budgets; SEC-001–005 and OC-REL/EXT/PRIV/BUDGET; complete proof knowledge/privacy;
independent rollback-resistant recovery freshness; durable holder state; deployed
transport and pending actual-ID isolation; downstream KYC action/acknowledgement policy.
No deployment, dependency installation, estimator campaign, proof or zkVM run occurred.

One bounded next recommendation is **S2-HOLDER-WITNESS-REVOCATION-INTEGRATION-1**:
connect issued holder checkpoints to authenticated public manager updates and local
atomic witness replacement, then check surviving/revoked KYC credential behaviour
against fresh independent-verifier challenges. Keep real local relation evaluation
separate from synthetic remote-proof verdicts. This advances the remaining KYC path
from issuance through revocation/witness maintenance to presentation, rather than
adding general infrastructure. Plan its focused cases and obtain an explicit test
allowance amendment first: **zero invocations remain**. It is not started.


## Measured validation closure

The single
[complete preservation audit](data/s2_durable_verifier_lifecycle_integration_1/result.json)
passed content/inventory comparison, report generation/readback and its unchanged
256 MiB cgroup guard, exit **0**. Coverage is 8,759
original and 1,106 supplementary
paths: **9,865 disjoint content paths** and
9,884 identity-inclusive paths. No unexpected
addition, removal or content change occurred; all three prior report prefixes remain
intact. Original code, vectors, parameters, dependencies, manuscript and historical
results are preserved. Required lint and formatting pass.

| Measurement | Result |
| --- | --- |
| Audit wall time | 2.406519050 s |
| Audit cgroup memory.peak | 23,465,984 bytes |
| Audit sampled aggregate tree RSS | 41,295,872 bytes |
| Maximum guarded-job cgroup memory.peak | 70,217,728 bytes, below 268,435,456 |
| Maximum sampled aggregate tree RSS | 81,997,824 bytes; separate metric |
| Guarded commands | 14, 26.057493165 s, including failed tests |
| New package charge | 31.057493165 s |
| Cumulative implementation charge | **116.659475644/300 s** |
| Remaining implementation time | **183.340524356 s** |
| Test invocations | **145 + 27 = 172/172; zero remain** |
| Final distinct-case outcomes | 24 pass; three earlier assertion failures/repeats retained |
| Resource breaches | Zero |
| Temporary storage | 295,512 observed peak bytes, zero retained |
| Package bytes at outer audit completion | 597,551 |

Cgroup-v2 memory.peak covers worker and descendants, charged anonymous/cache/kernel
memory; swap remains zero. The external RSS monitor is separate and can double-count
shared pages. Final bounded bookkeeping adds no content rescan: 256 MiB address-space,
five-second CPU/alarm, two CPUs, 1 MiB file cap, included in the five-second charge.
It checks names, links and prefixes, then writes the
[closure](data/s2_durable_verifier_lifecycle_integration_1/validation-closure.json) and
[additive seal](data/s2_durable_verifier_lifecycle_integration_1/manifest.json) once.
Historical baselines are not regenerated. Cumulative output accounting also retains
1,488,267 bytes from prior packages.

Analysis **270.181481168 s** and isolation **250.22 s** remain untouched. Stages
2–3 stay open. No deployment, installation, proofs or zkVM executions; isolation
safely stopped/unactivated; proof ledger two used/one unused. The next recommendation
is **S2-HOLDER-WITNESS-REVOCATION-INTEGRATION-1**, not started and requiring an explicit
new test allowance before execution. Production-security and complete proof
knowledge/privacy obligations remain open.
