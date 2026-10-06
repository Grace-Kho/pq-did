# KYC milestone measurements

The implemented harness in [benchmarks/kyc_milestone_1](../benchmarks/kyc_milestone_1/)
completed all 276 scheduled trials with real bounded ML-DSA baseline operations.
No benchmark trial failed, timed out or required a retry. All raw records and
CSV/JSONL hashes passed per-session and pooled readback. The complete private
proof backend is unavailable; proof times and sizes are null with reasons, never zero.

All 276 trials retained: 12 cold-process, 24 warm-up and 240 warm measurements.
Setup/key generation are excluded from operation latency and included in resource accounting.

| Scenario | Warm n | Median (ms) | Nearest-rank p95 (ms) |
| --- | ---: | ---: | ---: |
| ISSUE | 60 | 189.175 | 268.009 |
| PRESENT-A | 60 | 465.898 | 565.499 |
| PRESENT-B | 60 | 468.337 | 572.229 |
| REVOKE-UPDATE | 60 | 534.213 | 620.661 |

These are descriptive local observations, not population percentiles or throughput.
Private authentication/proof timings and sizes are unavailable, never zero.


## Workload and provenance

Three independent fresh processes per scenario each ran one cold-process trial,
two warm-ups and twenty warm observations. Material/key generation and prerequisite
issuance are outside the operation interval but inside setup/resource accounting.
Warm trials reuse that session's fresh synthetic key set and loaded code, with fresh
stores, signatures and outcomes. This is not a single production namespace whose
allocation history is reset. Cold-process means the first operation after required
setup in a fresh process, not a cache-flushed cold-start measurement.

The synthetic clock is epoch 1,800,000,000 plus monotonic elapsed, validUntil is
base+86400, and sessions last 120 seconds. The regenerated fixture digest binds
canonical parameters, substituted attributes, base policy and the explicit validity
transformation; the original immutable alpha-42-old-002c source hash is separate.
DID resolution is off. No context, schema, DID or status service is fetched.

ISSUE measures intent/reservation, holder possession, real issuer signing,
certification, recipient retrieval and holder acceptance. PRESENT-A/B include signed
request creation, holder presentation, real signature/policy/path/current-state
checks and final durable consumption. REVOKE-UPDATE includes actual signed manager
publication, survivor witness advancement and authenticated local rejection of the
revoked holder. The latter is a labelled witness-update rejection, not a proof test.

Operation timestamps exclude report-only final snapshots/hashes. Named stages retain
nesting and are not summed into a second end-to-end measure. Exact byte-observer
re-encoding remains bounded instrumentation inside relevant measured stages.
Attempts per bounded signer are unavailable because the core does not export that
counter. Entropy/sampler/attempt failures are separately covered by synthetic fault
cases, not hidden from measured outcomes.

On this Intel Core i7-14650HX WSL host, jobs were serial with no unrelated agent
workloads. Per-job cgroup peaks include setup and descendants/cache/kernel charges;
RSS fields are process-lifetime high-water marks. No per-trial peak memory or WAN
latency is inferred. Benchmark peak cgroup memory was 69,517,312 bytes, within
256 MiB. Hardware/software/dependency/source identities and affinity are retained
in each raw row, with authoritative post-exit resources in its job record.

Representative actual canonical/local-transport payload sizes: credential 11,012 B;
request 7,554 B; presentation 22,948 B; nonce 32 B; current reply 6,792 B; published
state 3,427 B; revocation update 11,162 B. Canonical and transport values are separate
fields; this local transport carries canonical bytes directly. No network envelope
or W3C credential size is implied.

[Raw sessions and pooled outputs](data/oct31_kyc_native_milestone_1/benchmarks/oct31-reference-01/)
retain all warm-ups, actual counters, timings, outcomes, message sizes, setup costs,
environment and unavailable operations. Successful fresh trial stores were disposed
only through the exact owned-file allowlist after disposition records; failed
validation fixtures remain. No historical store or evidence was deleted. Secret-key
contents and hashes are excluded from exported disposition records.

A post-measurement C11-only classification assertion changed the test-inclusive H
source-tree digest. [The reconstructed measured snapshot](data/oct31_kyc_native_milestone_1/benchmark-source-provenance.json)
matches the independently retained measured tree hash exactly. Historical row hashes
were not rewritten; generic reuse correctly rejects the changed current tree. The
measured runtime modules and baseline semantics did not change.

## Validation and interpretation

| ID | Contract case | Recorded invocations | Result |
| --- | --- | --- | --- |
| H-01 | required-record-schema | M1-0001: pass | passed at recorded inputs |
| H-02 | unknown-record-category | M1-0002: pass | passed at recorded inputs |
| H-03 | negative-or-missing-duration | M1-0003: pass | passed at recorded inputs |
| H-04 | nested-timing-not-double-counted | M1-0004: pass | passed at recorded inputs |
| H-05 | canonical-versus-transport-bytes | M1-0005: pass | passed at recorded inputs |
| H-06 | warmup-excluded-from-statistics-not-ledger | M1-0006: pass | passed at recorded inputs |
| H-07 | failure-denominator-retained | M1-0007: pass | passed at recorded inputs |
| H-08 | timeout-censoring | M1-0008: pass | passed at recorded inputs |
| H-09 | unavailable-proof-null-fields | M1-0009: pass | passed at recorded inputs |
| H-10 | environment-and-input-identities | M1-0010: pass | passed at recorded inputs |
| H-11 | output-run-id-no-overwrite | M1-0011: pass | passed at recorded inputs |
| H-12 | output-chunk-byte-cap | M1-0012: pass | passed at recorded inputs |
| H-13 | measured-versus-synthetic-category | M1-0013: pass | passed at recorded inputs |
| H-14 | nearest-rank-percentile | M1-0014: pass | passed at recorded inputs |
| H-15 | exclusive-measurement-lock | M1-0015: pass | passed at recorded inputs |
| H-16 | counter-reservation-race | M1-0016: pass | passed at recorded inputs |

| ID | Contract case | Recorded invocations | Result |
| --- | --- | --- | --- |
| C-01 | issued-key-bound-to-presentation | M1-0091: pass | passed at recorded inputs |
| C-02 | same-credential-independent-A-B | M1-0092: pass | passed at recorded inputs |
| C-03 | reopen-holder-and-both-verifiers | M1-0093: pass | passed at recorded inputs |
| C-04 | manager-update-between-challenge-and-verify | M1-0094: pass | passed at recorded inputs |
| C-05 | revoke-one-holder-retain-other | M1-0095: pass | passed at recorded inputs |
| C-06 | no-partial-credential-or-acceptance | M1-0096: pass | passed at recorded inputs |
| C-07 | normal-PQ-DID-proof-path-fail-closed | M1-0097: pass | passed at recorded inputs |
| C-08 | no-baseline-signature-as-proof-object | M1-0098: pass | passed at recorded inputs |
| C-09 | native-caller-coverage-export | none | not run; blocked |
| C-10 | changed-input-invalidates-reuse | M1-0099: pass | passed at recorded inputs |
| C-11 | shared-resource-accounting-and-output-roles | M1-0100: pass, M1-0378: pass | passed at recorded inputs |
| C-12 | end-to-end-export-readback-with-proof-unavailable | M1-0101: pass | passed at recorded inputs |

C11's counted rerun confirms explicit registered binary destinations and ordinary
accounting for renamed unregistered files. C09 is pending the blocked final native
matrix, and does not invalidate the independently authorised baseline measurements.
These local descriptive statistics establish neither throughput/SLA nor complete
PQ-DID/PQ-DAA overhead, privacy, W3C conformance or overall post-quantum security.
No RISC Zero forecast or Boolean proof-size projection is changed. Stages 2–3 and
the complete authentication/security obligations remain open.

## Final preservation checkpoint

The complete audit passed with exit status 0: 8,759 original and 2,142 disjoint
supplemental content comparisons (10,901 total; 10,936 identity-inclusive historical
paths), protected immutable inputs and report prefixes, and a 10,625-entry inventory.
There were no unexpected or missing paths. All 841 local documentation links passed.
The worker completed report generation and readback; its outer guard also passed.
Guarded elapsed time was 6.058319 seconds (audit child 4.163477 seconds). Peak
cgroup-v2 memory was 51,773,440 bytes under the unchanged 268,435,456-byte cap,
including charged worker descendants, file cache and kernel memory; swap and memory
events were zero. Independently sampled summed tree RSS peaked at 62,828,544 bytes;
shared mappings can be counted more than once in that separate metric.

The first preparation failed at the auditor's 10,000-entry traversal admission.
Its helper, new-output inventory and failure remain in `corrections/` and `jobs/`.
The correction partitions the same inventory by its 16 disjoint original roots,
retains the 10,000-entry limit per partition and requires full expected-path union
with no overlap. Corrected preparation and final lint/format checks passed. No
historical baseline, expected entry, digest, permitted-content boundary or file
limit was changed. This is preservation completion; it does not clear the native
admission blocker or establish proof security. Final accounting and post-report
inventory/readback are recorded in the [closure](data/oct31_kyc_native_milestone_1/validation-closure.json).

## Confirmed final validation — 29 September 2026

Normal approval review admitted the directly confirmed native checks. All 24
strengthened-final-binary cases, 16 transcript comparisons and C-09 passed once,
with no new build or functional correction. Earlier-binary results and both prior
approval rejections remain historical evidence. The baseline's 48 cases, 16 harness
cases, other 11 integrations and all 276 measurement trials were reused unchanged;
all 12 integration cases are now covered. No benchmark statistics changed.
See [individual final native outcomes](stage3_aurora_masking_native.md#final-binary-validation--29-september-2026).

The cumulative ledger is 867/1,050: 419 milestone invocations, 181 remaining plus
two separate historical tooling slots. Builds remain 8/13. All originally planned
392 distinct cases/trials are covered; the extra 27 invocations retain scoped failed
checks and affected revalidation. Functional scope is complete; final preservation,
readback and resource closure follow in the continuation evidence. This milestone
does not close Stages 2–3 or AURORA-BRIDGE-001 and establishes no private-proof claim.

## Final milestone closure — 29 September 2026

**OCT31-KYC-NATIVE-MILESTONE-1 is complete at its approved reference/component
validation scope.** All originally planned 392 distinct cases/trials are covered,
including all 41 pending final-binary/transcript/C-09 checks. There were no native
failures or new builds in this continuation. Baseline and all 276 benchmark results
were reused unchanged; earlier-binary results, failures and rejected admissions
remain separately preserved.

The continuation's complete preservation audit exited 0: 8,759 original plus
2,142 disjoint supplemental comparisons, 10,936 identity-inclusive historical paths,
complete prior seals/report prefixes and a 10,732-entry inventory with no missing
or unexpected names. Audit worker reporting/readback and outer guard passed.
Elapsed guard time was 4.872552 s (worker 4.203994 s); cgroup memory peak was
46,354,432 B under the unchanged 256 MiB ceiling, with no memory-event breach or
swap. Separately sampled summed process-tree RSS was 63,078,400 B; shared mappings
can be counted repeatedly in that metric. All 1,520 local link checks passed.

The first preparation reported the already-sealed `benchmarks/README.md` outside
its traversal root. Content matched its historical seal. Its helper, snapshots and
failure are retained in `native-finalisation-1/failed-preparation-1`; the correction
traverses `benchmarks` in place of its existing testbed subdirectory and retains all
expected names and hashes. Corrected preparation and affected lint/format passed.
No baseline or expected digest was regenerated, no content permission broadened,
and no functional test was repeated for this tooling correction.

Final report seals, final inventory/readback, exact-unit shutdown and all time and
storage accounting are recorded in the [completed continuation closure](data/oct31_kyc_native_milestone_1/native-finalisation-1/validation-closure.json).
The invocation ledger is 867/1,050 (419 milestone invocations; 181 milestone slots
plus two separate historical tooling slots remain). Builds remain 8/13. Analysis
and isolation allowances are unchanged; completion reserves remain inside unused
implementation/evidence balances.

The next bounded native validation target is a nontrivial public R1CS fixture
through the corrected components before considering private integration; no such
work is started here. Complete Aurora correctness, authentication/private-proof
feasibility, query/masking and commitment-transformation arguments, extraction/privacy,
concrete-hash composition, adaptive Delta_tail and production security remain open.
Stages 2–3/AURORA-BRIDGE-001 remain open; isolation stopped/unactivated and CPU
proving paused. No proof or zkVM execution occurred; proof ledger two used/one unused.
