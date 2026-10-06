# OCT31-KYC-NATIVE-MILESTONE-1 execution

The ML-DSA reference baseline and shared benchmark streams are implemented and
validated. All 276 measured trials completed. The isolated native correction is
implemented and compiled, with 24 cases passing at the prior binary; final native
case admission is blocked by automatic approval review. **The overall milestone is
not complete.** No new private-proof package is started.

## Approved scope and accounting

The approved immutable [plan](data/october_implementation_milestone_1/execution-plan.json)
has SHA-256 `cbb310bee67ed9c237b0e1055b3e68d81652fffd96ccad611dc2f1c6a4fc0b27`;
its proposal manifest is `158539d9c54fd5a33ae49b794b9f9716f620911a61e78bd973536e0aa3a28d8e`.
The separate [approval record](data/oct31_kyc_native_milestone_1/approval.json) preserves
that plan's historical unapproved flag and records its later approval. Thirty-four
sealed inputs and the manuscript identity were checked before implementation.

The active ceiling is 4,274 implementation seconds with 562.1783621237846 seconds
historically consumed; the opening available balance was 3,711.8216378762154.
The 300-second completion reserve is inside that balance. The allocation is 600
new invocations (392 initial/208 corrections), cumulative ceiling 1,050, with two
older tooling slots kept separate. Builds opened at five used of thirteen; eight
new attempts were available. No prior usage was refunded or transferred.

Evidence opened at 16,665,098 B against 32 MiB; the 2 MiB completion reserve is
inside that cap. Historical artifacts opened at 27,839,915 B against the unchanged
128 MiB cap. Ordinary metadata/source files retain 1 MiB admission, registered
artifacts 32 MiB, diagnostics 60 KiB per command, ordinary temporary storage 8 MiB,
and experiment-storage stop 9 GiB. Retired native/provisioning/build microcaps are
recorded as retired admission gates, with their history preserved. Analysis,
isolation and proof allowances are unchanged.

Three agents worked on separate source trees; one coordinator controlled shared
accounting. Guarded execution was serial (below the two-job allowance), one compiler
at a time. Native workers were capped at 1 GiB, Python/tool/audit workers at 256 MiB,
zero swap, two assigned CPUs and TasksMax 128. The named ephemeral user slice also
has a 2 GiB/200% CPU limit. Per-worker cgroup measurements exclude the small external
monitor, whose coordinator has a 256 MiB address-space bound; the serial admission
keeps aggregate workload below 2 GiB. No measurement claims the monitor is inside
the worker's memory.peak. Resources include full worker descendants.

## Delivered results

- [Baseline implementation/report](stage2_mldsa_reference_baseline.md): 48 distinct
  cases passed in 50 invocations, with two retained failures and scoped corrections.
- [Native implementation/report](stage3_aurora_masking_native.md): three counted builds
  (first failed, second/third linked), 24 cases passed on build 2; build 3 revalidation
  and 16 EXP2 cases pending. No unchanged library is presented as newly validated.
- [Benchmark report](kyc_milestone_benchmarks.md): 16 harness cases passed, 11 distinct
  integration cases passed in 12 invocations, 276 trials passed/read back. C09 pending.

Total at this checkpoint: 378 milestone invocations, cumulative 826/1050; 222 milestone
slots and the separate two historical tooling slots remain. Builds are 8/13 used.
All failed compiler, lint and functional outcomes remain in the ledger. Ordinary
fixes did not weaken expected results or cryptographic assumptions. The final
closure record supplies precise time/storage/audit figures after completion work.

The post-measurement output-role correction narrows binary admission to the 22
registered native slots plus four exact compiler-ID/ABI outputs. Renamed unknown
files remain ordinary evidence; database/key/wallet roles are explicit. The earlier
87-byte artifact charge for a fixture receipt is retained conservatively as those
bytes are also correctly charged as evidence. No previous charge is removed.

## Preservation and completion decision

A single complete preservation workflow is being finalised against the original
8,759-file baseline, 2,142 disjoint supplemental comparisons, immutable dependency/
source/manuscript seals, retained repair artifacts and explicit new inventories.
The append-only historical status/traceability/issue prefixes remain protected.
Final inventory, report readback and outer resource result must pass before
preservation is labelled complete; partial comparison is not completion.

The recorded October 18 implementation, October 25 measurement and October 31 closure
checkpoints are met early for B/H. Native closure has an admission risk, not a measured
resource deficit: automatic review twice applied the retired 24-case native cap.
Direct user confirmation of the existing milestone 40-case allocation/correction pool
has been requested. Neither rejected TR command ran. The next action is to resolve
that admission, run the compiled N04-improved matrix,16 TR cases and C09, then close
this same milestone. No new budget increase or research profile is proposed here.

Full private authentication, query/masking/composition, nontrivial R1CS correspondence,
commitment transformation, extraction/privacy, concrete-hash security, adaptive
Delta_tail and production security remain open. Only manuscript II–VIII and agreed
clarifications are authoritative. Production code, active BC-1, dependencies and
parameters are preserved. Stages 2–3/AURORA-BRIDGE-001 stay open; isolation remains
stopped/unactivated, CPU proving paused, proofs two used/one unused. No installations,
service activation, full proofs or zkVM executions took place.

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

## Closed execution checkpoint and remaining work

Final inventory and report readback passed. The 44 recorded worker units and their
named ephemeral slice were stopped/confirmed inactive or not found, and the slice's
runtime override was removed. Complete systemd properties and descendant-cgroup
checks are retained in [resource closure](data/oct31_kyc_native_milestone_1/resource-closure.json);
no isolation or unrelated service was touched. All failed evidence and synthetic
validation stores remain. No worker workload survives this checkpoint.

The milestone charged 381.396519 implementation seconds, leaving
3330.425119 seconds under the cumulative 4,274-second ceiling. This includes
measured guarded jobs/controller cleanup and 50 conservative seconds for local
coordinator/agent bookkeeping; it is not a measurement of conversational elapsed
time. Analysis and isolation balances remain 107.05463749935384 and 250.22 seconds.
Cumulative invocations are 826/1050 (378 new, 222 milestone slots plus two separate
historical tooling slots remaining); builds are 8/13, with five unused attempts.
Final evidence/artifact bytes and seal identity are in the closure record.

The completed preservation checkpoint leaves the overall milestone incomplete:
24 final-binary N reruns, TR-01–TR-16 and C-09 remain pending the admission block.
The next action is to resolve that block and finish those already-scoped validations
against the retained binaries; no further build or new research package is needed
for that action. The 300-second/2 MiB reserves remain within the unused balances.

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
