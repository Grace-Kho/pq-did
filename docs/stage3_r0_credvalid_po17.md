# R0-CREDVALID-PO17-1 — CredValid partition and final-attempt admission

19 September 2026, Asia/Singapore; machine timestamps are UTC. **The single
CredValid execution completed and accepted with the exact expected journal. Its
actual partition is 182 segments: 181 at po2 17 and one at po2 15, down from 582.**
The workload forecast exceeds the 600-second proof deadline by a wide margin.
**No proof was launched. Two cumulative attempts are used; one remains. This
package is closed.**

## Preserved baseline and authority

AGENTS, the [enrolment po2-17 report](stage3_r0_enrol_po17.md),
[preceding proof report](stage3_r0_succinct_proof_1.md),
[EXEC24 report](stage3_r0_credvalid_exec24.md), their experimental configurations,
[profile proposal](stage3_profile_change_proposal.md) and
[provisional benchmark targets](benchmark_targets.md) were reviewed. Only manuscript
Sections II–VIII are authoritative. The selected PDF retains SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The manuscript, active suite, reference implementation, SPEC-001–004, dependencies,
original vectors and historical evidence/STOP markers are preserved.

The starting **enrolment** evidence is one independently verified real Succinct
receipt, eight successful tamper rejections, segment count 10 to 3, guarded pipeline
**343.898929933 seconds**, kernel aggregate peak **1535385600 bytes (1.430 GiB)**,
and **238485 serialised receipt bytes**. Its SDK combined call was 343.792883226
seconds. Attempt 1 timed out during its sixth lift; that 600-second stop is not a
completed baseline. Attempt 2 succeeded for enrolment. None of these enrolment
proof measurements is a CredValid measurement.

The [new baseline record](../experiments/r0_credvalid_po17_1/evidence/baseline.json)
references both immutable prior manifests by digest and records the corrected
source bundle, fixture and original validation. Six native tests and all 35
reference comparisons are reused after checking unchanged code and input digests.
No guest optimisation, rebuild, crypto change, installation or download occurred.

| CredValid identity | Retained value |
|---|---|
| Source inventory revision (SHA-256, not a Git commit) | `fd5e917d158f2bf74e0825b0e5415f910e466d8cd8acd95ee5e4257da6144084` |
| Source bundle | `experiments/r0_credvalid_cycle_1/snapshots/builds/corrected-plain` |
| Guest ML-DSA source SHA-256 | `7d066f5d0eff97e363b8c8fbdd7bb31b0f85681cca32c9359dedacc6499a2731` |
| Uninstrumented release user ELF SHA-256 | `d5ef3682a8956ba03b710cdee14f02dbf967ec05e935c3d73fcc582aac19aaf2` |
| Combined user/kernel programme SHA-256 | `668dd886b66772593aea42e53d967d61f2e1a8c1e750add482acc0ed09963a09` |
| Guest image ID | `a7b77747d5ebff0e520d17fc188afef06dfb91690062cb96f6b3cff78e93ae94` |
| Fixture | Original synthetic `cred-alpha-42` |
| Public / private fixture SHA-256 | `63e0cbdedab8ba7a9e56ee7e3295cf6f1fbc2b31be1e35dcfd84db9554679231` / `8d670ab5ae1339ba162a0b124d4657a67043d567eb1d3bf5bafe7a7f8f4b8ead` |
| Expected journal | 5147 bytes; SHA-256 `f9fa7cce56b47699ff3ec198b2a2b1e2aa46b36f5a5f9d4d9839f4622d8579c2` |
| SDK / actual r0vm SHA-256 | 3.0.6 / `751b9b188d341e8bec5e02060086b7b1dc3f7289e90f726c38589bb6735dd6d7` |
| SDK release commit | `1cc70cf05033a79ebc90f07c679cb4bd1cd301b9` |
| Host Cargo.lock SHA-256 | `f75302dce44982f4b14a93a32533c2bfd5884743ec457d7f452a76a2855cb117` |

Guest compiler remains custom rustc 1.97.0-dev
`e638c6cfea1eff5fbbb24a27e60538e3760d21b8`, LLVM 22.1.6, cargo 1.97.0-dev
`c980f4866`. Original target `riscv32im-risc0-zkvm-elf`, optimisation 3, thin LTO,
one codegen unit, overflow checks, panic abort, no diagnostic features. Frozen flags:

```text
-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"
```

Only the isolated host was rebuilt offline with the same release profile and
compiler; debug assertions are disabled. The unchanged prebuilt prover's ELF comment
instead records rustc 1.97.1 `8bab26f4f`, GCC 9.4.0 and LLD 22.1.6. Its exact vendor
optimisation/LTO flags are not attested and are not inferred from host flags. The
same embedded recursion archive retains SHA-256
`744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849`.
No guest/prover recompilation or archive replacement was used.

## Execution configuration and enforcement

The actual input builder uses **`segment_limit_po2(17)`**, matching enrolment's
validated segmentation, and retains **`session_limit(Some(1 << 24))`**. This cap
counts SDK `Executor.cycles.user`, including instructions charged through VM/kernel
hooks. It is not a cap on padded proving capacity or host OS user time. The pinned
executor compares that user counter with the cap; its meaning is unchanged from
EXEC24. The distinction matters because padded capacity exceeds 2^24 here.

`ProverOpts::succinct().with_dev_mode(false)` still has maximum segment po2 **22**,
poseidon2 and the existing allowed controls. This option is separate from actual
executor segmentation. Verifier-parameter digest remains
`ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013`; control root
`a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56`.
Both actual lift sizes 15 and 17 belong to the unchanged allowed set. The po2-17
lift ID is `c9b08054994f542a6310b00d9b6fc6528ed7bb6f4ca5476a686847127cdfdc5b`;
the po2-15 ID is `1ca3ca03030719064ba61b3125bdd326fc57f74e799ef860bdea6f3227381e16`.
The existing archive supplies both. Registry/image/parameter checks passed.

The [configuration](../experiments/r0_credvalid_po17_1/config.json),
[contract](../experiments/r0_credvalid_po17_1/CONTRACT.md),
[preflight](../experiments/r0_credvalid_po17_1/evidence/preflight.result.json) and
[pre-execution manifest](../experiments/r0_credvalid_po17_1/evidence/manifest-before-launch.json)
fix the following envelope before execution:

- Exactly one execution-only run, **60 seconds**, 2^24 user cycles; no retry.
- One worker, two Rayon/OMP threads, CPU quota 200%, 128 tasks, **2 GiB aggregate
  descendant cgroup memory**, zero swap. Local CPU only; private network namespace,
  no external routes, GPU, fake/development mode, remote proving or Groth16.
- Existing preparation/build aggregate 1200 seconds; execution aggregate 300 seconds;
  execution/proving aggregate 1800 seconds; conditional complete proof deadline
  600 seconds. Checks retain 256 MiB/60 seconds and 300 seconds aggregate with
  verification. Fresh verification retains 1 GiB/10 seconds and tampering 60 seconds.
- Total experimental storage 10 GiB, conservative stop 9 GiB; output 256 MiB/240 MiB
  stop; diagnostics 64 MiB/60 MiB stop; each retained stream at most 64 KiB. Receipt
  admission remains 10 MiB, complete presentation 12 MiB. No limit was raised.

WSL MemAvailable immediately before execution admission was **4891160576 bytes**,
above the full 2 GiB allowance plus 2 GiB reserve. Preflight found about 1.014 TB
free in WSL and 398.35 GB on the Windows volume. Effective cgroup memory/swap/CPU/task
limits were checked before the target. Prior experiments were read-only in services.
The namespace probe confirmed local IPC, no external connectivity and inaccessible
private inputs/traces in the fresh-verifier namespace; this probe verifies isolation,
not a receipt. The sampled experimental disk peak during execution was 7618551880
bytes, below the conservative stop. All existing resource ceilings were respected.

## Actual execution result

The single execution returned **`Halted(0)`, accepted, exact expected public journal**.
Segment counts and sizes came from SDK callbacks, not division of user cycles by
2^17. The first-256-record diagnostic ceiling is unchanged; all 182 actual segments
fit. Aggregate counters would retain later segment counts without retaining more
individual records. Private callback assets were discarded.

| Measurement | Previous EXEC24, po2 16 | This run, po2 17 |
|---|---:|---:|
| SDK user cycles | 16313474 | **16313474** |
| Actual segments | 582 | **182** |
| Actual size distribution | 581 × po2 16 + 1 × po2 15 | **181 × po2 17 + 1 × po2 15** |
| Padded segment capacity | 38109184 | **23756800** |
| Capacity minus user cycles | 21795710 | **7443326** |
| Execution API seconds | 0.577716649 | **0.302627684** |
| Guarded service seconds | 0.649665937 | **0.392469114** |
| Kernel process-tree peak bytes | 48459776 | **48640000** |
| Sampled summed process-tree RSS bytes | 68956160 | **71516160** |
| Sampled temporary storage peak / bytes at exit | 0 / 0 | **0 / 0** |
| Swap / memory-limit / OOM events | 0 / 0 / 0 | **0 / 0 / 0** |
| Expected versus actual journal | Exact 5147 bytes | **Exact 5147 bytes, same SHA-256** |

The final po2-15 segment has 2511 user cycles. User-cap headroom remains **463742
cycles (2.7641%)**. Segment count fell by 400 (68.7285%); padded capacity fell by
14352384 (37.6612%). These are partition/capacity changes, not complete-proof speedup.
Separate system/paging/reserved counters are **not exposed by execute IPC**. The
7443326 residual combines paging/reservations/padding; it is not a paging-only
measurement. Recursion work is additional to the reported padded VM capacity.

Both EXEC24 and this API timer start after subprocess-client creation, but host
input/diagnostic bookkeeping differs and OS cache/load is uncontrolled. The guarded
wall includes service overhead. These are single observations, not a stable latency
ratio. Sampled RSS can miss peaks and double-count shared pages; kernel memory is
charged cgroup memory, including cache. Neither measures proving memory. The
[partition record](../experiments/r0_credvalid_po17_1/evidence/execution.result.json),
[resource record](../experiments/r0_credvalid_po17_1/evidence/execution.json) and
[public journal](../experiments/r0_credvalid_po17_1/evidence/execution.public-journal.bin)
retain the exact result. **This journal is execution output, not a cryptographic
receipt.** No new negative execution was authorised or performed.

## Measured enrolment phase inputs

The complete 54123-byte enrolment log has no omitted middle. The
[timing inputs](../experiments/r0_credvalid_po17_1/evidence/cost-model-inputs.json)
record its SHA-256, source line numbers, UTC boundaries and pinned SDK source hashes.
Intervals below use those UTC boundaries; tiny differences from the prior report's
monotonic capture intervals reflect clock/capture boundaries, not another run.

| Repeated component | Observed seconds in execution order | Scope |
|---|---|---|
| po2-17 base preflight | 0.033347, 0.015590, 0.023720 | Preflight log to core-start log |
| po2-17 core through next boundary | 40.711678, 41.307898, 41.550666 | Core proving plus verification/I/O/bookkeeping; last includes Composite verification |
| Combined base blocks | **40.745025, 41.323488, 41.574386** | Preflight to next preflight, or first lift for final segment |
| po2-17 lifts | **43.463084, 44.315287, 43.195444** | Lift start to lift-finished log |
| Ordinary joins | **44.343086, 44.737210** | Join start to join-finished log |
| Between recursion operations | 0.010334, 0.010614, 0.011175, 0.010801 | Integrity checks and other handoff work |

Observed base block total is **123.642899 seconds**, recursion block total
**220.097035 seconds**. The guarded total is 343.898929933 seconds. The remaining
**0.158995933 seconds** jointly covers work outside those blocks, including startup,
loading/initial execution, final return, host checks, serialisation and teardown.
Those parts cannot be individually separated from these logs. Host self-verification
is separately measured at **0.011631573 seconds** within the pipeline; independent
fresh verification was **0.011627595 seconds** outside it. Do not add self-verification
a second time to that residual, or invent a pure final-construction timer.

The SDK log for execution completion is a boundary, not a timer for pure guest
execution or initialisation. Recursion artefact loading/preprocessing can occur
inside each lift/join call and is already included there. No additional recursion
operation appeared in the successful enrolment log. Preparation/build is a separate
one-time project cost, outside per-proof generation.

## Workload forecast and conditional admission

Pinned `server/prove/prover_impl.rs` performs preflight, proving and integrity
verification for each segment, retains their receipts, and verifies the Composite.
`server/prove/mod.rs::composite_to_succinct` folds them sequentially: first lift,
then a lift and join for each remaining segment. With this unchanged software-hash
guest there are no receipt assumptions, Keccak coprocessor requests or PoVW jobs.
Succinct does not invoke Groth16 or an extra identity compression step.

Thus CredValid requires **182 base segment proofs, 182 lifts and 181 ordinary joins**:
181 base/lift pairs are po2 17, and the final pair is po2 15. The allowed control set
supports both. The successful enrolment log measures po2 17 and ordinary join types;
**it does not measure the po2-15 lift**. For an illustrative conservative engineering
forecast, the final smaller segment uses the po2-17 rate as an explicit proxy, not
an established upper bound. This uncertainty could not authorise a close admission.

Use the maximum observed combined po2-17 base block, **41.574386 s**. Use separate
maximum lift and join observations, adding the maximum **0.011175 s** handoff to
each operation: lift **44.326462 s**, join **44.748385 s**. Handoff is allowed even
for the terminal operation. Do not count preflight twice or assume lifts and joins
have identical costs. Add the measured execution time as a proxy and an explicitly
assumed **10 s** combined initialisation/finalisation envelope; then add **50% of
the entire subtotal** for engineering uncertainty, host load/cache variability,
longer workloads and incompletely isolated bookkeeping.

| Estimated component, before uncertainty | Seconds |
|---|---:|
| 182 base blocks | 7566.538252 |
| 182 lifts | 8067.416084 |
| 181 joins | 8099.457685 |
| Measured execution used as proxy | 0.302628 |
| Assumed initialisation/finalisation allowance | 10.000000 |
| Subtotal | **23743.714649** |
| Explicit 50% uncertainty allowance | **11871.857324** |
| Conservative engineering scenario | **35615.571973 s ≈ 9.89 hours** |

This is an extrapolation, **not measured complete CredValid proving time**, a
statistical confidence bound or a guaranteed worst case. Even removing the unmatched
po2-15 base/lift entirely, using the *minimum* observed lift and join times, ignoring
all base proving and overhead, the 181 measured-type lifts plus 181 joins alone
project **15844.473930 s (4.40 hours)**. That sensitivity scenario is not a rigorous
lower bound, but shows why uncertainty about the terminal pair or a small one-time
cost cannot plausibly make the unchanged two-thread pipeline fit 600 seconds.
No whole-enrolment/user-cycle ratio, timeout-as-completed baseline or calibration
proof was used.

### Memory assessment

Memory was assessed separately from time. SDK `ExecutorImpl::run` defaults to a
temporary directory and `FileSegmentRef` for every segment. The Session retains
those files until the pipeline returns; **182 segment files**, references and
charged filesystem cache replace the enrolment workload's three. Exact CredValid
file sizes were not measured by this execution path, which discards callback assets.
On resolution, file bytes and the deserialised segment can temporarily coexist.

Base proving is sequential, but a decoded segment, preflight/witness/polynomial
buffers, host/executor state, allocator caches and the growing retained collection
of segment receipts coexist. During recursion the complete Composite and Session
references remain live. The accumulated left Succinct receipt and newly lifted
right receipt coexist with join input/output and working buffers. Recursion witness
generation allocates control, data, accumulation and global arrays together; their
sizes depend on the recursion programme, not only the VM segment exponent.

The enrolment **1.430 GiB** peak is therefore **not an upper bound**. No known
unsupported segment/circuit configuration was found, but the per-segment retained
bytes and concurrent CredValid proving working set have no measured aggregate
bound below 2 GiB. Execution's 48.64 MB kernel peak cannot fill that gap. Memory
admission remains unresolved; the time forecast independently excludes launch.

### Decision and application feasibility

[Admission record](../experiments/r0_credvalid_po17_1/evidence/admission.result.json):
execution, exact journal, supported sizes and registered parameters pass. The
conservative forecast fails the **600-second whole-pipeline deadline**, terminal
po2-15 timing lacks a matching successful observation, and a 2 GiB proving bound
is unresolved. **Do not spend the final attempt to confirm an expected timeout.**
No proof or receipt was generated, and no new actual-receipt verification/tamper
result exists. The prior enrolment receipt and its eight checks remain historical.

The provisional application proposals are **p95 generation ≤30 s**, verification
≤2 s and end-to-end presentation ≤45 s, with complete authentication/privacy and
network/lifecycle work included. The 600-second engineering cutoff is a different
budget. **The present two-thread CPU configuration is unlikely to meet the intended
KYC latency targets.** Even this credential fragment's projected work is far beyond
them. No percentile or throughput result follows from these few runs; complete
presentation size, authentication memory and end-to-end performance remain unknown.
The earlier 20.26% improvement remains isolated-component execution evidence only.

## Commands, validation and closure

Commands from the project root, with exact effective environments and systemd
properties retained in the [run ledger](../experiments/r0_credvalid_po17_1/evidence/run_ledger.json):

```sh
python3 experiments/r0_credvalid_po17_1/scripts/run_limited.py --seconds 60 --slot 1 execute execution -- target/release/pqdid-r0-host execute
python3 experiments/r0_credvalid_po17_1/scripts/run_limited.py --seconds 60 --memory 268435456 check cost-admission -- /usr/bin/python3 scripts/cost_model.py
```

Host preparation reused the isolated compiled cache and ran the pinned
`cargo build --locked --offline --release -p pqdid-r0-host`. A direct invocation of
the copied, non-executable shell script initially returned EACCES **before the
compiler started**. Its failed service/STOP record is retained as
[preparation evidence](../experiments/r0_credvalid_po17_1/evidence/preparation-correction.json).
The invocation was corrected to `/bin/bash scripts/build_host.sh`; no resource
limit, execution slot or proof attempt was consumed by that launch error. A final
host-only build followed an operation-mutation adaptation correction. Total guarded
preparation/build, including the failed launch, was **193.012037 seconds**; peak
build cgroup memory was **1702682624 bytes**. These costs are outside execution and
outside the proving forecast. No historical STOP marker was removed or changed.

Relevant checks cover frozen source/ELF/fixture/image identity, offline release
settings, actual executor versus prover maximum, both actual control sizes, exact
public framing, all segment counters, cost arithmetic/log provenance, resource
configuration, Python lint/format/syntax, Rust format/build, shell syntax,
JSON/TOML, documentation links and ledger/STOP enforcement. Preservation checks
cover **8583 pre-existing files**, allowing only requested status/traceability edits.
The original six native tests/35 comparisons are reused. Results and final
checks are in the [final audit](../experiments/r0_credvalid_po17_1/evidence/final-audit.result.json)
and [manifest](../experiments/r0_credvalid_po17_1/evidence/manifest.json).

The [cumulative ledger](../experiments/r0_credvalid_po17_1/evidence/cumulative_attempt_ledger.json)
references the previous ledger by SHA-256: **two used, one remaining, zero new
proofs**. The [STOP marker](../experiments/r0_credvalid_po17_1/evidence/STOP.json)
closes this package against further execution/proving. No conditional proof command
was launched and no proof-generation time, proving peak or final receipt size was
measured for CredValid.

**One next recommendation:** undertake a design review of how to reduce the total
proved credential-verification and recursion work, comparing backend/architecture
options against the 30-second generation proposal while preserving the exact
private ML-DSA-65 relation and required security/privacy properties. Retain the final
attempt until that review supplies a credible latency and aggregate-memory case;
any material profile/backend change needs explicit approval. Another automatic
cycle, segment or wall-time budget increase is not recommended.

Complete authentication, selective-disclosure/non-revocation composition, lifecycle
freshness/replay/atomic consumption, complete guest equivalence/BC-1 conformance,
privacy/ZK metadata and unlinkability, quantum-security accounting, Section VIII
extraction/simulation, DEP-001/002 and remaining Stage 2 bounded keygen/signing/
revocation/update/release obligations remain open. The active suite, inactive 64M
proposal and unadopted replacement profile remain unchanged. Stop after this package.
