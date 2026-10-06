# R0-ENROL-PO17-1 — measured enrolment segmentation and conditional proof

19 September 2026, Asia/Singapore; raw timestamps are UTC. This package authorises
one enrolment execution-only check and conditionally one proof pipeline, cumulative
attempt 2 of the original three. CredValid proving remains outside this package. **Enrolment
completed with a real Succinct receipt in 343.792883 seconds, peak cgroup memory
1.429939 GiB, successful independent verification and eight tamper rejections.
Two cumulative attempts are used, one remains, and the package is closed.**

## Frozen comparison and build configuration

AGENTS, the [preceding proof report](stage3_r0_succinct_proof_1.md), its raw phase
logs, manifests, configuration and the relevant pinned SDK source were reviewed.
Only manuscript Sections II–VIII are authoritative. The PDF remains SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The manuscript, active suite, reference code, dependencies, guest sources, vectors
and historical evidence/STOP markers are preserved. No guest or prover was rebuilt.
Unchanged reference validation is reused.

The previous enrolment attempt **timed out**, rather than completing in 600 seconds:
600.128431264 seconds guarded wall, 1521070080-byte (1.416 GiB) kernel memory peak,
no final Succinct receipt. All ten segment proofs, **five lifts and four joins**
completed. The **sixth lift was underway**, starting at 593.684859 seconds, when the
whole-pipeline deadline terminated it. The observed segment phase was 204.630950
seconds, followed by approximately 395.4 seconds of partial recursion/teardown.
There was one used proof attempt and two unused before this package.

| Identity / setting | Retained value |
|---|---|
| Enrolment fixture | `enrol-alpha-42` |
| User ELF SHA-256 | `9fbacd2f38ec5d9177cbf5dbd050261af1bd86a9cd1978407056afbab7f26449` |
| Combined user/kernel programme SHA-256 | `4db93d3c9463e13db2a172923fdbc917558eabea867b3fd3d0124b6b9f54dc1c` |
| Guest image ID | `66e4c8e0c468edaea2bbef55ac470fab92de3c59e8c0f352905b8a741bac160c` |
| Public fixture SHA-256 | `e6e505a433aed207ee2cfbb8e9cb72ab01b426739ed731e7b3e598f71cf939c8` |
| Private fixture SHA-256 | `e2bf2101764d9ed2728649b05512f6c97059f84a2d190b31677fd55435d15c7b` |
| Expected public journal | 15380 bytes; SHA-256 `aebac85219e0df161bda4e9d6661e4a7eccc619812eb45bb106ee46180cfa41c` |
| Host lock SHA-256 | `f75302dce44982f4b14a93a32533c2bfd5884743ec457d7f452a76a2855cb117` |
| Actual prover binary SHA-256 | `751b9b188d341e8bec5e02060086b7b1dc3f7289e90f726c38589bb6735dd6d7` |
| SDK / prover | RISC Zero 3.0.6; release commit `1cc70cf05033a79ebc90f07c679cb4bd1cd301b9` |
| VM / recursion circuits | 4.0.5 / 4.0.5 |
| Receipt mode / hash | Explicit Succinct STARK / poseidon2 |
| Total execution limit | `session_limit(Some(1 << 22))`, unchanged SDK user-cycle counter |

The frozen guest source inventory/compiler/flags and historical results are in the
[baseline](../experiments/r0_enrol_po17_1/evidence/baseline.json). The journal is the
same diagnostic `r0-result` framing, profile, operation and complete public statement
used previously; it is not the proposed production presentation format.

The new host was built offline with the same `--release` configuration: optimisation
3, thin LTO, one codegen unit, checked overflow and **debug assertions disabled**.
Runtime host inspection confirms the latter. Its compiler remains custom rustc
1.97.0-dev `e638c6cfe`, with LLD/LLVM 22.1.6. Cargo profile fingerprints and empty
host `rustflags` match the preceding build; Cargo manifests/lock are byte-identical.
Only host execution/admission/measurement and cumulative-budget bookkeeping changed.
Fresh-verifier isolation additionally hides execution temporary files.

The actual prover is the **same prebuilt SDK release binary** used previously.
Its ELF compiler comment records rustc **1.97.1 (`8bab26f4f`)**, GCC 9.4.0 and
LLD 22.1.6. This is distinct from the local host compiler. The distributed artefact
does not attest exact vendor optimisation/LTO flags; its release provenance is not
used to invent those settings. There is no switch to a differently built prover.
The embedded recursion archive retains SHA-256
`744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849`;
its existing extracted copy was checked read-only. No download or new recursion
artefact was required.

CPU configuration is unchanged: one worker, two Rayon threads, two OMP threads,
200% cgroup CPU quota, no GPU. The same restricted SDK debug logging and bounded
phase capture are used. Affinity remains the available WSL CPU set, not a newly
pinned core. The compiled host cache was copied into an isolated target and rebuilt;
each execution/proof launches a fresh prover process. OS page cache was neither
flushed nor controlled. No blocking configuration incompatibility was found. Cache
and host-load variability prevent treating these individual observations as a stable
benchmark; the earlier timeout cannot yield an exact overall speedup.

## Actual segment setting and supported verifier

The shared execution/proof input builder now calls
**`ExecutorEnv::builder().segment_limit_po2(17)`**, instead of 16. SDK client/server
serialization passes this value to the actual executor. This is separate from
`ProverOpts.max_segment_po2`, which remains **22**, as confirmed by serialising the
actual `ProverOpts::succinct().with_dev_mode(false)` options. No maximum, accepted
control set or verifier context was broadened.

The registered verifier-parameter digest remains
`ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013`, and control root
`a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56`.
The po2-17 lift ID
`c9b08054994f542a6310b00d9b6fc6528ed7bb6f4ca5476a686847127cdfdc5b`
belongs to the existing allowed control set and has a programme in the unchanged
embedded archive. The host confirms the same registry/context identity. Details,
actual prover options, CPU/build/cache metadata and source hashes are in the
[preflight record](../experiments/r0_enrol_po17_1/evidence/preflight.result.json).

## Single execution-only check and proof admission

The authorised execution **completed and accepted**, with exact expected journal
bytes and SHA-256. It used **196311 user cycles**, unchanged from the historical
po2-16 evidence. The partition was measured through the SDK callback, not obtained
by dividing user cycles by the segment capacity.

| Measurement | Historical po2 16 | New po2 17 execution |
|---|---:|---:|
| Actual segment count | 10 | **3** |
| Segment sizes | 9 × 2^16, final 2^15 | **3 × 2^17** |
| SDK user cycles | 196311 | **196311** |
| Padded segment capacity | 622592 | **393216** |
| Capacity minus user cycles | 426281 | **196905** |
| Execution API wall | 0.063151058 s, historical | **0.023427499 s** |
| New guarded service wall | — | **0.235104347 s** |
| New kernel process-tree memory peak | — | **15249408 bytes** |
| New sampled summed RSS peak | — | **8986624 bytes** |
| New temporary-file peak / swap | — | **0 / 0 bytes** |
| Journal | Expected 15380 bytes | **Exact equality** |

Measured segment user cycles were **71057, 85969 and 39285**. Each occupies a
131072-cycle padded segment; the final segment also rounds to po2 17. Segment count
fell by seven (70%), while padded capacity fell by 229376 (36.8421%). These are
partition/capacity reductions, not percentages of complete proving speedup.

The execute IPC does not expose separate paging, reserved or system-cycle totals;
the residual includes those overheads and padding. The very short execution was
missed by much of the RSS sampling: the kernel peak is the authoritative aggregate
memory high-water mark, and the smaller sampled RSS must not be presented as exact.
Execution memory says nothing conclusive about proving memory. The new execution
API timer starts after subprocess-client construction; the historical
`ExternalProver::execute` timer included that construction. Those timing scopes
and uncontrolled cache state prohibit an execution-speedup claim. The measured
partition comparison is unaffected, and the proof timer retains the preceding
`ExternalProver::prove_with_ctx` scope.

[Execution result](../experiments/r0_enrol_po17_1/evidence/execution.result.json),
[resource record](../experiments/r0_enrol_po17_1/evidence/execution.json) and
[admission decision](../experiments/r0_enrol_po17_1/evidence/admission.result.json)
record all gates: success, exact journal, fewer segments, supported sizes and no
known configuration/resource incompatibility. Every gate passed. The required
proof workload is now **three segment proofs, three lifts and two joins**, from the
SDK's sequential lift/join fold. No extra execution-only run was performed.

## Resource envelope, receipt checks and budget

The [pre-execution manifest](../experiments/r0_enrol_po17_1/evidence/manifest-before-launch.json),
[pre-proof manifest](../experiments/r0_enrol_po17_1/evidence/manifest-before-proof.json),
[configuration](../experiments/r0_enrol_po17_1/config.json) and
[contract](../experiments/r0_enrol_po17_1/CONTRACT.md) fix the limits before launch:

- One worker, **2 GiB aggregate descendant memory**, no swap, two CPU threads,
  200% CPU quota, 128 tasks. WSL admission reserves another 2 GiB MemAvailable.
- One execution-only check: 60 seconds. One conditional proof: **600 seconds for
  the entire pipeline**, including execution, all segment proofs, lifts, joins,
  final receipt construction and host self-verification. No stage gets a new deadline.
- Existing 300-second execution-only, 1800-second execution/proving and 1200-second
  preparation/build aggregate ceilings; no retries, automatic raises or fallback.
- Total experimental disk 10 GiB / 9 GiB conservative stop; output 256 MiB / 240 MiB
  stop; diagnostics 64 MiB / 60 MiB stop; at most 64 KiB retained per log stream.
  Receipt bound 10 MiB, complete presentation admission 12 MiB.
- Fresh verification 1 GiB/10 seconds, focused tampering at most 100 cases/60 seconds;
  ancillary checks 256 MiB/60 seconds and 300 seconds aggregate checks/verification.

Effective cgroup, CPU/task limits and absent external routes are checked before
launch. Original workspaces are read-only. Local CPU proving explicitly disables
development/fake modes; external networking, GPU and Groth16 are unavailable.
Fresh verification additionally hides private fixtures, all previous experimental
directories, original private tests and this execution's temporary files. Namespace
isolation was probed before execution. The verifier receives the saved receipt,
expected public statement and registered image/verifier identities only.

A final receipt must be Succinct/poseidon2, use the registered parameters, have the
expected image and pruned claim, and match the exact expected journal. Full
`Receipt::verify_with_context` requires successful execution and no unresolved
assumptions. Receipt mutations test seal data, journal, expected image and public
statement, with operation/context/hash-suite/trailing-data checks also retained.
Intermediate segment or recursion proofs cannot stand in for a final receipt.

The [cumulative attempt ledger](../experiments/r0_enrol_po17_1/evidence/cumulative_attempt_ledger.json)
references the historical ledger by hash and preserves it unchanged. Launching this
pipeline advanced the used count **from one to two before process creation**; one
attempt remains. This package cannot consume cumulative attempt 3 or prove CredValid.

## Conditional proof result and next decision

**Completed: one real enrolment Succinct receipt was generated and independently
verified. All eight focused tamper cases rejected. Two cumulative proof attempts
are used and one remains; this package is closed.**

| Proof measurement | Measured outcome |
|---|---:|
| SDK combined execution/segment/recursion call | **343.792883226 s** |
| Whole guarded proving pipeline, including self-verification/save/teardown | **343.898929933 s** |
| Margin below 600 s, SDK call / guarded pipeline | **256.207116774 / 256.101070067 s** |
| Observed segment phase, first preflight to first lift | **123.642647494 s** |
| Observed complete recursion phase, first lift to final join completion | **220.097009557 s** |
| Completed segment proofs / lifts / joins | **3 / 3 / 2** |
| Complete SDK user / paging / reserved cycles | **196311 / 78207 / 118698** |
| SDK total padded cycles | **393216** |
| Host self-verification | **0.011631573 s** |
| Kernel aggregate proving-memory peak | **1535385600 bytes / 1.429939 GiB** |
| Sampled summed process-tree RSS peak | **1571074048 bytes / 1.463177 GiB** |
| Temporary storage peak / bytes retained after proving | **236187 / 0 bytes** |
| Swap / memory-limit events / OOM events | **0 / 0 / 0** |
| Raw STARK seal | **222668 bytes** |
| Public journal | **15380 bytes**, exact expected journal |
| Complete serialised receipt | **238485 bytes** |
| Final receipt SHA-256 | `2c711beaa6144968aac66421eba10dff1f883133f4d5ec3e1256e3b68e529cc5` |

The SDK returned complete `ProveInfo.stats`, so paging/reserved counters are now
available and sum with user cycles to the padded total. Their SDK labels are retained;
no extra system-only counter is invented. The execution-only result and proof stats
agree on user cycles, segment count and total padded capacity.

The external API reports a combined execution/segment/recursion time. The additional
phase intervals above come from observed SDK log boundaries and include the work
and verification/bookkeeping between those boundaries. They are not invented pure
kernel timers. Absolute capture timestamps and the SDK-call timer have different
origins. The individual completed recursion intervals observed in the full log were:

| Operation in order | Observed wall seconds |
|---|---:|
| Lift 1 | 43.463084 |
| Lift 2 | 44.315287 |
| Join 1 | 44.343086 |
| Lift 3 | 43.195444 |
| Join 2 | 44.737210 |

The final control ID is the registered ordinary join programme
`7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e`, with inclusion
index 1 and eight sibling digests under the unchanged root. The claim is pruned;
full verification binds the expected successful unconditional execution. This is
an actual final Succinct receipt, not an execution journal or partial Composite.
The canonical bounded bincode receipt is an experimental container, not adoption
of the proposed production wire adapter.

### Independent verification and rejection checks

A fresh verifier with private fixtures, historical directories and execution traces
inaccessible accepted the saved receipt using the expected enrolment image, fixed
verifier parameters and original public statement. Full verification took
**0.011627595 seconds**; its guarded service took **0.240132201 seconds**, with
**8044544 bytes** of kernel cgroup peak memory.

A separate fresh process then accepted the original receipt and rejected all eight
mutations: **journal, public statement, public context, expected image, operation,
seal data, hash suite and trailing container bytes**. The valid-plus-negative checks
took **0.026887186 seconds** inside the host, **0.240488862 seconds** guarded wall,
with **8790016 bytes** kernel peak. They consumed no proof attempt. Both processes
used zero swap and had no memory-limit/OOM events. Brief-run RSS samples may miss
their target entirely; the retained kernel peaks and wrapper snapshots provide the
aggregate memory evidence.

[Receipt](../experiments/r0_enrol_po17_1/receipts/attempt2.bin),
[receipt metadata](../experiments/r0_enrol_po17_1/receipts/attempt2.bin.json),
[independent verification](../experiments/r0_enrol_po17_1/evidence/verify.result.json),
[tamper results](../experiments/r0_enrol_po17_1/evidence/adversarial.result.json), and
[combined measurements](../experiments/r0_enrol_po17_1/evidence/results.json).

### Comparison, preservation and commands

The measured segment count decreased from ten to three, and the observed complete
segment phase changed from 204.630950 to 123.642647 seconds. The new complete proof
fits the original 600-second/2 GiB envelope, whereas the prior configuration timed
out. **No exact overall speedup is calculated:** the old complete proof time is
unknown, its recursion interval is partial, and cache state was not controlled.
These observations support this fixed enrolment fixture, not percentile, throughput,
stable-average or all-input feasibility claims.

Guarded preparation cost was **161.890351 seconds**: 1.028996 seconds copying the
host cache and 160.861355 seconds for the offline host-only release build. Build
kernel peak was 1548292096 bytes. No dependencies were installed, no guest/prover
was recompiled and no artefacts downloaded. Before final reporting checks, all
completed guarded services totalled **507.514607 seconds**, including preparation,
the one execution, proof, independent verification and checks. This excludes agent
editing time, original installation/build costs and gaps between commands. The
[final manifest](../experiments/r0_enrol_po17_1/evidence/manifest.json) records
completed reporting checks separately as well: including the final audit, guarded
services total **508.138925699 seconds**. The
[final audit](../experiments/r0_enrol_po17_1/evidence/final-audit.result.json) confirms
preservation, frozen configuration, receipt checks and the closed attempt budget.

The sole execution and proof commands from the project root were:

```sh
python3 experiments/r0_enrol_po17_1/scripts/run_limited.py --seconds 60 --slot 1 execute execution -- target/release/pqdid-r0-host execute
python3 experiments/r0_enrol_po17_1/scripts/run_limited.py --seconds 600 --slot 2 prove attempt2 -- target/release/pqdid-r0-host prove enrol-alpha-42 receipts/attempt2.bin
```

Verification used `verify2` with `--seconds 10 --memory 1073741824` and
`target/release/pqdid-r0-host verify enrol fixtures/public/enrol-alpha-42.bin
receipts/attempt2.bin`; `tamper2` used the same inputs with command `adversarial`
and the 60-second corpus limit. Exact systemd commands and effective settings are
in the [run ledger](../experiments/r0_enrol_po17_1/evidence/run_ledger.json).
The [STOP marker](../experiments/r0_enrol_po17_1/evidence/STOP.json) prevents another
execution/proof launch, and the cumulative ledger retains one unused attempt.

Relevant checks cover release-profile/CPU/prover identity, actual executor versus
prover maximum, supported control IDs, journal/partition admission, real receipt
verification, eight tamper cases, frozen hashes, Python/Rust/shell/JSON/TOML checks,
new documentation links, attempt sequencing and STOP enforcement. Preservation
covers **8485 pre-existing files**, allowing only requested status/traceability edits.
Unchanged reference/native validation was reused. Original reports, run records,
registries, dependency configuration and previous temporary evidence are unchanged.

### Feasibility decision: retain the final attempt until CredValid admission is measured

This result establishes bounded **enrolment** proof generation and independent
verification for the selected diagnostic guest. It does **not yet justify spending
the final attempt on CredValid** under a concrete unchanged plan of po2 17,
2^24 user cycles, local two-thread CPU, 2 GiB/no swap and 600 seconds for the whole
pipeline. CredValid's last measured partition was **582 segments at po2 16**; its
actual po2-17 partition is unknown. The new enrolment proof spends about 220 seconds
on only three lifts and two joins. Neither its segment-count reduction nor its
runtime can be transferred to CredValid by a ratio of user cycles.

Recommend one separately authorised **CredValid execution-only admission check**:
reuse the corrected ELF/image and original `cred-alpha-42` fixture, set actual
executor po2 17, keep the existing 2^24 user cap, 60-second execution limit,
2 GiB/no swap, one worker and existing disk limits, and run exactly once. Require
acceptance and exact journal equality; record the actual partition and resulting
segment/lift/join workload before reviewing whether a final 600-second proof attempt
has credible margin. Execution memory still will not establish proving memory.
If that workload cannot justify the fixed envelope, retain the final attempt for
a separately reviewed feasibility proposal instead of automatically raising limits.
No CredValid execution or proving is performed in the present package.

The active manuscript profile is unchanged. Full authentication, selective disclosure,
non-revocation/Merkle and lifecycle freshness/replay integration, CredValid proving,
complete guest equivalence/BC-1, privacy and quantum-security justification,
Section VIII extraction/simulation, DEP-001/002, and remaining Stage 2 bounded
keygen/signing/revocation/update/release work remain open. One final receipt and
its tamper checks do not establish unlinkability or a security/privacy theorem.
This package is complete and stops here.
