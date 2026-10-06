# R0-CREDVALID-EXEC24-1 — complete bounded CredValid execution

19 September 2026, Asia/Singapore; raw timestamps use UTC. **The unchanged corrected
CredValid guest completed and accepted the original valid fixture at 16313474 SDK
user cycles.** Its public journal matched the reference byte-for-byte. The one
authorised negative execution then rejected with `Guest panicked: relation rejected`,
without a successful session or acceptance journal. Both runs stayed within the
resource envelope. This package is complete and closed against replay.

**Two new zkVM executions, zero proofs, no receipts. All three proof attempts remain
unused.** An execution journal is local execution output, not a cryptographic receipt.

## Baseline, authority and configuration

AGENTS, the [cycle-attribution report](stage3_r0_credvalid_cycle_attribution.md),
[preceding feasibility report](stage3_r0_succinct_feasibility_1.md), relevant host/guest
configuration and pinned execution API were reviewed. Only manuscript Sections
II–VIII remain authoritative. The selected PDF is unchanged, SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The active suite, SPEC-001–004, dependencies, original vectors, guest sources and
historical evidence/STOP markers are preserved.

This package reuses the **existing uninstrumented release artefact**, not a rebuilt
guest. Its six native sampler/arithmetic tests and 35 reference comparisons are
reused after checking source/build/input identities. No new optimisation, primitive,
sampler bound, guest feature or cryptographic parameter was introduced.

| Identity | Recorded value |
|---|---|
| Original corrected source package revision | `fd5e917d158f2bf74e0825b0e5415f910e466d8cd8acd95ee5e4257da6144084` — SHA-256 source inventory, not a Git commit |
| Frozen build-source bundle | `experiments/r0_credvalid_cycle_1/snapshots/builds/corrected-plain` |
| Guest ML-DSA source SHA-256 | `7d066f5d0eff97e363b8c8fbdd7bb31b0f85681cca32c9359dedacc6499a2731` |
| User ELF SHA-256 | `d5ef3682a8956ba03b710cdee14f02dbf967ec05e935c3d73fcc582aac19aaf2` |
| Combined user/kernel programme SHA-256 | `668dd886b66772593aea42e53d967d61f2e1a8c1e750add482acc0ed09963a09` |
| Image ID | `a7b77747d5ebff0e520d17fc188afef06dfb91690062cb96f6b3cff78e93ae94` |
| Guest features | None: no diagnostic or component feature |
| Positive fixture | Existing `cred-alpha-42` |
| Public fixture SHA-256 | `63e0cbdedab8ba7a9e56ee7e3295cf6f1fbc2b31be1e35dcfd84db9554679231` |
| Private fixture SHA-256 | `8d670ab5ae1339ba162a0b124d4657a67043d567eb1d3bf5bafe7a7f8f4b8ead` |

The [baseline record](../experiments/r0_credvalid_exec24_1/evidence/baseline.json)
contains the complete original compiler/build manifest and previous capped result;
the [host build manifest](../experiments/r0_credvalid_exec24_1/evidence/build-manifest.json)
records the new host binary/source digest and unchanged guest registration.

Original guest build: SDK/r0vm **3.0.6**, SDK commit
`1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`; custom rustc **1.97.0-dev**,
commit `e638c6cfea1eff5fbbb24a27e60538e3760d21b8`, LLVM 22.1.6; cargo
**1.97.0-dev (c980f4866)**. Target `riscv32im-risc0-zkvm-elf`, release optimisation 3,
thin LTO, one codegen unit, overflow checks enabled, panic abort. Original guest flags:

```text
-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"
```

Only the host executor's `session_limit` changed, from `Some(1 << 22)` to
`Some(1 << 24)`. `segment_limit_po2(16)` is unchanged. Host bookkeeping was adapted
for two conditional runs, output comparison and bounded aggregate diagnostics.
The old 256-record diagnostic bound is retained: the first 256 individual segment
records are saved, and later segments update aggregate counters. No additional
segment-record allowance or executor segment-size increase was used. Guest ELF and
programme bytes remain identical to those used in the preceding capped run.

The new host was built offline with the existing compiler, read-only cached crates
and an isolated copy of the compiled host cache. The host lockfile is byte-identical
to the preceding package's lock. There was no installation or guest compilation.

## Limits, preflight and cycle meaning

The [contract](../experiments/r0_credvalid_exec24_1/CONTRACT.md) and
[configuration](../experiments/r0_credvalid_exec24_1/config.json) preserve all other
resource ceilings: one worker, two CPU threads, **2 GiB aggregate descendant cgroup
memory**, no swap, 60 seconds per execution, 300 seconds aggregate execution,
1200 seconds build/preparation, 10 GiB total experimental storage with a conservative
9 GiB stop, and 64 MiB diagnostic output with a 60 MiB stop. Streams remain capped
at 64 KiB. Ancillary checks retain 256 MiB/60 seconds each and 300 seconds aggregate.

Preflight and the wrapper immediately preceding every target checked cgroup limits,
CPU/task limits, no external routes and available WSL memory of at least the worker
allowance plus 2 GiB reserve. Available memory immediately before the valid/negative
guard admissions was **5232209920 / 5220196352 bytes**. Cgroup
`memory.max=2147483648`, `memory.swap.max=0`, CPU quota 200% and 128-task limit
were effective. Prior descendant OOM-control evidence is reused; no deliberate
memory-exhaustion test or additional zkVM execution was necessary. Filesystem
inspection found about 1.016 TB available in WSL and 399.2 GB on the Windows volume.
Historical workspaces were mounted read-only in each local service. No external
network service, GPU, development mode or proving API was invoked.

The authorised **16777216 limit counts the same SDK `Executor.cycles.user` as before**.
It includes work charged through VM instruction/syscall hooks, including kernel
instructions using those hooks; it is not host OS user time or application-only
retired instructions. Separate paging/reserved/padding accounting does not consume
this hard user-cycle allowance.

Pinned SDK 3.0.6 `ApiClient::execute` returns segment user counts and powers of two,
but does not expose separate system/paging/reserved totals through this IPC path.
We therefore report their combined residual capacity, not an invented paging-only
or system-only measurement. Padded segment capacity corresponds to the executor's
segment-capacity total and must not be substituted for the hard-cap counter.

## Valid execution and public output

| Measurement | Valid result |
|---|---:|
| Outcome | **Completed, accepted, `Halted(0)`** |
| Complete SDK user cycles | **16313474** |
| Margin below 16777216 | **463742 cycles / 2.7641%** |
| Segments | **582**: 581 at po2 16, final one at po2 15 |
| Total padded segment capacity | **38109184** |
| Capacity minus user cycles | **21795710**, combined paging/reserved/padding |
| Execution API wall time | **0.577716649 seconds** |
| Guarded service wall time | 0.649665937 seconds |
| Sampled summed process-tree RSS peak | **68956160 bytes** |
| Exact cgroup `memory.peak` before exit | **48459776 bytes** |
| Swap / sampled temporary-file peak / temporary bytes at exit | **0 / 0 / 0 bytes** |
| Expected and actual public journal | **5147 bytes, exact equality** |

The expected journal was independently framed in Python as
`enc_r0-result(PQDID-R0S-DIAG1, cred-valid, original_public_statement)` and cross-checked
against the existing relation encoder. Expected and actual journal SHA-256:
`f9fa7cce56b47699ff3ec198b2a2b1e2aa46b36f5a5f9d4d9839f4622d8579c2`.
The [actual public journal](../experiments/r0_credvalid_exec24_1/evidence/valid.public-journal.bin)
contains only the original public statement/operation/profile framing. Runtime
private inputs and internal signature values were not logged or added to it.

This is a complete measurement for **this unchanged guest and one valid fixture**,
with only 2.76% cycle headroom. It does not validate every possible credential under
the cap. The earlier 20.26% reduction remains an **isolated matrix-polynomial result**;
there is no comparable complete execution of the original eager guest, so no such
whole-CredValid percentage improvement is claimed. The historical enrolment result
remains 196311 user cycles; no new enrolment execution was run here.

## Meaningful negative execution

After valid completion, the existing `cred-rid-changed` fixture was checked with the
unchanged Python reference. It changes only the canonical certified revocation
identifier while preserving the original signature, binding, attributes, metadata,
holder secret and public statement. Its private-fixture SHA-256 is
`ebdef01dc6a4387cc7ee81fc8cb589ed9b9e70e54a8df2ed6c85c349e8430601`.

Canonical decoding succeeds; a wrapper around the **actual** bounded verifier
confirms one invocation from `cred_valid` and rejection. It records only the call
count, never verifier arguments. This rules out a mere malformed-input or holder-
opening negative test. See the [reference result](../experiments/r0_credvalid_exec24_1/evidence/negative-reference.json).

| Measurement | Negative result |
|---|---:|
| Outcome | **Credential rejected**, `Guest panicked: relation rejected` |
| Returned successful session / acceptance journal | **None / none** |
| Complete user-cycle count | **Unavailable**: panic does not return `SessionInfo` |
| Completed-segment user-cycle prefix | **16298606** |
| Completed segments | **581**, all po2 16 |
| Completed-segment padded capacity | **38076416** |
| Prefix capacity minus user cycles | **21777810** |
| Execution API wall time | **0.577708103 seconds** |
| Guarded service wall time | 0.668027199 seconds |
| Sampled summed process-tree RSS peak | **68980736 bytes** |
| Exact cgroup `memory.peak` before exit | **48345088 bytes** |
| Swap / sampled temporary-file peak / temporary bytes at exit | **0 / 0 / 0 bytes** |

This is a rejection, not a cycle-cap result. The error is the unchanged guest's
explicit relation-failure path before journal commit. The SDK returns no session
on this panic: actual journal fields are `null`, not a claimed observed zero-length
journal, and the final partial segment's cycles are unavailable. No acceptance
journal file was produced. The raw negative record also retains the same public
**acceptance template** hash for detecting erroneous acceptance; its expected
acceptance is false. The completed-segment prefix is not the total rejection cost.

The unchanged guest emits no phase markers. No per-phase attribution is inferred
from segment counts in either run, and the original instrumented prefix is not
substituted for this build. Segment payloads were discarded; no witness/memory/
register/instruction traces were retained.

## Evidence, commands and checks

The [machine-readable manifest](../experiments/r0_credvalid_exec24_1/evidence/manifest.json)
combines identities, configurations, exact outcomes and resource records. Original
records remain in the [ledger](../experiments/r0_credvalid_exec24_1/evidence/run_ledger.json),
[valid result](../experiments/r0_credvalid_exec24_1/evidence/valid.result.json),
[negative result](../experiments/r0_credvalid_exec24_1/evidence/negative.result.json),
per-target `.service.json`, `.progress.json`, `.segments.jsonl` and bounded logs.

The resource wrapper records cgroup peaks before teardown. Summed RSS samples can
double-count shared pages and miss brief peaks; cgroup charged memory includes
cache and counts shared charges differently, explaining why the two peak measures
are not interchangeable. Temporary-file peaks are sampled, not a claim of tracing
every transient file. Both executions had zero memory-limit/OOM events and no time,
swap, disk or diagnostic-output stop. No retries or compensating increases occurred.
Exact disk/output usage and cumulative setup/build/check costs are in the
[final audit](../experiments/r0_credvalid_exec24_1/evidence/final-audit.json).

From the project root, the two completed execution commands were:

```sh
python3 experiments/r0_credvalid_exec24_1/scripts/run_limited.py --seconds 60 --slot 1 execute valid -- target/release/pqdid-r0-host run valid
python3 experiments/r0_credvalid_exec24_1/scripts/run_limited.py --seconds 60 --slot 2 execute negative -- target/release/pqdid-r0-host run negative
```

The guard records its local transient-service command and configuration. Preflight,
cache reuse and `cargo build --locked --offline --release -p pqdid-r0-host` were
separate guarded preparation steps. No guest build command exists in this package.
The conditional native negative reference used the existing virtual environment
under the 256 MiB check envelope. Its initial output basename collided with the
guard resource record; the resource record was preserved separately and the
reference result recovered verbatim from its retained log before slot 2. The
[recovery record](../experiments/r0_credvalid_exec24_1/evidence/reference-record-recovery.json)
documents both identities. Neither the native reference nor a guest was rerun.

Checks cover Python lint/format, Rust formatting, shell syntax, JSON/TOML/Python
parsing, documentation links, unchanged source/lock/ELF/programme/input hashes,
byte-exact journal output, rejection classification, resource/sequence limits and
zero proofs/receipts. Premature slot 2 and a proving command were refused before
launch; the final STOP marker refuses replay. Preservation covers **8315 pre-existing
files**, permitting only the requested status/traceability edits. The six native
tests/35 comparisons and earlier production regression are reused, not rerun or
reported as new coverage.

## One next-step recommendation: a bounded real Succinct proof pilot

Recommend a separately authorised **`R0-SUCCINCT-PILOT-2`**, using the **three still
unused proof attempts** and the existing resource proposal. No proof work starts in
this package. Execution now supplies the prerequisite positive and meaningful
negative evidence for this CredValid fixture, but it establishes no proving memory,
recursion cost, proof size or proving time. The 582 segments are planning input,
not a conversion formula for those unknowns.

Use the pinned local CPU SDK 3.0.6 pipeline and trusted image/control parameters.
Keep genuine Succinct/poseidon2 receipts, a pruned unconditional claim and complete
`Receipt::verify_with_context` verification; reject Fake, Composite, Groth16,
conditional or wrong-image/journal receipts. Prepare a new isolated host registry
for the exact corrected image above. Do not alter historical registries or STOPs.

1. Attempt 1: the original `enrol-alpha-42` guest/image, to exercise real Succinct
   generation and fresh-process verification on the smaller known computation.
2. Only after successful generation, verification and resource admission, attempt 2:
   the exact corrected CredValid image and `cred-alpha-42` measured here.
3. Only after attempt 2 succeeds, attempt 3: existing `cred-alpha-43`, with fresh
   proving randomness. It already has the same public statement as `cred-alpha-42`
   and a distinct native-validated private witness. First require one separately
   counted execution of that fixture at the same 2^24/60-second limits in the future
   package. A failure/resource stop leaves the third proof attempt unused. Compare
   public metadata/control paths and lengths without claiming a privacy theorem.

Retain one worker/two CPU threads, **2 GiB aggregate memory/no swap, 600 seconds per
proof attempt, 1800 seconds aggregate execution/proving**, and count each launch
before spawn, including failures. Retain segment exponent 16 and explicitly adopt
the measured **2^24 user-cycle admission ceiling** for the future CredValid proof
executions; the present authorisation does not extend automatically to that pilot.
Keep 1200-second preparation, 10 GiB disk/9 GiB stop, 256 MiB experiment output and
the tighter 64 MiB diagnostic ceiling, with worker allowance plus 2 GiB memory
reserve checked before each stage. Verification stays at 1 GiB/10 seconds per case;
the malformed/tampering corpus stays within 100 cases/60 seconds, 10 MiB receipt
and 12 MiB complete-presentation input bounds.

A fresh verifier must receive only public data, the receipt and trusted identities,
with private fixtures inaccessible. Require seal/journal/image/operation/context
tamper rejection and record raw seal/envelope/presentation bytes, execution/proving/
recursion/verification times and separate memory peaks. Stop the pilot on any
resource limit or incorrect outcome; no hidden retry, cap increase or alternate
receipt mode. Three exploratory attempts cannot establish percentiles or throughput,
and the current two executions support neither claim.

Full authentication, selective disclosure, Merkle/non-revocation and lifecycle
integration, complete guest equivalence/BC-1 conformance, actual proofs, candidate
privacy/ZK leakage and quantum/security accounting, Section VIII extraction/
simulation, DEP-001/002 and remaining Stage 2 keygen/signing/revocation/update/release
obligations remain open. No replacement profile or production deployment is approved.
