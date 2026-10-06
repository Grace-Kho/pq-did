# R0-SUCCINCT-PROOF-1 — bounded local Succinct pilot

19 September 2026, Asia/Singapore; machine timestamps use UTC.

## Authority and frozen baseline

The user explicitly authorised this isolated real-proof pilot after
[R0-CREDVALID-EXEC24-1](stage3_r0_credvalid_exec24.md). Its sequence supersedes the
older alpha-43 proposal: enrol-alpha-42, conditionally cred-alpha-42, then optionally
**the identical cred-alpha-42 input/configuration with fresh prover randomness**.
There are at most three top-level attempts; failures and interruptions consume slots.
No retry or heavier target may follow a hard resource, correctness or verification
failure. This authorisation does not adopt a replacement production profile.

AGENTS, the [original report](stage3_r0_succinct_feasibility_1.md),
[profile proposal](stage3_profile_change_proposal.md),
[draft specification](stage3_profile_spec_draft.md) and pinned local SDK sources were
reviewed. Only manuscript Sections II–VIII are authoritative. The PDF remains SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The active suite, reference implementation, SPEC-001–004, guest sources, dependencies,
original vectors and historical evidence/STOP markers are preserved.

Both existing uninstrumented release binaries are copied byte-for-byte. There is
**no guest rebuild, optimisation, new coprocessor or cryptographic parameter change**.
The six corrected native tests and 35 comparisons are reused after identity checks.
The original enrolment validation and complete EXEC24 positive/negative results are
also reused; no extra execution-only profiling was performed.

| Frozen identity | Enrolment | Corrected CredValid |
|---|---|---|
| Fixture | `enrol-alpha-42` | `cred-alpha-42` |
| Source package inventory SHA-256 | `cbd6c003b70589460c95213e23704f10bcd9ceda17460e573eb5380c518616a9` | `fd5e917d158f2bf74e0825b0e5415f910e466d8cd8acd95ee5e4257da6144084` |
| User ELF SHA-256 | `9fbacd2f38ec5d9177cbf5dbd050261af1bd86a9cd1978407056afbab7f26449` | `d5ef3682a8956ba03b710cdee14f02dbf967ec05e935c3d73fcc582aac19aaf2` |
| Combined user/kernel programme SHA-256 | `4db93d3c9463e13db2a172923fdbc917558eabea867b3fd3d0124b6b9f54dc1c` | `668dd886b66772593aea42e53d967d61f2e1a8c1e750add482acc0ed09963a09` |
| Image ID | `66e4c8e0c468edaea2bbef55ac470fab92de3c59e8c0f352905b8a741bac160c` | `a7b77747d5ebff0e520d17fc188afef06dfb91690062cb96f6b3cff78e93ae94` |
| Expected public journal bytes | 15380 | 5147 |
| Expected journal SHA-256 | `aebac85219e0df161bda4e9d6661e4a7eccc619812eb45bb106ee46180cfa41c` | `f9fa7cce56b47699ff3ec198b2a2b1e2aa46b36f5a5f9d4d9839f4622d8579c2` |

These source identities are SHA-256 inventories, not Git commits. Full public/private
fixture digests, source snapshots, build settings and validation references are in the
[baseline](../experiments/r0_succinct_proof_1/evidence/baseline.json). Expected journals
were independently framed in Python from the original public statements and checked
by the host encoder. The diagnostic contract is
`enc_r0-result(PQDID-R0S-DIAG1, operation, public_statement)`; it is not the unadopted
production wire format in the draft.

Original compiler: custom rustc 1.97.0-dev, commit
`e638c6cfea1eff5fbbb24a27e60538e3760d21b8`, LLVM 22.1.6; cargo 1.97.0-dev
`c980f4866`. Guest target `riscv32im-risc0-zkvm-elf`, release optimisation 3,
thin LTO, one codegen unit, checked overflow, panic abort. The original flags are
retained in the baseline. The new **host only** uses the existing offline compiler
and cached dependencies, with lock SHA-256
`f75302dce44982f4b14a93a32533c2bfd5884743ec457d7f452a76a2855cb117`, unchanged from
CYCLE-1/EXEC24-1. Guest locks and production dependency configuration are unchanged.

## Actual prover, recursion artefacts and supported workload

RISC Zero SDK/r0vm **3.0.6**, release commit
`1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`; unchanged local r0vm SHA-256
`751b9b188d341e8bec5e02060086b7b1dc3f7289e90f726c38589bb6735dd6d7`.
RV32IM and recursion circuits are 4.0.5; software SHA3/SHAKE remains inside the guest.
The host explicitly calls `ExternalProver::prove_with_ctx` with
`ProverOpts::succinct().with_dev_mode(false)` and a verifier context with development
mode disabled. Local CPU only, no remote service, GPU, Fake or Groth16 proving.
The upstream SDK release archive/checksum provenance is copied into the manifest.

The pinned prebuilt prover already embeds `recursion_zkr.zip`. The archive was
located inside its unchanged ELF, extracted into the new experiment for provenance,
and its **59768781 bytes** matched the 4.0.5 `build.rs` SHA-256 pin:
`744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849`.
No download was required. Runtime continues to use the original `include_bytes!`
archive, not a new override. Its 32 entries and upstream content-addressed URL are
in the [artefact record](../experiments/r0_succinct_proof_1/evidence/recursion-artifacts.json).
No Groth16 setup artefacts were prepared or invoked.

Registered Succinct verifier-parameter digest:
`ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013`.
Registered control root:
`a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56`.
The pinned `ALLOWED_CONTROL_IDS` contains the actual po2-15 and po2-16 lift IDs and
join ID, and the embedded archive contains their programmes. The rebuilt host
confirmed that these registered parameters match its default verifier context.
The proof's control path must have eight digests and index below 256; the full
verification API checks membership under the registered root.

| Prior execution evidence / required proof workload | Enrolment | CredValid |
|---|---:|---:|
| Complete SDK user cycles | 196311 | 16313474 |
| Reported segments | 10 | 582 |
| Segment powers of two | 9 × 16, 1 × 15 | 581 × 16, 1 × 15 |
| Padded segment capacity | 622592 | 38109184 |
| Capacity minus user cycles | 426281 | 21795710 |
| Required segment proofs | 10 | 582 |
| Required ordinary lifts / joins | 10 / 9 | 582 / 581 |

SDK `server/prove/prover_impl.rs` proves every segment; `server/prove/mod.rs`
then performs a sequential lift/join fold. These guests require no assumption
resolution or Keccak coprocessor proofs. The stated workload counts follow that
source and the prior executions, **not an estimated complete proving time**.
Recursion has additional work not included in VM padded capacity. A Composite
receipt before recursion is only an intermediate artefact.

The hard session cap still counts SDK `Executor.cycles.user`: 2^22 for enrolment,
2^24 for CredValid. It is not a cap on padded segment capacity. Segment exponent 16
is unchanged; the session exponent 24 does not request an unsupported po2-24 lift.
Prior execute IPC did not return separate paging/reserved/system counters, so the
residual above includes paging, reservations and padding. A successfully returned
`ProveInfo.stats` can expose paging/reserved counts; unavailable counters remain
unmeasured on failure.

## Enforced envelope and verifier contract

The [pre-launch manifest](../experiments/r0_succinct_proof_1/evidence/manifest-before-launch.json)
records exact limits and source/binary/input digests before the first launch.
The [guard](../experiments/r0_succinct_proof_1/scripts/run_limited.py) checks those
digests and maintains a persistent serial lock and attempt ledger.

- Whole target process tree, including r0vm and recursion: **2 GiB MemoryMax**,
  **zero swap**, one worker, at most two CPU threads, CPU quota 200%, 128 tasks.
- **600 seconds per complete proof pipeline**, **1800 seconds aggregate
  execution/proving**. Segment proving, lifts and joins share one deadline.
  These limits come from the proposal, not the earlier 0.578-second execution.
- Preparation/build: 1200 seconds aggregate, separately accounted. Positive
  verifier: 1 GiB/10 seconds per case; tampering: at most 100 cases/60 seconds.
  Ancillary checks: 256 MiB/60 seconds, 300 seconds aggregate checks/verification.
- Total experiment storage: 10 GiB, conservative stop at 9 GiB; output 256 MiB,
  stop at 240 MiB; diagnostics 64 MiB, stop at 60 MiB. Per-stream retention stays
  within 64 KiB using first 48 KiB plus last 16 KiB and aggregate SDK phase counters.
  Receipt input is limited to 10 MiB; receipt plus bounded public data fits the
  existing 12 MiB complete-presentation admission bound.
- Before each service, WSL MemAvailable must exceed its allowance plus 2 GiB
  reserve. Effective memory/swap/CPU/task controls and absence of external routes
  are checked before the target starts. Kernel enforcement and sampled aggregate
  RSS/disk/output watchdogs stop the whole descendant cgroup on a limit.

Local loopback IPC is permitted inside a private network namespace; external routes
are absent. Private device namespaces exclude GPU access. Original experiments are
mounted read-only. The fresh verifier additionally cannot access the new private
fixture directory, any of the three historical experimental directories, or the
project's original private test fixtures. A separate namespace probe confirmed
loopback operation, external-connect failure and private-fixture inaccessibility.

The verifier requires the Succinct variant, poseidon2, registered verifier/control
parameters, expected guest image, pruned claim and exact independently constructed
public journal. `Receipt::verify_with_context` binds successful complete execution
and an empty assumption list; integrity-only verification is insufficient. The
host self-verifies within its proof deadline before saving a receipt; a separate
fresh process must then verify it without private inputs. Tampering tests cover
seal, journal, public statement, context, image, operation, hash suite and trailing
container data. They generate no new proofs. Receipt-based tests can only run if an
actual Succinct receipt is obtained.

## Individual results and decision

**The only attempted pipeline timed out during enrolment recursion. No final Succinct receipt was produced; the package is stopped.**

### Attempt 1: enrolment — deadline reached during the sixth lift

**No final Succinct receipt was obtained.** The complete target process tree was
terminated by the configured 600-second deadline (`Result=timeout`, SIGTERM).
This is a resource failure, not credential rejection or successful proof completion.
The package stopped immediately; **one proof attempt used, two unused**. CredValid
and the optional repeat were not launched. No limit, segment setting or parameter
was changed, and no retry occurred.

| Measurement | Actual observation |
|---|---|
| Whole guarded pipeline wall time | **600.128431264 s**, including service startup/termination bookkeeping |
| Systemd reported service runtime | 600.094 s; the configured proving deadline remained 600 s |
| Guest execution | `Halted(0)`, 10 segments, exact expected public journal in the retained SDK session log |
| Expected / actual execution journal | **15380 bytes**, SHA-256 `aebac85219e0df161bda4e9d6661e4a7eccc619812eb45bb106ee46180cfa41c` |
| Completed segment proofs | **10 of 10**, before recursion began |
| Completed recursion operations | **5 lifts and 4 joins** |
| Exact last observed phase | **Sixth lift started at 593.684859 s; no completion logged before termination** |
| Remaining work at stop | Sixth lift unfinished, four later lifts and five later joins; final receipt return and verification |
| Kernel aggregate cgroup memory peak | **1521070080 bytes (1.416 GiB)** |
| Sampled summed process-tree RSS peak | **1557245952 bytes (1.450 GiB)** |
| Swap / memory-limit / OOM events | **0 / 0 / 0** |
| Sampled temporary storage peak / retained temporary bytes at stop | **436542 / 436542 bytes** |
| Largest sampled total experimental storage | **6419555718 bytes (5.979 GiB)** |
| Retained attempt diagnostic stream | **65536 bytes**, bounded first/tail retention; 7333 middle bytes omitted |
| Final seal / receipt-journal / serialised receipt bytes | **Unavailable — no final receipt** |
| Independent verification / actual-receipt tamper tests | **Not run — prerequisite receipt absent** |

SDK control flow and phase logs show real RV32IM segment proofs and completed
recursion proofs inside this attempt. Those intermediate components were not saved
as successful application receipts. There is no Composite/fake fallback and no
claim that an execution journal proves acceptance to an independent verifier.

The first `prove_session` log arrived at 0.113071 seconds from stream capture start;
it confirms execution completion, but includes host/IPC startup and is not a pure
execution timer. The observed interval from first segment preflight to first lift
was **204.630950 seconds**. Recursion then occupied approximately **395.4 seconds**
until the service stopped, including final termination bookkeeping. These are
observed phase boundaries, not a completed combined proving cost. The external API
never returned `ProveInfo`, so new user/paging/reserved/total counters and a complete
SDK timing are unavailable. The baseline's 196311 user cycles and padded capacity
remain prior execution evidence, not newly returned proof statistics.

The guard recorded the exact final kernel peak through systemd after termination;
the killed service wrapper could not save its normal post-exit snapshot. Sampled
RSS can double-count shared pages and miss brief peaks; cgroup memory includes
charged cache, so the two values are not interchangeable. Temporary-file peaks are
sampled. The systemd resource result and final SDK phase counters were retained
before resetting only this experiment's transient failed-service state. The STOP
marker and attempt ledger remain persistent.

### Preparation, evidence and checks

Guarded preparation/build cost was **160.117499 seconds**: embedded-archive
inspection/extraction 1.383842 s, isolated cache reuse 1.062914 s and offline host
build 157.670743 s. Downloads: **zero bytes**. The build's kernel memory peak was
1540845568 bytes. Preparation, initial preflight checks and the stopped attempt
sum to **760.957108 seconds of guarded subprocess wall time** before reporting
checks. This is a cold cost for the new host/pilot using already installed pinned
tools and frozen guest binaries; it excludes original installation/guest builds,
agent authoring and gaps between commands. Final cumulative records also include
reporting checks. Including the final audit, the completed guarded-service total is
**761.542739 seconds**: 160.117499 s preparation/build, 600.128431 s proof attempt
and 1.296809 s checks/namespace probe. These costs are separate from the proof
attempt's deadline. The [final manifest](../experiments/r0_succinct_proof_1/evidence/manifest.json)
and [final audit](../experiments/r0_succinct_proof_1/evidence/final-audit.result.json)
record those costs and preservation results.

The [results](../experiments/r0_succinct_proof_1/evidence/results.json),
[attempt resource record](../experiments/r0_succinct_proof_1/evidence/attempt1.json),
[SDK progress](../experiments/r0_succinct_proof_1/evidence/attempt1.sdk-progress.json),
[ledger](../experiments/r0_succinct_proof_1/evidence/run_ledger.json) and
[STOP record](../experiments/r0_succinct_proof_1/evidence/STOP.json) preserve the raw
outcome and sequence. Every service command, effective environment and limit is in
the ledger; the pre-launch manifest freezes the configuration and 32 source/input/
binary files. Fixture framing/preparation source is retained alongside the evidence.

The sole proof command, from the project root, was:

```sh
python3 experiments/r0_succinct_proof_1/scripts/run_limited.py --seconds 600 --slot 1 prove attempt1 -- target/release/pqdid-r0-host prove enrol-alpha-42 receipts/attempt1.bin
```

Before it, guarded preparation extracted the pinned archive, reused the build cache,
and ran `cargo build --locked --offline --release -p pqdid-r0-host`. Separate
preflight, namespace and host-inspection checks passed. Admission probes rejected
premature slot 2, a 601-second deadline, slot 4 and a wrong proof command without
launching a service or consuming an attempt. Unchanged native/reference validation
was reused. Final checks cover Python lint/format/syntax, Rust format, shell syntax,
JSON/TOML, documentation links, attempt accounting, bounded logs, frozen artefacts
and preservation of **8394 pre-existing files**, allowing only requested status/
traceability edits. No actual-receipt verification result is implied by these checks.

### Interpretation and one next recommendation

Execution succeeded and real component proving ran, but **complete Succinct
production failed the 600-second envelope even for enrolment**. Complete CredValid
proving cost, final receipt size, independent receipt verification and actual-receipt
tamper rejection remain unmeasured. The stopped cost is not an estimate of complete
proving time. No percentile, throughput or stable average follows from this single
attempt. The earlier 20.26% result remains isolated-component execution evidence.

Recommend one separately authorised **enrolment-only segmentation check at po2 17**:
one execution-only run of the same frozen guest/fixture, preserving its 2^22 user
cap, 60-second execution deadline, 2 GiB/no-swap and existing storage limits. Measure
the actual segment count before spending either remaining proof attempt. The
present run required 19 lift/join operations, of which only nine completed before
the deadline; fewer segments could reduce that repeated recursion work. The pinned
allowed control set contains the po2-17 lift, but the larger segment's proving memory
and complete runtime remain untested. This is a future configuration proposal,
not a change or another run in this package; it does not assume a larger deadline
will solve the problem or that po2 17 will fit.

Full authentication, selective disclosure, Merkle/non-revocation integration,
lifecycle freshness/replay, complete guest equivalence and BC-1 conformance remain
open. Actual final enrolment/CredValid proofs and independent verification remain
open. Privacy/ZK leakage and qualified unlinkability, quantum/security accounting,
Section VIII extraction/simulation, DEP-001/002, and remaining Stage 2 bounded
keygen/signing/revocation/update/release obligations remain open. The active manuscript
profile and inactive 64M BC-1 proposal are unchanged. This package ends here.
