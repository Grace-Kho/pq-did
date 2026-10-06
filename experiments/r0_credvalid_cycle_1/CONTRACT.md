# R0-CREDVALID-CYCLE-1 — pre-instrumentation contract

Authorised execution-only diagnostics, 19 September 2026. No proving commands,
proof generation, receipt generation, remote services or development mode.
The previous experiment, all historical source/builds/locks/evidence and its STOP
marker remain unchanged. Active suite, manuscript, SPEC-001–004, production Python
and dependencies are protected. Reuse installed SDK/compiler and cached locked
crates without network or version changes. Write only in this separate workspace
and the requested report/status/traceability documents.

Baseline: enrolment completed at 196311 user cycles; valid cred-alpha-42 reached
4194304 user cycles; zero proof attempts and no receipts. Identities, original flags,
versions, fixture and resource record are copied into evidence/baseline.json.

## Source map before instrumentation

The original guest reads public/private bytes, calls relation::evaluate, builds the
public journal and commits it. Evaluate parses the diagnostic envelope, validates
parameters (suite/keys/iref/repeated schema), expected metadata and private credential
framing. CredValid validates certificate B, signature width, both attribute vectors,
rid, empty auxiliary and metadata, then opening (canonical attributes plus SHA3-384),
exact Mcred and mldsa::verify with the fixed credential context.

The verifier formats the external context, unpacks the public key, response and
hints, allocates all 30 matrix polynomials, then for each row/column creates a fresh
SHAKE128 state and eagerly materialises 1026 bytes before bounded RejNTTPoly. It
hashes the public key (tr), tr plus formatted message (mu), materialises a 256-byte
SHAKE256 prefix for bounded SampleInBall, computes twiddle factors, five response
NTTs, matrix/vector products, challenge/key NTTs, six inverse NTTs with hints/packing,
final SHAKE256 challenge and finally the strict norm/challenge comparisons.

Possible costs, not measured conclusions: software Keccak on RV32; eager unused
XOF bytes; repeated allocations/copies; checked i64 modular arithmetic; dynamic
zetas; bit-at-a-time unpacking. Release opt-level=3, thin LTO, one codegen unit,
overflow checks and panic=abort are already enabled. This Rust code uses ordinary
arrays/integer arithmetic: no pqdid.bc1 gate emitter or BC-1 division emulation is
linked or called. Do not infer the dominant cost from native timings.

## Pinned measurement mechanism

SDK 3.0.6 env::cycle_count -> SysCycleCount -> SyscallContext::get_cycle returns
risc0-circuit-rv32im 4.0.5 Executor.cycles.user, the same counter tested by Hard(limit).
The count excludes separate paging and reserved/padded segment accounting. It counts
work charged by inc_user_cycles, including instructions and charged ecall operations;
it is not simply retired application instructions or wall time.

The built-in pprof output is finalised after exec.run succeeds, so it cannot be relied
on to export a capped prefix. Use feature-gated fixed-size phase/cycle records on
stderr, written incrementally to a bounded local file, plus the existing Execute
segment callback retaining only user cycles/po2 (discard segment assets). No memory,
register, instruction or witness dump. No diagnostic counters affect relation
acceptance, hashes, arithmetic or journal construction. Instrumented builds are
separate and labelled; no instrumentation in the final corrected guest, if any.
Counter values are unchecked host diagnostics, never proof claims.

Marker overhead will be calibrated by adjacent empty markers. Raw phase deltas
include instrumentation at boundaries; separately disclose layout/compiler effects.
Do not add nested/inclusive costs or isolated components into a claimed full cost.

## Limits and adaptive run allocation

At most six new VM executions, persisted before launch, failed/interrupted starts
included. Slot 1: original valid cred-alpha-42 with instrumentation. Slots 2–5:
at most four focused component runs, each justified by that result and using the
same implementation functions/runtime inputs. Slot 6 is reserved exclusively for
same-fixture, same-cap uninstrumented validation of one justified correction; unused
slots need not be filled. No unchanged capped-target retry. Native tests are not VM
executions. A cap ends that target, not automatically the independent diagnostic
questions authorised in this package. Memory/time/disk exhaustion stops large work.

Every execution: 2^22 user cycles, segment exponent 16, 60 s wall; 300 s aggregate
execution (also below the prior 1800 s package envelope); 2 GiB complete descendant
cgroup, MemorySwapMax=0, CPUQuota=200%, one worker, at most two threads. Build/setup:
one job, 1200 s cumulative subprocess wall, same 2 GiB/no-swap cap. Native/format/data
checks: 60 s each, 300 s aggregate, 256 MiB except compilation under build limits.
Require MemAvailable >= worker allowance +2 GiB reserve before each guarded phase.

Total ordinary disk across both R0 workspaces stays below 10 GiB, with a conservative
9 GiB stop. New evidence/fixtures/snapshots/artefacts/scripts/source (excluding compiler
cache and target/tmp) are diagnostic files, capped at 64 MiB aggregate with a 60 MiB
stop; baseline experiment output also remains inside its 256 MiB allowance. Marker
streams are capped at 64 KiB per execution and segment metadata at 256 entries.
Private network namespace permits loopback IPC only. The baseline workspace is
mounted read-only inside transient services. Reuse the previously validated cgroup
control design; confirm effective settings and available headroom on new runs.

A correction is optional and evidence-led: one small change, all predicates/hashes/
contexts/canonical bytes/sampler bounds/exhaustion retained. Snapshot before/after
sources and image/build identities; native differential and relevant boundary tests
must pass before slot 6. Do not use fixture constants or unchecked intermediate
results in full CredValid. Any isolated component fixture is labelled as such.
