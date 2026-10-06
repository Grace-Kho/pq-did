# R0-CREDVALID-CYCLE-1 — execution-only cycle attribution

19 September 2026, Asia/Singapore. **Package complete and stopped.** The original
instrumented CredValid reaches its 4194304-cycle cap while generating matrix
polynomial 25 of 30. Completed matrix SHAKE prefixes account for 77.15% of that
capped prefix. One isolated correction reduces the measured single-polynomial
SHAKE/sampling interval by 20.26%, but the corrected, uninstrumented full guest
still reaches the same cap. Complete CredValid guest execution remains unvalidated.

Five new executions used slots 1, 2, 3, 4 and 6; slot 5 was unused. **Zero proof
attempts, no receipts; all three earlier proof attempts remain unused.** Execution
measurements establish no proving memory, proof size, proving time or privacy claim.

## Preserved baseline and identities

The [previous report](stage3_r0_succinct_feasibility_1.md),
[profile proposal](stage3_profile_change_proposal.md),
[draft amendments](stage3_profile_spec_draft.md), AGENTS, Python verifier/relations
and original Rust guest/host were reviewed. Only manuscript Sections II–VIII are
authoritative. The unchanged PDF SHA-256 is
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
No active suite, SPEC-001–004, production implementation, dependency version,
existing fixture or historical evidence was changed. The original experiment's
STOP marker remains in force.

The historical outcome remains: enrolment completed at **196311 user cycles**;
CredValid stopped with `Session limit exceeded: 4194304 >= 4194304`; zero proof
attempts and no receipts. This error is resource exhaustion, not a credential
rejection or a successful relation result. Native acceptance of the valid fixture
does not establish its complete guest execution.

The new workspace is
[experiments/r0_credvalid_cycle_1](../experiments/r0_credvalid_cycle_1/CONTRACT.md).
The [baseline record](../experiments/r0_credvalid_cycle_1/evidence/baseline.json)
copies original build/tool/resource and fixture identities. The
[new manifest](../experiments/r0_credvalid_cycle_1/evidence/manifest.json) records
all five registered images, ELF/program hashes, source inventories and build-source
snapshots. Each snapshot matches every source hash captured at registration.

| Build | User ELF SHA-256 | Image ID |
|---|---|---|
| Original, preserved | `ed892a4aa0325dec09eb505f9cdb4e65e747bbc654c9b87c43fbdf28d577f0cb` | `6bc26dc2988e528e155085ca960c558787e2be1c1bd0e880205cffeca1498c71` |
| Original computation, diagnostic | `70725d97679c6ad3381b2dfc9cb115e60bfb786a7309b64c124b3080c9ffc5ce` | `b47d9b4a712711fc525fb43537ae0d13c210074f739b14a3b03b040dbc3b3d78` |
| Corrected, uninstrumented | `d5ef3682a8956ba03b710cdee14f02dbf967ec05e935c3d73fcc582aac19aaf2` | `a7b77747d5ebff0e520d17fc188afef06dfb91690062cb96f6b3cff78e93ae94` |

The original combined user/kernel programme SHA-256 is
`153cf7a5758a8097d3b192fd590301546c64fde7582dde2cfc2db3aa3261c3d3`;
the corrected programme is
`668dd886b66772593aea42e53d967d61f2e1a8c1e750add482acc0ed09963a09`.
The original manifest's registry labels its combined `.bin` as `elf`; the table
above distinguishes the actual user ELF. Both identities are retained.

All full-guest runs use the original synthetic `cred-alpha-42` fixture. Its public
SHA-256 is `63e0cbdedab8ba7a9e56ee7e3295cf6f1fbc2b31be1e35dcfd84db9554679231`;
its private-fixture SHA-256 is
`8d670ab5ae1339ba162a0b124d4657a67043d567eb1d3bf5bafe7a7f8f4b8ead`.
Private bytes are runtime inputs and are not logged.

Installed SDK/r0vm **3.0.6**, SDK commit
`1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`, custom rustc **1.97.0-dev**
(`e638c6cfea1eff5fbbb24a27e60538e3760d21b8`, LLVM 22.1.6) and cargo
**1.97.0-dev** (`c980f4866`) were reused offline. Target:
`riscv32im-risc0-zkvm-elf`; release optimisation 3, thin LTO, one codegen unit,
overflow checks enabled, guest panic abort. Original flags remain:

```text
-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"
```

Diagnostics add a feature-gated SDK cycle-count/stderr dependency and markers;
component builds also enable `components`. Corrected full CredValid enables neither.
Host/guest lockfile differences are local path/feature edges only: every registry
package name, version and checksum matches the original locks. Platform/zkos 2.2.3,
rv32im 4.0.5, sha3 0.10.8 and keccak 0.1.6 remain pinned. Earlier dependency/security
qualifications remain applicable; this package makes no new adoption decision.

## What the cap counts and how evidence survives

The [pinned source inventory](../experiments/r0_credvalid_cycle_1/evidence/source_api_review.json)
supports this exact API chain:
`guest::env::cycle_count` → `SysCycleCount` → `ctx.get_cycle` → rv32im
`Executor.cycles.user`. `CycleLimit::Hard` checks this same counter against 4194304.
The count advances through instruction and charged syscall/accelerator hooks.
There is no machine-mode exclusion in `inc_user_cycles`: “user cycles” is the
executor's accounting name, not application-only retired instructions or host OS
user CPU time. VM kernel instructions charged through these hooks are included.

The pinned executor separately accumulates paging cycles and reserved capacity.
Each completed segment contributes `2^po2` capacity; its reserved accounting is
capacity minus user and paging cycles, including unused padding. Segment admission
also reserves fixed overhead. Those quantities do **not** consume the hard user-cycle
allowance. Host wall/CPU time is a different measurement.

`ApiClient::execute` with local r0vm is execution-only; this host contains no proving
command or proving API call. `disable-dev-mode` is compiled in, development mode
is zero, and execution has no external network. The callback exposes completed
segment user cycles and `po2`, but not separate paging/system/reserved counts.
We retain only those metadata and discard the private segment assets. Therefore
capacity minus user cycles is reported as an **aggregate**, not a paging-only cost
or full-session total for an interrupted run. A separate VM kernel/user split is
not exposed by this measurement path.

Pinned pprof finalisation follows successful `exec.run`; it cannot be relied on
after this error. Instead, 16-byte phase-ID/cycle records are written incrementally
to bounded stderr files, outside the journal. No instruction/register/memory/witness
dump is enabled. Counter values never enter calculations, acceptance branches or
the public statement. The journal encoding and commit remain unchanged.

Adjacent empty markers measured **153 cycles** in every instrumented run. Reported
intervals are raw boundary-to-boundary deltas, including one marker and intervening
glue. The 95-marker prefix has nominal marker cost about 14535 cycles (0.35% of the
cap), not a precisely measured global subtraction. Instrumentation, outlining,
inlining, memory layout and paging may change other costs. The isolated original
polynomial interval differs from the full guest's interval; neither is substituted
for the other. There is no call-stack profile separating every nested helper's cost.

## Computation map and observed prefix

The [pre-instrumentation contract](../experiments/r0_credvalid_cycle_1/CONTRACT.md)
records the complete call map. Input framing precedes expected-instance/schema and
credential validation, holder opening with SHA3-384 and exact Mcred construction.
Signature verification then formats the pure context, decodes public-key/response/
hints, expands all 30 matrix polynomials, hashes `tr`/`mu`, samples the challenge,
constructs twiddles, computes five response NTTs and matrix products, challenge and
six public-key NTTs, six inverse NTTs and hints, final challenge hashing, strict norm
and hash comparison, then journal preparation/commit.

This is ordinary Rust integer/array code. No BC-1 gate emitter or BC-1 division
emulation is linked or called. Release optimisation was already enabled. Inspection
found bit-at-a-time unpacking, matrix allocation/zeroing, seed copies, fresh XOF
initialisation per polynomial, eagerly generated prefixes, dynamic twiddle powers,
and software 64-bit remainder helpers in NTT/inverse NTT. These are source findings;
only the measurements below establish costs.

The following rows partition the **entire 4194304-cycle observed prefix**, without
overlap. Fine-grained deltas and marker positions are in the
[prefix analysis](../experiments/r0_credvalid_cycle_1/evidence/baseline-prefix.analysis.json).

| Observed work | Raw user cycles | Boundary/status |
|---|---:|---|
| Entry, initial calibration | 757 | Before input marker |
| Input reads | 1657 | Complete |
| Envelope/parameters/schema and hand-offs | 12108 | Complete; parameter interval 7740 |
| Credential structure | 12097 | Complete |
| Holder opening and preceding marker | 98095 | Complete; nested SHA3 interval 86023 |
| Exact Mcred and hand-offs | 5023 | Complete; Mcred interval 4681 |
| Signature context/key/response/hints and hand-offs | 439745 | Complete; key unpack 163712, response unpack 267968, hints 4992 |
| Matrix allocation/initialisation | 50039 | Complete |
| SHAKE/seed preparation, first 24 polynomials | 3236060 | Complete; 134832–134836 each |
| Rejection sampling, first 24 polynomials | 220226 | Complete; 9172–9186 each |
| Matrix loop hand-offs | 3904 | Complete |
| Polynomial 25 SHAKE/seed preparation | 114593 | **Partial at cap**, row 4/column 4, zero-based |
| Total observed prefix | **4194304** | Resource stop |

Nested examples in the last column are **included** in their row, not additional
costs. Matrix work including allocation accounts for 86.42% of this capped prefix;
completed SHAKE intervals alone account for 77.15%. These percentages do not describe
the complete computation. Polynomial 25 sampling, polynomials 26–30, `tr`/`mu`,
challenge sampling, all arithmetic/hints/final checks and journal work were not
reached in this run. Complete relation costs for those phases remain unmeasured.

## Isolated measurements and the single correction

The first result justified investigating unused SHAKE output. Slot 2 measures the
same `shake`/`rej_ntt` functions through an outlined `matrix_poly` helper also used
by CredValid. Slot 3 measures that same helper after the correction. Both receive
the original row-0/column-0 seed and an independently checked expected polynomial
as runtime inputs. Python `hashlib`, the unchanged bounded sampler and a separate
literal candidate decoder agree. Only the comparison status enters the component
journal; fixture values are kept in private local files.

| Isolated component | Raw interval | Complete component session |
|---|---:|---:|
| Original matrix polynomial | 142199 | 154451 |
| Corrected matrix polynomial | 113393 | 125641 |
| Unchanged twiddle construction | 567539 | Included in NTT component below |
| One unchanged response NTT | 409218 | 991483, including twiddles/input/comparison/journal |

The polynomial interval drops **28806 cycles / 20.26%**. Original subintervals are
134594 for SHAKE/setup and 7605 for sampling. Corrected subintervals are 18540 for
XOF initialisation and 94853 for sampling **including deferred SHAKE output**.
Those subintervals change meaning; their combined interval is the useful comparison.

The sole correction is demand-driven matrix XOF output, in
[mldsa.rs](../experiments/r0_credvalid_cycle_1/relation/src/mldsa.rs).
It fills the bounded buffer in 168-byte chunks, with a final partial chunk up to
1026. For this component, 768 bytes are consumed and 840 generated, versus the
original eager 1026. Pinned SHAKE's reader permutes after each emitted block:
five output-block calls replace seven, with identical prefix bytes. It still
consumes three bytes per candidate, counts rejected candidates and errors before
consuming beyond 1026. The arithmetic/mask/acceptance test and the separate 256-byte
challenge sampler are unchanged. No private check or computation moves to the host.

Before/after source bundles and ELF/program identities are immutable snapshots;
the [diff](../experiments/r0_credvalid_cycle_1/evidence/correction.diff) also shows
feature-gated diagnostic wrappers and focused tests. The helper outlining is shared
by both component builds. No second optimisation was attempted.

Slot 4 resolves a remaining uncertainty: whether eliminating unused matrix output
leaves only cheap arithmetic. It calls the unchanged `zetas` and `ntt` on the first
original response polynomial, checked independently by the unchanged Python NTT.
Both are substantial. Static selected-function inspection finds `__moddi3` calls,
but these measurements do not isolate remainder-helper cycles. Twelve forward
transforms and six inverse transforms occur in full verification; one isolated NTT
does not establish their total or a full guest count. No component totals are added
into a claimed complete execution cost.

Slot 6 uses the corrected full guest with **no diagnostics**, the same original
fixture and the same cap. It again returns the exact cycle-limit error. Its zero
marker bytes confirm that no phase evidence was emitted, so its stopping phase is
unknown. The capped before/after full executions establish neither full-guest speedup
nor accepted/rejected guest equivalence.

## Runs and resource boundaries

Every execution retained segment exponent 16, 4194304 user cycles, one worker,
2 GiB for the complete descendant cgroup, no swap, two CPU threads, 60 seconds per
target and a 300-second cumulative execution envelope. Setup/build retained one job
and 1200 seconds cumulative; both workspaces share the existing 10 GiB allowance
with a conservative 9 GiB stop. Diagnostic output is capped at 64 MiB, with a 60 MiB
stop; markers have a separate 64 KiB/run limit and segment metadata 256 entries/run.
The baseline workspace is mounted read-only in guarded services. Admission checks
require worker allowance plus 2 GiB of available-memory reserve.

| Slot / target | Result | Host execute seconds | Completed segment prefix: user / padded capacity | systemd memory peak |
|---|---|---:|---|---|
| 1 / baseline-prefix | Cycle cap | 0.218498 | 4170359 / 11010048, 168 segments | 39.7M |
| 2 / matrix-before | Complete | 0.033253 | 154451 / 409600, 7 segments | 39.2M |
| 3 / matrix-after | Complete | 0.032394 | 125641 / 360448, 6 segments | 39.3M |
| 4 / ntt-z0 | Complete | 0.084887 | 991483 / 2195456, 34 segments | 95.4M |
| 5 | Unused | — | — | — |
| 6 / corrected-full | Cycle cap | 0.244553 | 4171733 / 11206656, 171 segments | 101.2M |

Times are single local execution-API observations, not benchmarks or proof times.
Memory figures retain systemd's rounded units; all report swap 0B. Short runs can
finish between RSS samples: the small sampled RSS values must not be mistaken for
exact peaks. Kernel memory limits remained effective. Peak sampled cgroup charge
across builds was about 1.60 GB; rounded initial-build systemd peak was 1.5G. No
memory, time or disk limit was hit. The only target stops were the two user-cycle
caps. Guard status `pass` means the diagnostic command completed correctly; the
separate result status `cycle_limit` does not mean CredValid accepted.

For slot 1, completed-segment capacity minus user cycles is 6839689; for slot 6 it
is 7034923. These combine paging/reserved/padding and exclude the unfinished segment.
The cap is still 4194304 **user** cycles, even though padded capacity is much larger.

Exact commands, admission readings, sampled peaks, cumulative times and output
sizes are retained in the [run ledger](../experiments/r0_credvalid_cycle_1/evidence/run_ledger.json),
[final audit](../experiments/r0_credvalid_cycle_1/evidence/final_audit.json) and per-run
`.log`, `.result.json`, `.segments.jsonl`, `.markers` and `.analysis.json` files.
No capped target was retried unchanged and no limit was increased.

## Commands and validation

Commands below describe the completed runs; the new STOP marker now rejects replay.
From the project root, the guard form was:

```sh
python3 experiments/r0_credvalid_cycle_1/scripts/run_limited.py --seconds 60 --slot 1 execute baseline-prefix -- target/release/pqdid-r0-host run baseline-diag cred-alpha-42 baseline-prefix
```

Subsequent slot/label/fixture/result tuples were `(2, component-before, matrix-00,
matrix-before)`, `(3, component-after, matrix-00, matrix-after)`, `(4, component-ntt,
ntt-z0, ntt-z0)` and `(6, corrected-plain, cred-alpha-42, corrected-full)`. Builds use
the same guard's `build` phase and the recorded `build_initial.sh`,
`build_component_before.sh`, `build_correction.sh`, `build_ntt.sh` and
`build_corrected_plain.sh` scripts. All Cargo builds are locked/offline; the initial
metadata resolution adjusts only local feature edges. Fixture scripts call the
existing project virtual environment. `analyse_run.py NAME` decodes saved markers
without another VM execution.

Initial native validation: three original sampler/arithmetic tests and all **35
comparisons** passed. Corrected native validation: **six tests and all 35 comparisons**
passed before slot 6. The three additional tests cover 12 rejection/refill cases
including exact 1026 consumption and exhaustion, the candidate high-bit mask and
`q-1/q` boundaries, and 120 seed/coordinate comparisons against the eager prefix.
The existing exact-256 challenge budget/rejected-byte test and signed arithmetic/
inverse test still pass. The 29 relation comparisons plus six signature-context
comparisons retain positive and negative acceptance expectations and exact journals.

Finite final checks cover Python Ruff lint/format, current Rust formatting, shell
syntax, JSON/TOML/Python parsing, documentation links, registered artefact and source
hashes, registry pin equality, immutable original assets/fixtures, execution count,
resource limits, zero proofs/receipts and refusal to replay the closed package.
The [preservation audit](../experiments/r0_credvalid_cycle_1/evidence/final_audit.json)
checks 7998 pre-existing files; only the authorised status/traceability documents
changed. Earlier 1432-test production regression evidence is reused, not rerun or
relabelled as new experimental coverage.

## Exactly one next-package recommendation

**Recommend a separately authorised higher-budget execution-only package,
`R0-CREDVALID-EXEC-24`: 16777216 user cycles (2^24) per execution.** Keep the corrected
implementation fixed, segment exponent 16, one worker, 2 GiB/no swap, 60 seconds per
run, existing storage limits and no proving. Allow at most two executions: first an
instrumented valid `cred-alpha-42`; only if it completes, one uninstrumented run of
the same fixture. Raise the metadata-only segment callback bound explicitly to
2048 records for that package; keep diagnostic output within 64 MiB. A cap/resource
stop ends the target with no retry or automatic increase.

The justification is observed substantial matrix work plus the isolated twiddle/
NTT costs and remaining transforms, while the corrected full guest still exhausts
2^22. Four times the cycle allowance is a bounded diagnostic headroom proposal,
**not a predicted complete cost or a guarantee of completion**. It aims to measure
the remaining full computation before further tuning. This proposal is neither
activated nor executed here. No renewed proof pilot is recommended at this boundary.

Full authentication/Merkle/non-revocation, complete guest equivalence, BC-1 conformance,
all proof work, candidate ZK leakage/quantum qualifications, concrete security losses,
Section VIII extraction/simulation, DEP-001/002, remaining Stage 2 signing/keygen,
revocation/update/release integration and lifecycle services remain outstanding.
No replacement profile is approved; the 64M/2 GiB BC-1 proposal remains inactive.
