# S3-AURORA-TRANSCRIPT-REGRESSION-1

**Sixteen regression cases passed; package completion is blocked.** The subsequent
preservation-scope preparation failed because the inherited traversal roots omit
the new experiment directory. No complete preservation audit ran. The failure and
all successful case evidence are retained; no retry or limit increase was made.

This package implements the approved **PQDID-AURORA-TRANSCRIPT-EXP2** public
transcript harness as a **source-faithful isolated Python reimplementation**.
It does not execute the pinned native libiop implementation or a native patch.
Results below establish only the implemented transcript behaviour on the specified
public inputs. No Aurora proof, private prototype or accepted profile is created.

## Authority, provenance and admission

Only manuscript Sections II–VIII and agreed clarifications are authoritative.
The [correction contract](stage3_aurora_transcript_correction_contract.md), its
exact pseudocode and TR-01–TR-16 matrix are reused. The
[preflight](data/s3_aurora_transcript_regression_1/preflight-evidence.json) verified
the preceding 48-file seal
`1dff5c6d002c88b68566924ca499dfd1397f98b99770ee726eee064024fabe77`,
53 assessed source identities, all 21 pinned upstream source files, and the
unchanged synthetic inputs before implementation. Manuscript SHA-256 remains
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The upstream source commit remains
`a2ed2ec2f3e85f29b6035951553b02cb737c817a`; no snapshot file was edited.

The direct user amendment raises invocations **386 → 402**, exactly sixteen
individually counted cases including the explicit TR-02 repeat. Opening
implementation use is **332.1767816620413/374 s**, leaving
**41.82321833795868 s**. This package has a 25-second cap, ten seconds reserved
inside it, and five charged operator/bookkeeping seconds under the existing
accounting convention. Preflight, checks, case group, scope preparation and audit
are charged by their measured outer guard times. Time spent inside a case is a
subset of the case-group time, never added twice.

The [configuration](data/s3_aurora_transcript_regression_1/config.json) retains
256 MiB cgroup memory, zero swap, one worker, two CPUs and four controlled
processes. Existing 60/55-second command/child maxima, 8 MiB temporary space,
1 MiB/file, 60 KiB diagnostics and 9 GiB disk stop remain; tighter reservations
are 1 s preflight, 1 s checks, 3 s cases, 1 s preparation and 4 s audit. The
256 KiB new-package subcap conservatively includes experimental sources and this
report as well as evidence. The cumulative output ledger opens at 9,704,449 bytes.
Analysis **211.51345554180443 s** and isolation **250.22 s**, with 22 original
identity cases pending, are unchanged and never borrowed.

## Implemented boundary and exact behaviour

The four isolated files are
[engine](../experiments/aurora_transcript_regression_1/transcript.py),
[independent oracle](../experiments/aurora_transcript_regression_1/reference_trace.py),
[cases](../experiments/aurora_transcript_regression_1/cases.py) and
[usage/provenance](../experiments/aurora_transcript_regression_1/README.md).

EXP2 uses exactly the contract's unkeyed sequential BLAKE2b-512, 64-byte output,
domain labels, big-endian integer/length framing and complete input spans.
The trusted local BASE/GROUPED descriptors bind parameter bytes, relation bytes
and a complete round/challenge plan. The statement is the existing canonical
`encode_auth_statement(expected_pp, X)`, not caller-provided status metadata.
Initialisation and challenge preimages include the full framed public statement.
Roots and separate message vectors are framed in order, including empty vectors
and empty scheduled rounds. The global counter advances per challenge; squeezing
does not mutate the stored state, and the next absorption binds the consumed
counter. All required preceding challenges must be consumed before the next round.

The immutable round interfaces enforce exact types, counts and widths. Boolean
counters, unsupported versions, alternate kinds or malformed round encodings are
rejected. Kind 1 returns the first 24 bytes as field bits; kind 2 returns the low
h bits for the fixed schedule, including zero for h=0. No unused bytes are pooled.
Synthetic indices are extraction checks, not actual Aurora query positions.
The replay path strictly decodes round frames, checks exact end of input and
canonical re-encoding, and reconstructs the same schedule. It returns diagnostics
only. No compatibility path to the old transcript or proof backend is installed.

Operations construct their next state, trace and outputs before publishing them.
Failure retains the prior state/counters for public diagnostics, poisons the object
and releases no partial value. Finished objects reject further operations.
Initialisation failure returns no usable object. Process/resource termination is
an incomplete run, never successful verification.

Fixture reads are bounded to 64 KiB before JSON parsing; base64url spelling and
re-encoding are exact, and decoded E is capped at 32 KiB. The typed adapter's
capacity walk bounds depth, node count, collections and aggregate byte material
before the existing canonical encoder allocates E. Schema strings and Boolean
policy values retain their existing types; they are not converted to transcript
integers. These are fixed synthetic harness capacities, not changes to accepted
credential semantics. No general streaming-parser or hostile-Python-object
security claim is made. No hidden credential, identifier, holder secret or path
is appended to the public statement. No URL or external service is contacted.

## Expected values and scope of comparisons

Expected transcripts come from the sealed contract's straight-line byte recipe,
implemented independently in `reference_trace.py`. It imports neither candidate
framing nor descriptor, schedule, state-transition or challenge helpers. Its
three-round plan and expected record construction are written independently;
only the existing BLAKE2b primitive is shared. Expected E starts with the sealed
presentation bytes. TR-03 independently replaces only the fourth canonical
context field (nonce) for expected E, then checks the candidate's typed encoding.

TR-01 derives its expected values inside its counted invocation; no vector probe
precedes it. Mutated expected traces are computed inside their respective cases.
Exact preimages, complete 64-byte states/blocks, round frames, counters, mapped
outputs and prover/replay agreement are compared in memory. The evidence retains
full states/blocks and round frames, fixture provenance and preimage equality
results. Repeated large X-containing preimages are reproducible from the recipe,
not copied or truncated into every report.

Mutation checks report the observations for the fixed vectors. They do not claim
that every input change changes every finite output. The zero-width result must
remain zero and an 8-bit index can coincide. An unexpected full-state anomaly
would stop the package; there is no search for alternative test inputs.

TR-16 is the explicit **negative control**: the source-equation model hashes only
the first 64 bytes of `S || u`, reproducing the omission for two distinct digests.
The length-only repair hashes all 128 bytes and is compared with independent
incremental hashing. This is neither execution of a native patch nor a forgery.
The minimal length repair and the versioned EXP2 construction remain distinct.

The qualified statement-binding finding is preserved: the selected fresh native
BLAKE2b chain lacks explicit initial full-statement binding, while **algebraic
primary-input checks exist** elsewhere in the verifier. This harness neither
executes those checks nor proves statement-independence of the whole protocol.

## Remaining obligations and next action

These local corrections do not close **AURORA-BRIDGE-001**. Native ABI/integration,
the exact registration/round schedule, full authentication relation/compiler,
joint query/mask simulation, grouped/selective commitment transformation,
restricted-state restoration/extraction, adaptive privacy and concrete-hash
composition remain unresolved. Arithmetic correctness and deterministic traces
do not establish knowledge soundness, zero knowledge or collision resistance.
Adaptive Delta_tail, component advantages at reduction budgets and production
custody, entropy, erasure and side-channel obligations remain open.

Recommend one next action: **S3-AURORA-TRANSCRIPT-PRESERVATION-REPAIR-1**. Correct
only the package's inventory-root construction to include the exact new root
`experiments/aurora_transcript_regression_1` alongside every inherited root. Retain
all four files in the required set, preserve the failed preparation record, and
reuse the completed cases without rerunning them. Validate the audit-helper change
and perform the still-unexecuted complete preservation audit within the unchanged
256 MiB ceiling and remaining implementation time, after explicit authorisation
for the correction/checks. No broader directory exclusion or baseline replacement
is justified. This repair has not started.

The concrete downstream integration gap remains mapping native registration,
direct-message/query order and the no-PoW transition to EXP2 with the BCS refinement
obligations explicit. That integration work is deferred until preservation closure;
no private witness, build, IOP/proof execution or profile adoption is admitted.

Production code, signed encodings, active profile, parameters, dependencies,
manuscript and historical results remain protected. Normal proof verification
remains fail-closed. **Stages 2–3 remain open.** Raw-view integration and CPU
proving remain paused; isolation stays safely stopped and unactivated. Proof
ledger remains **two attempts used, one unused**.


## Individual executed outcomes

The authorised matrix completed once. Each row links its full retained result;
times include local expected-value derivation and evidence writing within that
case, and are not throughput or cryptographic-performance claims.

| ID / cumulative invocation | Contract case | Outcome | Seconds |
| --- | --- | --- | --- |
| [TR-01](data/s3_aurora_transcript_regression_1/TR-01.json) / 387 | baseline complete trace, including empty scheduled records, four challenges and legal absorb after squeeze | Pass | 0.005772703 |
| [TR-02](data/s3_aurora_transcript_regression_1/TR-02.json) / 388 | fresh second baseline run, counted repeat | Pass | 0.002133696 |
| [TR-03](data/s3_aurora_transcript_regression_1/TR-03.json) / 389 | typed public context nonce first byte XOR1, re-encode unchanged remaining fields | Pass | 0.003043789 |
| [TR-04](data/s3_aurora_transcript_regression_1/TR-04.json) / 390 | root_a last byte XOR1 | Pass | 0.002252964 |
| [TR-05](data/s3_aurora_transcript_regression_1/TR-05.json) / 391 | field_a last byte XOR1 | Pass | 0.002458826 |
| [TR-06](data/s3_aurora_transcript_regression_1/TR-06.json) / 392 | submit round1 before round0 | Pass | 0.000979981 |
| [TR-07](data/s3_aurora_transcript_regression_1/TR-07.json) / 393 | swap the two one-field R0 messages | Pass | 0.002331949 |
| [TR-08](data/s3_aurora_transcript_regression_1/TR-08.json) / 394 | second trusted harness plan uses one two-field R0 message rather than two one-field messages | Pass | 0.002256473 |
| [TR-09](data/s3_aurora_transcript_regression_1/TR-09.json) / 395 | empty canonical statement byte input to typed adapter | Pass | 0.000068394 |
| [TR-10](data/s3_aurora_transcript_regression_1/TR-10.json) / 396 | root_a truncated to63 bytes | Pass | 0.001086496 |
| [TR-11](data/s3_aurora_transcript_regression_1/TR-11.json) / 397 | field_a truncated to23 bytes | Pass | 0.001096617 |
| [TR-12](data/s3_aurora_transcript_regression_1/TR-12.json) / 398 | request transcript version1 | Pass | 0.000092943 |
| [TR-13](data/s3_aurora_transcript_regression_1/TR-13.json) / 399 | after R0 challenge0, attempt R1 before remaining two R0 challenges | Pass | 0.001148157 |
| [TR-14](data/s3_aurora_transcript_regression_1/TR-14.json) / 400 | request challenge1 before challenge0 | Pass | 0.000998908 |
| [TR-15](data/s3_aurora_transcript_regression_1/TR-15.json) / 401 | append a fourth round after valid finish | Pass | 0.002274214 |
| [TR-16](data/s3_aurora_transcript_regression_1/TR-16.json) / 402 | isolated old omission equation and length-only repair for two64-byte digests | Pass | 0.000057618 |

Case-group internal elapsed: **0.033862325 s**; outer guarded
execution **0.153468895 s**. Effective cgroup memory.peak was
**18,161,664 bytes**, with separately sampled
tree RSS **36,843,520 bytes**. No resource event or
incomplete result occurred. These timings include this small transcript harness,
not native IOP execution, proof generation or verification.

TR-16 reproduced identical old states for the two distinct digest inputs; the
full-span repair produced the independently expected distinct states for those
fixed vectors. The negative control remains isolated from EXP2. No forgery was
attempted. TR-01/TR-02 traces matched exactly. TR-03/04/05/07/08 matched their
independent changed-input traces. Mapped-output equality to the baseline was:

| Case | Field 0 | 8-bit index | Zero-width index | Field 1 |
| --- | --- | --- | --- | --- |
| TR-03 | different | different | equal | different |
| TR-04 | different | different | equal | different |
| TR-05 | different | different | equal | different |
| TR-07 | different | different | equal | different |
| TR-08 | different | different | equal | different |

These are observed finite-vector results. The zero-width output intentionally
coincides. Malformed/phase cases retained prior state and yielded no new value;
subsequent challenge requests on poisoned objects were rejected. TR-09/TR-12
returned no usable object. No resource-exhaustion or native-library fault was
injected: source handling of such exceptions is not validated by those tests.
The approved sixteen cases are not exhaustive parser, counter-overflow or
cryptographic-failure coverage.


## Stopped completion and resource ledger

The regressions passed **16/16**, but the package is **incomplete**. The
[scope preparation](data/s3_aurora_transcript_regression_1/prepare.log) exited 1
in **0.214534309 s**. `prepare.py` inherited the preceding inventory
roots and added the four new experiment files to required names without adding
`experiments/aurora_transcript_regression_1` to the traversed roots. The inventory
therefore reported those four present files as missing (2,575 names traversed,
no unexpected names). This is an audit-scope construction error, not a transcript
mismatch, resource breach or detected protected-file modification.

No `scope.json` was published, and **zero full preservation audits ran**. Original
baseline identities were checked during preparation, but that is not the required
complete content/inventory audit. The [incomplete result](data/s3_aurora_transcript_regression_1/result.json)
records this distinction. `STOP.json` remains in place. Preparation was not
repeated, the scope/engine was not repaired after execution and no more cases were
admitted. The success-only `close.py` helper was not executed. Its prepared success
branch is not evidence of closure. No audit success is claimed by the additive
failure-evidence seal.

| Measurement | Result |
| --- | --- |
| New counted invocations | 16, including authorised TR-02 repeat |
| Cumulative invocation ledger | **402/402** |
| Guarded job elapsed, including failed preparation | 0.676312445 s |
| Implementation charge including five bookkeeping seconds | **5.676312445 s** |
| Cumulative implementation charge | 337.853094107/374 s |
| Remaining implementation allowance | **36.146905893 s** |
| Package cap / completion reserve | 25 s / 10 s, preserved |
| Maximum guarded cgroup-v2 memory.peak | 23,035,904 bytes |
| Maximum separately sampled tree RSS | 50,630,656 bytes |
| Failed-preparation cgroup peak | 23,035,904 bytes |
| Audit memory / wall time | Not measured: audit not started |
| Temporary storage observed / retained | 0 / 0 bytes |
| Analysis unchanged | 211.51345554180443 s remaining |
| Isolation unchanged | 250.22 s; 22 original cases pending |

All guarded commands returned and their child workloads terminated. No service or
host resource was activated. The unchanged 256 MiB cgroup scope covers each worker
and descendants, including charged file-cache/kernel memory; swap is zero. RSS
is a separate sampled metric, and the monitor remains outside the worker cgroup.
No memory max/OOM event occurred. Final failure bookkeeping is bounded by 256 MiB
address space, five-second CPU/alarm, two CPUs and 1 MiB/file and is included in
the five-second charge. Executed-source identities, append-only historical report
prefixes and local links were checked during closure; this does not replace the
unexecuted full preservation audit. No functional tests or transcript computations
were repeated during closure.

The immediate next action is the narrow preservation repair above, superseding
the earlier conditional adapter recommendation in the running status updates.
AURORA-BRIDGE-001 remains open; Stages 2–3 remain open. Raw-view integration and CPU
proving stay paused, isolation safely stopped/unactivated. Proof ledger remains
**two attempts used, one unused**.


## S3-AURORA-TRANSCRIPT-PRESERVATION-REPAIR-1 — stopped after audit discrepancy

**The root omission is corrected; the regression package remains incomplete.**
The sole traversal addition is `experiments/aurora_transcript_regression_1`.
Its authorised `README.md`, `cases.py`, `reference_trace.py` and `transcript.py`
were confirmed against the unchanged failure-evidence seal. All inherited roots,
expected entries, digests and existing allowlists remain. No exclusions or baseline
regeneration were introduced. The original preparation, STOP marker, manifests and
all sixteen passed case records remain unchanged; no case was rerun.

Repair-only seal verification, lint and formatting passed. The **one authorised
corrected preparation** passed in 0.237286419 s with
**2,596 names**, zero missing and zero unexpected entries:
all four false missing-file reports were resolved. The complete scope is stored
losslessly as `repair-1/scope.json.gz` to preserve the existing storage subcap;
its decoded fields are unchanged apart from the root and explicit repair evidence
bookkeeping. Baselines and the protected-file allowlist were not replaced.

The **one authorised full audit failed**, exit 1, after 2.539544389 s.
The adapter reused the original audit with its output directory set to `repair-1`.
Although JSON reads correctly reused the original case ledger, the audit's direct
`(D / row["evidence"]).is_file()` check consequently looked for `TR-01.json` under
`repair-1/`, not its retained location one directory above. This is an error in
this repair's evidence-path adapter. All sixteen original case files exist; their
hashes were checked in the earlier frozen-input comparison. No evidence was
missing or relocated. No correction or second audit was attempted after this error.

[Audit diagnostic](data/s3_aurora_transcript_regression_1/repair-1/full-audit.log),
[phases](data/s3_aurora_transcript_regression_1/repair-1/phases.json) and
[incomplete result](data/s3_aurora_transcript_regression_1/repair-1/result.json)
are retained. Completed phases include baseline identities, **8,759 original +
2,142 supplemental = 10,901 disjoint content comparisons**, historical report
prefixes, frozen assessed/experimental inputs, sealed isolation inputs and ledgers.
The later evidence-presence check failed; final inventory, complete validation
report/readback and successful outer-guard completion were not reached. Completed
content comparisons do **not** establish a completed preservation audit.

| Repair/aggregate measurement | Result |
| --- | --- |
| Audit wall time / exit | 2.539544389 s / 1 |
| Audit cgroup-v2 memory.peak | 23,654,400 bytes |
| Audit sampled tree RSS | 40,808,448 bytes |
| Maximum repair cgroup peak / sampled RSS | 24,141,824 / 40,808,448 bytes |
| New guarded command time | 2.931766078 s |
| Additional repair charge, including five bookkeeping seconds | **7.931766078 s** |
| Original plus repair package charge | **13.608078523/25 s** |
| Remaining aggregate package allowance | **11.391921477 s**, including protected ten-second reserve |
| Remaining implementation allowance | **28.215139815 s** |
| Regression invocations | **402/402**, zero new invocations |
| Analysis / isolation remaining, unchanged | 211.51345554180443 s / 250.22 s |
| Temporary storage observed / retained | 0 / 0 bytes |

No limit was raised and no resource breach occurred. The 256 MiB cgroup still
covers each worker and descendants, including charged cache/kernel memory; swap
is zero. RSS is a distinct sampled metric. The final failure bookkeeping uses
256 MiB address space, five-second CPU/alarm, two CPUs and 1 MiB/file within the
five-second repair charge. Commands and children returned; no host activation or
persistent workload was introduced. Both failure records remain preserved.

**Stop outcome:** no further attempt is authorised or started. The remaining
blocker is correct resolution of retained case-evidence paths in the audit adapter;
the passed transcript cases must continue to be reused. Package completion is not
claimed. The original ten-second reserve remains within the displayed package
balance; that balance is not permission for another attempt.
AURORA-BRIDGE-001 and Stages 2–3 remain open. There is no native patch validation,
proof-security claim or private prototype admission. Raw-view integration and CPU
proving remain paused; isolation safely stopped/unactivated, 22 identity cases
pending. Proof ledger: **two attempts used, one unused**.


## Repair-2 stopped before audit

All 16 retained case paths matched their original manifest. Inputs remain in
`docs/data/s3_aurora_transcript_regression_1/`; new outputs are in
[repair-2/evidence.json.xz](data/s3_aurora_transcript_regression_1/repair-2/evidence.json.xz).
This lossless JSON archive contains source and named records; staging was removed.
Static lint failed on the new helper's 144-column accounting string (E501).
No preparation or audit ran; package remains incomplete. No retry or case rerun.
Repair charge 5.153995s; combined 18.762074/35s; package16.237926s
remain including 10s reserve; implementation 23.061144s remain.
Cgroup peak 27148288B; no resource breach. Ledger 402/402. Earlier failures preserved.
Stages 2–3 and AURORA-BRIDGE-001 open; proof ledger 2 used/1 unused.
Archive SHA-256: `b2f3886339159a8737d3c4cc259f9dfe39577faf4826b95e4d024aa5211d45eb`.

[Continuation](status.md#repair-2-stop)

## Approved completion continuation — amended admission

The user raised only this package's aggregate output cap from 262,144 to
1,048,576 bytes and its combined time cap from 35 to 40 seconds. Opening charges
are 23.762073883 seconds, leaving 16.237926117 package seconds and
18.061144455 implementation seconds. Both budgets retain all previous failures
and bookkeeping. Analysis/isolation balances and the 402/402 invocation ledger
are unchanged. The ten-second reserve is inside the package cap and may be used
for the audit, reporting and cleanup. No overall implementation increase applies.

The separate [amendment record](data/s3_aurora_transcript_regression_1/repair-2/continuation-1/amendment.json)
retains the old values, current balances, exact source provenance and admission
estimate. Prior audit time was 2.539544389 seconds. One static pass (1 second),
preparation (1 second), audit (3.750 seconds) and the established five-second
operator/bookkeeping charge total at most 10.750 seconds of reservations.
At audit admission, five seconds of additional headroom remain reserved; the
audit may consume the completion reserve as explicitly authorised. Resource
enforcement remains 256 MiB per worker cgroup including descendants/cache/kernel,
zero swap, two CPUs, one worker, the same process, temporary and per-file ceilings.

The archived helper's E501 correction splits one literal into adjacent literals;
its complete parsed AST and runtime string remain identical. The corrected copy
is `repair-2/continuation-1/driver.py`. The old archive and bootstrap remain
unchanged. The [continuation wrapper](data/s3_aurora_transcript_regression_1/repair-2/continuation-1/run.py)
reuses the existing helpers and guard while applying the approved caps, cumulative
accounting, and fresh output directory. Its inventory additions enumerate only
the continuation's evidence files; no old expected entries, digests or allowed
protected-file changes are removed or broadened. Both historical evidence and
new outputs count in the original aggregate output scope.

Original case inputs remain `docs/data/s3_aurora_transcript_regression_1/`;
the retained archive remains `repair-2/evidence.json.xz`. New results go only
under `repair-2/continuation-1/`. The corrected traversal root remains
`experiments/aurora_transcript_regression_1`. The 16 passing cases and completed
reference checks are reused. Only lint/format, preparation and one complete
audit are admitted; no new regression or cryptographic execution is requested.
Completion is pending the recorded results below.


## Completion continuation outcome

**Stopped at the first preparation discrepancy; the package remains incomplete.**
The formatting-only E501 correction passed the first authorised static pass;
no second pass was needed. The corrected helper's entire AST equals the archived
helper, including the exact accounting-string value. The wrapper was formatted
in that pass. No EXP2, independent oracle, case, production or cryptographic input
was modified. All 16 passing regressions and completed evidence-reference checks
were reused; no regression invocation was added.

The one preparation attempt exited **1**. It inspected **2,622 names**, reported
**zero missing files** and exactly one unexpected entry:
`docs/data/s3_aurora_transcript_regression_1/repair-1/prepare.json`. This historical preparation-success record exists unchanged
and matches its retained seal:
`0d4fb8f16d38fee2952f769bb541a05366fd0fa7e150f3d17d752489936227f8`. It is absent from both the inherited required-name inventory and
repair-1's required/optional lists, although it is protected by the repair-1
content seal. The continuation failed to add that existing sealed output to its
expected-name inventory. This is an inventory bookkeeping omission; it does not
indicate altered regression evidence. No list or baseline was changed after this
failure and no preparation retry was launched.

[Preparation diagnostic](data/s3_aurora_transcript_regression_1/repair-2/continuation-1/prepare.log),
[static record](data/s3_aurora_transcript_regression_1/repair-2/continuation-1/checks.json),
[run ledger](data/s3_aurora_transcript_regression_1/repair-2/continuation-1/run-ledger.json)
and [closure](data/s3_aurora_transcript_regression_1/repair-2/continuation-1/validation-closure.json)
retain the commands and outcomes. The STOP marker is preserved. **No full audit
was launched:** audit exit status is null/not applicable, no new baseline content
comparison was completed, and final inventory/audit reporting remain unfinished.
The earlier 8,759 + 2,142 = 10,901 comparisons remain partial historical evidence.
No successful preservation claim follows from the static pass or source checks.

| Continuation measurement | Result |
| --- | --- |
| Static pass / wall / exit | 1 / 0.199510384 s / 0 |
| Preparation / wall / exit | 1 / 0.155905381 s / 1 |
| Full audits / new regression cases | 0 / 0 |
| Guarded wall time | 0.355415765 s |
| Established operator/bookkeeping charge | 5 s, including setup and final reporting |
| Total continuation charge | 5.355415765 s |
| Combined package charge / amended cap | 29.117489648 / 40 s |
| Package / implementation seconds remaining | 10.882510352 / 12.705728690 |
| Cgroup memory.peak, checks / preparation | 25,104,384 / 22,044,672 bytes |
| Maximum sampled process-tree RSS | 60,313,600 bytes |
| Temporary storage observed / retained | 0 / 0 bytes |
| Aggregate retained package output / amended cap | 310,992 / 1,048,576 bytes |
| Regression invocation ledger | 402/402, unchanged |

Memory scope remains the worker cgroup plus all descendants and charged file-cache
and kernel memory, under 256 MiB with zero swap. Tree RSS is a separate sampled
metric. Both services terminated; no resource breach, leftover temporary data,
new persistent workload or host activation occurred. The five-second bookkeeping
charge is conservative accounting, not five seconds of measured audit runtime.
The ten-second reserve remains inside the displayed package balance. Analysis
211.513455542 s and isolation 250.22 s remain unchanged.

All original and repair evidence counts towards the output cap. The original
`repair-2/evidence.json.xz` retains SHA-256
`b2f3886339159a8737d3c4cc259f9dfe39577faf4826b95e4d024aa5211d45eb`; no historical file was overwritten, moved or
regenerated. The [new continuation seal](data/s3_aurora_transcript_regression_1/repair-2/continuation-1/manifest.json)
is additive failure evidence, not a replacement baseline or successful audit.
Original case inputs and repair outputs remain separate; the corrected experiment
traversal root is retained. The only fresh files are the explicitly enumerated
continuation helper, amendment, guard and closure records; documentation is append-only.

**Remaining action, not executed:** a separately authorised narrow correction
must add the exact sealed historical `repair-1/prepare.json` entry to the expected
inventory, then complete the outstanding preparation and full audit. The current
stop condition prohibits that correction/retry in this continuation.
Stages 2–3 and AURORA-BRIDGE-001 remain open. Passing Python EXP2 cases do not
establish native correspondence, proof security or private-prototype admission.
CPU proving/raw-view integration remain paused; isolation stopped/unactivated.
Proof ledger remains **two used, one unused**. No proof, zkVM execution, installation
or activation occurred. This continuation is stopped; no next package is started.

## Inventory finalisation — authorised continuation

The user authorised restoration of exactly
`docs/data/s3_aurora_transcript_regression_1/repair-1/prepare.json`
to the expected-name inventory. Its SHA-256 is unchanged:
`0d4fb8f16d38fee2952f769bb541a05366fd0fa7e150f3d17d752489936227f8`.
The entry remains protected by its existing historical seal and is not added to
any permitted-change list. The [manifest reconciliation](data/s3_aurora_transcript_regression_1/repair-2/finalisation-1/inventory-reconciliation.json)
checks 88 unique retained evidence names across the original, repair-1 and
continuation-1 manifests, including the seals themselves. It found this one
known omission, no further inventory omissions and no seal/target discrepancy.
No file was admitted merely because it existed on disk.

The existing corrected helper and its passing static results remain unchanged.
The [invocation shim](data/s3_aurora_transcript_regression_1/repair-2/finalisation-1/run.py)
reuses the same guard, preparation and audit functions, adds the protected entry,
directs new records to `repair-2/finalisation-1/`, and references the retained
static result without copying or rerunning it. It records fresh static checks
only for the shim. Original case inputs remain at the original regression root;
the corrected experiment traversal root and all inherited comparisons remain.
Its finite list of new output names is separate from historical inventory.

Opening combined consumption is 29.117489648/40 seconds; package 10.882510352
seconds and implementation 12.705728690 seconds remain. Existing reserve may be
consumed for inventory finalisation, preparation, audit, reporting and cleanup;
it is not an extra allowance. The [admission record](data/s3_aurora_transcript_regression_1/repair-2/finalisation-1/admission.json)
retains all previous charges. The five-second bookkeeping charge plus the
one-second static, one-second preparation and 3.750-second audit reservations
fit within 10.750 seconds. No new regression invocation or limit amendment applies.
Outcome remains pending the complete audit and guard result below.


## Inventory finalisation result

**The existing regression/preservation package is now complete.** One corrected
preparation and one complete audit passed, exit **0**, with final inventory,
report generation/readback and the outer resource guard all successful. The
[complete guard result](data/s3_aurora_transcript_regression_1/repair-2/finalisation-1/result.json),
[content report](data/s3_aurora_transcript_regression_1/repair-2/finalisation-1/validation.json),
[phase record](data/s3_aurora_transcript_regression_1/repair-2/finalisation-1/phases.json)
and [final ledger](data/s3_aurora_transcript_regression_1/repair-2/finalisation-1/validation-closure.json)
record this outcome. The content report's `pending-outer-finalisation` field is
the inner-audit handoff state; the later guard result explicitly confirms successful
outer finalisation. Earlier failures remain immutable historical records.

The only historical inventory restoration is
`docs/data/s3_aurora_transcript_regression_1/repair-1/prepare.json`. Its original digest remains
`0d4fb8f16d38fee2952f769bb541a05366fd0fa7e150f3d17d752489936227f8`. It is protected content, not an allowed modification.
All 88 retained manifest names were reconciled first, with no further omission.
Nothing was admitted solely from on-disk presence. Existing helpers, corrected
traversal root, original evidence-input directory, E501 correction and passed
validation were reused. One static pass checked only the new invocation shim;
no regression case or cryptographic test was rerun.

| Completed audit coverage | Result |
| --- | --- |
| Original baseline entries | 8,759: 8,756 unchanged and three authorised documentation changes |
| Supplemental entries | 2,142 unchanged |
| Disjoint content comparison union / overlap | **10,901 / 0** |
| Identity-inclusive unique paths | **10,936** |
| Preparation inventory | 2,639 names; no missing or unexpected |
| Final audit inventory | **2,644 names; no missing or unexpected** |
| Primary / supplemental bytes hashed | 293,955,592 / 18,466,092 |
| Local documentation links checked | 592 |
| Complete report written/read back / outer guard | Passed / passed |

The three permitted original-document changes remain `docs/status.md`,
`docs/traceability.md` and `docs/spec_issues.md`, with historical prefixes checked.
All required baseline identities, frozen assessed inputs, historical evidence,
isolation seals and proof/invocation ledgers passed their comparisons. No baseline,
seal or original expected digest was regenerated. The output inventory permits
only the explicitly enumerated fresh records; closure checked those names without
rerunning baseline comparisons. Counts differ between preparation and audit because
the named audit/phase records are created during the authorised workflow.

| Resource/accounting measurement | Result |
| --- | --- |
| Shim static wall / exit | 0.157519833 s / 0 |
| Preparation wall / exit | 0.156205485 s / 0 |
| Full audit wall / exit | **2.834623713 s / 0** |
| Guarded wall total | 3.148349031 s |
| Established operator/bookkeeping charge | 5 s, includes reconciliation, setup, reporting and closure |
| Total finalisation charge | **8.148349031 s** |
| Combined package consumption / cap | **37.265838679 / 40 s** |
| Package / implementation remaining | **2.734161321 / 4.557379659 s** |
| Audit cgroup-v2 memory.peak / ceiling | **28,528,640 / 268,435,456 bytes** |
| Audit sampled process-tree RSS | 49,819,648 bytes |
| Maximum cgroup peak / sampled RSS across new guards | 28,528,640 / 57,012,224 bytes |
| Final aggregate package output / cap | **366,946 / 1,048,576 bytes** |
| Continued output including previous packages / cap | 10,071,395 / 10,485,760 bytes |
| Temporary storage observed / retained | 0 / 0 bytes |
| Regression ledger / new regression invocations | **402/402 / 0** |

The memory metric covers the full worker cgroup and descendants, including charged
anonymous, file-cache and kernel memory; the external monitor separately samples
process-tree RSS. Memory/swap events show no breach; swap stayed zero. All guarded
commands exited, temporary storage is empty and no persistent workload was created.
The bookkeeping amount is conservative accounting, not a measured five-second audit.
This continuation used the completion reserve within the unchanged cap, as authorised;
no ten-second allowance was added or reset. Analysis 211.513455542 seconds and
isolation 250.22 seconds remain untouched. The in-flight audit time reservation in
the inner report is replaced by actual elapsed time in this final ledger.

Retained and new output both count in the original package scope. The original
archive still has SHA-256 `b2f3886339159a8737d3c4cc259f9dfe39577faf4826b95e4d024aa5211d45eb`.
The [additive finalisation seal](data/s3_aurora_transcript_regression_1/repair-2/finalisation-1/manifest.json)
protects the new records; all previous failed-attempt evidence, seals and sixteen
passing regression outcomes remain. No earlier record is reclassified as a pass.

This completes preservation alongside the existing isolated Python EXP2 tests.
It does not validate a native upstream patch, establish proof knowledge/privacy,
or close AURORA-BRIDGE-001. Only manuscript Sections II–VIII and agreed
clarifications remain authoritative. Stages 2–3, native correspondence and the
existing security obligations remain open. CPU proving and raw-view integration
stay paused; isolation remains safely stopped/unactivated. No proof, zkVM execution,
installation or activation occurred. Proof ledger: **two used, one unused**.
Work stops with this package; no next package has started.
