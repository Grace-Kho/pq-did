# S3-MLDSA-FULL-FORWARD-NTT-PILOT-1

This authorised isolated component experiment implements the
[sealed complete plan](stage3_mldsa_full_forward_ntt_plan.md). The source kernels,
production circuits, active BC-1 profile, parameters, dependencies, manuscript and
historical evidence remain unchanged. Only manuscript Sections II–VIII and agreed
clarifications govern the scheme. The plan's input seal is
`74ed0c4c8a3688ae73ee010f8aa4e1d246fb9aa7f23cda4e92a3d15a9285ef3a`;
the guarded preflight verifies it and the manuscript identity before execution.

## Admission, contract and limits

Direct authorisation adds 107 invocations (279→386),74 implementation seconds
(300→374 cumulative) and at most 30,000,000 aggregate emitted gates. Opening
consumption is 238.73526890808716 s, leaving 135.26473109191284 s. This package is
capped at 135 s, including measured guarded work and the established five-second
operator/bookkeeping charge. Ten seconds remain reserved for cleanup/evidence;
required post-execution reporting/audit reservations are additionally considered
before admitting a batch. Analysis 245.42378315888345 s and isolation 250.22 s are
separate and untouched. No automatic retry, uncounted probe or limit increase.

The complete planned scope is 97 partitions and ten cases:32 entry partitions,
64 butterfly partitions across eight stages/1,024 nodes, and one final boundary;
six complete-transform cases plus M0/M1 and T0/T1. Every generation counts once.
Six full cases contain 582 ordinary evaluator calls and 582 independent trace
passes when complete; no new vector combinations are hidden inside a case.

The [configuration](data/s3_mldsa_full_forward_ntt_pilot_1/config.json) retains
256MiB aggregate cgroup memory, zero swap, two CPUs, one worker, four controlled
processes,60s command/55s child maxima,128MiB arithmetic-process RSS and 256MiB
address-space stops,8MiB retained trace/temporary data,1MiB per disk file,
60KiB command diagnostics,10MiB cumulative package output,9GiB storage stop and
2GiB headroom reserve. Each of 13 serial work batches reserves10s, with a9s inner
stop. Generation retains the inherited10s maximum, tightened to9s locally;
ordinary evaluation stays2s and2,000,260 wires. The observer shares the bounded
batch. A450,000-gate local limit is stricter than the unchanged2M trace ceiling.
The aggregate30M counter never resets at partitions or batches. An interruption
with no exact emitted prefix retains its full admitted gate reservation as a
conservative charge; no resource failure can become a rejection-test pass.

## Exact representation and schedule

The [isolated wrapper](../experiments/mldsa_full_forward_ntt_1/candidate.py) accepts
exactly 256 signed64 coefficients and private active/prior-rejection controls.
Exact integer typing rejects booleans/coercions and values outside signed64.
All 256 words receive the existing complete SPEC-004 mod64 normalisation before
the first butterfly. Negative values, q, MIN and MAX are legal entry values;
generic raw-butterfly overflow rejection is not imposed before normalisation.
Original signed input remains separate from normalised state for any later norm
check. This is not an extension to arbitrary-size Python integers.

E00..E31 each convert/mask eight successive lanes. For s=0..7, L=128>>s,
ordinal t=0..127 gives g=t//L, u=t%L, left=2Lg+u, right=left+L and twiddle index
m=2^s+g. N00..N63 each perform 16 successive nodes within one stage; twiddles are
ordinary `1753^BitRev8(m) mod8380417`, checked against the pinned verifier table.
Product, right subtraction, left addition preserve old left and the exact
Algorithm41 order. Canonical-producer arithmetic is imported unchanged from the
[stage candidate](../experiments/mldsa_forward_ntt_stage_1/candidate.py), which in
turn uses the completed isolated scalar kernel. F masks all 256 final lanes and
returns final validity. There is no inverse scaling or Montgomery convention.

Entry establishes `[0,q-1]` on active valid paths and zero on unusable paths.
For every canonical butterfly, product≤(q-1)^2<2^46, sum<2q and difference has
absolute value<q. The unchanged restoring reduction uses 46 steps and signed25
corrections. Original scalar guards, raw64 overflow checks and full64 masks
remain; only already-proven identity conversions are omitted. Each node preserves
canonicality, and stage induction applies to the entire schedule. All private
control remains wires; loop indices, cuts and constants are public and fixed.
Validity is NOT R, with sticky R carried across all cuts. Inactive clean scope
can have validity1 but its outputs are unusable zeroes; R=1 produces validity0
and zero final outputs. This structural argument is distinct from finite tests.

## Private-state composition and counting boundary

Every partition declares16,386 private bits:256 MSB-first signed64 words, active
and raw R. The next partition consumes the actual observed output words and raw
R from its predecessor, never oracle replacements or public-specialised values.
Its Scope is explicitly seeded from that private R input. Endian mapping is
input64i+k→previous internal word[i][63−k]. Untouched lanes alias their producers;
active always aliases the original active wire. Partial-stage state is never
released as a full transform result.

The [runner](../experiments/mldsa_full_forward_ntt_1/run_pilot.py) maintains a
fixture-independent virtual wire map. Local input IDs resolve to prior producer
IDs; local gate outputs receive cumulative-offset global IDs. It verifies all
crossing bits remain private and records contiguous changed-output wire runs,
raw-R wire, input/output alias hashes, opcode counts and each partition fingerprint.
Current public-only folding does not exploit actual witness values or identities
between private wires. Thus the mapping accounts for a connected logical DAG
without additional equality gates, duplicated input declarations, entry conversions
at cuts, or omitted masks. The final metadata check requires all 256 entry lanes,
all 1,024 distinct schedule nodes, all 97 partitions in order and one final boundary.

This is **host-managed partitioned evaluation and logical composition accounting**.
It does not materialise a monolithic circuit, produce its fingerprint, prove
separate partitions, or cryptographically bind independently supplied intermediate
witnesses. A successful complete alias/coverage check permits a logical count;
otherwise only measured fragments/prefixes are reported. Checkpoint digests bind
trusted harness state/parent/source identities for fault detection, not adversarial
proof soundness. Synthetic state remains private-classified during construction,
but its values are intentionally recorded as research evidence, not real secrets.

## Independent checks and release boundary

Each valid full result compares all 256 exact canonical64 outputs with pinned
`bounded_mldsa._ntt` and a separately implemented
[odd-root Horner oracle](../experiments/mldsa_full_forward_ntt_1/oracle.py).
The latter shares no schedule, partition or twiddle-table helper. V0 is zero;
V1 is polynomial X; V2 includes MIN/MAX and reduction boundaries; V3 is dense and
asymmetric; V4/V5 exercise inactivity and prior rejection. M0 refuses 255 words;
M1 refuses 2^63. T0/T1 mutate separate copies of the actual post-entry checkpoint
to check noncanonical state and cleared rejection refusal. No fault is injected
into protected project files or ordinary production APIs.

All cases are counted before starting. A case stays pending until its full
97-partition path and final comparisons complete. Partial successes are not full
transform passes. Limits stop the run, preserve diagnostics and prevent further
work admission. Report assembly and the single corrected preservation audit then
use their reserved time; they do not repeat arithmetic work. Required shutdown is
termination of these bounded transient user jobs and release of temporary state;
no isolation service or host deployment is activated.

Complete-authentication knowledge/privacy, adaptive Delta_tail, outer-oracle
composition, production security, inverse NTT and full-verifier integration remain
unestablished. Stages 2–3 remain open; proof ledger two attempts used, one unused.
CPU proving remains paused; isolation safely stopped and unactivated.


## Measured experiment outcome

**Component composition/counting validated; NO-GO for integration with the unchanged raw-view proof encoding.** Completed partitions: 97/97; entry lanes:
256/256; butterflies: 1024/1,024; final boundaries: 1/1.
New counted invocations: 107/107;
cumulative **386/386**. All individual generation
admissions, including any incomplete prefix, are in
[the invocation ledger](data/s3_mldsa_full_forward_ntt_pilot_1/pilot-state.json).
No retry or extra case was launched. No failure or retry occurred.

| Case | Kind | Outcome | Completed observations / refusal |
| --- | --- | --- | --- |
| M0 | malformed-entry | pass | exactly 256 signed64 coefficients required |
| M1 | malformed-entry | pass | exact signed64 integer coefficients required |
| V0 | full-transform-case | pass | 97 |
| V1 | full-transform-case | pass | 97 |
| V2 | full-transform-case | pass | 97 |
| V3 | full-transform-case | pass | 97 |
| V4 | full-transform-case | pass | 97 |
| V5 | full-transform-case | pass | 97 |
| T0 | checkpoint-refusal | pass | checkpoint noncanonical frontier |
| T1 | checkpoint-refusal | pass | checkpoint rejection changed |

All planned case IDs and exact inputs remain those in the sealed plan. Six case
records contain initial values, all 256 uninterrupted reference and independent
Horner outputs, expected wrapper outputs and, when completed, actual outputs plus
canonical64 byte strings. They are `case-V0.json` through `case-V5.json` alongside
the [summary](data/s3_mldsa_full_forward_ntt_pilot_1/pilot-summary.json).
Completed evaluator calls: 582; independent trace
passes: 582. These are constituent observations of
six cases, not additional test combinations. Intermediate records include
canonical-prefix, unchanged unprocessed lanes, private active and sticky R checks.

## Counts and timings

Completed emitted opcode counts: XOR=16,022,016,
AND=10,679,298, NOT=343,042.
Aggregate emitted gates/charged conservative bound:
**27,044,356**. Any unresolved interrupted prefix retains
an additional **0** reserved gates.
Only a passed complete result with zero unresolved prefix permits a connected
logical full-transform count. No full reference-circuit saving is measured.

| Partition ordinal | Total gates | AND gates | Generation/counting seconds | Completion |
| --- | ---: | ---: | ---: | --- |
| 00 | 287,664 | 107,168 | 0.347761 | complete |
| 01 | 287,664 | 107,168 | 0.348736 | complete |
| 02 | 287,664 | 107,168 | 0.340952 | complete |
| 03 | 287,664 | 107,168 | 0.339879 | complete |
| 04 | 287,664 | 107,168 | 0.346478 | complete |
| 05 | 287,664 | 107,168 | 0.346649 | complete |
| 06 | 287,664 | 107,168 | 0.336719 | complete |
| 07 | 287,664 | 107,168 | 0.333612 | complete |
| 08 | 287,664 | 107,168 | 0.355625 | complete |
| 09 | 287,664 | 107,168 | 0.339919 | complete |
| 10 | 287,664 | 107,168 | 0.341485 | complete |
| 11 | 287,664 | 107,168 | 0.343898 | complete |
| 12 | 287,664 | 107,168 | 0.338876 | complete |
| 13 | 287,664 | 107,168 | 0.348152 | complete |
| 14 | 287,664 | 107,168 | 0.332271 | complete |
| 15 | 287,664 | 107,168 | 0.338346 | complete |
| 16 | 287,664 | 107,168 | 0.353309 | complete |
| 17 | 287,664 | 107,168 | 0.349126 | complete |
| 18 | 287,664 | 107,168 | 0.339539 | complete |
| 19 | 287,664 | 107,168 | 0.340908 | complete |
| 20 | 287,664 | 107,168 | 0.336120 | complete |
| 21 | 287,664 | 107,168 | 0.343448 | complete |
| 22 | 287,664 | 107,168 | 0.340991 | complete |
| 23 | 287,664 | 107,168 | 0.341417 | complete |
| 24 | 287,664 | 107,168 | 0.353417 | complete |
| 25 | 287,664 | 107,168 | 0.351757 | complete |
| 26 | 287,664 | 107,168 | 0.337352 | complete |
| 27 | 287,664 | 107,168 | 0.341621 | complete |
| 28 | 287,664 | 107,168 | 0.342483 | complete |
| 29 | 287,664 | 107,168 | 0.336424 | complete |
| 30 | 287,664 | 107,168 | 0.338157 | complete |
| 31 | 287,664 | 107,168 | 0.341020 | complete |
| 32 | 278,480 | 113,024 | 0.338535 | complete |
| 33 | 278,480 | 113,024 | 0.340572 | complete |
| 34 | 278,480 | 113,024 | 0.331705 | complete |
| 35 | 278,480 | 113,024 | 0.329394 | complete |
| 36 | 278,480 | 113,024 | 0.333446 | complete |
| 37 | 278,480 | 113,024 | 0.332235 | complete |
| 38 | 278,480 | 113,024 | 0.334272 | complete |
| 39 | 278,480 | 113,024 | 0.330642 | complete |
| 40 | 278,480 | 113,024 | 0.339496 | complete |
| 41 | 278,480 | 113,024 | 0.338458 | complete |
| 42 | 278,480 | 113,024 | 0.323179 | complete |
| 43 | 278,480 | 113,024 | 0.326313 | complete |
| 44 | 278,480 | 113,024 | 0.325270 | complete |
| 45 | 278,480 | 113,024 | 0.326743 | complete |
| 46 | 278,480 | 113,024 | 0.329904 | complete |
| 47 | 278,480 | 113,024 | 0.329396 | complete |
| 48 | 278,480 | 113,024 | 0.344124 | complete |
| 49 | 278,480 | 113,024 | 0.337619 | complete |
| 50 | 278,480 | 113,024 | 0.326183 | complete |
| 51 | 278,480 | 113,024 | 0.329555 | complete |
| 52 | 278,480 | 113,024 | 0.324598 | complete |
| 53 | 278,480 | 113,024 | 0.329445 | complete |
| 54 | 278,480 | 113,024 | 0.324292 | complete |
| 55 | 278,480 | 113,024 | 0.330068 | complete |
| 56 | 278,480 | 113,024 | 0.343794 | complete |
| 57 | 278,480 | 113,024 | 0.337189 | complete |
| 58 | 278,480 | 113,024 | 0.326937 | complete |
| 59 | 278,480 | 113,024 | 0.326523 | complete |
| 60 | 278,480 | 113,024 | 0.326946 | complete |
| 61 | 278,480 | 113,024 | 0.332608 | complete |
| 62 | 278,480 | 113,024 | 0.328893 | complete |
| 63 | 278,480 | 113,024 | 0.332589 | complete |
| 64 | 278,480 | 113,024 | 0.341820 | complete |
| 65 | 278,480 | 113,024 | 0.348341 | complete |
| 66 | 278,480 | 113,024 | 0.332404 | complete |
| 67 | 278,480 | 113,024 | 0.337011 | complete |
| 68 | 278,480 | 113,024 | 0.335367 | complete |
| 69 | 278,480 | 113,024 | 0.335516 | complete |
| 70 | 278,480 | 113,024 | 0.339060 | complete |
| 71 | 278,480 | 113,024 | 0.333743 | complete |
| 72 | 278,480 | 113,024 | 0.352263 | complete |
| 73 | 278,480 | 113,024 | 0.349307 | complete |
| 74 | 278,480 | 113,024 | 0.336920 | complete |
| 75 | 278,480 | 113,024 | 0.337009 | complete |
| 76 | 278,480 | 113,024 | 0.335997 | complete |
| 77 | 278,480 | 113,024 | 0.329537 | complete |
| 78 | 278,480 | 113,024 | 0.337564 | complete |
| 79 | 278,480 | 113,024 | 0.334692 | complete |
| 80 | 278,480 | 113,024 | 0.345806 | complete |
| 81 | 278,480 | 113,024 | 0.341158 | complete |
| 82 | 278,480 | 113,024 | 0.338877 | complete |
| 83 | 278,480 | 113,024 | 0.338450 | complete |
| 84 | 278,480 | 113,024 | 0.339530 | complete |
| 85 | 278,480 | 113,024 | 0.342198 | complete |
| 86 | 278,480 | 113,024 | 0.336551 | complete |
| 87 | 278,480 | 113,024 | 0.329466 | complete |
| 88 | 278,480 | 113,024 | 0.335753 | complete |
| 89 | 278,480 | 113,024 | 0.339520 | complete |
| 90 | 278,480 | 113,024 | 0.328830 | complete |
| 91 | 278,480 | 113,024 | 0.334398 | complete |
| 92 | 278,480 | 113,024 | 0.330007 | complete |
| 93 | 278,480 | 113,024 | 0.332126 | complete |
| 94 | 278,480 | 113,024 | 0.334645 | complete |
| 95 | 278,480 | 113,024 | 0.328370 | complete |
| 96 | 16,388 | 16,386 | 0.022275 | complete |

Generation/counting: **32.391877992 s**;
ordinary circuit evaluation: **39.296167895 s**;
independent trace observation: **10.836545261 s**;
uninterrupted reference plus Horner: **0.011842597 s**.
These are distinct measured activities, not proof-generation or statistical
latency measurements. Per-batch guards also include source checks, state transfer,
alias accounting, measurement writes and process overhead. Each partition record
contains peak-so-far process RSS/cgroup observations and retained trace bytes;
maximum retained trace is **4,890,410 bytes**.
No trace is written to disk. Source, unchanged inherited limits and complete
command/resource records accompany the invocation ledger. Retained synthetic
checkpoints: `['retained-frontier.bin', 'retained-state.json']`; temporary directory emptied without deleting failure evidence.

## Target implications and decision

The [KYC thresholds](benchmark_targets.md) are proposed, not agreed SLAs:
raw authentication proof ≤10MiB, presentation≤12 MiB, generation p95≤30s,
verification p95≤2s and end-to-end p95≤45s. Six synthetic component cases establish
none of those percentiles or complete-authentication costs.

Conditional projection, if this measured private-wire subgraph embeds unchanged
and the existing 480-round raw-tape/raw-view proof representation is retained:
`P_auth = 5,363,104 + 960*ceil(T_auth/4)` for the recorded 42,632-bit auth witness,
and `T_auth >= T_NTT` gives **2568395104 bytes** when a complete count exists.
This is a conditional encoding calculation, never a generated proof or an
unconditional lower bound for a differently lowered authentication circuit.
Changed input visibility, cross-component simplification or a different compact
proof encoding require fresh accounting and security arguments. Unmeasured
inverse transforms, private products/accumulation, hashes, samplers, norms,
decomposition, hint linkage and the Merkle/disclosure relation are excluded.
No overlapping historical fragments are added. RISC Zero forecasts are unchanged.

This successful result rules out the route that simply retains the measured
subgraph and raw-view encoding under the proposed byte targets. Arithmetic
improvement alone is insufficient; prioritise the proof representation decision
over further integration. It is not a demonstrated attack or a universal lower
bound for every possible authentication lowering or proof system.
One next action only: **S3-COMPACT-AUTH-PROOF-PROFILE-REVIEW-1: a bounded source-only review of compact transcript candidates, exact relation/security obligations and KYC resource admission, before more circuit integration.** It has not started.
Stages 2–3 remain open. ARITH-LOWER-001 still covers full-verifier/compiler
conformance; OC-REL/EXT/PRIV/BUDGET, adaptive Delta_tail, production security and
complete proof knowledge/privacy remain unresolved. No inverse experiment,
proof, zkVM execution, installation or activation occurred. CPU proving paused;
isolation safely stopped/unactivated; proof ledger two used/one unused.


## Complete cost breakdown and evidence interpretation

All 97 physical generation records completed. The connected logical accounting
contains **27,044,356 total gates /10,679,298 ANDs**, leaving 2,955,644 aggregate
gates unused. There is no missing or capped partition and no unresolved gate
reservation. These actual totals happen to equal the plan's nominal estimates;
that agreement is observed across all 255 twiddle assignments, not assumed in
place of generation. The current fixed-width/public-only-folding implementation
emitted the same per-node cost for every used twiddle.

| Measured region | Coverage | Total gates | AND gates |
| --- | --- | ---: | ---: |
| Checked entry mod64 conversions |256, including signed quotient/remainder checks |9,188,352 |3,412,736 |
| Entry masks |256 complete64-bit masks/control |16,896 |16,640 |
| Forward stage0 |N00..N07;128 butterflies |2,227,840 |904,192 |
| Forward stage1 |N08..N15;128 butterflies |2,227,840 |904,192 |
| Forward stage2 |N16..N23;128 butterflies |2,227,840 |904,192 |
| Forward stage3 |N24..N31;128 butterflies |2,227,840 |904,192 |
| Forward stage4 |N32..N39;128 butterflies |2,227,840 |904,192 |
| Forward stage5 |N40..N47;128 butterflies |2,227,840 |904,192 |
| Forward stage6 |N48..N55;128 butterflies |2,227,840 |904,192 |
| Forward stage7 |N56..N63;128 butterflies |2,227,840 |904,192 |
| Final boundary |All 256 output words and final validity |16,388 |16,386 |
| Total |One logical full forward transform |27,044,356 |10,679,298 |

All scalar guards, multiplication/reduction, overflow checks, add/sub corrections,
node masks and node validity gates are included in the stage rows. Cuts are
wire aliases, not new logical inputs or free independent witnesses. The full
unpartitioned logical input count is 16,386; the 97 local input declarations are
not added as arithmetic gates. Exact wire descriptors and paired frontier hashes
permit checking the source-level alpha-renaming; there is no monolithic emitted
trace, circuit fingerprint or cryptographic composition artifact.

The conditional **2,568,395,104-byte** raw-view projection uses the frozen encoding
formula from the [earlier feasibility review](stage3_feasibility_review.md), with
`ceil(10,679,298/4)=2,669,825`. It already exceeds the proposed 10,485,760-byte KYC
raw-proof target under the stated unchanged-subgraph/encoding assumptions.
A compact replacement transcript would need its own concrete security,
extraction/privacy, implementation and resource admission; the current 480 rounds
and ideal-oracle argument do not automatically transfer. No proving-time or
proving-memory figure is derived from these execution measurements.

Only the bounded full-forward **component** validation/accounting obligation is
newly satisfied. Finite tests are not a universal equivalence proof. Full compiler
conformance, inverse NTT, private products and full authentication remain open.
The remaining implementation balance will be recorded by the final guarded
preservation closure; no further implementation package is started.


## Preservation and final resource closure

Lint/format and the single complete preservation audit pass, exit0, including
content, inventory, report readback and outer guard. Coverage:
10,482 disjoint content paths and
10,512 identity-inclusive paths.
Original baselines and report prefixes are preserved.

| Measurement | Result |
| --- | --- |
| Audit wall time | 2.438798105 s |
| Audit cgroup memory.peak | 24,190,976 bytes /256MiB |
| Audit sampled tree RSS | 41,918,464 bytes |
| Maximum guarded cgroup peak | 31,719,424 bytes |
| Maximum separately sampled tree RSS | 50,401,280 bytes |
| Guarded commands and wall time | 22; 88.441512754 s |
| Package charge, including five bookkeeping seconds | 93.441512754/135 s |
| Cumulative implementation charge | 332.176781662/374 s |
| Remaining implementation allowance | **41.823218338 s** |
| Invocation count | **386/386** |
| Analysis balance unchanged | **245.423783159 s** |
| Temporary disk observed peak | 176,607 bytes; zero temporary files retained |

The cgroup-v2 metric covers worker descendants and charged cache/kernel memory;
swap is zero. Sampled RSS is a separate observation. Synthetic checkpoints and
failure diagnostics are retained as explicitly named evidence, not live resources.
Final bookkeeping uses256MiB address space, CPU/alarm5s, two CPUs and1MiB/file
within the five-second charge; it does not repeat content comparisons.
[Guard result](data/s3_mldsa_full_forward_ntt_pilot_1/result.json),
[closure](data/s3_mldsa_full_forward_ntt_pilot_1/validation-closure.json) and
[additive seal](data/s3_mldsa_full_forward_ntt_pilot_1/manifest.json) record completion.
Analysis/isolation were not borrowed; isolation remains safe-stopped/unactivated,
250.22s and22 identity cases pending. Stages2–3 open; CPU paused; proof ledger2/1.
