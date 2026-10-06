# S3-MLDSA-FULL-FORWARD-NTT-PLAN-1

**Decision: the source-level design is ready for a separately authorised pilot;
execution is not admitted under the current allowances.** A complete forward
transform needs explicit entry normalisation, all 1,024 butterflies and a final
output boundary. The proposed 97 partitions preserve one logical private-wire
computation. They do not make its aggregate cost disappear.

The sole next recommendation is **S3-MLDSA-FULL-FORWARD-NTT-PILOT-1**, with the
inactive amendment specified below: 107 invocations, 74 additional implementation
seconds, and a 30,000,000-gate aggregate generation ceiling. The existing 2M
per-trace ceiling and memory/storage/process ceilings remain unchanged. No part
of that experiment has started; no candidate implementation is added here.

## Authority, preserved state and opening balances

Only manuscript Sections II–VIII, SPEC-001 through SPEC-004 and the current
[specification](implementation_spec.md) govern the scheme. The manuscript SHA-256
remains `d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The guarded [preflight](data/s3_mldsa_full_forward_ntt_plan_1/preflight-evidence.json)
verified all 61 paths in the preceding stage seal and all 53 assessed source
identities. Preceding seal SHA-256:
`39f670dd40a5ff07b97d30c578501ef5b799f4592fa24c2a3068939dbe3f9265`.

| Ledger at entry | Consumed | Remaining / constraint |
| --- | --- | --- |
| Analysis | 46.39351484295912 / 300 s | 253.60648515704088 s; this package only |
| Implementation | 238.73526890808716 / 300 s | **61.264731091912836 s, unchanged** |
| Test/generation invocations | **279/279** | Zero authorised; none run here |
| Isolation | Separate sealed ledger | Safely stopped/unactivated; 250.22 s and 22 original identity cases pending; 100 historical invocations unchanged |
| Proof attempts | Two used | One unused; CPU proving paused |

Analysis accounting follows the existing workflow: measured guarded documentation
commands plus five seconds of operator/bookkeeping charge. No implementation or
isolation time is transferred. The analysis reserve is ten seconds. Evidence at
entry occupies 5,938,794 cumulative bytes against the existing 10 MiB output
ceiling. The [configuration](data/s3_mldsa_full_forward_ntt_plan_1/config.json)
retains 256 MiB cgroup memory, zero swap, one worker, two CPUs, four controlled
processes, 60 s command/55 s child, 8 MiB temporary data, 1 MiB/file, 60 KiB/command
diagnostics, the 9 GiB experimental-storage stop and 2 GiB headroom reserve.

The [reviewed-input record](data/s3_mldsa_full_forward_ntt_plan_1/reviewed-inputs.json)
pins the existing verifier, arithmetic/control/emitter code, independent observers,
feasibility plan and prior evidence. Reused results include the
[modmul](stage3_mldsa_modmul_lowering_pilot.md),
[butterfly](stage3_mldsa_butterfly_composition_pilot.md),
[four-lane stage](stage3_mldsa_forward_ntt_stage_pilot.md) and
[hint](stage3_private_hint_lowering_pilot.md) pilots. Their results, failures,
counts and fingerprints are preserved. Neither arithmetic lowering nor the hint
candidate is canonical BC-1. The [arithmetic review](stage3_mldsa_arithmetic_lowering_review.md)
and [feasibility plan](stage3_auth_proof_feasibility_plan.md) remain applicable.

## Complete schedule coverage

The public schedule follows FIPS 204 Algorithm 41, printed page 43, and the pinned
[`bounded_mldsa._ntt`](../src/pqdid/bounded_mldsa.py). The constants are ordinary
unscaled residues: q=8,380,417, n=256, root=1753,
`z[m] = 1753^BitRev8(m) mod q`. Appendix B's ordinary table, not a Montgomery
table, applies. [FIPS 204, August 2024](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf).

This formula specifies every lane, dependency and twiddle without a generated
schedule artifact. For stage `s=0..7`, let `L=128>>s`. Visit butterfly ordinal
`t=0..127` in order, with `g=t//L`, `u=t%L`, `j=2*L*g+u`, `m=2^s+g`.
Read **old** `a=state[j]`, `b=state[j+L]`; compute:

```text
p = (z[m] * b) mod q
state[j+L] = (a - p) mod q       # right update first, retaining old a
state[j]   = (a + p) mod q       # left second
```

| Stage s | L / lane distance | Public groups g | Twiddle indices m | Lane pairs for each group | Nodes / proposed N partitions |
| --- | --- | --- | --- | --- | --- |
| 0 | 128 | 0 | 1 | (u,128+u), u=0..127 | 128 / N00..N07 |
| 1 | 64 | 0..1 | 2..3 | (128g+u,128g+64+u), u=0..63 | 128 / N08..N15 |
| 2 | 32 | 0..3 | 4..7 | (64g+u,64g+32+u), u=0..31 | 128 / N16..N23 |
| 3 | 16 | 0..7 | 8..15 | (32g+u,32g+16+u), u=0..15 | 128 / N24..N31 |
| 4 | 8 | 0..15 | 16..31 | (16g+u,16g+8+u), u=0..7 | 128 / N32..N39 |
| 5 | 4 | 0..31 | 32..63 | (8g+u,8g+4+u), u=0..3 | 128 / N40..N47 |
| 6 | 2 | 0..63 | 64..127 | (4g+u,4g+2+u), u=0..1 | 128 / N48..N55 |
| 7 | 1 | 0..127 | 128..255 | (2g,2g+1) | 128 / N56..N63 |

There are `8*128=1,024` distinct `(s,g,u)` nodes and 255 distinct twiddle
assignments, each used L times in its group. Each stage touches every lane once;
groups and u values partition its 256 lanes. Every node reads the two same-index
outputs from the preceding stage (stage 0 reads the normalised entry frontier).
All previous-stage partitions must complete before the next stage begins.
Within a stage, butterfly lane pairs are disjoint; the shared rejection state
still follows the stated serial order. This is a coverage derivation, not an
executed enumeration or a claim that the future harness is already correct.

The prior fragment comprises stage-0 t=0 and 64, then stage-1 t=0 and 64:
lanes `(0,128)`, `(64,192)`, `(0,64)`, `(128,192)` with twiddles
4,808,194; 4,808,194; 3,765,607; 3,761,513. Its four nodes are genuine members of
this schedule, not a uniform-cost template for all twiddles.

## External contract and complete representation boundary

The proposed isolated entry takes exactly 256 **coefficient-domain signed64
words**, in coefficient order, plus private Boolean `active` and incoming
`rejected` (R). The synthetic fixture adapter requires exact Python integers,
not bool/float/string, with `-2^63 <= x_i <= 2^63-1`; it refuses malformed
length/type/range before allocating a circuit or truncating a value. Symbolic
construction checks word width, wire ownership and domain with existing helpers.
No caller-selectable canonicality shortcut is exposed.

The mathematical transform operates on residues. The Python `_ntt` helper first
computes `[x % q for x in coefficients]` and incidentally accepts unbounded Python
integers; it is not a typed signed64 admission API. The planned word contract
preserves **all** representable signed64 inputs, including negative values,
q, MIN and MAX, and compares `_ntt` on that entire declared domain. It does not
claim to represent arbitrary-size Python integers or preserve Python coercions.
The generic raw butterfly's overflow-dependent domain is a different interface.
Applying raw `z*x` checks before entry normalisation would wrongly reject legal
full-transform inputs and is prohibited.

| Boundary | Required operation and representation |
| --- | --- |
| Entry | 256 complete SPEC-004 `scope.checked(mod64(x_i,q))` calls, in lane order; both quotient/remainder checks remain, including MIN's unsigned magnitude |
| Entry mask | For each converted word, emit `usable=active AND NOT R` and mask all 64 bits; do not add a separate `scope.output` per lane |
| Working slots | Internally tag normalised words as NTT-workspace slots for the existing butterfly API; this annotation is not a claim that entry alone performs an NTT |
| Every butterfly | Reuse `_from_canonical_producers` arithmetic from the isolated stage candidate, with its full product-overflow predicate, canonical scalar guard, exact 46 product/restoring reduction, raw64 add/sub checks, q corrections, masks and node validity |
| Between nodes/stages | Carry canonical64 words and sticky raw R; no mod64 conversion at a cut or stage boundary; no unchecked alternate arithmetic |
| Final boundary | Mask all 256 words by final `active AND NOT R`; expose canonical64 NTT outputs and `scope.output(()) = NOT R` |

The exact future implementation location is `experiments/mldsa_full_forward_ntt_1/`.
It should introduce only fixed entry/partition/final wrappers and a bounded
runner around the pinned isolated kernel, not edit that kernel or production
files. The kernel's current docstring restricts callers to the old fragment;
the new wrapper must document its own producer-invariant proof. It is an internal
construction use, not permission to expose the underspecified kernel to callers.

Final lane order is source order 0..255, with no additional bit reversal or
permutation. All accepted active outputs must match reference **canonical
integers and their 64-bit encodings**, not merely congruence classes. For inactive
clean scope, validity is1 but all outputs are zero and unusable. Incoming R=1
remains1; final validity is0 and every output is zero. Intermediate output/R
observations are private diagnostic state, never a successful result or receipt.
The original signed response z must remain separately available for the verifier's
norm check; normalised NTT state cannot replace it.

### Inductive range and rejection argument

Positive q division of any signed64 input has a signed64 quotient and remainder
in `[0,q-1]`; SPEC-004's Q-then-R-then-positive-divisor checks therefore accept
this entry domain. Converted words are canonical on clean active paths and
masked zero on all other paths. This establishes the first complete frontier's
canonicality **for every witness**, independently of validity.

Assume a,b in `[0,q-1]`. All public twiddles are in that range and below 2^23.
The product is at most `(q-1)^2 < 2^46`, exactly representable by the existing
46-bit construction, and cannot overflow signed64. Restoring reduction scans all
46 bits: with r<q, `T=2r+bit <=2q-1 <2^24`; `T-q` lies in `[-q,q-1]` and fits
signed25. Its fixed correction yields one canonical remainder p. The butterfly
sum is in `[0,2q-2]` (24 bits) and difference in `[-(q-1),q-1]` (signed25).
One q subtraction/addition respectively yields canonical 23; zero extension and
the existing full64 mask preserve the interface. Original checked raw add/sub
and product predicates stay in the graph even where these bounds imply success.

Thus each node re-establishes the canonical frontier; disjoint updates preserve
untouched lanes. Stage induction applies through all eight stages. Prior R is
never cleared, and active is unchanged. Omitting repeated positive-q mod64 on
these producer words removes only identity conversions with true validity. There
is no secret-dependent host branch: all loops, cuts and twiddles are public;
all private decisions remain wires. No overflow rejection is removed from a
domain on which the original arithmetic could overflow.

This supplies the missing **source-level whole-schedule invariant**, not a
machine-checked proof of a future implementation. Full wire mapping, entry MIN/MAX
handling, every twiddle and all final outputs still require the proposed validation.
Equivalence does not imply frozen BC-1 conformance: narrow multiplication,
restoring reduction and invariant-based omission require a proposed profile
change. Knowledge/privacy and outer-oracle composition are separate obligations.

## 97 partitions and private state transfer

The complete ordered partition list is E00..E31, N00..N63, F. This is an exact
definition of all boundaries, not a request to choose partitions adaptively.

| Partitions | Exact covered work | State after each |
| --- | --- | --- |
| E_b, b=0..31 | Convert/mask lanes `8b..8b+7`; eight entry conversions | Processed prefix canonical, untouched suffix retains original signed64 bits; R carried |
| N_k, k=0..63 | Stage `s=k//8`, ordinals `t=16(k%8)..16(k%8)+15`; sixteen butterflies | Full canonical frontier; R carried; fixed lane order |
| F | One final all-lane mask and validity operation | 256 ordered final words and validity |

No N partition begins until E31 completes. Each E touches eight previously
unconverted lanes; each N covers sixteen previously unvisited nodes of one
stage. Hence entry coverage is32*8=256 exactly and node coverage64*16=1,024
exactly, with no duplicated partition. F occurs once. There are no intermediate
stage-final masks or new per-partition acceptance gates.

Every local emitter declares **16,386 private input bits**: 256 serialised64-bit
words followed by active and raw R. This is within the existing 65,536-input cap.
Use the existing MSB-first word serialisation and `words.from_serialised` to
obtain internal little-endian word bits. At a cut, local input `64*i+k` aliases
the previous frontier's internal word bit `[i][63-k]`, k=0..63. The last two
inputs alias the original active and the previous scope's raw rejected wire.
Untouched lanes alias themselves. This mapping is part of the construction
contract; neither endian conversion nor lane reordering may be inferred from
values. Before all E partitions complete, preserve the exact two's-complement
bit pattern of unprocessed signed inputs.

Initialise each local Scope with the private active input and explicitly seed
`scope.rejected` from the incoming private R wire. Do not seed it from a fresh
zero or a Boolean "previous case passed". Intermediate `Emitter.finish(R)` may
use the raw rejection wire as the trace's single observed output, without adding
gates. Its expected bit means **rejection**, not acceptance. F alone finishes
with final validity. The observer exports all frontier words and raw R; its
numeric outputs, not oracle-generated replacement values, feed the next partition.

Generate each partition once, count its emitted gates, evaluate all six declared
whole-transform cases on it, independently observe their frontier bits, then
release its trace before generating the next. Even an observed zero or known
canonical high bit remains a private input/wire in subsequent construction.
No witness enters public constants, public folding, schedule decisions or source
generation. Private input metadata must be checked at every cut.

Batch the 97 partitions into 13 serial guarded commands: global partition ordinals
0..7,8..15,…,88..95,96. Six small synthetic numeric checkpoints and one live
wire-alias frontier pass between commands. Checkpoints bind public partition
ordinal, lane/bit order, original active, raw R, parent-state digest and immutable
source identity. Reject missing/duplicate/out-of-order records, inconsistent
parents, cleared R and noncanonical post-entry state before admitting a consumer.
The retained parent record is authoritative in this trusted harness; a digest is
an integrity cross-check, **not** a MAC or a proof binding separate computations.
Do not auto-resume an interrupted batch or regenerate a missing trace.

### What a justified complete count would mean

Partitioned evaluation is one logical transform only if every consumer uses the
actual producer frontier. Separate fragment counts alone establish neither that
wiring nor the transform relation. To claim a composed logical count, the future
runner must also record/verify:

1. All256 entry indices, all `(s,g,u)` nodes and F exactly once, in order, with
   twiddles checked against both the pinned table and an independent exponent
   derivation. No schedule helper shared with the arithmetic oracle.
2. A complete public alias map resolving each local input to the original input
   or previous producer. Virtual gate IDs follow cumulative partition offsets;
   constants0/1 retain their identities. Local gate outputs are renamed by this
   fixed offset; they never create extra independent witness variables.
3. XOR/AND/NOT counts and gate-segment fingerprints for every complete partition,
   plus entry masks, all node checks/masks and the single final boundary. Input
   declarations and wire aliases cost no Boolean gates. Count the 16,386 original
   inputs once, not97 times, in the connected logical graph.
4. Public/private classifications across aliases. All entry masks and node masks
   yield private wire objects even for high zero bits under current public-only
   folding. Untouched wires/active/R are also private. Therefore the proposed cut
   does not create or destroy public-folding opportunities. If implementation
   inspection finds otherwise, stop or count the explicit boundary overhead;
   do not silently subtract an assumed conversion/check.

A live 16,386-entry alias vector suffices; compact output-run descriptors, coverage
records and hashes can document its transitions. Existing masks emit contiguous
output runs; verify that property before relying on the compact encoding, and
stop on a mismatch. No need to retain 97 full alias vectors or re-emit 27M gates.
This public alpha-renaming argument, verified transitions and complete partition
counts justify the sum as a **connected logical DAG count**, with no missing
operations. Without them report only complete fragment counts, not a complete
NTT count. No new interface equality constraints are claimed: the interfaces
are aliases within one graph, not separately proved statements.

There will be no materialised full-transform trace or full BC-1 fingerprint.
An ordered partition-fingerprint/alias-manifest digest is a different artifact;
do not present it as the hash of a monolithic trace. Independently evaluated
fragments with freely chosen intermediate witnesses would accept a larger
relation. Harness checks alone cannot make independent proofs compose.

## Proposed validation and invocation accounting — inactive

Compare every usable final coefficient against the pinned `_ntt`, evaluated
uninterrupted as ordinary exact-integer source, and an independent direct
polynomial-evaluation oracle. The latter uses Horner evaluation modulo q at
`r_k=1753^(2*BitRev8(k)+1) mod q`, k=0..255, with its own eight-step reversal and
no `_ZETAS`, butterfly, partition or stage helper imports. This is the odd-root
evaluation convention derived from Algorithm 41 and its negacyclic factorisation,
corresponding to FIPS 204 §2.5/§7.5. The schedule and Horner oracle must agree
on all outputs, including ordering. No oracle has run in this planning package.

Each of the following is one distinct counted case; it is incomplete until all
97 partition observations, controls, complete outputs and required comparisons
pass. Canonical frontiers and sticky R are checked throughout. For inactive or
rejected paths compare the documented wrapper semantics (zero unusable outputs),
not speculative unmasked reference internals.

| ID | Exact input / controls | Purpose and required result |
| --- | --- | --- |
| V0 | 256 zeros; active=1, R=0 | Zero boundary; all outputs=0, validity=1 |
| V1 | Coefficient 1 is1; all others0; active=1, R=0 | Unit polynomial X;256 distinct ordered odd roots exercise every stage and twiddle assignment; validity=1 |
| V2 | Repeat `[MIN,MAX,-q,q,-1,0,1,q-1]`32 times; active=1, R=0 | Full entry domain including extremes; complete canonical output equality, no raw-entry overflow rejection |
| V3 | `x_i=(-1)^(i mod2)*(((i+1)^3+17i+11) modq)`; active=1, R=0 | Dense asymmetric signed input; lane dependencies, corrections, final representation |
| V4 | V3; active=0, R=0 | No active-path rejection; validity=1 but all outputs=0/unusable |
| V5 | V3; active=1, R=1 | Sticky rejection through every partition; validity=0, all outputs=0 |
| M0 | 255 integer coefficients | Typed shape refusal before circuit allocation, no output |
| M1 | Coefficient 0=2^63, other 255 zero | Typed range refusal before truncation/allocation, no output |
| T0 | Separate copy of V0 post-E31 checkpoint with coefficient 0 changed to q | Reject malformed noncanonical internal frontier before N00; original case state untouched |
| T1 | Separate copy of V5 post-E31 checkpoint with raw R cleared | Reject parent/state inconsistency before N00; original sticky state untouched |

MIN=-2^63 and MAX=2^63-1. Other invalid types and length excesses remain explicit
source-contract obligations, not additional executed cases concealed inside M0/M1.
The T cases test harness transport integrity, not arbitrary malicious intermediate
witness soundness. Post-entry host checks only diagnose circuit outputs; the
mathematical invariant and connected wires justify eliminating repeat conversions.

Exactly **97 generation/counting invocations +6 full-transform cases +2 malformed
entry cases +2 checkpoint cases =107 new invocations**, proposed cumulative
ceiling **279→386**. Counted generation happens once per partition, not an extra
count-only pass followed by generation. Six cases imply **582 ordinary evaluator
calls and 582 independent observer passes**, transparently constituent observations
of those same six cases, not 582 unreported test vectors. Record each generation
and case admission before work; failed, interrupted and incomplete invocations
consume their admission. No retries or extra parameterised cases are implicit.

There is no feasible uninterrupted full Boolean evaluation under the existing
retained-trace/gate limits. Compare partitioned candidate evaluation with both
uninterrupted integer implementations, reuse prior four-node uninterrupted versus
partitioned evidence, and verify the full new alias/coverage contract. This is
finite full-output validation plus a structural argument, not exhaustive full-NTT
equivalence or compiler certification. All-stage metadata coverage and the X
oracle are meaningful error detectors, not guarantees of detecting every bug.

## Cost evidence, separate estimates and admission

All new numbers below are source/evidence arithmetic, **not new measured counts**.
The complete stage pilot measured 621,868 total /246,058 AND gates for its reference
fragment, 357,016 /135,162 for fully guarded experimental nodes, and 213,448 /81,838
with internal canonical reuse. Earlier single-butterfly counts 155,402 /61,450
and 89,189 /33,726, and two-node counts 310,804 /122,900 and 178,378 /67,452 remain
unchanged. They cover their own boundaries, not a complete transform.

From the recorded phase deltas, removing two repeated SPEC-004 conversions saves
71,784 total /26,662 AND gates at the measured internal boundary. A measured
canonical-producer node is therefore 17,405 /7,064 including its existing guards,
corrections, masks and validity. One checked mod64 anchor is 35,892 /13,331.
The proposed per-entry 64-bit mask adds 66 /65; final 256-lane masking plus validity
adds 16,388 /16,386 under the current emitter conventions.

| Work | Conditional nominal total gates | Conditional nominal AND gates | Scope of estimate |
| --- | --- | --- | --- |
| 256 checked entry conversions and masks | 9,205,248 | 3,429,376 | `256*(35,892+66)`; all signed64 inputs |
| 1,024 canonical-producer butterflies | 17,822,720 | 7,233,536 | `1,024*17,405`; **uniform anchor assumption**, all twiddles not measured |
| One final boundary | 16,388 | 16,386 | 256 full words plus final predicate |
| Complete nominal logical graph | **27,044,356** | **10,679,298** | No omitted cuts, no duplicated entry conversion |

Public-constant folding and bounds may change counts with the 255 twiddles and
different scope histories. These totals are planning estimates, not uniform exact
costs or a claimed speedup. Future actual counts must cover every partition; even
a complete candidate count cannot establish a measured complete-reference saving.
Entry conversions alone are substantial. Multiplying the four-node saving by 256
would miss them and misrepresent internal reuse and final-boundary costs.

Complete reference **circuit generation is not necessary** to answer this pilot's
question: can this isolated candidate implement and count a full forward transform
with the stated input/output relation and bounded live storage? Uninterrupted
reference evaluation, independent Horner outputs, the structural argument and
complete connected count accounting suffice for that experimental question.
The deliverable deliberately excludes a measured reference-vs-candidate full-NTT
gate reduction. Such a comparison would require separately authorised complete
reference count coverage with the same entry/final boundaries; summing old
generic butterfly counts is not that evidence.

### Generation, evaluation, memory and storage estimates

Stage evidence measured 0.246019996 s for the 213,448-gate reuse count and
0.259453527 s for materialisation. Reference partitions took approximately 0.366–
0.368 s for 311k gates. Combined generation rates suggest 1.1–1.4 microseconds/gate.
Per-case evaluation **plus independent observation** of those partitions was
roughly 0.30–0.40 microseconds/gate. These are small historical samples; the
16,386-input frontier, all twiddles and new mapping code add uncertainty.

| Future aggregate cost | Planning range, seconds | Includes |
| --- | --- | --- |
| Generate/count all 97 partitions once | 30–38 | Nominal 27.04M gates; no duplicate count-only generation |
| Six evaluations and observations over entire logical graph | 49–65 | Both trace passes, all 582+582 calls |
| Integer references/Horner and four refusal cases | 1–3 | Unmeasured bound estimate; no native ABI harness |
| State/alias handling and measurement records | 1–3 | All 97 transitions and complete result assembly |
| 13 serial guarded work-batch starts | 2–3 | No overlapping workers |
| Preflight, lint/format, documentation, audit and closure | 8–10 | Reuse ~2.535 s audit anchor; include five-second bookkeeping charge |
| Cleanup/evidence reserve | 10 | Held back, not admission space for more work |
| Total with reserve | **101–132** | Engineering estimate, not a guaranteed upper bound |

The proposed package stop is 135 s including this work and reserve. Keep an
append-only package clock across batches; charge actual durations and existing
bookkeeping, never reset per partition. Before each batch require its declared
reservation plus the still-needed checks/audit and cleanup within remaining time.
Use at most eight partitions per batch with a conservative 10 s work reservation;
the existing 60 s command/55 s child maxima remain hard ceilings, not permission
to spend 60 s on each batch. Keep 10 s generator and 2 s ordinary evaluator limits per
partition/pass, with the independent observer inside the same bounded batch.
Retain the prior evaluator wire cap of 2,000,260; even the stricter partition
stop uses at most 466,388 wires. All passes remain subordinate to the
batch/package deadlines. If measured progress invalidates the remaining-work estimate, stop admission and report
incomplete; do not exploit empty reservations or skip checks to finish.

Nominal E/N partitions contain 287,664/278,480 gates. With the current 17-byte
gate record, 56-byte header, 33-byte footer and 33-byte bytes-object overhead, a
retained trace is approximately 4,890,410 /4,734,282 bytes; F is 278,718 bytes.
A stricter 450,000-gate partition stop bounds retained trace size near 7,650,122
bytes, below 8 MiB, while leaving the existing 2M physical emitter ceiling intact.
Transient serialisation copies and live wire objects require separate memory
accounting. Emit to memory, never a multi-MiB disk file that violates 1 MiB/file.

The stage pilot measured 32,874,496-byte Python high-water RSS and 29,597,696-byte
cgroup peak; its maximum separately sampled tree RSS was 52,207,616 bytes.
These different metrics are not interchangeable. Estimate 60–96 MiB process RSS
for a new partition including its wider input frontier, live aliases, checkpoints
and one trace; this is unmeasured. Preserve the 128 MiB arithmetic RSS stop,
256 MiB process address-space and aggregate cgroup ceilings, and zero swap.
No two traces, duplicate per-case copies or child helper outside the monitor.

Temporary state target is below 256 KiB: six 256-word checkpoints plus compact
metadata and one live 16,386-entry alias frontier. Persist binary/small bounded
representations, not full Python object graphs. Keep 8 MiB temporary and 1 MiB/file
hard limits. Store at most 8 KiB compact evidence per partition, plus case results,
guard/audit records and source seals: a 1.2 MiB package target, within the cumulative
10 MiB output envelope after this planning package. Verify actual available
balance at future admission. Full ~460 MB monolithic trace storage is unnecessary
and not proposed. Memory, disk storage and hypothetical trace size are distinct.

### Admission and smallest proposed amendment

**Do not execute with current resources.** The test ledger is exhausted and
61.264731091912836 s is below even the 101 s planning range. Although partitions
fit individual physical limits, their logical ~27M gates exceed the existing 2M
gate allowance; it must not be reset at cuts. The following changes are proposed
only, never activated by this document:

| Amendment | Exact proposal | Rationale |
| --- | --- | --- |
| Invocations | +107; cumulative279→386 | 97 generation probes and ten explicit cases |
| Implementation time | **+74 s**, cumulative300→374 s | Remaining135.264731091912836 s; package cap135 s |
| Aggregate generation gates | **30,000,000** for all partitions combined | Nominal27,044,356 plus limited twiddle/overhead uncertainty; incomplete prefixes also charged |
| Per-trace/memory/process/storage | No increase | 2M physical gate ceiling; stricter450k partition stop, existing256 MiB/8 MiB/1 MiB limits |

For this 135 s design the exact shortfall is73.735268908087164 s;74 is the smallest
whole-second addition that covers it. It is not an empirically proven minimum
runtime. The upper estimate 132 s has only a small rounding margin, and actual
guards may still stop the run. No safe smaller amendment is established by the
existing samples. No 64M-gate/2 GiB proposal, analysis/isolation transfer or future
amendment is implicit. A smaller partial schedule would fail this package's
complete-forward question; it is not recommended as a substitute outcome.

## Exact next package, gates for success and stop conditions

The inactive [machine-readable proposal](data/s3_mldsa_full_forward_ntt_plan_1/proposal.json)
and [estimate record](data/s3_mldsa_full_forward_ntt_plan_1/resource-estimates.json)
are the implementation brief for **S3-MLDSA-FULL-FORWARD-NTT-PILOT-1**. Implement
its isolated wrappers/independent oracle/driver only after explicit authorisation
of that package and its amendments. Before any generation, review source and
static alias coverage, seal inputs, confirm the current ledgers and headroom,
and confirm estimated work plus required closure fits. No automatic preliminary
probe is permitted beyond the 107 declared invocations.

Success requires all 97 generation records complete, all ten cases pass, all 256
entry lanes and 1,024 nodes uniquely covered, exact final output equality, valid
private alias composition, complete XOR/AND/NOT accounting, and passed resource,
lint/format, preservation and report-completion checks. Report stage-specific
counts, total connected count, separate boundary/internal costs, actual time and
peak memory/storage. A capped prefix, missing transition, failed observer,
incomplete case or failed report cannot be labelled a complete transform result.

Stop on first mismatch, invalid alias/public classification, repeated/missing
coverage, unexpected rejection or accepted malformed input, resource breach,
insufficient remaining closure time, or incomplete reporting. Preserve consumed
invocations, prefix counts, last completed partition and partial diagnostics;
release the live synthetic trace/checkpoints as authorised cleanup. No retry,
smaller partition redesign, replacement oracle, baseline regeneration or limit
increase during the run. A failed pilot is evidence, not permission to spend the
remaining proof attempt.

The route after a successful pilot still needs separately scoped inverse NTT,
pointwise private products/matrix accumulation, full-verifier integration, norm/
decomposition/hint linkage and complete authentication. This is one forward-NTT
component, not a whole signature circuit or proof. Signed messages, contexts,
certified fields, holder binding, revocation linkage, samplers and caps are
unchanged. No complete-verifier/proof saving or RISC Zero forecast is inferred.

ARITH-LOWER-001 remains open for actual full-transform validation and compiler/
profile conformance. HINT-LOWER-001, OC-REL/EXT/PRIV/BUDGET, adaptive Delta_tail,
component advantages at reduction budgets, DEP-001/DEP-002 production release,
custody/entropy/erasure/side-channel protection, and complete proof knowledge/
privacy remain open. Stages 2–3 remain open; isolation remains safely stopped
and unactivated; proof ledger two attempts used, one unused.

## This package's permitted checks

Only the existing documentation helpers are adapted in this package's evidence
directory. The runner has exactly preflight, import sorting, helper formatting,
helper lint, format-check, scope preparation and one full preservation-audit
command. It imports no candidate and offers no test/build/generation command.
The corrected chunked auditor preserves the original 8,759-path baseline and
all subsequent supplementary seals, exact name inventory and historical report
prefixes. The baseline is not regenerated. Measured closure below includes
report completion and the outer 256 MiB guard, not just content comparisons.


## Measured documentation and preservation closure

The full forward plan is complete; execution is not admitted under the current
allowance. The separate 107-invocation/135-second/30M aggregate-gate proposal is
inactive; no profile or execution allowance is activated.
Helper lint/format and documentation/static consistency checks pass. No test,
circuit generation, arithmetic probe, build, estimator or cryptographic execution ran.
The single [preservation audit](data/s3_mldsa_full_forward_ntt_plan_1/result.json)
completed content/inventory comparison, report readback and outer guard, exit 0.
Coverage: 10,440 disjoint content paths;
10,469 identity-inclusive paths.
Original baselines and historical document prefixes are preserved.

| Measurement | Result |
| --- | --- |
| Audit wall time | 2.442549156 s |
| Audit cgroup-v2 memory.peak | 23,318,528 bytes |
| Audit sampled process-tree RSS | 41,005,056 bytes |
| Maximum guarded-job cgroup peak | 23,318,528 bytes |
| Maximum separately sampled tree RSS | 41,005,056 bytes |
| Guarded commands | 7, 3.182701998 s |
| New analysis charge, including five bookkeeping seconds | 8.182701998 s |
| Cumulative analysis charge | 54.576216841/300 s |
| Analysis remaining | **245.423783159 s** |
| Implementation unchanged | **61.264731092 s**, **279/279 tests** |
| Temporary disk observed peak | 0 bytes; zero retained |
| Evidence bytes at audit completion | 344,228 |

No failures, retries or resource breaches. The unchanged 256 MiB cgroup guard
covers the worker and descendants, including charged file-cache/kernel memory;
swap is zero. Sampled RSS is a separate metric. Final bounded bookkeeping uses
256 MiB address space, five-second CPU/alarm, two CPUs and 1 MiB/file inside the
five-second charge; it does not repeat content comparisons.
The [closure](data/s3_mldsa_full_forward_ntt_plan_1/validation-closure.json)
and [additive seal](data/s3_mldsa_full_forward_ntt_plan_1/manifest.json)
record the exact balances. Isolation remains safely stopped/unactivated with
250.22 s and 22 original cases pending. Stages 2–3 remain open; proof ledger
**two attempts used, one unused**, CPU proving paused.
