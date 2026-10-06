# Stage 3 BC-1 foundation

The foundation measurements below are preserved historical evidence. SPEC-003's
initialisers are now agreed; fresh stability checks and limits are recorded in
[the validation report](stage3_hash_enrolment.md#confirmed-convention-and-extended-validation).
Full BC-1 conformance is still unverified.

## Contract recorded before implementation

Only manuscript Sections II–VIII are authoritative. The pinned PDF SHA-256 remains
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The source is VII-A.6, “Circuit profile BC-1”, printed p. 16; input/relation definitions
are VII-A.5/.6, pp. 15–16, and V-B/C, p. 8. Admission/proof-size accounting is VII-A.6
and the closing VII formula, pp. 16–17, and VIII-A, pp. 17–18. Confirmed requirements
are R-034–R-037/R-041; Stage 2 local relations remain the later correctness oracle.

| Prescribed rule | Foundation contract |
|---|---|
| Basis and ordering | XOR, AND, NOT and constants; OR expands as `(a XOR b) XOR (a AND b)`. Evaluate left operand first, retain source order, increasing array indices and left-fold sums; AND ordinals follow emission order |
| Wires | Reserve 0/1 for constants, then number private inputs in serialised order and gate outputs in emission order; copies/permutations reuse wires |
| Input bits | Serialised bytes MSB-first; internal arithmetic tuples indexed by increasing bit weight; conversion is rewiring, not arithmetic or a changed protocol encoding |
| Arithmetic | Signed 64-bit words, sign-extended 65-bit addition/subtraction, 128-bit products, representability checked before narrowing; no private width reduction |
| Ripple | Low bit first: t=a XOR b; s=t XOR carry; next=(a AND b) XOR (t AND carry). Add starts carry 0; subtraction complements rhs and starts carry 1 |
| Equality/comparison | Equality left-folds XNORs; signed comparison uses the sign of the extended difference |
| Multiplication | Multiply unsigned magnitudes through shifted partial products in increasing bit order, then apply sign; narrow only with a validity wire |
| Deferred arithmetic rules | Reduce each ring operation modulo q=8380417, retaining FIPS centred representatives; positive-constant division/reduction scans magnitude bits high to low with conditional subtraction and signed floor/remainder correction; integer shifts use checked multiplication/floor division by powers of two |
| Bitstrings versus integers | Bytes and Keccak lanes remain 8-/64-bit bitstrings; attribute integers remain eight-byte strings inside the circuit, with disclosed unsigned range checks outside |
| Selection | `mux(s,a,b)=a XOR (s AND (a XOR b))`, selecting b on 1; private reads scan all cells using equality selectors; writes multiplex from a snapshot |
| Control/rejection | Both branches are constructed, true before false; private faults set sticky rejection only on active paths. Invalid reads yield zero; invalid writes do nothing. Fixed loops retain source initialisation/tests/increments and every iteration; termination masks later work; sampler byte counters are shared across each invocation; parallel FIPS updates read the preceding state |
| Public-only folding | Evaluate an operation during construction only when all its operands are public constants. Retain every other gate, including private identities and partial-constant operations; no CSE, reassociation or gate reorder |
| Output | One conjunction of the required checks and absence of rejection; a private failure never stops construction |

The foundation implements deterministic emission/evaluation, Boolean and word
selection, equality/signed comparison, checked add/subtract/multiply, fixed-array
selectors and active-path rejection. Positive-constant division/reduction, integer shifts,
ring/centred reduction, sampler-loop lowering, complete parsing/hashing and relation
compilation remain unimplemented. Bitstring shifts/permutations are rewiring only.
The actual relation sizes stay 256 and 42632 private bits; smaller component circuits
are development tests, not replacement enrolment/authentication profiles.

Routine internal choices (not protocol changes): Python symbolic Bit handles carry only
wire identity and public classification, never private values. Bit-to-bool conversion
rejects host branching. Arithmetic tuples are least-significant-bit first. The
following fold convention is now agreed under **SPEC-003** (other derived details
still require full conformance review): equality starts from public 1 and visits bit
index 0 upwards; ripple emits the
terminal carry too. Magnitudes are formed by a sign-extended negate and selection;
64×64 raw partial bits are padded/shifted into 128-bit words, all 64 full-width sums
are retained, and sign application follows. Development traces pin this explicit recipe;
they do not claim a compiled complete CGen circuit or a proof-system identity.

A compact internal gate record stores opcode/operand wire IDs; output and AND IDs
are implicit from emission order. A versioned development header and final output/count
footer are hashed with SHA-256 for comparison. This is not a proof commitment, HRO
invocation, protocol encoding or replacement for E(X). Public construction data and
private-input count enter the header; witness values are only supplied at evaluation.

Materialised, counting and streamed-file sinks share one canonical operation path.
Counting hashes each record without storing gate history or per-wire classification.
The caller still retains live symbolic values, and a materialised evaluator retains
one byte per wire; streaming alone is not a bounded-memory compiler/evaluator guarantee.
Limits abort before excess gate/storage output and poison the emitter; unfinished output
has no completed-circuit result. A footer is written only at finalisation; an I/O or
time failure during/after that write still means failure, so a footer alone must never
be treated as completion. Unexpected writer failures also poison the emitter.

Initial development budgets, selected after inspecting actual WSL memory/storage:
one worker, 200000 emitted Boolean gates, 8 MiB output, 10 s generation, 5 s evaluation,
65536 private-input positions; resource probes additionally cap address space at
256 MiB. These are configurable harness limits, not suite or BC-1 constants. Small
deterministic limits will test termination. No complete authentication circuit or
proof-sized allocation will be attempted. Measured resources and final evidence follow.

## Implemented interfaces and representation

| Module | API and evidence boundary |
|---|---|
| [emitter.py](../src/pqdid/circuits/emitter.py) | `Emitter(private_inputs, limits=..., mode=..., public_data=..., sink=...)`, `inputs`, `constant`, `xor/and_/not_/or_/mux`, `finish`; `Circuit`, `Counts`, `Limits`, `ResourceLimit`; `evaluate` accepts packed private bytes only after construction |
| [words.py](../src/pqdid/circuits/words.py) | `add64/sub64/mul64` return `Checked(value, valid, wide)`; `less64/less_equal64`, `equal`, `mux_word`, `from_serialised/to_serialised`, `constant`, bitstring `bit_shift/rotate_left`; private arithmetic consists entirely of gates |
| [control.py](../src/pqdid/circuits/control.py) | `Scope.require/checked/output`, true-before-false `branch`, fixed-array `read/write`; a gadget API, not a Python AST compiler |
| [accounting.py](../src/pqdid/circuits/accounting.py) | `authentication_proof_bytes`, `authentication_view_bytes`, `authentication_count_admitted`; integer arithmetic only, no proofs or full CGen admission |
| [measurement driver](../scripts/measure_bc1_foundation.py) | `--suite` runs four components in three modes sequentially, compares traces/counts, exercises three small limits and writes resource/projection evidence |

`Emitter` receives a private-input **count/position layout**, public construction bytes
and budgets; there is no witness argument. Serialised position i is wire 2+i, with
MSB-first packing and zero unused terminal bits in small development witnesses. A
word conversion rewires those positions into increasing numerical weight; it emits
no gates. Production relation widths remain enrol=256 and auth=42632. Authentication
layout remains `xH || Esch(m) || rid || sigma || w` (32+1024+4+3309+960 bytes), as
specified in [stage2_relations.md](stage2_relations.md). Public E(X) is not an additional
private input. The component probes do not lower either complete relation.

The `Bit` handle rejects Python truth conversion and cannot index a Python sequence.
All gadget loops traverse public widths/capacities; no evaluator value feeds back
into emission. A caller must still follow this API discipline when writing a later
compiler: this is not a sandbox preventing arbitrary incorrect compiler code.
Private identities (`x XOR x`, `x AND 0`, `x AND 1`, repeated expressions) remain
distinct emitted gates. Fully public operations increment separate fold counters
and reuse constant wires. No gate-list optimisation follows emission.

`Checked.valid` must be required through `Scope.checked`/`require` before treating a
result as an accepted integer. Low bits remain defined on overflow so compilation
continues and the rejection wire decides acceptance. Comparisons use a 65-bit signed
difference, without rejecting differences merely outside the 64-bit range. The
current derived `<=` is `< OR ==`; its extra gates are explicit under SPEC-003.
Reads scan every cell (development cap 1024); invalid indices yield zero and writes
leave the snapshot unchanged. Inactive reads also yield zero and inactive writes
leave cells unchanged. Branch return values are muxed after both callbacks run.
Scope rejection accumulates monotonically; termination-mask tests demonstrate the
primitive but do not implement a sampler or complete source-programme lowering.

Development format **PQDID-BC1-DEV1** is fixed as:

- 56-byte header: `>16sQ32s`, padded magic, input count, SHA-256 of public construction
  bytes (development limit 65536 bytes; not the protocol's E(X) admission bound).
- 17-byte record per emitted gate: `>BQQ`, opcode 1=XOR/2=AND/3=NOT, operand a/b;
  NOT uses b=0. Gate output is `2+inputs+record_index`; AND ordinal starts at zero
  and increments only for AND records. Constants use no gate records.
- 33-byte footer: `>BQQQQ`, marker 255, output wire, XOR/AND/NOT counts. Exactly one
  Boolean output is selected. `Scope.output` left-folds checks and absence of rejection.
- SHA-256 over the entire header/records/footer is the development fingerprint.
  Generation time and witness values are excluded. This is never HRO, a proof
  commitment, E(X), an accepted prover-supplied circuit or a protocol wire encoding.

The evaluator validates the internal trace hash/header/footer, operand ordering and
counts, then computes each Boolean wire. Count/stream results have no materialised
trace and cannot be evaluated by this evaluator. Arbitrary external circuit parsing
is outside its contract; protocol verification will derive its own full CGen circuit.

## Correctness and determinism evidence

**135 focused tests passed**, using independent integer expectations rather than
calling the reference arithmetic as a substitute for private gates:

- [Emitter tests](../tests/unit/test_bc1_emitter.py): literal hand-rendered OR bytes
  and fingerprint, full OR/mux truth tables, private identities/CSE avoidance, public
  folds, constant numbering, input padding, foreign-wire and host-branch/index errors,
  deterministic successful/rejected witnesses and materialised/count/stream equality.
- [Word tests](../tests/unit/test_bc1_words.py): exhaustive signed 2-/3-/4-bit
  add/subtract/multiply, 17 full-width operand pairs for each operation, true 128-bit
  products including MIN×MIN, min/max comparisons, carry/borrow/overflow, wrong
  expected-validity rejection, a literal two-bit ripple trace with terminal carry,
  exact full-width component counts, big/little-byte rewiring and bit shifts/rotations.
- [Control tests](../tests/unit/test_bc1_control.py): active/inactive index boundaries,
  invalid zero/no-op behaviour, snapshot and sequential writes, true-first branches,
  selected/inactive overflow, public inactive branch construction, merge orientation
  and exhaustive fixed-iteration termination/sticky-fault masks.
- [Accounting tests](../tests/unit/test_bc1_accounting.py): both frozen formula forms,
  byte/ceil boundaries, existing authentication arithmetic vectors, huge Python
  integer counts, invalid types and exact view-admission boundary. No proof allocation.

Audited operation-only counts with two private 64-bit operands and output=`valid`:

| Operation | Intermediate | XOR | AND | NOT | Total |
|---|---:|---:|---:|---:|---:|
| add64 | 65 | 196 | 131 | 1 | 328 |
| sub64 | 65 | 196 | 131 | 66 | 393 |
| mul64 | 128 | 25867 | 21254 | 322 | 47443 |

Addition has 65 full five-gate ripple steps and three narrowing gates. Subtraction
adds 65 complement gates. Multiplication retains both 65-bit magnitude preparations,
4096 raw partial ANDs, 64 full 128-bit sums, sign application and representability
checks; only all-public operations fold. These counts pin the provisional development
recipe, not a unique manuscript circuit. The equality-initialiser example and proposed
resolution are recorded precisely in [SPEC-003](spec_issues.md#spec-003--fold-initialisers-and-derived-gadget-recipes-affect-gate-identity).

The measured predicates below additionally require no active fault and compare the
result with public targets: add(2,3)=5, sub(2,3)=-1, mul(2,3)=6, and selecting cell 2
from `[0x81,0x36,0xA5,0xFA]` gives 0xA5. Targets are public constants during generation;
the example witnesses are supplied only after completion. Thus their counts differ
from the operation-only table. All twelve runs matched counts, logical bytes, folds
and fingerprint across modes. Stream files were independently hashed and size checked;
the small unit fixture also compares the full materialised/stream bytes directly.

## Resource budgets and termination

The initial host snapshot at 2026-09-17 11:28:09 UTC recorded 8126111744 bytes WSL
RAM, 5478871040 available, and 2147483648 free swap bytes. Workspace available storage
was 1021614362624 bytes; `/tmp` had 4003999744 bytes available. The conventional
cgroup memory-limit paths were not exposed; no stronger cgroup bound is inferred.
The measurement record preserves this snapshot and a second snapshot at measurement.
No host/native configuration or dependency was changed.

Per-component defaults: **one worker**, 200000 Boolean gates, 8 MiB stored output,
10 s generation, 65536 input positions, 5 s evaluation and 300000 evaluator wires.
The CLI additionally sets Linux RLIMIT_AS to **256 MiB address space**, and `--suite`
uses a fresh child process and **30 s wall timeout** for each probe. These are
development controls, not additions to the confirmed cryptographic profile.

Gate/input bounds are checked before excess emission/allocation; stored-output bounds
include header/footer. Counting emits zero stored bytes, so its output budget is not
a limit on the logical trace length; gate/time/input bounds still apply. Generation
checks elapsed time at API/gate/folding boundaries, and evaluation checks per input/
gate plus completion. These are cooperative limits: a blocked custom sink or arbitrary
work between gadget calls cannot be pre-empted by them. The external probe timeout
and address-space limit provide additional containment only for the measurement driver.

Small resource probes completed their failure reporting, not their circuits:

| Limit | Reason | Gates emitted | Bytes stored | Completed circuit |
|---|---|---:|---:|---|
| max_gates=3 | gate-count limit | 3 | 107 | no |
| max_output_bytes=60 | output-storage limit | 0 | 56 | no |
| max_seconds=0 | generation-time limit | 0 | 0 | no |

The unit tests additionally cover exact-limit success, failure while writing the footer,
input limits before allocation, all-public time exhaustion, partial sink writes and
evaluation time/wire limits. Aborted emitters cannot resume or finalise. The probe
reports `complete: false`/reason/progress and exits 2 for handled resource failures;
`generation_complete` separately identifies a successful generation if evaluation fails.
Unexpected exceptions/child timeouts propagate as process failure and cannot produce a
successful suite record. Temporary stream files are discarded, including partial ones.

Materialised emission uses one growing bytearray and briefly a second immutable copy
at finalisation, then drops the mutable copy. Counting/streaming retain no gate history
or classification table; input handles and current gadget words still occupy memory.
The evaluator uses **one byte per wire**, plus Python overhead; it is not a streaming
evaluator. Custom sinks can retain memory themselves (e.g. BytesIO); the measured sink
is a bounded temporary file. Arbitrary future compiler liveness, caches, ASTs, loop
unrolling and witness state are not bounded merely by this emitter design.

## Recorded component measurements

The following tables are generated from
[stage3_bc1_measurements.json](data/stage3_bc1_measurements.json). They are single
instrumented runs on the inspected WSL host with `tracemalloc` enabled; generation
and evaluation timings include that overhead. RSS is Linux process high-water RSS
and includes interpreter/imports/allocator state, not just the trace. Traced memory
excludes allocations before tracing and some native allocations. Serialised bytes
are actual materialised/stream sizes, or the identical logical count-mode size.
No measurement is a complete authentication count or a rigorous lower bound for it.

| Predicate | XOR | AND | NOT | Total gates | Wires | Trace bytes |
|---|---:|---:|---:|---:|---:|---:|
| add64 | 262 | 199 | 67 | 528 | 658 | 9065 |
| sub64 | 262 | 199 | 132 | 593 | 723 | 10170 |
| mul64 | 25933 | 21322 | 388 | 47643 | 47773 | 810020 |
| select4 | 338 | 308 | 266 | 912 | 1010 | 15593 |

| Predicate | Mode | Generation s | Evaluation s | Peak RSS MiB | Retained trace bytes | Traced generation retained / peak bytes |
|---|---|---:|---:|---:|---:|---:|
| add64 | materialised | 0.001625 | 0.000647 | 23.219 | 9098 | 18612 / 34878 |
| add64 | count | 0.001631 | — | 23.055 | 0 | 9514 / 16641 |
| add64 | stream | 0.001544 | — | 23.488 | 0 | 9514 / 16641 |
| sub64 | materialised | 0.002016 | 0.000728 | 23.289 | 10203 | 19717 / 37207 |
| sub64 | count | 0.001650 | — | 23.312 | 0 | 9514 / 20889 |
| sub64 | stream | 0.001813 | — | 23.344 | 0 | 9514 / 20889 |
| mul64 | materialised | 0.165541 | 0.168949 | 24.664 | 810053 | 821303 / 1694332 |
| mul64 | count | 0.147084 | — | 23.266 | 0 | 11250 / 67841 |
| mul64 | stream | 0.161337 | — | 23.453 | 0 | 11250 / 67937 |
| select4 | materialised | 0.002624 | 0.001233 | 23.238 | 15626 | 23652 / 41011 |
| select4 | count | 0.002604 | — | 23.285 | 0 | 8026 / 10347 |
| select4 | stream | 0.002728 | — | 23.484 | 0 | 8026 / 10347 |

Retained-trace memory uses `sys.getsizeof(bytes)`, so materialised rows include a
33-byte Python object overhead beyond payload length. The retained input tuple/Bit
handles occupy 8240 bytes for arithmetic probes, 6192 for select4; these are subsets
of traced retained memory, not totals to add again. For multiplication, generation
traced peak falls from 1694332 bytes materialised to 67841 counting, while counting
still retains 11250 traced bytes at the reporting point. Stream sink buffering and
its final file-hash pass affect process/traced peaks too; the JSON separately records
whole-probe peak traced memory. Materialised multiplication's evaluation wire array
occupies 47830 bytes including overhead. No claim is made that these small observations
predict later hash/sampler/ML-DSA compiler memory or practical authentication execution.

## Integer-only authentication size projections

For the **complete authentication circuit's** AND count g, the implementation uses
only integer arithmetic:

```text
V = (42632 + 2*g + 7) // 8
proof_bytes = 64 + 480 * (515 + 2*V)
            = 5363104 + 960 * ((g + 3) // 4)
```

| Assumed complete-authentication g | Projected proof bytes |
|---:|---:|
| 0 | 5363104 |
| 1000000 | 245363104 |
| 10000000 | 2405363104 |

These are projections, including the algebraic zero-count example, not measured
proof sizes. No component AND count is substituted as if it were the whole circuit
or a proved lower bound. The view-admission helper tests only `V <= 2**32-1`; it does
not check every public domain, E(X), protocol admission or resource feasibility.
The complete authentication AND count and full BC-1 equivalence remain null in the
manifest. No view/tape/proof-sized buffer, prover, verifier or complete auth circuit
was created; the 480 raw-tape repetitions and every suite constant remain unchanged.

## Validation commands, preservation and remaining work

Executed using the established environment (17 September 2026):

```bash
.venv/bin/ruff format src/pqdid/circuits scripts/measure_bc1_foundation.py tests/unit/bc1_cases.py tests/unit/test_bc1_emitter.py tests/unit/test_bc1_words.py tests/unit/test_bc1_control.py tests/unit/test_bc1_accounting.py
.venv/bin/python -m pytest tests/unit/test_bc1_emitter.py tests/unit/test_bc1_words.py tests/unit/test_bc1_control.py tests/unit/test_bc1_accounting.py -q
.venv/bin/python -m pytest tests/unit tests/integration tests/smoke/test_hashes.py -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python scripts/measure_bc1_foundation.py --suite --host-snapshot /tmp/pqdid-bc1-host.json --output docs/data/stage3_bc1_measurements.json
```

Results: **135 focused passed in 0.99 s; 1025 regression passed in 4.45 s** (1002 unit,
19 integration, four fixed hash); lint passed, all **77 files** formatted. The new
files alone were formatted; previous files passed checking unchanged. During test
development, two expectations were corrected: the internal header is 56 bytes, and
subtracting a public constant legitimately folds its 65 constant NOTs. The latter
still emits the private ripple/rejection gates; the final test asserts the exact
668-gate composed predicate and fold count. No previous vector was adjusted.

The pre-change host snapshot is preserved inside the measurement JSON; future runs
can omit `--host-snapshot` to record only their current host. Use a new output path
for later measurements so the recorded evidence is retained. The JSON pins all five
circuit modules and the measurement script by SHA-256; the manifest records the
module digests under implementation evidence, not confirmed parameters. A SHA-256
fingerprint is useful for byte identity only, not proof of semantic correctness.

The preservation audit compares 6802 protected pre-existing files: the 6801 outside
`configs/suite.json` are unchanged. Only implementation evidence changed in the suite;
all confirmed groups, deployment placeholders and agreed SPEC-001/002 records match
the pre-change manifest. Earlier production/tests/fixtures, manuscript, plan, dependency
and lock files, native sources/install, environment evidence and editor settings remain
unchanged. Documentation/status/traceability updates and new foundation files are the
work-package changes. No reinstall or native rebuild was performed.
The temporary standard-library audit also checked all 52 main requirement rows,
115 local links and 22 Markdown tables in the five updated overview/foundation
documents, source hashes, mode equality, gate/byte arithmetic and limit outcomes.

**Implemented subset:** emitter/evaluator, three canonical emission modes, Boolean
and checked 64-bit add/sub/multiply, comparisons/selection, bit/byte rewiring, active
fault accumulation, scanned arrays, development limits and integer accounting.
**Unimplemented:** positive-constant division/reduction with signed correction, checked
integer shifts, q/centred ring arithmetic, full FIPS sampler loops/shared counters,
SHA3/SHAKE, canonical parser circuits, complete enrolment/authentication CGen, relation
circuit equivalence, protocol admission, proofs and full-circuit feasibility.

SPEC-003 initialisers have since been agreed. These historical Boolean tests alone
do not establish complete canonical identity; see the new trace/stability audit below.
Remaining Stage 2 work stays separate: bounded key generation/signing and setup/import,
production revocation/witness updates, DEP-001 signing-tail/Delta-tail validation and
remaining DEP-002 release-role integration. Freshness, trusted-time expiry, request/
controller authentication and atomic consumption are later lifecycle responsibilities.

**Historical next work package (since implemented):** implement SHA3/SHAKE Boolean gadgets and canonical parsing
gadgets, compare them with independent/reference vectors and rejection cases, and
retain witness-independent generation and these conservative resource controls. Then
construct and validate the complete enrolment circuit against the Stage 2 relation.
Independently establish full conformance before claiming complete BC-1 identity. Stage 3
remains in progress; this foundation package ends here without starting that next work.

## SPEC-003 adoption and reproduced foundation — validation follow-up

**Agreed user clarification (17 September 2026):**

> Initialise equality with public 1. Initialise magnitude multiplication with a public 128-bit zero accumulator; add all 64 shifted partial products in increasing order using full-width ripple addition, retaining terminal carry operations.

Preserve all existing BC-1 gate/operand ordering, checked narrowing and public-only
folding. VII-A.6's equality/magnitude sum wording on printed p. 16 requires later
alignment with this sentence; the PDF is unchanged. The existing production path
already implements it and has no alternative selector. Test-only first-term variants
remain diagnostic. Other historically proposed derived details are not implicitly
approved; full independent canonical compiler conformance remains unverified.

[test_confirmed_bc1.py](../tests/unit/test_confirmed_bc1.py) adds a literal two-bit
1-seeded equality trace, a hand-expanded first zero-accumulator product/ripple with
its terminal carry, and the actual 64-partial full-128-bit addition schedule. Existing
exhaustive checked arithmetic, carry, ordering and public-fold tests pass again.
The exact historical multiplication demonstration (target 6, witness 2 and 3) retains
25933 XOR / 21322 AND / 388 NOT = 47643 gates, 47773 wires and 810020 serialised bytes.
Its complete fingerprint remains
`88d78f60c37cc7223662e64f2a6bd8cb9e257125dd0377412e4f3faeb3afd19b`.
Enrolment retains 194691 gates / 38787 AND, 194949 wires and 3309836 bytes, fingerprint
`57712c0fdb2e6ace69c7cc2ddda40028eef8b97b192766aee30efcb624b1c0e2`.

Fresh original/extended materialised traces and an extended stream compare byte for
byte; counting has the same counts/fingerprint. Old measurements stored digests, not
raw traces, so historical equality is digest/count/length equality. There is no
construction difference to explain: adoption confirms the already fixed convention.
Resource metadata never enters the circuit header or logical fingerprint.

The approved separate operational profile is 2000000 gates / 41943040 trace bytes,
one worker; generation/evaluation stay 10/5 seconds. After inspecting actual WSL
memory/storage, the existing 256 MiB address-space cap is retained alongside a 128 MiB
RSS watchdog polled every 0.01 seconds and a 30-second per-case wall guard. RSS is
measured separately; the sampled watchdog is not a kernel hard RSS limit. Routine
emitter defaults remain 200000 gates / 8 MiB. See [the full controls and host snapshot](stage3_hash_enrolment.md#approved-profile-host-inspection-and-enforcement).

All 17 previously skipped hash tests, nine diagnostic probes and both stability
cases complete. Counts/stream probes establish construction, not witness evaluation.
Regression: 1106 passed, no skips, in 31.91 s; seven new audit/control tests pass;
Ruff lint and formatting pass for 93 files. The exact per-case outcomes and full
commands are in [the validation report](stage3_hash_enrolment.md#confirmed-convention-and-extended-validation),
with [new measurements](data/stage3_hash_enrolment_validation.json). Historical
foundation/alternative/hash records retain their original hashes.

Ready for authentication private parsing and checked division/reduction/ring gadgets;
this validation package stops here. Full BC-1 conformance, authentication, sampler
lowering, complete 480-repetition raw-view proofs and feasibility remain open. The
9587104-byte enrolment proof projection is a calculation only. Stage 2 keygen/signing,
revocation/update, DEP-001 tail and DEP-002 release obligations remain open.
