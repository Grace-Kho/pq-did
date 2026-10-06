# SPEC-004 adoption and counting-only resource preflight

SPEC-004 is **agreed** with the user's explicit sign-correction wiring. **241 focused
and 1421 regression tests pass without skips.** Message preparation has a complete
count; three hint-containing targets exceed the authorised 32-million-gate cap.
No larger functional evaluation, sampler/NTT integration or proof was attempted.

Only manuscript Sections II–VIII were used. The PDF remains unchanged at SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
SPEC-001/002/003, cryptographic parameters, the 5329-byte witness, all previous
vectors/results and the environment are preserved.

## Adopted construction and audit

[The complete agreed wording](spec_issues.md#spec-004--restoring-division-work-registers-and-exact-emission-schedule)
fixes the unsigned64 magnitude (including MIN's `2^63`), public-zero 65-bit remainder,
64-bit quotient, all 64 descending scan steps, one full 65-bit trial subtraction per
step, retained terminal carries and both outputs for every div/mod call. With
`mux(s,a,b)` selecting b on true, all correction values are 65 bits:

```text
Q65 = zero_extend(Q)
nz = NOT equality(R, public_zero65)       # equality starts with public 1
negative_Q = negate65(Q65)
negative_Q_minus_one = subtract65(negative_Q, public_one65)
corrected_negative_Q = mux(nz, negative_Q, negative_Q_minus_one)
b_minus_R = subtract65(b65, R)
corrected_negative_R = mux(nz, public_zero65, b_minus_R)
output_Q = mux(input_sign, Q65, corrected_negative_Q)
output_R = mux(input_sign, R, corrected_negative_R)
```

Named intermediates are reused in that order. Check signed64 representability of
output_Q then output_R before narrowing; validity is `(Q_valid AND R_valid) AND (b>0)`.
Active-path sticky rejection remains mandatory. Zero constructs and returns invalidity
with unusable outputs; negative/private/out-of-signed64 divisors fail at construction.
VII-A.6, printed p. 16, needs this wording in a later manuscript/lowering-reference
update; it is an agreed clarification, not an existing manuscript quotation.

The [implementation](../src/pqdid/circuits/division.py) deliberately replaces the
old private-R false arm with public zero and swaps the final validity AND operands
to the agreed order. The previous source is frozen in
[a test-only reference](../tests/reference/spec004_provisional.py), labelled with
its original source hash. No production alternative selector exists.

New [literal wiring tests](../tests/unit/test_spec004_adoption.py) record all 68
65-bit subtractions, 69 muxes, equality, descending trial-bit inputs, named reuse,
Q/R narrowing and the last two AND operand records. Old/new traces differ while
counts, values and invalidity agree for seven public divisors and twelve signed64
endpoints/exact/inexact cases. Existing independent Fraction/floor fixtures and
exhaustive widths 2–5 still pass, including `a=b*Q+R`, `0<=R<b`, MIN/1, MAX, zero,
unsupported divisor rejection, inactive/active faults and three-mode identity.

### Refreshed dependent measurements

All **30** dependent component/mode probes complete under the unchanged ordinary
extended profile. Every fingerprint changes; all gate/AND counts, fold counts and
trace lengths remain unchanged. New modes agree. These are the preserved probe
definitions including their explicit expected-output comparisons:

| Predicate | Gates | AND |
|---|---:|---:|
| divmod-q | 36280 | 13462 |
| canonical-q | 36087 | 13397 |
| centred-even | 37004 | 13725 |
| ring-add | 36420 | 13530 |
| ring-subtract | 36485 | 13530 |
| ring-multiply, two private operands | 83535 | 34653 |
| ring-public-multiply, public left 25847 | 82950 | 34458 |
| decompose | 110695 | 41047 |
| use-hint | 184266 | 68373 |
| ntt-butterfly, two private operands/public twiddle | 155658 | 61451 |

[Raw dependent measurements](data/stage3_spec004_dependent_measurements.json) retain
timings, resource controls and complete fingerprints. Three additional
[core-only counts](data/stage3_spec004_core_measurements.json) refresh the multiplication,
public-left multiplication and butterfly identities: respectively 83342/34588,
82757/34393 and 155272/61321 gates/ANDs. Their additional test predicates remain
193/65, 193/65 and 386/130 gates/ANDs. Required overflow/reduction/validity gates are
retained. The legacy driver's `historical_predicate_fingerprint` field here means
the old **probe definition rebuilt against the adopted source**, not the original
historical bytes. The previous JSON records are unchanged. SPEC-004's resolution
does not establish full BC-1 conformance or make differently specialised operands
interchangeable.

## Counting execution and exact targets

The separate `signature_count_preflight_v1` profile permits 32000000 emitted gates,
1073741824 logical trace bytes and at most 10485760 diagnostic bytes per target,
300 seconds and one worker. It retains the stricter existing **128 MiB sampled RSS**,
**256 MiB kernel AS**, 10 ms polling and 2 MiB log limit. Ordinary/materialised limits
remain 2000000 gates, 40 MiB trace, 10/5-second generation/evaluation and 30-second
case wall time. No enlarged evaluation profile is installed.

Initial WSL available RAM was 5010931712 bytes (4.667 GiB) and free storage
1021589123072 bytes. The runner re-inspects both before each target and records the
actual snapshots. The count-only wrapper calls the same canonical emitter operations,
incrementally hashes every actual gate record and enforces a separate logical-byte
guard, including header/footer. It has no trace buffer/sink, full graph or wire-value
array. Only symbolic inputs, live gadget words, counters and a hash state remain.
Guard tests demonstrate byte-identical fingerprints to ordinary emission, exact
logical/gate boundaries and absence of stored traces. Counts are not formulas.

All targets use existing fixture **`alpha-42-old-002c`** in
`tests/fixtures/relations_vectors.json`. [The raw preflight record](data/stage3_signature_count_preflight.json)
pins its file hash and stores the **exact canonical E(X) in hexadecimal** plus its
SHA-256 for every target. Expected pp/key/schema/X are public. All targets retain
42632 original private input positions, with no decoded/advice fields:

| Private field | Byte interval (end exclusive) |
|---|---|
| xH | 0:32 |
| canonical attributes | 32:1056 |
| rid | 1056:1060 |
| signature | 1060:4369; its hints are 4308:4369 |
| siblings | 4369:5329 |

Message preparation composes parsing/disclosure, holder/B/Mcred/framing, expected-key
decoding, public tr and private FIPS representative, without signature decoding.
Hint reconstruction uses just the original hint slice and all required syntax/index/
padding checks. Signature-with-norm adds response decoding and requires its separate
strict norm result after full decoding. Full preparation calls the existing same-witness
preparation function, including decoding, then requires the norm. These diagnostic
predicates are not complete FIPS verification/authentication. Each final output retains
sticky rejection; **test-only comparison gates are zero**.

The previously capped targets were counted once each; the stronger signature/norm
and preparation/norm targets replace redundant weaker attempts. Previously completed
response, norm, key and hash-kernel components were not recounted under the larger
profile. Public/private operands and source schedules were not changed to fit.

| Target | Result | Gates | AND | Wires | Logical bytes | Seconds | Peak worker RSS |
|---|---|---:|---:|---:|---:|---:|---:|
| Message preparation | Complete count | 2034776 | 413709 | 2077410 | 34591281 | 5.930 | 30.668 MiB |
| Complete hints | Gate limit, prefix only | 32000000 | 13532448 | 32042634 | 544000056 | 54.848 | 41.566 MiB |
| Signature with norm | Gate limit, prefix only | 32000000 | 13503270 | 32042634 | 544000056 | 55.842 | 49.840 MiB |
| Preparation with decode/norm | Gate limit, prefix only | 32000000 | 13451261 | 32042634 | 544000056 | 55.268 | 50.621 MiB |

The completed message-preparation construction fingerprint is
`7778652f244202f6fda785104a5113964dc4172fccc6f39ec404a137d50a15b7`.
Stopped prefixes have **no complete fingerprint or complete count**. They stop within
hint decoding; later norm and (in full preparation) representative hashing remain
unreached. The logical bytes for prefixes exclude the un-emitted footer. All stored
trace bytes are **zero**; retained per-target diagnostic files occupy 20213–20316
bytes, with bounded checkpoint rewrites also separately recorded. The sampled RSS
maximum is 53448704 bytes (50.973 MiB); sampling can miss transient overshoot.
Gate limits, not logical bytes, memory or time, caused all three non-completions.

## Proposed functional-evaluation resources — not activated

There is **no existing streaming evaluator**. `Emitter(mode="stream")` writes a
trace incrementally, but `evaluate` explicitly requires a materialised `Circuit`.
It retains the trace bytes and allocates one byte per wire; observed Python bytearray
overhead is 57 bytes. At materialisation, generation briefly holds a mutable trace
and its immutable copy. Current output-observation tests also expect a full trace.

The [machine-readable plan](data/stage3_evaluation_resource_plan.json) uses:

```text
W = inputs + emitted_gates + 2
T = completed trace bytes
materialised peak estimate = max(B + 2.25*T, B + T + W + 57)
future streaming peak estimate = B + W + 57 + 1 MiB I/O allowance
B = 96 MiB allowance for Python, fixtures, live gadget/output state and headroom
```

B and 2.25 are conservative **planning allowances**, not measured constants or
proven memory bounds. The multiplier covers the mutable buffer/copy and spare
capacity; it is not a claim about exact allocator growth. Calibration against four
existing completed evaluations reproduces their exact wire allocations (379334,
1563340, 324442 and 1761755 bytes). All modelled peaks exceed the recorded process
peaks of 48.523, 87.066, 39.125 and 83.391 MiB respectively. These checks support a
pilot budget, not a guarantee; trace size is never treated as total process memory.

| Target | Recommended subsequent budget | Readiness |
|---|---|---|
| Message preparation | 2.1M gates; 40 MiB trace; RSS 192 MiB; AS 256 MiB; generation 10 s, evaluation 5 s per witness, wall 30 s; one worker | Complete count supports a separately authorised materialised pilot. Exact wire allocation 2077467 bytes (1.981 MiB), trace 32.989 MiB; estimated peak 170.225 MiB. No new evaluator required. |
| Complete hints | **Conditional** 64M gates; 2 GiB trace storage; RSS 256 MiB; AS 512 MiB; generation 300 s, evaluation 120 s per witness, wall 600 s; one worker | Feasibility review and complete count first; file-streaming evaluator/oracle required. |
| Signature with norm | Same conditional 64M / 2 GiB / RSS 256 MiB / AS 512 MiB / 300 s + 120 s / wall 600 s envelope | No complete count; norm is still unreached. Same prerequisites. |
| Preparation with decode/norm | Same conditional 64M / 2 GiB / RSS 256 MiB / AS 512 MiB / 300 s + 120 s / wall 600 s envelope | No complete count; representative hashing and norm remain unreached. Same prerequisites. |

**64M is a proposed ceiling, not an extrapolated full count.** Do not launch those
evaluations unless a separately approved complete counting run establishes the target
fits. A possible next counting decision is 64M gates / 2 GiB logical bytes / 300 s,
retaining the present 128 MiB RSS/256 MiB AS; it has not been executed or authorised
by this package. If it still caps, stop and revisit feasibility again.

At that conditional ceiling, exact structural storage would be 64042691 wire bytes
(61.076 MiB) and 1088000089 trace bytes (1037.598 MiB); the streaming peak model is
158.076 MiB. A 2 GiB disk allowance covers one trace plus modest diagnostics; retain
one target trace at a time. Just the measured 32M prefix already implies over 518.799
MiB of materialised trace and a 1263.297 MiB estimated generation peak. Thus the
existing materialised evaluator is unsuitable for these targets under present limits.

At the old materialised evaluator's measured hash-kernel throughput, message replay
would take roughly 0.45 s and 64M gates roughly 14.1 s. Counting-prefix throughput
suggests 110–112 s to emit the conditional ceiling. These are **estimates**, not
full-target/streaming measurements; the proposed limits reserve time for I/O and
validation. A new file reader must incrementally check fingerprint/header/footer,
opcode counts and operand bounds, keep the byte-per-wire array, and avoid loading
the trace or a second array. Generation/evaluation and independent observation should
run sequentially in separate workers. Literal small-trace/malformed-file equivalence
tests and measured RSS/runtime pilots are necessary before large evaluations.

The bottleneck is the prescribed 6*55 unrolling with repeated full 61-cell reads and
256-cell signed64 snapshot writes. Review that source-order lowering and obtain
complete counts before the hint-containing feasibility decision. Do not reduce
capacity, narrow representations or modify parameters to fit. A successful count is
not functional validation, full BC-1 conformance, authentication or proof feasibility.

## Reproducible validation and remaining work

From the project root, using the existing interpreter and the inspected host snapshot:

```bash
.venv/bin/python -c 'import json; from scripts.preflight_signature_inputs import host_snapshot; print(json.dumps(host_snapshot()))' > /tmp/pqdid-preflight-host.json
.venv/bin/python scripts/validate_signature_inputs.py \
  --host-snapshot /tmp/pqdid-preflight-host.json \
  --output docs/data/stage3_spec004_focused.json --separate-test-targets --tests \
  tests/unit/test_spec004_adoption.py tests/unit/test_count_preflight.py \
  tests/unit/test_bc1_division.py tests/unit/test_spec004_alternatives.py \
  tests/unit/test_scalar_ring_circuit.py tests/unit/test_bc1_emitter.py \
  tests/unit/test_validation_support.py
.venv/bin/python scripts/preflight_signature_inputs.py \
  --output docs/data/stage3_signature_count_preflight.json
.venv/bin/python scripts/preflight_signature_inputs.py --arithmetic \
  --output docs/data/stage3_spec004_dependent_measurements.json
.venv/bin/python scripts/validate_signature_inputs.py \
  --host-snapshot /tmp/pqdid-preflight-host.json \
  --output docs/data/stage3_spec004_core_measurements.json --cases \
  legacy-ring-multiply/count legacy-ring-public-multiply/count legacy-ntt-butterfly/count
.venv/bin/python scripts/validate_signature_inputs.py \
  --host-snapshot /tmp/pqdid-preflight-host.json \
  --output docs/data/stage3_spec004_regression.json --separate-test-targets --tests \
  tests/unit/test_*.py tests/integration/test_*.py tests/smoke/test_hashes.py
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Outputs are exclusive-create; use new paths when repeating. The host snapshot is
embedded in the raw records. [Focused](data/stage3_spec004_focused.json): **241 passed**
in 15.51 total child seconds. [Regression](data/stage3_spec004_regression.json):
**1421 passed**, no skips, 122.99 total child seconds over 34 sequential targets;
peak worker RSS 124059648 bytes (118.313 MiB). Lint passes; **119 Python files** are
formatted. The counting command exits 1 to signal its three intentional non-completions;
all 30 dependent probes and three refreshed core counts pass. The initial focused
subset also passed; no failing functional run or higher-budget retry was needed.

[The audit](data/stage3_spec004_audit.json) records preservation and source consistency.
Full hint/signature/preparation functional validation remains open, as do independent
full BC-1 conformance, samplers/NTT/Merkle/authentication composition, proofs and all
outstanding Stage 2/DEP-001/DEP-002 work. This package stops here.
