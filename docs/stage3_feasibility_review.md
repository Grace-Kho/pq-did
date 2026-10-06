# Bounded message-preparation pilot and feasibility review

18 September 2026. **All nine message-preparation pilot cases passed.** The measured
hint prefix's 13,532,448 AND gates are core work in the current decoder lowering;
no test-comparison gates or accidental widened byte cells were found. Its frozen
raw-view size implication is **3,253,150,624 bytes**, presently a **conditional
projection for authentication**, not a generated proof or an unconditional audited
whole-circuit lower bound. Prepare a reviewed change to the concrete profile before
larger integration. No construction change is made by this review.

Only manuscript **Sections II–VIII** were used. The selected PDF still hashes to
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
SPEC-001/002/003/004, crypto parameters, original vectors and earlier JSON evidence
are preserved. The prior [resource preflight](stage3_resource_preflight.md) and
[evaluation proposal](data/stage3_evaluation_resource_plan.json) remain historical
records; their conditional 64M-gate/2 GiB envelope is **inactive**. The previous plan
proposed file streaming for those large cases, not permission to materialise them.

## Evidence and exact constructions

All four prior count targets use fixture `alpha-42-old-002c`, from
`tests/fixtures/relations_vectors.json`, SHA-256
`e2e5981ffa88eb5efef5ec3c6c6af424c3a5f35aa020c8cb4abf2b5f6c2661f2`.
Their exact public E(X) is preserved in
[the original raw count record](data/stage3_signature_count_preflight.json), with digest
`eeca5991bd3b0ac6f48819be07bd0e54fa8015ea1bbc34919a616f1e3d883db5`.
Expected pp/key/schema/statement are public. The original 42632 private positions
remain: xH bytes 0:32, attributes 32:1056, rid 1056:1060, signature 1060:4369,
siblings 4369:5329. The 61 hint bytes are 4308:4369 (bits 34464:34952).
There is no separate decoded hint, coefficient, B, Mcred or representative witness.

| Prior target | Exact core entry/schedule | Recorded result |
|---|---|---|
| Message preparation | `parse_auth_witness`, `link_disclosure`, `certified_message`, `decode_expected_public_key`, `message_representative`, then `scope.output(())` | Complete 2034776 gates / 413709 ANDs |
| Complete hints | `signature.decode_hints` on the original hint slice | 32M-gate prefix / 13532448 ANDs |
| Signature with norm | `decode_signature`, then require `response_norm(...).within_bound` | 32M-gate prefix / 13503270 ANDs; norm unreached |
| Preparation with decoding/norm | `prepare_verifier_inputs`, then require the response norm | 32M-gate prefix / 13451261 ANDs; representative and norm unreached |

The complete message fingerprint is
`7778652f244202f6fda785104a5113964dc4172fccc6f39ec404a137d50a15b7`.
The three original capped prefixes have **no complete construction fingerprint**.
This review extracts the unchanged message schedule into the shared diagnostic
`preflight_signature_inputs.message_preparation` helper. Every pilot reproduces the
original counts, fold counts and fingerprint. Production circuit modules are unchanged.

## Functional message pilot

The separate `message_preparation_pilot_v1` profile enforces the authorised per-case
2.1M gates, 40 MiB trace, 192 MiB RSS, 256 MiB address space, 10 s generation,
5 s evaluation and 30 s wall, with one sequential worker. The evaluation deadline
also covers independent output observation and reference comparisons. Ordinary
profiles and the existing 32M count profile are unchanged. RSS is sampled every
10 ms; RLIMIT_AS independently enforces address space. Sampling is not a kernel
RSS hard limit and may miss transient peaks.

Initial WSL available RAM was 5004357632 bytes (4.661 GiB), with 1021582753792 bytes
of virtual filesystem free space. The runner rechecked headroom before each case.
Worker baseline RSS after fixture/import preparation was 30543872–30683136 bytes
(29.129–29.262 MiB), and baseline virtual size was 39718912 bytes (37.879 MiB).
Existing environment evidence records a 7.57 GiB WSL guest and RAM-backed `/tmp`;
virtual disk free space is not a host physical-storage guarantee.

`evaluate` requires a complete materialised trace: **streaming emission exists,
streaming evaluation does not**. The pilot uses the existing evaluator, followed by
an independent trace reader in sequence, without two simultaneous wire arrays.
Both observe the same full circuit. No comparison gate is added. Eight outputs
(holder preimage/value, encoded B, Mcred, formatted message, tr, representative
preimage and mu) match independent length/tag framing and stdlib SHA3/SHAKE, with
additional Stage 2 reference comparisons on structurally valid inputs. The public
key's existing standalone decoding tests are retained. Recorded outputs are only
from explicitly synthetic fixtures, not operational holder data.

| Case | Circuit output; message/key/representative validity | Observed contract |
|---|---|---|
| Original valid fixture | 1; 1/1/1 | All prepared bytes match references |
| Invalid attribute length | 0; 0/1/0 | Structural rejection remains sticky |
| Nonzero attribute tail padding | 0; 0/1/0 | Structural rejection remains sticky |
| Out-of-domain rid | 0; 0/1/0 | Structural rejection remains sticky |
| Well-formed disclosed value mismatch | 0; 0/1/0 | Same-witness projection rejects |
| Changed holder secret | 1; 1/1/1 | Holder hash, binding and message/representative change |
| Changed hidden attribute | 1; 1/1/1 | Binding and message/representative change |
| Changed valid rid | 1; 1/1/1 | Message/representative change |
| Changed signature bytes only | 1; 1/1/1 | Prepared bytes unchanged; signature verification is absent |

Invalid-case hash outputs are recorded for reproducibility but are **unusable**.
Acceptance at this preparation layer is not credential authentication. A changed
certified message must be checked against its signature in the later verifier.

All nine fresh circuits have 2034776 gates, 413709 ANDs, 2077410 wires and 34591281
trace bytes (32.989 MiB). The evaluator allocates exactly 2077467 bytes for wire
values, including bytearray overhead. Generation took **3.686–3.768 s**, Boolean
evaluation **0.437–0.458 s**, and evaluation plus independent observation/comparison
**0.564–0.583 s**. Total child times were 4.268–4.367 s. Maximum process high-water
RSS was **107380736 bytes (102.406 MiB)**; maximum sampled RSS was 106381312 bytes.
The previous materialisation model's 170.225 MiB estimate exceeded this measured
peak. That supports this pilot's margin, not a bound on future circuits or proofs.
There were no resource terminations or correctness failures in the pilot.

[Raw pilot evidence](data/stage3_message_preparation_pilot.json) contains every output,
flag, mutation, fingerprint, timing, baseline, headroom snapshot and enforced profile.

## Hint-prefix cost audit

Reviewed manuscript VII-A.6 p. 16 against `signature.py`, `control.py`, `words.py`,
`emitter.py`, and the actual probe. The invoked standard's verification/decode chain
is Algorithms 3 → 8 → 27 → 21. Algorithm 21 reconstructs six polynomials from the
61-byte hint encoding, with within-row ordering and unused-byte checks.
[FIPS 204, Algorithms 8/21/27](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf).

The current implementation uses the prescribed distinction between representations:

- Six rows, 256 coefficient cells per row, and 55 masked slots per row; the trailing
  padding loop has another 55 slots. The row number and capacities are public.
  The source Index, First, endpoint and coefficient positions are private where
  derived from the encoding; private values never set host iteration bounds.
- Encoded hint cells stay **8-bit bytes**. Counters, comparisons, decoded positions
  and polynomial coefficients use the prescribed signed64 integer representation.
  The binary coefficient values 0/1 do not turn integer polynomial slots into
  one-bit control predicates. Predicates/rejection masks themselves are single bits.
- Each ordering check reads y[Index-1] and y[Index] in source order. The assignment
  reads y[Index] again. Each private read scans all **61** byte cells. Restricting
  the scan to a smaller array using inferred ranges or reusing a private read would
  change the current lowering. Writes scan all **256** signed64 cells from a snapshot.
- Bounds, ordering, padding, arithmetic representability and active-path rejection
  remain. Masked iterations still emit their source tests, checked increments and
  writes. Private inactivity does not authorise host skipping.
- Folding is only for entirely public operands. In particular, a public zero
  difference AND a private selector is retained. Thus even upper coefficient bits
  whose mathematical values stay zero acquire private wires after the first write.
  Equality with a zero-extended byte still retains private-accumulator AND public-1
  steps in its 64-bit fold. Removing these gates would be partial simplification.

An attributed count calls the same canonical emitter, recording disjoint host-side
categories. Small completed traces reproduce the uninstrumented fingerprint and
all fold counts; category totals count each emitted gate once. The single necessary
32M audit rerun reproduces the historical XOR/AND/NOT and byte totals exactly:

| Category | Emitted gates | AND gates | Share of prefix ANDs |
|---|---:|---:|---:|
| Write equality selectors | 5828960 | 4663168 | 34.459% |
| Write data muxes | 13891045 | 4663116 | 34.459% |
| Read equality selectors | 9978624 | 3326208 | 24.579% |
| Read data muxes | 1251720 | 417240 | 3.083% |
| Step tests, arithmetic and control | 540883 | 209397 | 1.547% |
| Write selection/bounds/validity | 292868 | 146292 | 1.081% |
| Read selection/bounds/validity | 212343 | 105837 | 0.782% |
| Row boundary checks | 3557 | 1190 | 0.009% |
| **Total** | **32000000** | **13532448** | **100%** |

It stops inside a write mux, at row 5 (zero based), its tenth slot: 284 of the 330
slots completed, the 285th is partial. Padding and final validity output are unreached.
There are 32042634 wires and 544000056 logical bytes, **zero stored trace bytes**,
no full wire-value array, and **zero test-comparison gates**. Attribution/reporting
adds Python work but emits no gates. The 60.232 s count stayed within the existing
300 s/128 MiB RSS/256 MiB AS limits; high-water RSS was 46.500 MiB (sampled 46.855).
Its incremental prefix-only digest is
`269371381e8079cb1eb3438e1d88872a6f553729030ff74f4ac175d28fd97947`;
this excludes the un-emitted suffix/footer and is **not** a circuit fingerprint.

[Raw cost breakdown](data/stage3_hint_prefix_audit.json) also records public-only
folded operations. No source-grounded representation/lowering error was demonstrated
in this audit, so no production correction or substitute construction was made.
This does not complete the independent BC-1 compiler-conformance audit.

## Inclusion and communication status

**Semantic inclusion is mandatory:** VII-A.6 requires the credential signature
verification on the original hidden signature and reconstructed Mcred. Its invoked
FIPS decoder includes hint reconstruction. The signature and preparation functions
already route that same private slice to this decoder; no public-key knowledge makes
the hints public. The same 6*55 lowering and private array scans would survive a
continuation of these exact sources. Upstream private rejection cannot make a private
operand public under all-public-only folding; a two-step context test supports that
local argument. Wire numbers and guard gates may change on embedding.

**Exact numerical inclusion is not yet independently established for CGen(auth).**
The complete compiler is absent, whole-program source/control lowering is unaudited,
and local tests are not a full embedded-prefix identity proof. In particular, the
preparation helper is explicitly partial and lacks the complete FIPS source-order
composition. The 13532448-AND figure is mandatory core cost of this decoder prefix,
not an unconditional theorem about every implementation of BC-1. A lower-bound claim
for the final authentication circuit needs an audited source mapping preserving this
recipe, operand classification and folding under full integration. The count remains
strong feasibility evidence for continuing the **current** concrete implementation.

Under those explicit continuation assumptions, g_auth >= 13532448 and the monotone
frozen formula gives:

```text
proof_bytes = 5363104 + 960 * ceil(g_auth / 4)
            >= 5363104 + 960 * 3383112
            = 3253150624 bytes
```

Status: **conditional authentication projection/lower bound**, 3.253 GB or 3.030 GiB;
no complete authentication circuit, proof or proof benchmark exists. Hint/signature/
preparation prefixes overlap and are **not added**. No count of later work is inferred.
[Machine-readable accounting and assumptions](data/stage3_feasibility_accounting.json).

## Three separate feasibility questions

**Relation correctness.** The complete message-only preparation passes the nine
functional cases, independent byte/hash comparisons and fixed-structure checks.
Existing hint fragments cover boundary/order/padding behaviour; the complete hint,
signature verification, Merkle/authentication circuit and proof implementation remain
unvalidated. The Stage 2 executable relation is separate evidence, not a circuit proof.

**Hardware execution.** Incremental counting demonstrates that these prefixes can
be emitted within modest compiler memory. It does not establish complete evaluation,
MPC sharing, proving or checking memory. Materialising just the hint prefix needs
518.799 MiB for trace bytes before wire values or runtime overhead, beyond present
AS limits. A faithful streaming evaluator could remove trace residence; it is absent
and would still need measured wire storage, I/O and output-observation machinery.
No larger evaluator was implemented here.

At the conditional AND count, each raw view is 3388441 bytes; keeping all 1440 views
would use 4879355040 bytes. Keeping those plus a copied proof would require 8132505664
bytes, already more than the guest's entire 8126111744-byte RAM, before the runtime,
trace or share-wire state. These are **illustrative retention strategies**, not
unavoidable peak-memory lower bounds: sequential evaluation and disk-backed raw views
could reduce RAM without reducing communication. Raw randomness must still be
preserved faithfully until openings are selected; seeded tapes are not authorised.
Full counts, a concrete prover/checker storage schedule, host-backed scratch capacity,
MPC wire representation and measured execution are missing. The old tentative 8 GiB
process budget cannot fit in this guest. `/tmp` is unsuitable for large proof storage.

**Application usefulness.** The implementation plan requires synthetic KYC workflows,
independent verifier sessions, freshness and end-to-end median/tail measurements,
but defines **no numerical proof-size, latency, throughput or uplink acceptance
threshold**. Deployment request lifetime is also unset. Thus no documented SLA can
be declared passed or failed. At illustrative ideal payload rates, 3.253 GB alone
needs 260.252 s at 100 Mbit/s, or 26.025 s at 1 Gbit/s; these are arithmetic scenarios,
not measured network or proving latency and not application targets. Protocol overhead,
proving/checking and state-update retries add work. Python generation time is never
multiplied by 480 to claim proving latency. This communication pressure warrants a
profile review even before completing larger counts; more gates cannot reduce this
conditional floor if the audited construction is retained.

## Recommended next package

**Prepare a reviewed change to the concrete profile**, preserving the implemented
relation, fixtures and lifecycle interfaces as the reference. First record numerical
application acceptance criteria and review the source-to-circuit inclusion argument.
Then compare explicit options on the unchanged private relation:

1. Retaining BC-1/raw views with faithful streaming/disk scheduling may improve RAM
   execution, but cannot remove the raw communication term. Propose it only if the
   resulting byte budget is acceptable; no automatic 64M run is justified now.
2. A revised circuit profile would have to explicitly reconsider signed64 coefficient/
   index representations, full private-index scans, fixed masked loop schedules and
   the ban on partial folding/CSE. These are construction changes, not silent fixes.
   Preserve required checks and prove equivalence; give the new profile an identity.
3. A revised proof representation/system would need separate review of raw tapes/views,
   commitments, challenge mapping, repetitions, openings and erasure. Do not silently
   seed tapes, reduce 480 repetitions or alter ML-DSA/tree/security parameters.

Affected manuscript areas are VII-A.6's bounded computation/BC-1/admission/shared
prover, VII-A.7's checker and VII's exact size rule (pp. 16–17); VIII-A's capacity,
correctness/resource and loss accounting, VIII-C's extraction and VIII-D's joint-view
privacy analyses must match any revised construction. Recheck VIII-E lifecycle/freshness
composition if execution/transcript behaviour changes. A decision proposal must identify
which claims/parameters remain valid and which need a new argument. Neither a candidate
replacement nor reduced communication is assumed secure or implemented here.

## Reproduction and validation

Use the existing `.venv`; output paths must be new to preserve previous evidence:

```bash
.venv/bin/python scripts/review_feasibility.py --kind pilot --output NEW-pilot.json
.venv/bin/python scripts/review_feasibility.py --kind hints --output NEW-hint-audit.json
```

The hint command exits 1 for its expected gate-limit non-completion. Each run embeds
its fresh WSL snapshots, source hashes and controls. No sampler or NTT integration,
proof generation, larger materialised evaluation or automatic resource escalation
was performed. Validation totals and preservation audit are recorded below.

The [focused suite](data/stage3_feasibility_focused.json) passes **119 tests** in
69.19 total child seconds across seven isolated targets; [regression](data/stage3_feasibility_regression.json)
passes **1432 tests**, no skips, in 123.43 total child seconds across 35 targets.
It includes existing division, control, hashes, signature/input, reference-relation
and native interoperability coverage. New tests check independent framing/mutation
contracts, attribution trace identity and local upstream-guard classification.
Ruff lint passes; **123 Python files** pass formatting. The initial 11-test harness
check also passed before the pilot. Full hint functional validation remains open.

```bash
.venv/bin/python -c 'import json; from scripts.preflight_signature_inputs import host_snapshot; print(json.dumps(host_snapshot()))' > /tmp/pqdid-feasibility-host.json
.venv/bin/python scripts/validate_signature_inputs.py \
  --host-snapshot /tmp/pqdid-feasibility-host.json --output NEW-focused.json \
  --separate-test-targets --tests tests/unit/test_feasibility_review.py \
  tests/unit/test_signature_inputs.py tests/unit/test_signature_circuit.py \
  tests/unit/test_bc1_control.py tests/unit/test_bc1_accounting.py \
  tests/unit/test_count_preflight.py tests/unit/test_validation_support.py
.venv/bin/python scripts/validate_signature_inputs.py \
  --host-snapshot /tmp/pqdid-feasibility-host.json --output NEW-regression.json \
  --separate-test-targets --tests tests/unit/test_*.py \
  tests/integration/test_*.py tests/smoke/test_hashes.py
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

[The preservation audit](data/stage3_feasibility_audit.json) checks original sources,
parameters/profiles, vectors and historical evidence, source hashes and arithmetic.
Correctness/conformance, complete hints/preparation/authentication, proofs, numerical
security-loss validation and remaining Stage 2/DEP-001/DEP-002 obligations stay open.
This bounded package is complete and stops here.
