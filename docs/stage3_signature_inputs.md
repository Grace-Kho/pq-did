# Stage 3 private signature decoding and verifier inputs

**Later update — 18 September 2026:** SPEC-004 is now agreed with public zero in the
negative-remainder correction's false arm and Q-then-R-then-b>0 validity order.
[The adoption/preflight report](stage3_resource_preflight.md) records deliberate
trace changes, refreshed measurements and new counting results. The pending/provisional
statements and numbers below are preserved historical evidence, not current status.

This package adds FIPS response/hint decoding and same-witness credential-message
preparation. These interfaces **do not verify a signature, authenticate a presentation
or produce a proof**. Completed component circuits are distinguished below from
full reconstruction/compositions that stop at the authorised resource limit.

Only manuscript Sections II–VIII are authoritative. The manuscript SHA-256 remains
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
SPEC-001/002/003, all suite parameters, the environment and earlier vectors are
preserved. The pinned [August 2024 FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
was rechecked directly: local PDF SHA-256
`57239b9f84c03227eda3ca0991204dc7764c79af9ce2e6824eda774918d46b6b`.
Existing DEP-001/002 dispositions remain in force.

## SPEC-004: pending exact division recipe

VII-A.6, “Circuit profile BC-1”, printed p. 16, fixes signed64 integers, extended
arithmetic, a high-to-low magnitude scan with conditional subtraction, and signed
floor/remainder correction. It does **not** specify the remainder/trial workspace
width, reuse of a subtraction's sign versus a distinct comparison/subtraction, or
whether quotient generation/correction also occurs for remainder-only calls. FIPS
§2.3 determines mathematical residues, not the manuscript's Boolean emission recipe.
Nothing in the authoritative text uniquely settles these choices. SPEC-004 stays
**pending**, and division-dependent traces/counts remain **provisional**.

The existing [division implementation](../src/pqdid/circuits/division.py) has one
development path, unchanged by this package. Its exact recommended clarification is:

> For division by a public positive signed64 constant b, form the unsigned64
> magnitude of the signed64 dividend by sign-extending to 65 bits, negating,
> selecting by the input sign, and retaining the low 64 bits. Initialise a 65-bit
> remainder R and a 64-bit quotient Q with public zeros. Visit magnitude bits 63
> down to 0. Wire trial=(R<<1)|magnitude[bit] in 65 bits; emit one full 65-bit ripple
> subtraction difference=trial-b, retaining its terminal carry. Set
> take=NOT difference[64], set R=mux(take,trial,difference), and copy take into
> Q[bit]. Always construct both quotient and remainder, including div-only and
> mod-only calls. After the scan, zero-extend Q to 65 bits; compute, in order,
> R!=0 using public-1-seeded equality and NOT, -Q, -Q-1, their nonzero-remainder
> mux, b-R, its nonzero-remainder mux, and input-sign muxes for Q then R. Check
> both outputs for signed64 representability before narrowing and conjoin those
> checks with b>0. A zero divisor follows the same bounded recipe and returns
> invalidity with unusable outputs. Reject negative, private or out-of-signed64
> divisors at construction. Preserve operand order, full-width terminal carries,
> all private-operand gates, public-only folding and active-path sticky rejection.

Here `mux(s,a,b)=a XOR (s AND (a XOR b))`; a true selector chooses b. This is a
proposal for later manuscript/lowering-reference alignment, **not user agreement**.
It preserves the current source instead of treating functional equivalence as proof
of canonical identity. MIN/1 remains valid: its magnitude is unsigned `2^63`.

| Alternative | Width/order/rejection implications | Evidence/status |
|---|---|---|
| Current one-difference recipe | 65-bit R/trial/difference/corrections; 64 rounds, bit 63 down to 0; both narrowed outputs checked; zero divisor invalid | Production path; existing literal/reduced-width/endpoint tests plus new schedule test |
| Separate comparison and subtraction | Same widths, iteration order, mathematical outputs and rejection; each round emits a comparison subtraction, then another written subtraction | Executable **test-only** alternative; no production selector; distinct counts/fingerprints measured below |
| Store a 64-bit unsigned R, retaining a 65-bit trial/difference | A bounded unsigned remainder can fit, but storage/mux widths and discarded-wire emission change; equivalence needs a separately frozen recipe | Not implemented or measured; not permission to narrow production integers |
| Remainder-only construction | Can omit quotient generation/correction while preserving the mathematical remainder on positive divisors; changes work/checks/traces | Not implemented or measured; current mod still constructs/checks both outputs |
| Treat magnitude/trial as a positive signed64 integer | Cannot represent MIN's magnitude `2^63`; may reject or miscompare a supported numerator | Incompatible with the required signed64 domain, not an acceptable silent alternative |

All conforming candidates must retain the prescribed high-to-low scan, checked
arithmetic and active-path failure behaviour. Changing to low-to-high traversal,
truncating signed division, dropping necessary representability checks or clearing
overflow after mod is not an ambiguity resolution. New diagnostic tests exhaust
widths 2–4 and positive divisors, compare real signed64 endpoints for 0,1,16,q,MAX,
and assert all 68 subtract operations in the production divmod use 65-bit operands.
The earlier independent Fraction/floor, reduced-width and boundary evidence is retained.

## Source-to-code map and boundaries

| Source | Implementation | Boundary |
|---|---|---|
| R-024/R-025; VII-A.5/.6 | `signature_inputs.prepare_verifier_inputs` consumes `auth_parsing.parse_auth_witness` | Exactly one 5329-byte witness, 42632 input wires; no decoded coefficient/hint advice |
| FIPS Algorithms 12/18/19/27, printed pp. 29–35 | `signature.unpack_unsigned`, `decode_responses`, `decode_signature` | Byte-order rewiring, checked signed64 response arithmetic; syntax separate from norm/authenticity |
| FIPS Algorithm 21, printed p. 32 | `signature._hint_boundary`, `_hint_iteration`, `_hint_padding`, `decode_hints` | Full private scan reads/writes and bounded source counters; full reconstruction exceeds this profile |
| FIPS Algorithm 8 line 13, printed p. 27 | `signature.response_norm` using existing `scalar_ring.norm_ok` | Separate strict bound; not moved into Algorithm 27 or exposed as cryptographic verification |
| FIPS Algorithm 23 | `signature_inputs.decode_expected_public_key` | Expected pp's public rho and six t1 polynomials; no caller-selected key or invented key-decoding rejection |
| VII-A.5/.6, R-009/R-010/R-023/R-024 | `signature_inputs.certified_message` and existing SHA3-384/holder gadget | Same xH, attributes and rid; exact nested binding/cred encodings |
| FIPS Algorithm 3; Algorithm 8 lines 6–7 | Pure framing in `certified_message`; `message_representative` uses existing SHAKE256 | Exact credential context once, public tr, private FIPS representative; complete hash composition is capped |

The existing Stage 2 bounded verifier, `relations.auth_private`, `credentials`,
binding codec and confirmed specification were inspected as references. Production
circuit code never calls a host parser, integer verifier or native hash on private
values. Public pp/X validation still uses the established canonical host boundary.

## Decoder interfaces and actual acceptance conditions

`decode_responses(scope, signature_bits)` consumes the original 3309-byte slice and
returns `ResponseDecoding(challenge_hash, responses, encoded_hints, valid)`. The
challenge occupies bytes 0:48; five response polynomials occupy 48:3248; hints occupy
3248:3309. Each polynomial has 256 coefficients packed in 640 little-endian bytes.
FIPS bit conversion simply reuses wires. Each unsigned 20-bit value is zero-extended
to signed64 and subtracted from `gamma1=524288` using the existing checked 65-bit
subtraction. All bit patterns decode into `[-524287,524288]`. There is **no** challenge
content check and **no** `abs(z)<524092` restriction at this decoder boundary.

`decode_hints(scope, encoded_hints)` returns six 256-coefficient polynomials plus
validity. Hint coefficients remain signed64 integers with values 0/1; this package
does not narrow integer array slots to save gates. Byte cells remain 8-bit bitstrings;
indices and arithmetic counters are signed64. `decode_signature` returns the named
`SignatureDecoding` tuple only after both components finish. Wrong public byte widths
are construction errors; invalid private syntax is a sticky circuit rejection;
resource exhaustion raises `ResourceLimit` and returns **no** decoded result.

Algorithm 21 is emitted as follows:

1. Initialise all six polynomials and Index with public zero. Visit rows 0–5.
2. Read the row's endpoint at its public offset. Reject an endpoint below Index or
   above 55. First copies Index without new wires.
3. Emit all 55 while-loop slots for that row. Each retains the private Index<end
   test and active/termination masks. On Index>First, compute checked Index-1,
   read y[Index-1] then y[Index] through complete 61-cell equality scans, and
   reject the source >= condition. A rejecting source return masks the later body.
4. Read y[Index] again, as written by the source; no CSE reuses the ordering read.
   Write integer 1 through all 256 polynomial cells from a snapshot. Increment Index
   with checked signed64 addition and mux the active update; inactive slots preserve it.
5. Carry Index across rows. The padding loop initialises its private counter from
   Index, retains all 55 masked tests/reads/increments, and rejects every nonzero
   unused byte. Invalid reads supply zero; invalid writes retain the snapshot;
   active failures remain sticky. Private values never set Python loop bounds,
   branches, slice offsets or indices.

Endpoints may be equal; all-zero hints are valid. Position zero and 255 are valid.
Strict ordering applies within a row, so a position may recur in another row. Maximum
population is 55 across all rows. Synthetic response/hint encodings exercise these
domains without claiming they form authentic signatures.

`response_norm(scope, responses)` separately returns `within_bound` and
`arithmetic_valid`. It visits all 5*256 signed64 coefficients in row/coefficient order,
using the existing checked absolute-value/strict-less-than helper and a left-fold AND.
Its test predicate explicitly requires the bound. The decoder and production input
preparation do not incorporate it as a syntactic condition; eventual Algorithm 8
integration still needs the final challenge-hash equality and the specified call order.

Validity fields describe absence of sticky rejection in the supplied scope **at that
point**; they are not independent attestations and an earlier flag cannot certify a
later operation. The single development output retains the scope's final rejection.
No function here is named or advertised as successful signature/auth verification.

## Same-witness message and public-key wiring

The public entry `compile_input_preparation(pp, statement, limits=...)` validates
E(X), allocates exactly 42632 symbolic inputs and calls `prepare_verifier_inputs`.
There is no argument for B, Mcred, decoded z/h or the FIPS message representative.
The low-level gadget results are internal symbolic data, not alternative trusted
inputs. Scope checks propagate through parsing, disclosure, response/hint decoding
and preparation. Complete return requires every assigned subcomponent to finish.

`CertifiedMessage` names the holder preimage, holder value Y, encoded binding,
certified message and pure formatted message. Framing uses only public tag/count/
length bytes plus the original symbolic field wires:

```text
Y = SHA3-384(enc_holder(suite, E(protocol_metadata), xH))
E(B) = enc_binding(Y, original_1024_attribute_bytes)
Mcred = enc_cred(suite, E(protocol_metadata), E(B), original_rid_bytes)
Mprime = 00 || 14 || ASCII("PQ-DID/credential/v1") || Mcred
tr = SHAKE256(expected_pp.issuer_public_key, 64 bytes)
fips_message_representative = SHAKE256(tr || Mprime, 64 bytes)
```

`14` above is one hexadecimal byte (20 decimal). The certified body's tag is `cred`,
while the external signing role is `credential`. Presentation context, policy, root,
signature and sibling bytes are absent from Mcred. Presentation context remains in
E(X); changing it changes the public trace digest without changing certified bytes.
The original attributes/rid also remain available for disclosure and later Merkle
work; they are neither re-encoded from unchecked values nor replaced by separate advice.

`PublicKeyDecoding` returns public rho and 6*256 zero-extended signed64 t1 values.
Every 10-bit value is allowed after the public fixed-length/instance checks; this is
not an issuer trust test. `MessageRepresentative` distinguishes the public-key hash,
its exact preimage and `fips_message_representative` from protocol instance metadata.
Both SHAKE invocations use the existing complete circuit gadget; public tr's entire
schedule folds to constants. No host hashing substitutes for a private computation.

This partial dependency composition is **not a complete Algorithm 8 trace**: ExpandA
must eventually precede tr/mu, followed by SampleInBall, transforms/matrix arithmetic,
UseHint, w1Encode and the final hash/norm comparison. Preparing these inputs does not
permit skipping or moving that work outside the private relation.

## Validation and resource evidence

**81 focused tests passed without skips.** The raw [focused record](data/stage3_signature_inputs_focused.json)
contains 58 decoder, 14 preparation and nine SPEC-004 diagnostic tests. The
[measurements](data/stage3_signature_inputs_measurements.json) contain 39 completed
probes and 12 clean gate-limit stops: 17 components, each in materialised/count/stream
mode, run sequentially. For every completed component, counts, folds and fingerprints
agree across modes. Every capped attempt stops at 2000000 gates, with no footer or
complete circuit identity. Count/stream completion checks construction; materialised
completion additionally runs the production evaluator and observes named outputs.

| Validation | Actual executed evidence | Limit of the result |
|---|---|---|
| Genuine signatures | Three relation-credential response fixtures; twelve existing ordinary-native signatures with reference cryptographic verification; reconstructed hint fragments for alpha/beta genuine signatures | Full private signature decoder does not complete under this profile |
| Synthetic decode domain | Independent bit-by-bit packing crosses byte/coefficient/polynomial boundaries and covers -524287 through +524288, including norm failures | Encoding-only fixtures, not claimed authentic signatures |
| Hint semantics | All six boundary positions; backwards/over-55/255 endpoints; duplicate/descending positions; empty rows; positions 0 and 255; repeated positions in distinct rows; populations 0 and 55; early/late unused bytes | Boundary, two-step and padding circuits plus sequential single-step fragment tests; no completed 6*55 circuit |
| Norm | All 1280 coefficients checked; zero, ±524091 accepted; ±524092 and outer decode endpoints rejected | Separate final-condition helper, not signature verification |
| Mutation and structure | Changed challenge remains reference-decodable and passes circuit response parsing while reference verification fails; same circuits evaluate valid/invalid private data; repeated mode identities agree | Unchanged hints are validated through component/reference evidence, not a fabricated full-decoder result |
| Witness linkage/failure | Original signature/attribute/rid wire identities; parser + holder/Mcred + response + first hint boundary compose; malformed attributes/rid/hint boundary survive later tautological equality as rejection | Complete hint/message/preparation composition remains capped |
| Exact message | Evaluated holder preimage/Y/B/Mcred/pure framing match existing constructors; holder/hidden attributes/rid mutations affect Mcred; presentation-only mutation does not; exact same observed bytes drive a standalone SHAKE fragment matching hashlib | Two executed traces, not one complete preparation circuit |
| Key/context | Alpha/beta expected-key decoding; full public tr SHAKE schedule; correct external credential context once; malformed instance rejection; doubled/misplaced context produces a different representative | Trust, presentation policy/state verification and full credential verification remain separate |
| SPEC-004 | Exhaustive reduced widths, actual-width endpoints/zero, independent floor expectations, literal subtraction-width schedule, equal outputs but different diagnostic traces/counts | Functional evidence does not approve a canonical recipe |

### Core costs and test overhead

All numbers below include the final core validity output. No expected-value comparison
gate is added by the new probes. Trace bytes include the 56-byte header and 33-byte
footer; they are **development traces, not proof bytes**.

| Completed core/component | Private input bits | Gates | AND | Trace bytes |
|---|---:|---:|---:|---:|
| Response/challenge extraction and decode | 42632 | 336643 | 112641 | 5723020 |
| Six hint endpoint checks only | 42632 | 2704 | 906 | 46057 |
| First hint boundary and two exact row iterations | 42632 | 172826 | 82941 | 2938131 |
| Full 55-slot unused-byte loop | 42632 | 780265 | 267076 | 13264594 |
| Response decode plus all strict norm checks | 42632 | 1520649 | 537603 | 25851122 |
| Expected public-key decode | 0 | 0 | 0 | 89 |
| Public tr via full SHAKE schedule | 0 | 0 | 0 | 89 |
| Parsing/disclosure + holder hash + exact Mcred/framing | 42632 | 281751 | 68109 | 4789856 |
| Standalone representative SHAKE kernel (test suffix) | 8672 | 1753024 | 345600 | 29801497 |

The input count 42632 means the probes reuse the fixed witness layout; individual
components do not inspect every field. Endpoint-only/padding-only/two-step success
is not successful complete HintBitUnpack. Core norm addition over the completed
response predicate is 1184006 gates / 424962 ANDs; the raw cumulative boundary before
response finalisation is 336641 gates. Parsing/disclosure before finalisation is
88212 gates, and the cumulative certified-message boundary is 281749 gates.

Materialised generation/evaluation took respectively 0.5071/0.0811 seconds for
responses, 0.9313/0.1785 for padding, 1.9166/0.3380 for response+norm, 0.5830/0.0670
for certified-message preparation and 2.2391/0.3862 for the standalone SHAKE kernel.
Public tr emitted zero gates but still took 0.8416 seconds to construct/fold its
complete schedule. These are local development measurements, not manuscript or
protocol performance claims. Maximum probe worker high-water RSS was 91295744 bytes
(87.066 MiB); maximum sampled RSS was 85770240 bytes (81.797 MiB).

The following all stop at the same **gate-count limit** in all three modes:
complete hints; complete signature decode; parsing/holder/framing/tr/mu message
composition; and the full named input-preparation composition. At the stop the
logical trace has 34000056 bytes (header plus partial gates), below the 41943040-byte
ceiling. Complete reconstruction, complete signature-decode evaluation and full
input-preparation evaluation were **not executed**. There is no successful fallback,
no host-private verification path and no changed representation/schedule.

### Clarifying the earlier arithmetic measurements

The existing `measure_auth_parsing_arithmetic.build` definitions were reconstructed
unchanged. Their full predicate fingerprints match the preserved earlier records.
The new companion cores keep **every** checked arithmetic/reduction/active rejection
operation, remove only comparisons to public expected outputs, and finalise the
same absence-of-rejection predicate.

| Operation/operand classes | Core gates / AND | Extra test gates / AND | Earlier full predicate gates / AND |
|---|---:|---:|---:|
| Mod-q multiply: two private signed64 words | 83342 / 34588 | 193 / 65 | 83535 / 34653 |
| Mod-q multiply: public left 25847, private signed64 right | 82757 / 34393 | 193 / 65 | 82950 / 34458 |
| Forward butterfly: two private signed64 words, public twiddle 25847 | 155272 / 61321 | 386 / 130 | 155658 / 61451 |

Each additional 64-bit target equality costs 64 XOR + 64 NOT + 64 AND; its extra
fold into the test predicate adds one AND. One multiplication output therefore adds
193 gates; the two butterfly outputs add 386. Required overflow/narrowing checks,
both divmod validity checks and final sticky rejection are retained in each core.
The public/private multiplication saves 585 gates / 195 ANDs relative to this
private/private case through permitted public folding. These are specific operand
classes/order/constants, not identical-cost interchangeable NTT gadgets.
These division-dependent core identities remain SPEC-004 provisional. The new
response/hint/hash helpers do not call division; none establishes full BC-1 conformance.

SPEC-004's production divmod-q core costs **35894 gates / 13332 ANDs**. The test-only
separate-comparison/subtraction core costs **56566 gates / 21588 ANDs**: an increase
of 20672 gates / 8256 ANDs despite identical tested values and invalidity. This is
direct evidence that the missing source detail affects canonical identity.

The resource profile is the existing `hash_enrolment_extended_v1`: 2000000 gates,
41943040 trace bytes, 65536 maximum inputs, 10-second generation, 5-second evaluation,
one worker, 268435456-byte kernel address-space limit, 134217728-byte RSS watchdog
sampled every 0.01 seconds, 30-second per-case wall time and 2097152-byte logs. RSS
sampling can miss transient overshoot; it is not a kernel hard RSS bound. Host RAM
and disk were inspected afresh without reinstalling/rebuilding anything.

New measurements use a final core validity predicate and observe result wires through
an independent test trace reader. **Zero additional comparison gates** are inserted.
The core includes parsing checks when that component composes parsing, all checked
arithmetic/index/padding rejection, named validity outputs and final rejection
conjunction. Cumulative phase counters identify the response stage inside the norm
probe and parsing/holder stages inside message preparation. Subtracting phase counts
is accounting, not a separately generated complete circuit identity.

Host fixture preparation, independent output comparisons, trace observation and
reporting are outside circuit counts. Timings separate generation, production
evaluation, independent observation and residual preparation/reporting (which also
includes rebuilding a diagnostic comparison trace for legacy/alternative probes).
RSS/AS apply to the entire worker, including that overhead. New probes do not enable
tracemalloc; older reported timings did. Source hashes, modes, folds, fingerprints,
limits and termination progress accompany the raw records. An unfinished trace has
no complete fingerprint/count and is never labelled accepted.

The message-hash kernel is a **test component**, with a public prefix and 1084 private
suffix bytes beginning at Y; even the two intervening public length fields are
private test positions. It is not the production authentication representation. The
functional fragment-chain test feeds bytes observed from the completed same-witness
holder/Mcred circuit into this separate SHAKE circuit and compares its 64-byte output
to hashlib/reference framing. No extra witness field or caller-supplied binding is
added to production. This checks evaluated bytes across two traces, **not completion
of the single composed preparation trace**; their gate counts must not be added and
advertised as a canonical full-relation count.

Hint fragment tests likewise expose a test-only input state (index, first, endpoint,
one polynomial) for one exact production step. They execute each occupied position
and a terminated step, compare every coefficient, and check boundary/padding
subcircuits separately. Their carried state is diagnostic input, not credential
witness advice. Complete 6*55 reconstruction remains a separately reported capped
attempt. Test-only probes/stubs never stand in for its execution.

### Commands and final outcomes

Run from `/home/grace/projects/pq-did`, using the existing environment. The initial
host snapshot was written to `/tmp/pqdid-signature-host.json` from `/proc/meminfo`
(kB converted to bytes) and `shutil.disk_usage('.')`. Its complete values are embedded
in each JSON record; initially available memory was 5022986240 bytes and free disk
was 1021588754432 bytes. The runner rechecks live available memory before launching.

```bash
.venv/bin/python scripts/validate_signature_inputs.py \
  --host-snapshot /tmp/pqdid-signature-host.json \
  --output docs/data/stage3_signature_inputs_focused.json \
  --separate-test-targets --tests \
  tests/unit/test_signature_circuit.py \
  tests/unit/test_signature_inputs.py \
  tests/unit/test_spec004_alternatives.py

.venv/bin/python scripts/validate_signature_inputs.py \
  --host-snapshot /tmp/pqdid-signature-host.json \
  --output docs/data/stage3_signature_inputs_measurements.json

.venv/bin/python scripts/validate_signature_inputs.py \
  --host-snapshot /tmp/pqdid-signature-host.json \
  --output docs/data/stage3_signature_inputs_regression.json \
  --separate-test-targets --tests tests/unit/test_*.py \
  tests/integration/test_*.py tests/smoke/test_hashes.py

.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Outputs use exclusive creation; use fresh paths for a repeat run. Focused: **81
passed**, 69.43 total child seconds, maximum worker high-water RSS 124022784 bytes
(118.277 MiB). [Regression](data/stage3_signature_inputs_regression.json): **1404 passed**,
119.34 total child seconds over 32 sequential test targets, maximum worker high-water
RSS 123928576 bytes (118.188 MiB), sampled maximum 118345728 bytes (112.863 MiB).
No skips or failures. The measurement command intentionally exits 1 because its
12 resource-limited attempts are non-completions; 39 probes pass. Ruff lint passes;
all **115 Python files** pass formatting.

Two initial combined pytest runs were stopped by the RSS watchdog, at sampled
136368128 and 137940992 bytes. The first also exposed two overly strong *test*
assertions about temporary state following invalid diagnostic counter inputs;
those now require rejection without imposing an unwritten post-fault state rule.
Source-return masking, invalid writes and inactive iterations retain their checks.
Releasing a completed emitter before the next fragment reduced live test storage;
the isolated hash-fragment chain passed at 115044352-byte high-water RSS. Retained
memory across a combined suite still reached the watchdog, so final runs launch
each test module in a **fresh sequential process**, with identical assertions and
unchanged gates, budgets and memory controls. There is still exactly one worker.
Development failures are preserved in [the development record](data/stage3_signature_inputs_development.json),
separately from the final successful runs and deliberate complete-circuit caps.

The [preservation audit](data/stage3_signature_inputs_audit.json) checks the original
protected-file hashes, confirmed manifest fields/agreed clarifications, manuscript,
all prior source/tests/vectors/data and environment/native/editor files. Only current
documentation/implementation-record entries are changed among pre-existing files;
new code/tests/evidence are listed separately. Earlier arithmetic/hash measurements
and all agreed conventions are retained unchanged.

## Remaining dependencies

Resolve SPEC-004's exact lowering before claiming canonical division identity.
Complete hint reconstruction and the single message/preparation composition need a
separately reviewed resource/validation plan; this package does not raise limits or
change representations/schedules to fit. Source review and fragment tests alone do
not establish full execution or feasibility.

Then bounded circuit RejNTTPoly/ExpandA and SampleInBall need their shared byte
counters, exact caps/exhaustion and private scans, followed by complete forward/
inverse NTTs, matrix/vector source order, UseHint/w1Encode/challenge-hash composition,
strict final norm/equality and complete bounded verification. Same-rid depth-20 Merkle
composition, the full authentication relation, independent BC-1 conformance audit
and public admission remain open. No complete authentication AND count or proof-size
projection is inferred here.

All 480 raw-tape proof repetitions, transcripts, privacy proofs and complete proof
feasibility remain unimplemented. Stage 2 bounded keygen/signing, release enforcement,
revocation/update/lifecycle services and DEP-001/002 obligations remain open. This
package stops at decoding/input preparation and its recorded validation boundaries.
