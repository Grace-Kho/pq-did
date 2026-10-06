# Stage 3 authentication parsing and scalar arithmetic

**Later update — 18 September 2026:** SPEC-004 is now agreed with public zero in the
negative-remainder correction's false arm and Q-then-R-then-b>0 validity order.
[The adoption/preflight report](stage3_resource_preflight.md) records deliberate
trace changes, refreshed measurements and new counting results. The pending/provisional
statements and numbers below are preserved historical evidence, not current status.

This bounded package implements protocol-level private witness parsing/disclosure,
checked public-constant division/residues, and scalar verifier arithmetic. It does
not implement complete authentication, FIPS signature decoding, full NTT/matrix/
sampling circuits or a privacy-preserving proof. The authentication witness remains
exactly 5329 bytes / 42632 bits; no quotient, remainder or other advice is added.

## Authority and exact construction boundary

Only manuscript Sections II–VIII are authoritative. The selected PDF still hashes to
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca` and is unchanged.
The extraction was rechecked against VII-A.1/.5/.6, especially the BC-1 paragraph on
printed p. 16. SPEC-001/002/003 remain agreed; equality starts with public 1, and
multiplication retains its public 128-bit zero accumulator, all 64 full-width partial
additions in increasing order and terminal carries. No alternate convention is added.

The pinned [FIPS 204 (August 2024)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
was consulted directly, using the existing PDF with SHA-256
`57239b9f84c03227eda3ca0991204dc7764c79af9ce2e6824eda774918d46b6b`.
Its §2.3 defines floor, canonical residues and centred residues; Algorithms 36–38/40
supply decomposition/high/low bits and hint use, and Algorithm 41 lines 12–14 supplies
the measured butterfly. Algorithm 8 determines the verifier call order. Existing
DEP-001/002 dispositions and the August 2024 parameter set are retained. No native
implementation's Montgomery arithmetic or early-exit schedule is inherited.

**New SPEC-004 is proposed, not agreed.** BC-1 specifies positive-constant division's
high-to-low magnitude scan and signed correction, but does not fix work-register
widths, compare/subtract reuse or quotient generation in a remainder-only call.
[The issue register](spec_issues.md#spec-004--restoring-division-work-registers-and-exact-emission-schedule)
records the precise ambiguity and concrete restoring recipe below. The production
module has one fixed development path; there is no alternative recipe switch.
Functional tests and deterministic traces establish that path's behaviour, without
claiming that it is already a uniquely specified canonical BC-1 compiler.

## Source and verifier dependency map

| Requirement/location | Gadget and intended call site | Boundary |
|---|---|---|
| R-006/R-007; VII-A.1, p. 14 | `auth_parsing.parse_attributes`, `link_disclosure`: private canonical Esch(m) and projection before later credential/path composition | Public schema offsets and public D/mD; all hidden lengths/types/padding checked in gates |
| R-024/R-025; VII-A.6 witness, pp. 15–16 | `parse_auth_witness`: split xH/m/rid/signature/siblings; `compile_auth_parsing` is a development parsing predicate only | Same raw field wires returned for future holder/Mcred/signature/PathRoot components; not CGen(auth) |
| R-034/R-035; VII-A.6 BC-1, p. 16 | `division.divmod64`, `div64`, `mod64`: ring reductions, Decompose division, UseHint modulo 16, future integer shifts/division by public powers of two | Only public positive signed64 divisors; proposed SPEC-004 exact scan |
| FIPS 204 §2.3; Algorithms 36/40, pp. 40–41 | `division.centred64`: low part modulo 2*gamma2; canonical mod-q for verifier scalars | Preserve even-modulus tie at positive half; ordinary residues remain nonnegative |
| R-032/R-034; FIPS Algorithms 8, 41/42 | `scalar_ring.reduce_scalar`, `add`, `subtract`, `multiply`, `ntt_pointwise_multiply` | Signed64 operands, checked 65/128-bit intermediates before mod q; scalar multiplication is not polynomial multiplication |
| FIPS Algorithms 36–38/40 | `decompose`, `high_bits`, `low_bits`, `use_hint`: recovering w1 from inverse-NTT output | Exact exceptional q-1 branch and hint wrap; full transforms and private hint decoder still needed |
| FIPS Algorithm 8 final check | `norm_ok`: scalar strict z coefficient bound, later combined across all 5*256 z coefficients | Must stay at its specified verification position; no early norm rejection moved ahead of other checks |
| FIPS Algorithm 41 lines 12–14, p. 43 | `ntt_butterfly`: one forward update with a public ordinary-residue twiddle | Emits product, new right, new left in that order using old slots; not a full transform |

Existing Stage 2 `relations.auth_private`, `schema`, `witnesses`, `credentials` and
`bounded_mldsa` were inspected as local reference boundaries. Their source, vectors
and ordinary/native backend remain unchanged. The scalar implementation does not
call the reference verifier or native arithmetic to evaluate any private operand.

## Authentication parsing contract

All inputs are symbolic private positions; only the public schema, pp, statement,
disclosure mask and disclosed bytes influence construction. Protocol bytes enter
MSB-first; unsigned lengths/identifiers are rewired and zero-extended to signed64
words for BC-1 comparisons. Actual private byte values never reach a host parser.

| Field | Byte offsets (end exclusive) | Width/domain | Circuit treatment and output |
|---|---|---|---|
| Holder secret | 0:32 | 256 raw bits; every 32-byte string permitted | Return original wires; no invented scalar, nonzero or format restriction |
| Attributes | 32:1056 | 1024 canonical bytes under public schema | Return exact original block and padded field slices; enforce length/type/padding checks below |
| rid | 1056:1060 | unsigned32 big-endian, required 0 <= rid < 2^20 | Return bytes and a zero-extended signed64 word; emit signed64 comparison to public 2^20 |
| Signature | 1060:4369 | exactly 3309 opaque bytes at protocol layer | Return all original wires, without decoding, normalising or certifying them |
| Merkle siblings | 4369:5329 | twenty 48-byte strings in increasing level order | Return exact slices; path hashing/root/zero-leaf validity remain subsequent work |

No private field tag/type byte exists in Esch(m): field types are supplied by the public
schema. Invalid type-1 payload values and wrong type-specific lengths reject; malformed
public descriptors are rejected by the existing Schema/public-parameter boundary.
Type-0 bytes remain opaque (including DID/version fields). Their existing capacities,
not a new DID syntax rule, determine the permitted payload lengths. Type-2 values
remain eight raw unsigned bytes, including `2^64-1`; they are never misinterpreted
as signed64 arithmetic operands. Policy range comparisons remain public unsigned work.

For each field in schema order, the parser slices at its public fixed offset, parses
its two-byte private length, then requires length<=capacity for type 0 or length=1/8
for type 1/2. A Boolean payload must equal byte 00 or 01. It scans **every** capacity
position in increasing order: compare public position against the private length,
compare the byte to public zero, and require `in_payload OR byte_is_zero`. Thus a
private length cannot control a host slice, loop bound, offset or shortcut. After
all fields, compare the entire unused vector tail to public zero. All checks feed
`Scope.require`, so invalidity remains sticky only on active paths.

Disclosure uses public ordered D validated by the existing public decoder. It
concatenates the selected **complete padded fields** from these same private slices
and compares them with public mD using the existing public-1-seeded byte equality.
The original full attributes, original rid bytes and original signature remain
available together in `ParsedAuthentication`; the later credential component must
consume these same wires. There is no replacement reconstructed/normalised m block.

`compile_auth_parsing(pp, statement, limits=..., mode=..., sink=...)` validates public
statement structure and returns only the parsing/disclosure predicate. Private bad
encodings yield circuit output 0; wrong evaluator witness length is an API error;
malformed public structure raises `EncodingError` before circuit return; a resource
limit is non-completion. Validly encoded changes to xH, hidden attributes, rid,
signature or siblings can pass this predicate and fail `auth_private` later. This is
intentional coverage separation, not a successful incomplete authentication verifier.
FIPS signature/hint decoding, norm verification, credential hashing/signature
verification and non-revocation are not bypassed or replaced: they remain absent.
`PubOK`, `Ppub`, state signatures and lifecycle checks retain their specified boundaries.

## Checked division and residue contract

`divmod64(e, a, b)` takes one signed64 symbolic/public word and a **public** integer
constant b in 1..2^63-1. It returns signed64 quotient/remainder, one validity wire,
and the selected 65-bit intermediates. Mathematically `a=b*q+r`, `q=floor(a/b)` and
`0<=r<b`; in particular `-17 divmod 16 = (-2,15)`, not truncation towards zero.
`div64` and `mod64` select outputs of this same complete computation; they do not
introduce a shorter alternative path or use quotient/remainder witness advice.

Divisor zero produces validity 0 on a fixed bounded schedule with unusable outputs.
Passing a negative/private divisor, non-integer/bool divisor, too-large constant or
wrong input width is a construction API error. MIN/-1 is outside this positive-
constant profile, not silently wrapped or implemented with a different rule. MIN/1
and all supported signed64 numerator endpoints are tested. There is no supported
positive-divisor pair whose mathematical quotient exceeds signed64, but both final
representations are still checked before narrowing. Tests also cover checked signed
multiply/add/sub overflow before these operations are used for modular arithmetic.

The proposed SPEC-004 schedule uses these exact stages:

1. Form an unsigned64 magnitude with the existing sign-extended negate/mux recipe.
   Keep a 65-bit zero remainder and a 64-bit quotient buffer of symbolic positions.
2. Visit magnitude bits 63 down to 0. Wire the next bit into a doubled remainder;
   retain 65 bits for the trial and one full ripple difference `trial-b`, including
   its terminal carry. Use NOT(sign(difference)) as the take bit; mux trial/difference
   in BC-1 operand order and wire take into that quotient position. No private branch
   changes construction and no 23-bit coefficient or shortened divisor scan is used.
3. Widen the magnitude quotient to 65 bits. Compute nonzero remainder by public-1
   equality, its negation, negative quotient and decremented negative quotient in
   that order. Select decrement only for a nonzero remainder. Compute `b-remainder`
   and select it only for a nonzero remainder; select corrected outputs by the input
   sign. Check both signed64 representations, then conjoin those checks with `b>0`.

For a valid divisor the processed prefix is at most 2^63, so the 65-bit trial and
difference safely represent MIN's magnitude and all subtraction signs. The internal
bit append is part of this explicitly proposed division algorithm, not a public API
for replacing checked signed integer shifts with bitstring shifts. Full 64-bit integer
shift integration still uses checked multiplication/floor division by powers of two.

`centred64(e,a,b)` first computes the canonical remainder, compares it with public
floor(b/2), computes the checked subtraction of b, then muxes only the selected
representative and active validity. Its interval is exactly
`-ceil(b/2) < r <= floor(b/2)`. For even b, +b/2 is retained and -b/2 maps to +b/2;
for q=8380417 the endpoints are -4190208 and +4190208. Validity of the underlying
division cannot be cleared by centring. Callers consume every Checked result through
`Scope.checked`; later equalities/modular reductions cannot convert a recorded fault
into acceptance. No public-memory exception is treated as mathematical rejection.

## Scalar ring and verifier-helper contract

`Scalar(value, Domain.COEFFICIENT|Domain.NTT)` carries a signed64 representative and
an explicit public domain annotation. Ordinary signed representatives are accepted;
`reduce_scalar` returns 0..q-1 without changing the domain. The annotation alone does
not perform a transform. Mixing domains is a construction error. Add/subtract apply
the existing signed65 checked operation; multiply uses the full signed128 product,
all agreed magnitude additions and sign correction. Each operation first records
representability failure in the scope, **then** reduces the selected signed64 value
mod q. An overflow is not repaired by reducing the wrapped low word.

Typical valid ring inputs are canonical 0..q-1, so a product can reach
`(q-1)^2=70231372333056`, requiring more than 32 bits while fitting signed64.
No coefficient is narrowed to 23 bits; no early reduction, Montgomery/Barrett path
or reassociation is introduced. `multiply` is one scalar product, including for
coefficient-domain values; it does not claim coefficientwise products equal general
polynomial multiplication. `ntt_pointwise_multiply` requires NTT slots explicitly.

The forward butterfly requires two NTT-domain slots and a public zeta in 0..q-1.
It emits `t=zeta*old_right mod q`, then `new_right=old_left-t mod q`, then
`new_left=old_left+t mod q`. Both updates use the old left. Measurement uses FIPS's
first forward twiddle `1753^128 mod q=25847`, not a native Montgomery table value.
All three arithmetic operations retain their individual representability/reduction
checks in this order. Inverse butterflies and the final inverse factor 8347681 are
mapped dependencies, not claimed implemented transforms.

`decompose(scope,r)` takes a signed64 representative and emits Algorithm 36:
canonicalise mod q; obtain the centred remainder modulo 523776; compute `rplus-low`
for the q-1 condition; construct the true branch before the false branch. The true
branch sets high=0 and decrements low; the false branch **recomputes** the written
`rplus-low` expression, divides by 523776, then returns the old low. No CSE reuses
the condition's subtraction. Both outputs remain 64-bit. High lies in 0..15;
low ordinarily lies in (-261888,261888], while the exceptional q-1 bucket also
permits -261888. At r=q-1 the result is (0,-1).

`high_bits`/`low_bits` each construct the complete decomposition and select their
specified output. `use_hint` accepts one Boolean wire, not an unchecked signature
byte; the future FIPS decoder must produce that wire. It constructs the first
`hint AND low>0` return branch, then the second `hint AND low<=0` branch inside
the remaining active scope. The branches compute checked high+1 / high-1 and
canonical mod 16 respectively; otherwise return high. Outputs are integers 0..15,
with no 4-bit representation shortcut. `norm_ok` performs active checked negation
for negative z, then the strict comparison `abs(z)<524092`; MIN negation faults
and cannot become acceptance. This helper does not reorder Algorithm 8's final test.

Signing-side Power2Round/MakeHint and signing rejection loops are not verifier
dependencies and are not added in this package. Public all-constant computations may
fold; every operation involving a private symbolic value still emits its prescribed
gates, including private identities and inactive-branch computations.

## Independent validation evidence

The focused suite has **217 passing tests, no skips**, in 15.69 seconds under the
approved supervisor. Individual parametrised tests often check multiple private
values; these are pytest counts, not a count of every mathematical comparison.
Existing vectors were read unchanged. New
[bc1_scalar_vectors.json](../tests/fixtures/bc1_scalar_vectors.json) contains 96
signed64 division cases, 55 centred-residue cases and 25 decomposition/hint boundary
cases, generated independently with exact rational floor and an alternative nearest-
multiple decomposition formula. [The generator](../tests/reference/generate_scalar_vectors.py)
and [oracle/trace reader](../tests/reference/scalar_oracle.py) have no production
imports and are hash-pinned in the fixture. These are synthetic expectations, not
official FIPS validation vectors. Existing real signed relation fixtures still
supply the parsing/reference/cryptographic separation cases.

| Area | Executed checks | Evidence limit |
|---|---|---|
| Protocol parsing | All 12 existing authentication fixtures; exact 42632 input positions, field/sibling order and original signature wires; malformed private lengths, Boolean values, per-field/tail padding; rid 0, 2^20-1, 2^20, 2^32-1; wrong total witness length | Signature bytes deliberately receive no FIPS syntactic/cryptographic validation here |
| Schema/disclosure | Zero-length/zero-capacity/full-capacity bytes; exactly 1024 used bytes; full uint64 maximum; complete selected padded-field mismatch; empty disclosure; invalid public mask/length; public malformed inputs separated from private circuit rejection | Opaque DID/version values are not checked by a new invented DID syntax rule |
| Parsing versus authentication | Validly encoded changed secret, hidden attribute, rid, signature and sibling cases pass parsing and fail the full Stage 2 private relation; changed state signature passes parsing and fails separate PubOK | Parsing is neither credential authenticity nor complete Rauth; policy/current-state/holder-approval boundaries remain separate |
| Division | Six public divisors 1,2,16,523776,q,MAX with 16 real signed64 values each; exact/non-exact divisions, MIN/MAX/zero/unit/negative cases; quotient identity and remainder bound against Fraction/floor | Negative/private divisors are explicitly unsupported; zero is invalid, not truncated/wrapped |
| Reduced-width supplement | Exhaustive signed inputs and every allowed positive divisor for widths 2,3,4,5; literal first two-bit restoring step with subtraction, sign test, mux and retained terminal carry | Test-only helper widths do not replace the actual signed64 programme |
| Residues | Even ties and odd endpoints, MIN/MAX, q and multiples; canonical and centred outputs; selected wide-result wires reused by narrowing | New exact division schedule remains SPEC-004 provisional |
| Checked scalar arithmetic | Private/private and private/public add/sub/mul; q-1 products, 3037000499/3037000500 squares, MIN*(-1), MAX+1/MAX*2 and extremes; full 128-bit intermediate observed; active/inactive faults and later tautological equality/reduction | Successful remainder equality never clears overflow; no narrowed coefficient or alternative multiplier |
| FIPS scalar helpers | Decompose, HighBits/LowBits, private/public hint 0/1, strict z norm boundaries and MIN negation; reference `_decompose`/`_use_hint`/`_norm_ok` plus independent boundary calculations | Does not implement private signature/hint decoding or full verifier scheduling |
| Intended composition | Actual first forward twiddle, product/right/left call order, old-slot use, canonical outputs; private/private and public/private multiplication; domain-mix rejection | One scalar butterfly, not a complete NTT or polynomial multiplication |
| Determinism and limits | Same completed circuits evaluated across valid/invalid private inputs; repeated parsing traces; literal stream/materialised equality; original/extended budget identity for scalar operations; all 12 probe mode digests/counts match; deliberate parsing gate limit and unchanged supervisor tests | Development trace fingerprint is not a protocol commitment or full conformance proof |

The test-only trace reader observes result wire values from the completed circuit;
expected quotient/remainder values are never extra private inputs. The production
evaluator independently checks each circuit's acceptance/validity output. Zero divisor
and arithmetic overflow tests include a tautological output comparison to demonstrate
that apparently consistent later values cannot repair the sticky fault.

During development, one test initially attempted a wrong-length call after finalising
its emitter; it was corrected to use a fresh emitter. Final focused/regression outcomes
below refer to the corrected test. Source review also removed a duplicated low-word
mux in `centred64`: narrowing now aliases the selected wide wires as BC-1 requires.
The [pre-review focused record](data/stage3_auth_arithmetic_focused_pre_review.json)
and [pre-review measurements](data/stage3_auth_arithmetic_measurements_pre_review.json)
are preserved. Final centred/decomposition/hint predicates each have 192 fewer gates
(128 XOR, 64 AND) solely from that copy correction, not from weakening a predicate
or changing a resource limit. These were new development records; all measurements
from preceding work packages remain byte-for-byte unchanged.

## Approved resource controls and measured component costs

The unchanged [extended profile](../configs/validation_profiles.json) permits at most
2000000 emitted gates and exactly 41943040 serialised trace bytes per case, one active
worker. Generation remains 10 seconds, evaluation 5 seconds; the parent enforces a
30-second case wall watchdog (reset on each regression test) and a 2 MiB log guard.
Kernel RLIMIT_AS remains 268435456 bytes (256 MiB). RSS is separately watched at
134217728 bytes (128 MiB), sampled every 0.01 seconds; this can miss transient
overshoot and is not a kernel hard RSS bound. Measured peak RSS below is not a cap.
No memory/time/gate limit was automatically raised.

The new inspected WSL snapshot records 8126111744 usable RAM bytes, 5335273472
available, and 2147483648 unused swap bytes. The process cgroup `/init.scope` still
has `memory.max=max`; no tighter numeric cgroup ceiling is exposed. Workspace free
space was 1021605662720 bytes; RAM-backed /tmp had 3994902528 available. These are
current guest observations, not Windows physical-disk guarantees. The supervisor also
rechecks current available memory at launch, reduces RSS if required by headroom and
rejects insufficient headroom for the retained address-space limit.

[validate_auth_arithmetic.py](../scripts/validate_auth_arithmetic.py) supervises fresh
sequential child processes. [The component driver](../scripts/measure_auth_parsing_arithmetic.py)
uses independent public expected targets prepared outside construction timing and
retains tracemalloc instrumentation. Temporary stream files are discarded after their
hash/length checks. Counting stores no trace; its logical size remains bounded by the
gate cap (maximum 34000089 bytes in this trace format). Materialised/stream writes
also enforce the explicit byte ceiling. A resource limit remains non-completion and
is recorded separately from a predicate failure, with independent cases continued.

**All 36 final probes completed:** 12 components in materialised/count/stream modes.
Twelve materialised probes evaluated their component predicates to 1. Twenty-four
count/stream probes checked construction/fingerprints, not witness evaluation. No
assertion failure, skip or resource non-completion remains in this final probe set.
The full-capacity attribute case actually exceeds the routine 200000-gate default and
was executed under the authorised profile. Component counts include the final validity
conjunction and, except for parsing, public-target comparisons; they are not naked
arithmetic instruction counts or a full authentication measurement.

| Component predicate | Private/public classification | Gates | AND | Wires | Serialised bytes |
|---|---|---:|---:|---:|---:|
| `auth-parsing` | 42632 private witness bits; alpha pp/X/schema/D/mD public | 88214 | 29709 | 130848 | 1499727 |
| `attribute-capacity` | 8192 private attribute bits; public 4-field schema using all 1024 bytes | 280729 | 94066 | 288923 | 4772482 |
| `divmod-q` | 64 private numerator bits (MIN example); public q and q/r targets | 36280 | 13462 | 36346 | 616849 |
| `canonical-q` | 64 private bits; public q, example -q-1 | 36087 | 13397 | 36153 | 613568 |
| `centred-even` | 64 private bits; public 523776, example gamma2+1 | 37004 | 13725 | 37070 | 629157 |
| `ring-add` | 128 private operand bits, example q-1 plus q-1; public modulus/target | 36420 | 13530 | 36550 | 619229 |
| `ring-subtract` | 128 private operand bits, example 0 minus q-1; public modulus/target | 36485 | 13530 | 36615 | 620334 |
| `ring-multiply` | 128 private NTT slot bits, both q-1; public modulus/target | 83535 | 34653 | 83665 | 1420184 |
| `ring-public-multiply` | 64 private NTT slot bits; public left twiddle 25847 and modulus/target | 82950 | 34458 | 83016 | 1410239 |
| `decompose` | 64 private r bits, example q-1; public parameters/targets | 110695 | 41047 | 110761 | 1881904 |
| `use-hint` | 64 private r bits plus one hint bit, example q-1/h=1; public parameters/target | 184266 | 68373 | 184333 | 3132611 |
| `ntt-butterfly` | 128 private NTT slot bits; public 25847 twiddle, modulus and two targets | 155658 | 61451 | 155788 | 2646275 |

| Component/mode | Outcome | Generation s | Evaluation s | Peak RSS MiB | Retained trace bytes | Traced peak bytes |
|---|---|---:|---:|---:|---:|---:|
| `auth-parsing/materialised` | pass | 0.379305 | 0.313193 | 40.273 | 1499760 | 7514572 |
| `auth-parsing/count` | pass | 0.344892 | — | 37.516 | 0 | 4607011 |
| `auth-parsing/stream` | pass | 0.368510 | — | 37.711 | 0 | 4607043 |
| `attribute-capacity/materialised` | pass | 1.104396 | 0.838708 | 36.355 | 4772515 | 10613442 |
| `attribute-capacity/count` | pass | 1.003421 | — | 26.438 | 0 | 855145 |
| `attribute-capacity/stream` | pass | 1.099055 | — | 26.496 | 0 | 855177 |
| `divmod-q/materialised` | pass | 0.122858 | 0.097260 | 26.328 | 616882 | 1324504 |
| `divmod-q/count` | pass | 0.111931 | — | 24.789 | 0 | 83490 |
| `divmod-q/stream` | pass | 0.123191 | — | 24.789 | 0 | 267827 |
| `canonical-q/materialised` | pass | 0.125791 | 0.099896 | 26.156 | 613601 | 1313242 |
| `canonical-q/count` | pass | 0.116634 | — | 24.941 | 0 | 83485 |
| `canonical-q/stream` | pass | 0.122897 | — | 24.957 | 0 | 267827 |
| `centred-even/materialised` | pass | 0.126417 | 0.106394 | 26.398 | 629190 | 1328832 |
| `centred-even/count` | pass | 0.115500 | — | 24.871 | 0 | 83518 |
| `centred-even/stream` | pass | 0.142675 | — | 24.871 | 0 | 267827 |
| `ring-add/materialised` | pass | 0.128158 | 0.101105 | 26.391 | 619262 | 1324172 |
| `ring-add/count` | pass | 0.117963 | — | 24.926 | 0 | 94218 |
| `ring-add/stream` | pass | 0.134078 | — | 24.855 | 0 | 267795 |
| `ring-subtract/materialised` | pass | 0.132044 | 0.100556 | 26.398 | 620367 | 1325282 |
| `ring-subtract/count` | pass | 0.118594 | — | 24.754 | 0 | 94607 |
| `ring-subtract/stream` | pass | 0.127519 | — | 24.953 | 0 | 267795 |
| `ring-multiply/materialised` | pass | 0.292441 | 0.228631 | 28.109 | 1420217 | 3000768 |
| `ring-multiply/count` | pass | 0.262514 | — | 24.805 | 0 | 96207 |
| `ring-multiply/stream` | pass | 0.291668 | — | 24.934 | 0 | 268539 |
| `ring-public-multiply/materialised` | pass | 0.295113 | 0.228665 | 27.203 | 1410272 | 2986798 |
| `ring-public-multiply/count` | pass | 0.268357 | — | 24.738 | 0 | 93302 |
| `ring-public-multiply/stream` | pass | 0.295594 | — | 24.812 | 0 | 268603 |
| `decompose/materialised` | pass | 0.396303 | 0.306226 | 29.469 | 1881937 | 3876378 |
| `decompose/count` | pass | 0.357538 | — | 24.852 | 0 | 118211 |
| `decompose/stream` | pass | 0.396525 | — | 24.965 | 0 | 267507 |
| `use-hint/materialised` | pass | 0.665152 | 0.509441 | 31.613 | 3132644 | 6307816 |
| `use-hint/count` | pass | 0.616777 | — | 24.863 | 0 | 118426 |
| `use-hint/stream` | pass | 0.676250 | — | 24.945 | 0 | 267763 |
| `ntt-butterfly/materialised` | pass | 0.567251 | 0.433744 | 30.211 | 2646308 | 5482558 |
| `ntt-butterfly/count` | pass | 0.518154 | — | 24.742 | 0 | 111631 |
| `ntt-butterfly/stream` | pass | 0.568211 | — | 25.000 | 0 | 268475 |

The three modes agree for every component on XOR/AND/NOT counts, folded operations,
serialised length and complete logical fingerprint. Stream files are independently
hashed, and tests compare actual stream/materialised bytes. Resource limits/report
metadata are outside the circuit fingerprint. The JSON records source hashes,
complete commands, gate/wire/fold counts, original targets' public classification,
per-case limits, process/sampled RSS and traced allocation peaks.

The largest trace is 4772482 bytes; the highest measured probe RSS is 40.273 MiB.
The maximum-capacity parser takes 1.104396 seconds to generate and 0.838708 seconds
to evaluate in its instrumented materialised run. Peak RSS includes imports, input
handles and native/interpreter memory; traced peaks omit allocations made before
tracemalloc starts and some native allocations. Retained immutable trace objects add
33 bytes to serialised length, and materialisation can transiently hold both a
bytearray and copied bytes. Count/stream modes still retain live compiler values and
input handles. Timings are single diagnostic runs, not benchmark averages or a full
transform/authentication feasibility guarantee. No component AND count is inserted
into the authentication proof-size formula.

## Commands, results and preservation

All commands used the established environment; no install, native rebuild or dependency
update occurred. A fresh `/tmp/pqdid-arithmetic-host.json` was captured from
`/proc/meminfo`, the actual cgroup, `statvfs`/disk usage and `RLIMIT_AS`; it is embedded
in every final evidence file. The runner also records the current available-memory
value at each launch. Commands below use new output paths rather than overwriting
historical records. Earlier development records retain their separate filenames.

```bash
.venv/bin/python tests/reference/generate_scalar_vectors.py
.venv/bin/python scripts/validate_auth_arithmetic.py --host-snapshot /tmp/pqdid-arithmetic-host.json --output docs/data/stage3_auth_arithmetic_focused.json --tests tests/unit/test_auth_parsing_circuit.py tests/unit/test_bc1_division.py tests/unit/test_scalar_ring_circuit.py
.venv/bin/python scripts/validate_auth_arithmetic.py --host-snapshot /tmp/pqdid-arithmetic-host.json --output docs/data/stage3_auth_arithmetic_measurements.json
.venv/bin/python scripts/validate_auth_arithmetic.py --host-snapshot /tmp/pqdid-arithmetic-host.json --output docs/data/stage3_auth_arithmetic_regression.json --tests tests/unit tests/integration tests/smoke/test_hashes.py
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

The fixture generator deliberately refuses to overwrite an existing fixture. The
supervised test child calls pytest with the selected paths and `-q --tb=short`, with
`PQDID_HASH_EXTENDED_BUDGET=1` so the previously approved larger hash cases also run.
One test/probe worker is active; no xdist or concurrent benchmark workers are used.

Results: **217 focused passed in 15.69 s; 1323 regression passed in 47.65 s, no skips**
(1300 unit, 19 integration, four fixed hash). All **36 final diagnostic probes**
completed as detailed above. Ruff: “All checks passed!”; formatting: “105 files
already formatted”. Regression worker wall time was 47.747 s, governed by the
per-test 30-second watchdog rather than a whole-suite 30-second deadline. Measured
regression peak RSS was 118.840 MiB, below the sampled 128 MiB watchdog ceiling;
focused peak was 65.539 MiB. These measurements do not enlarge the approved limits.

Machine-readable evidence: [focused tests](data/stage3_auth_arithmetic_focused.json),
[component measurements](data/stage3_auth_arithmetic_measurements.json),
[regression](data/stage3_auth_arithmetic_regression.json) and
[preservation/consistency audit](data/stage3_auth_arithmetic_audit.json).
All earlier production source, vectors, measurement files, manuscript, environment,
editor/native files and SPEC-001/002/003 are preserved. The parameter manifest adds
implementation evidence only; cryptographic suite parameters remain unchanged.

## Assessment and next integration task

| Assessment | Outcome |
|---|---|
| Functional correctness | Finite independent/reference checks pass for private protocol parsing/disclosure, supported division/residues, checked scalar arithmetic, FIPS helper endpoints and one forward butterfly |
| Deterministic construction | Selected literal traces, source-order/copy checks, repeated generation and byte/digest/count equality across modes and budgets pass for the fixed development recipes; private values do not control construction |
| Full canonical BC-1 conformance | Unverified. SPEC-004 needs an explicit decision on the exact division schedule, followed by independent complete lowering audit; parser/derived branch recipes also remain within that broader review |
| Complete authentication/proof feasibility | Unimplemented/unmeasured. No full authentication AND count or authentication proof-size estimate is inferred; the earlier 9587104-byte enrolment figure remains a calculation with no generated/verified proof |

The next bounded integration task is **private FIPS signature/hint decoding and
verifier input wiring**: consume the retained 3309 signature bytes in their exact
48-byte challenge / five 640-byte z / 61-byte hint layout; enforce canonical hint
counts/order/zero padding with fixed scans and active rejection; produce signed64 z
and Boolean hints without adding private inputs. Wire the same original xH/attribute/
rid fields into canonical holder/B/Mcred construction, keeping public state/policy
checks separate. Validate this boundary independently before claiming a composed
credential verifier. Resolve SPEC-004 before freezing its canonical gate identity;
that decision is not presumed by the functional results.

Subsequent dependencies are explicit: public key bit unpacking and row-major matrix
expansion; full 256-coefficient NTT/inverse schedules with their public twiddle order,
separate inverse subtraction/product reductions and final factor 8347681; ordered
matrix-vector sums and NTT pointwise products; full SHAKE-based 1026-byte RejNTTPoly
and 256-byte SampleInBall circuits with shared counters and bounded private indexing;
UseHint across all coefficients, w1 encoding, strict final norm and challenge equality;
20-level zero-leaf hashing for the **same** rid/path; and complete same-witness relation
composition/admission. Component success does not establish that those full circuits
fit the present operational budgets.

Stage 2 bounded key generation/signing, setup/import, production revocation/witness
updates, DEP-001 signing-tail validation and remaining DEP-002 release obligations
stay open. Stage 3 raw-tape sharing, 480 repetitions, commitments, Fiat–Shamir,
transcripts, checking, privacy/erasure and full proof feasibility stay open. This
package ends here; no subsequent integration package is started.
