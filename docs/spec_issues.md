# Specification issues and decisions

Source: `docs/manuscript/PQ_DID__Implementation.pdf`, SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
Only **Sections II–VIII** are authoritative. Updated 19 September 2026.
Locations below use section numbers and printed PDF pages. Agreed clarifications
and remaining author wording updates are recorded here; the manuscript is unchanged.

Current disposition (19 September 2026): [R0-DESIGN-REVIEW-1](stage3_r0_design_review.md)
checks the 9.893-hour CredValid forecast and recommends keeping current CPU proving
paused, retaining two used/one unused attempts. No evaluated option yet supports
complete private authentication at the unchanged targets. **PROP-002 below records
proposals, not adoption or a new agreed SPEC issue.** The next recommendation is
bounded reference lifecycle work, not the final proof attempt.

The subsequently authorised [S2-VERIFY-STATE-1](stage2_verifier_state.md) now
implements that reference lifecycle boundary, with 58 focused/29 regression cases
passing. Real services, persistent state and proof verification remain open; the
next bounded proposal is S2-UPDATE-WIT-1. CPU proving remains paused and the ledger
is unchanged. See the implementation record at the end of this register.

Earlier feasibility finding (18 September 2026): [the bounded pilot/review](stage3_feasibility_review.md)
recommends preparing a reviewed concrete-profile change proposal before larger
integration. This is a resource/application decision, not a new ambiguity reopening
SPEC-001/002/003/004 or permission to change the construction. The 3.253 GB figure is
a conditional authentication projection; exact full-compiler inclusion remains open.

## Agreed in-scope clarifications — manuscript wording updates remain

### SPEC-001 — Sibling-path payload inside the public update record

**Status: agreed by the user on 17 September 2026; no implementation decision remains open.**

- **Exact locations:** Section VII opening encoding rule, p. 14; VII-A.5,
  definition of `w=(s0,…,s19)`, p. 15; VII-A.6, 960-byte private witness field,
  p. 15; VII-A.8, `ue+1=(rse,rse+1,r*,w*,υ)` tagged `rupdate` and the displayed
  `Mu` signing-message equation, p. 17.
- **Missing detail:** the generic rule recursively tags tuples, but no path-tuple
  tag is supplied for the `w*` field of the outer `rupdate` record. The authentication
  witness and signed `Mu` explicitly use 960 raw sibling bytes. The bytes signed by
  `Mu` are clear; the outer update record's path representation is not explicit.
- **Effect:** two encoders could agree on update-signature verification and disagree
  on the enclosing update-record bytes. This affects interoperability, not the
  defined Merkle-root equation or authentication-witness length.
- **Agreed clarification (user decision, not existing manuscript wording):** wherever a path is an encoding field,
  represent `w` as `s0 || … || s19` (exactly 960 bytes), including the single path
  field in `enc_rupdate(E(rse),E(rse+1),[r*]4,w*,υ)`. Each sibling is exactly 48
  bytes, in increasing level order. Do not add a new tuple tag or another internal
  length prefix; the enclosing `enc` still applies its ordinary `LP` to this field.
- **Conflict check:** the raw payload agrees with VII-A.5/.6 and the signed `Mu`
  equation in VII-A.8. No explicit in-scope requirement conflicts with the decision.
  The transport is `enc_rupdate(E(rse),E(rse+1),[r*]4,path,υ)` (five fields).
  The signed message is `enc_update(suite,E(µ),E(refe),E(refe+1),[r*]4,path)`
  (six fields). Preserve those distinct tags, contents, counts and enclosing LPs.
- **Manuscript edit still needed:** explicitly define the outer `rupdate` path payload
  as the raw concatenation in VII-A.8 or the opening codec rules. The PDF is unchanged.
- **Implementation:** `codec.pack_sibling_path`/`unpack_sibling_path` and separate
  transport/signing framing vectors implement the byte convention. Merkle root/path
  reference checking is now implemented; signed updates, state transitions and production
  witness updating remain later work. Packing alone is not verification.

### SPEC-002 — Expiry timestamp origin and boundary

**Status: agreed by the user on 17 September 2026; no implementation decision remains open.**

- **Exact locations:** IV-A, `ctx` and trusted-time assumptions, p. 5; IV-B,
  stateful verification's unexpired/pending checks, p. 6; VII-A.1, eight-byte UTC
  expiry in seconds, p. 14; VII-A.7, atomic expiry recheck and application lifetime,
  pp. 16–17.
- **Missing detail:** an eight-byte unsigned expiry and UTC seconds are specified,
  but the epoch and exact equality convention are not written down. No application
  request lifetime is supplied; that is explicitly a deployment-policy input.
- **Effect:** implementations using different epochs or equality tests can disagree
  at the lifecycle acceptance boundary. The proof binds the exact `texp` bytes
  regardless, so this does not change the private relation.
- **Agreed clarification (user decision, not existing manuscript wording):** encode unsigned POSIX seconds since
  `1970-01-01T00:00:00Z` as `[texp]8`; compare trusted time in the same convention
  and accept only while `now < texp`. Recheck this condition inside atomic challenge
  consumption. Do not add a grace window, clock-skew allowance or implicit lifetime.
  Application configuration must supply a lifetime before request creation.
- **Conflict check:** the decision preserves VII-A.1's eight-byte unsigned,
  big-endian seconds representation and VII-A.7's final expiry recheck. No explicit
  in-scope requirement specifies a different epoch or permits acceptance at equality.
- **Manuscript edit still needed:** name the POSIX epoch and strict comparison in
  IV-A/VII-A.1 and reference that predicate at every expiry check. The PDF is unchanged.
- **Implementation:** `expiry.encode_timestamp`, `decode_timestamp` and
  `is_unexpired(texp, now=...)` reject invalid types/ranges and require strict inequality.
  No system clock, current-state service or atomic verifier service is implemented.
  Request approval, presentation and final verifier consumption must use this convention
  when those services are implemented. No lifetime is silently supplied.

## Agreed Stage 3 clarification — full compiler conformance remains unverified

### SPEC-003 — Fold initialisers and derived gadget recipes affect gate identity

**Status: SPEC-003 agreed by the user on 17 September 2026.** The precise
implementation clarification is:

> Initialise equality with public 1. Initialise magnitude multiplication with a public 128-bit zero accumulator; add all 64 shifted partial products in increasing order using full-width ripple addition, retaining terminal carry operations.

Gate order, operand order, checked arithmetic and public-only constant folding stay
as specified. The existing production path already implements this convention and
has no alternate-initialiser selector. `test_spec003_alternatives.py` remains labelled
diagnostic evidence outside that path. No cryptographic or dependency change is needed.

This resolves the initialiser/full-width accumulation decision only. The broader
historical proposal below (including other derived recipes) was not approved wholesale.
Full BC-1 compiler conformance and complete canonical CGen equivalence remain unverified.
New trace, stability and validation evidence is in
[the validation record](stage3_hash_enrolment.md#confirmed-convention-and-extended-validation).

**Required later manuscript alignment:** add the exact agreed sentence to VII-A.6's
BC-1 equality and magnitude-multiplication wording on printed p. 16. A complete
versioned lowering specification and independent construction audit remain subsequent
conformance work; do not treat them as settled by this decision. The PDF is preserved.

The following gap analysis and proposal are retained as **historical rationale**, not
current pending initialiser decisions or additional user approvals.

- **Exact location:** VII-A.6, “Circuit profile BC-1”, printed p. 16: source-order
  left-fold sums, equality left-folding XNORs, magnitude partial-product sums, then
  sign application; only entirely public operations may fold.
- **Precise gap:** the equality fold has no written initialiser. Starting with the
  first XNOR versus ANDing public 1 with that first private XNOR yields the same
  value but differs by one AND gate. Partial-product accumulation similarly does
  not explicitly say whether the first partial product seeds the accumulator or
  is added to an all-zero full-width accumulator. The latter retains private/zero
  operations under the stated folding restriction. These are choices before
  emission, not permission to simplify emitted private operations.
- **Effect:** different otherwise equivalent lowerings can produce different wire
  identities, `g`, packed views and proof lengths. This is an interoperability and
  exact accounting gap, not evidence that the Boolean predicates differ or that
  the manuscript security theorem fails. Component counts cannot resolve it.
- **Proposed resolution:** explicitly freeze the development recipes described in
  [stage3_bc1_foundation.md](stage3_bc1_foundation.md): equality starts with 1 and
  visits increasing arithmetic-bit indices; magnitude sums start with a 128-bit
  zero and include all 64 full-width additions; sign extension/negation/selection
  derives magnitudes, and sign correction follows the sum. Pin subtraction's
  increasing-index complement pass before its ripple, terminal carry emission,
  narrowing checks and the `<=` expansion (`< OR ==`) alongside those recipes.
  Source digests and exact small traces make the proposal reviewable. Any approved
  different recipe must deliberately update those traces/counts before use in proofs.
- **Current treatment:** the emitter follows the explicit basis, ordering, numbering
  and folding rules; compound gadgets use the documented provisional recipe. They
  are a tested foundation, not a claim that the manuscript uniquely determines
  these component circuits. Complete canonical CGen equivalence, full authentication
  `g`, proof generation and canonical-profile validation remain absent; provisional
  enrolment compilation is now recorded in the assessment below. Proceed with
  unaffected hash/parser implementation; resolve this recipe before declaring full
  canonical circuit conformance or using counts for security accounting.
- **Manuscript proposal only:** add the initialisers and a versioned exact lowering
  reference to VII-A.6. No PDF, confirmed suite parameter, repetition count, raw-tape
  rule or existing convention was changed. No new decision is presumed accepted.

**Historical pre-adoption hash/enrolment assessment (17 September 2026):** rechecked the exact
VII-A.6 wording against the pinned manuscript and foundation implementation. No
in-scope text uniquely chooses the initialisers. The alternatives are now executable
in `tests/unit/test_spec003_alternatives.py`: equality seeded with 1 versus first
XNOR, and magnitude sum seeded with zero versus first partial product. Exhaustive
small cases and signed64 minimum/maximum/overflow cases agree on values and validity.
Order, AND counts, total gates and fingerprints differ. Equality differs by one AND;
the 64-bit multiplication comparison predicates differ by 638 total gates and 255
ANDs. The first-partial alternative also leaves high bits public in the next sum,
enabling additional permitted public folds; the difference is not just one omitted add.

Affected foundation gadgets include equality/byte equality and their callers
(selectors, derived <=, narrowing tests), magnitude accumulation and later relation
conjunction recipes. Enrolment uses digest/attribute equality, not multiplication.
Its functional checks can pass independently of resolving canonical circuit identity.
Hash round expressions with explicit operands follow FIPS 202 literally; theta's
five written terms use four left-associated XORs, chi retains XOR-with-1, iota emits
all 64 XORs and absorption retains private XOR-zero capacity operations. The state
traversal and byte fold order are recorded in the new report as construction choices,
not a new approved profile. All new counts/identities remain labelled provisional.

**Historical broader proposal (not approved wholesale):**

> Equality starts with public 1 and ANDs each bitwise XNOR in increasing bit-index
> order. Magnitude multiplication starts with a public 128-bit zero accumulator and
> adds all 64 shifted partial products, including the first, using full-width ripple
> addition in increasing partial-product order. Retain the terminal carry operation
> at each step. Form magnitudes by 65-bit sign extension, negation and selection;
> apply the product sign before checking representability and narrowing. Subtraction
> complements the second operand in increasing bit order before ripple addition.

For byte arrays, the proposed development extension visits bytes in serialised order
and bits in increasing numerical weight, with one initial 1 across the entire byte
comparison. Pin final conjunctions and FIPS traversal along with these choices before
asserting complete BC-1 interoperability. The recommendation retains the already
audited foundation recipe, makes gate accounting reproducible and avoids silently
changing private/constant operations. See [hash/enrolment evidence](stage3_hash_enrolment.md)
for actual alternative traces, tests, resource limits and the complete enrolment predicate.

**Executed post-adoption validation:** all 17 previously skipped tests and all nine
originally capped diagnostic probes complete under the separate approved
2000000-gate/41943040-byte profile, one worker, retained 10/5-second generation/
evaluation controls, kernel 256 MiB address-space cap and sampled 128 MiB RSS watchdog.
The exact multiplication and enrolment fixtures reproduce their historical counts,
trace lengths and fingerprints; fresh traces are byte-identical across budgets and
storage modes. Independent small traces check the initial public-1 AND and first
zero-accumulator ripple/terminal carry, and an actual-width audit checks all 64 sums.
Regression passes 1106 tests without skips; lint/format pass. Per-case resources,
host inspection and enforcement details are in the linked validation report.

No required deferred functional case remains unfinished. Full canonical BC-1
conformance still needs an independent complete lowering audit, including remaining
derived recipes, traversal/conjunction details and authentication/sampler composition.
The enrolment 9587104-byte proof projection remains a calculation; proof implementation
and feasibility are open. The next bounded parsing/division/reduction/ring package is
ready, but is not started here. Stage 2/DEP-001/DEP-002 obligations remain unchanged.

## Open Stage 3 division lowering clarification

### SPEC-004 — Restoring-division work registers and exact emission schedule

**Status: agreed implementation clarification, 18 September 2026.** The user
adopted the restoring recipe with explicit sign-correction operands and validity
order. SPEC-001/002/003 remain unchanged. This resolves SPEC-004 only; full BC-1
conformance, complete authentication and proofs remain open.

**Adopted wording.** For public positive signed64 divisor b, form the dividend's
unsigned64 magnitude by sign-extension to 65 bits, negation and input-sign selection,
retaining its low 64 bits. The magnitude 2^63 for MIN is valid. Initialise a 65-bit
remainder R and 64-bit quotient Q with public zeros. Scan magnitude bits 63 down to
0; wire the 65-bit trial `(R<<1)|bit`, subtract zero-extended b once across all 65
bits with terminal carry retained, set `take=NOT difference[64]`, assign
`R=mux(take,trial,difference)` and copy take to Q[bit]. Construct both outputs for
every div-only/mod-only call. All following intermediates are 65 bits; mux(s,a,b)
selects b on true. Emit these named intermediates once and reuse them in order:

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

Apply signed64 representability checks to output_Q then output_R before narrowing;
combine `Q_valid AND R_valid`, then AND that result with `b>0`. Preserve active-path
sticky rejection, full-width carries, operand order and public-only folding. Divisor
zero constructs the bounded recipe and returns invalidity with unusable outputs;
negative, private and out-of-signed64 divisors fail at construction. No private
advice is introduced.

**Deliberate change:** the old false arm of corrected_negative_R was private R;
it is now public zero. The final validity AND's operands are now `(Q_valid AND
R_valid, b>0)`, instead of `(b>0, Q_valid AND R_valid)`. These mathematically
equivalent changes preserve tested values and gate counts but change operand records
and fingerprints. The old source is frozen in a test-only reference and all earlier
vectors/measurement JSON files are preserved. New literal wiring audits check every
mux arm, width, reuse and validity operand; independent floor/remainder checks retain
MIN/MAX, zero and positive-divisor boundaries. See [the adoption/preflight report](stage3_resource_preflight.md).

**Required later manuscript update:** add this complete lowering to VII-A.6, printed
p. 16, or its authoritative versioned lowering reference. Only Sections II–VIII were
used. The manuscript PDF remains unchanged; this is a user-agreed clarification,
not text already present in it.

#### Preserved pre-adoption proposal and evidence (historical)

Everything below in this SPEC-004 subsection records the earlier pending state;
the adoption above supersedes that status and its less explicit sign-correction text.

**Status: proposed development recipe; not user-agreed.** SPEC-001/002/003 remain
agreed and unchanged. Functional floor/remainder semantics are fixed; this issue
concerns exact gate identity for the newly required division/reduction gadget.

- **Source:** VII-A.6 BC-1, printed p. 16, requires signed64 words, extended arithmetic,
  high-to-low magnitude scans with conditional subtraction, then signed floor/remainder
  correction. FIPS 204 §2.3 defines positive and centred residues; Algorithms 36/40
  require public positive divisors q, 2*gamma2 and 16. No private/negative divisor
  is required by the verifier programme.
- **Precise missing detail:** the text does not fix the restoring scan's remainder/
  trial register width, whether a comparison computes a second subtraction or uses
  the subtraction's sign, or whether a remainder-only call also constructs quotient
  and quotient correction wires. Equivalent choices yield different counts and traces.
  The signed64 minimum has magnitude 2^63, so treating that magnitude as a positive
  signed64 value would also give incorrect functional results.
- **Concrete proposed recipe:** extend the magnitude into a 65-bit remainder workspace,
  initialise it with public zero, and visit exactly 64 dividend magnitude bits from
  63 down to 0. Form `trial=(remainder<<1)|bit` by internal bit wiring; subtract the
  public zero-extended divisor once across all 65 bits with terminal carry retained;
  let `take=NOT difference[64]`; select the difference or trial with BC-1 mux and wire
  `take` into the corresponding quotient bit. This is an explicitly specified source
  temporary, not common-subexpression elimination of two source operations. Generate
  both quotient and remainder for every div/mod call. Use 65-bit negation and decrement
  for negative quotient correction when the magnitude remainder is nonzero, and
  divisor-minus-remainder for the corrected nonnegative remainder. Select by sign,
  check both outputs' representability, then expose the signed64 outputs and validity.
  Preserve operand order, all private/constant gates and terminal carries throughout.
- **Zero and unsupported operations:** public divisor zero follows a fixed bounded
  construction but has an unconditional invalidity wire; its outputs are unusable.
  Negative constants, private divisors and constants outside signed64 are rejected
  by the construction API, rather than inventing a different division convention.
  In particular MIN/-1 is outside the permitted positive-constant interface; MIN/1
  is supported exactly. Ring arithmetic checks full add/sub/mul representability
  before reduction; a later equality or mod operation cannot clear sticky rejection.
- **Effect/current treatment:** the new `circuits.division` path freezes this one
  documented development recipe, with no alternate selector or auxiliary witness.
  Small literal traces, reduced-width exhaustive checks and real-width tests assess
  it. Scalar consumers inherit its provisional identity. Functionality may be used
  for bounded integration, but no complete canonical BC-1 identity/security count is
  claimed while this detail and the broader conformance audit remain open.
- **Later author action:** explicitly fix this lowering in VII-A.6 or an authoritative
  versioned lowering reference. The manuscript is preserved. The user has authorised
  this package's implementation/validation and recording of genuine ambiguities;
  this proposal is not silently marked accepted and does not block unaffected work.

**Executed evidence:** 217 focused and 1323 regression tests pass without skips;
36 component/mode probes complete under the unchanged approved profile. The literal
restoring-step trace, exhaustive reduced widths, real signed64 endpoints, Fraction/
floor identities, centred ties, overflow propagation and scalar reference comparisons
support functional correctness of the proposed recipe. Materialised/count/stream
identities agree. This evidence does not change SPEC-004 to an agreed convention.

**18 September 2026 review: still pending.** Re-reading VII-A.6 does not uniquely
resolve widths, comparison/subtraction reuse or quotient construction in mod-only
calls. The new [signature-input report](stage3_signature_inputs.md#spec-004-pending-exact-division-recipe)
records alternatives and their distinct emission consequences. The production
signed64 divmod-q core is 35894 gates / 13332 ANDs; a test-only separate-comparison/
subtraction version is 56566 gates / 21588 ANDs with the same tested outputs/rejection.
Reduced-width exhaustive and actual signed64 endpoint tests support functionality,
not canonical approval. No production algorithm or divisor domain was changed.

**Complete recommended clarification (proposal, not agreement):**

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

`mux(s,a,b)` selects b when s is true. All arithmetic consumers retain provisional
circuit identity pending this clarification and the wider BC-1 conformance audit.
The PDF is preserved; this wording is proposed for VII-A.6 or its authoritative
versioned lowering reference. The signature/input package adds no new protocol
convention, witness advice or approval of SPEC-004.

The new [parsing/arithmetic report](stage3_auth_parsing_arithmetic.md) records contracts,
actual tests/costs and subsequent dependencies. Parser source traversal and final
conjunction schedules are also documented engineering lowerings within the existing
full-conformance review; this issue does not assert that their entire gate identity
has been independently standardised.

## Standards/dependency findings — separate from manuscript contradictions

### DEP-001 — FIPS 204 potential updates and the signing-tail model

**Status: reviewed; fixed algorithm parameters retained; quantitative validation pending.**

Relevant manuscript locations are VII-A.1 (August 2024 FIPS 204), VII-A.6
(bounded operations, pp. 15–16), and VIII-A (`βS=(41/51)^1024`, conditional-tail
model, `Δtail` and aggregate cap loss, pp. 17–18). No conflict between manuscript
sections is asserted here.

Reviewed the official [FIPS 204 potential-updates spreadsheet](https://csrc.nist.gov/files/pubs/fips/204/final/docs/fips-204-potential-updates.xlsx),
last updated 31 July 2026, SHA-256
`5bc93ce63bc647e6d1d456cb2d3a171426c15aca4a7a0e0edd40d08b7a34c793`.
Its items are potential corrections, not a replacement standard. Initial retrieval
was rejected with HTTP 403; a browser-user-agent download succeeded. No dependency
was installed or changed during this review.

Implementation-relevant dispositions:

| Spreadsheet location | Disposition for this implementation specification |
|---|---|
| FIPS §§2.5/7.5, NTT explanation | Use the algorithmic NTT root and a single polynomial evaluation; do not implement the prose's duplicate evaluation. |
| FIPS §§6.2/6.3, message notation; §3.3, challenge input order | Follow the numbered algorithms: the context-processed message and `mu \|\| w1` order. Preserve external contexts. |
| FIPS §6, routine naming; §5.3, oversized-context failure | Treat the Power2Round naming and false/failure notation as editorial; all invalid verification outcomes reject. |
| FIPS Appendix A, Montgomery reduction | Any optimised native adapter must respect the corrected interval/signed intermediate. BC-1 uses its prescribed checked arithmetic, not an unspecified Montgomery shortcut. |
| FIPS §7.4, UseHint output range | Use the bound implied by the algorithm and accepted by `w1Encode`; document boundary tests in Stage 2. |
| FIPS §4/Appendix C, signing retries | Revised average counts include a previously omitted rejection; the suggested minimum retry limit becomes 821. Retain the manuscript's explicit cap of 1024. Its conditional signing-tail estimate needs rechecking. |

The corrected mean alone does **not** prove a conditional geometric rejection bound.
Do not silently replace `41/51` by a ratio inferred from that mean, set `Δtail=0`
for arbitrary adaptive SHAKE inputs, or claim the aggregate numerical loss is verified.
The specification records Section VIII's expressions as conditional manuscript claims.
Before using the numerical bound, derive/justify the conditional tail for the actual
algorithm or propose a corrected loss expression. No protocol parameter changes are
authorised by this standards review.

**Impact:** does not block byte codecs, relations, fixed-cap implementation or circuit
engineering; blocks treating the signing-tail/security-loss estimate as validated.
Mathematical validation belongs with Stage 2's bounded-operation work and later security
review. The future adapter must record exactly which standard algorithms/corrections
it implements. This is not a failure of the already tested ordinary liboqs API.

### DEP-002 — Ordinary backend versus manuscript-specific operations

**Status: bounded reference verification and local CredValid complete; remaining
keygen/signing/release integration open in Stage 2.**

The existing evidence establishes ordinary ML-DSA-65 operations, external contexts
and representation sizes for the pinned backend. It does not establish VII-A.6's
sampler-byte limits, signing-attempt limit, pre-release bounded verification, exact
FIPS operation schedule or BC-1 circuits. Keep the unchanged library as a cross-check
backend. The separate Python bounded verifier now supplies reference verification;
no new library selection or native rebuild was required.

The credential work package inspected the actual pinned sources and generated build
configuration. [bounded_mldsa_plan.md](bounded_mldsa_plan.md) now maps verification
entry/context/hash/decoding/arithmetic functions, uncapped matrix/challenge refill loops,
and the separate native signing-attempt bound (13106 for this build, not 1024).
Those sources remain unchanged. The separate implementation and exact boundary tests
are recorded in [stage2_bounded_mldsa.md](stage2_bounded_mldsa.md). DEP-002 is tracked
by subtask so reference verification does not prematurely close service obligations:

| Subtask | Status/evidence |
|---|---|
| Complete pure ML-DSA-65 reference verification | Complete in `bounded_mldsa.py`; real SHAKE, decoding, arithmetic, hints/norms/context/challenge; native differential agreement |
| RejNTTPoly ≤1026 and SampleInBall ≤256 | Complete for verification; exact-limit success, deterministic exhaustion, all 30 matrix invocations and propagation tested |
| Local CredValid composition | Complete in `credentials.cred_valid`; same credential structure/opening/Mcred, pinned issuer key/context; invalid signatures and exhaustion reject |
| Bounded key generation and setup/import consistency | Pending; RejBoundedPoly ≤512, matrix expansion, key consistency/randomness and no partial activation |
| Bounded signing | Pending; exactly ≤1024 attempts, all invoked sampler limits and abort semantics; ordinary fixture signing is uncapped |
| All-role bounded pre-release verification | Pending; original-B logging, atomic nonce/log/release and state/service integration remain required |
| Complete local relations and public StateAuth | Complete and tested in `stage2_relations.md`; both credential and state verification use actual fixed sampler caps; controller/request/current/update service integration remains pending |
| Circuit integration | BC-1 synthesis/equivalence and privacy-preserving proofs remain Stage 3 work |

Validation: 208 focused checks and 689 regression checks passed; lint and formatting
passed. These results do not establish formal/FIPS validation or overall security.
DEP-001's quantitative signing-tail/Δtail obligation remains separate and unchanged.

## Routine engineering decisions resolved without changing the protocol

These are project decisions, not additional manuscript parameters:

- Use exact byte equality for opaque issuer/key/audience/session identifiers; perform
  no Unicode or case normalisation inside the protocol codec. Their application-layer
  interpretation remains explicit input. Tags and schema names have the manuscript's
  ASCII restriction.
- Treat the disclosure mask as the unsigned integer `sum(2^(j-1) for j in D)`,
  encoded in two big-endian bytes under VII's `[a]k` convention. Bit numbering is
  numerical, while serialised bytes enter BC-1 most-significant-bit first. This
  reconciles the two stated conventions without changing either.
- Sort policy clauses by their complete canonical encoded bytes; reject duplicates.
  Schema/policy lists occupy one `enc` field per descriptor/clause, following VII's
  list rule; do not invent an additional list wrapper or count field.
- Keep `refI` and explicitly encoded `E(…)` values as bytes when nesting them;
  apply the enclosing `LP` once. `meta` is the tag for `µ`, not an invented tag for
  the publication API's local `(active,rotate)` argument.
- Make the planned canonical reference evaluator the versioned input to BC-1.
  Preserve VII's private-field/check order and the invoked numbered FIPS algorithms;
  record its eventual source digest and circuit vectors in Stages 2–3. Do not use
  liboqs's optimised internal execution order as the circuit specification.
- Use named error categories internally, mapping them to the specified `⊥` or
  `b=0` at the interface. Errors never log secrets or roll back durable allocations,
  released certificates or committed public updates.
- Database choice, process layout and local representation may vary provided the
  specified atomic operations, owner separation, ordering and public bytes remain
  unchanged. No transport protocol or conformance claim is selected implicitly.

## Application/deployment inputs, not missing cryptographic constants

III-A/B, IV-A/B and VII-A.1/.7 deliberately leave issuer/key identifiers, trust keys,
the immutable schema, audience/session values and request lifetime to configuration.
`configs/suite.json` leaves actual deployment inputs null. A synthetic schema and
two disclosure-policy examples are documented separately as engineering fixtures in
`implementation_spec.md`; they are not claimed to come from the manuscript.

The W3C representation design in that specification is experimental. Context IRIs,
proof/status-extension publication, transport authentication and a conformance test
adapter must be finalised before Stage 5 integration. Section III-A explicitly does
not confer W3C conformance on the binary protocol. No private relation work depends
on publishing those extensions. Likewise, experimental time/memory/scratch budgets
are deployment inputs, not values to invent in the cryptographic suite manifest.

## Previous findings reclassified under the authoritative scope

| Earlier status concern | Current classification |
|---|---|
| Abstract/Section I and later conclusion use different construction terminology | Deferred author edits; excluded from consistency and parameter extraction. |
| Unrevised implementation section describes a different prototype and proof assumption | Deferred author edits; no role in this specification or its implementation readiness. |
| Unrevised evaluation has token sizes/timings and a different machine | Excluded performance evidence; not compared against this profile and not an implementation blocker. |
| Plan cites a differently named V3 file | Source identity established by the sole selected project PDF and its unchanged digest; the user has fixed its authoritative section range. |

None of the excluded sections was reread for specification extraction. No excluded
benchmark value or construction is imported into the manifest, requirements or tests.
There is no verified contradiction among Sections II–VIII selecting a different
signature, holder binding, revocation tree or proof system.

## Vector review and implementation scope (17 September 2026)

Reviewed E01–E32 against VII's codec/schema/policy equations and the Stage 1 synthetic
fixture before testing. No original expected output was changed. E15/E28 concern
proof-view packing and remain Stage 3 vectors; proof-size cases remain arithmetic
records. E31 is a context-framing example, not an authenticated statement. New
SPEC-001/002 vectors were calculated from the encoding equations independently of
`pqdid` implementation imports. Their signatures/roots are explicitly unauthenticated
fixture bytes. See `docs/stage2_codec.md` for the implemented boundary and evidence.

## Holder-binding/Merkle implementation review — 17 September 2026

Checked VII opening/A.1/A.5, pp. 14–15, against the existing specification and manifest.
No new unresolved detail or conflict was found. The hash preimages use exactly suite,
encoded µ and the specified fields. No identifier is added to a leaf, and attributes
remain the separate canonical block in B rather than being added to the holder hash.

Routine engineering choices: `HashDomain` derives the schema from canonical `refI`
rather than accepting a contradictory duplicate; it is not complete pp or issuer trust.
`check_binding_consistency` names the local equations without claiming certification.
`verify_non_revocation_path` takes a supplied root, not an authenticated/current state.
Malformed inputs raise the existing `EncodingError`; valid mismatches return False.
These choices preserve V-B's separation of private relation and public/lifecycle checks.
Old-root path validity is intentionally retained, as required by that separation.

Independent synthetic fixture construction and actual test evidence are in
[stage2_binding_merkle.md](stage2_binding_merkle.md). Existing vectors and parameter
values are unchanged. SPEC-001/002 remain agreed; DEP-001 signing-tail/Δtail validation,
DEP-002 bounded ML-DSA work and Stage 3 proof feasibility remain open.

## Parameter/credential implementation review — 17 September 2026

No new in-scope ambiguity was found. VII-A.1/.5 fixes pp/µ/B/cert/vc and exact Mcred.
That earlier package implemented canonical structure and externally expected pp/metadata;
FIPS key expansion, signature decoding/verification and full CredValid were then pending
and are now covered by the bounded verification package below. Trust remains separate.
No fields or message digest/context prefix were added. Public keys are not separate
Mcred fields; expected-pp, signature and eventual trust checks prevent substitution
without changing the manuscript formula.

Frozen Python records, private repr suppression and explicit structural-validator names
are routine engineering choices. Synthetic signature-shaped fixtures make no authenticity
claim. Details and evidence: [stage2_credentials.md](stage2_credentials.md). SPEC-001/002,
DEP-001's separate quantitative validation and the selected manuscript remain unchanged.

## Bounded verifier/CredValid implementation review — 17 September 2026

No new protocol ambiguity or manuscript correction was identified. The Python integer
reference, internal exhaustion exception, fixed-prefix SHAKE reader and separate ordinary
native fixtures are engineering choices implementing the unchanged FIPS processing and
manuscript budgets. The verifier was validated before integration into local CredValid.
That predicate checks an opening supplied locally; it does not establish remote knowledge,
current non-revocation, freshness, authorised service issuance or a privacy-preserving proof.
SPEC-001/002 and the source PDF remain unchanged. DEP-002 stays open as split above.

## Executable relation review — 17 September 2026

Rechecked V-B/C and VII-A.1/.5/.6/.7 against R-020/R-024/R-025 before coding. No new
in-scope ambiguity or manuscript correction was found. Complete authentication includes
PubOK (with StateAuth), the same-witness private conjunction and Ppub. State signatures
are now bounded-verified under the exact state context. Disclosed-only policy stays
public; no hidden predicate was introduced.

Enrolment's private relation is BindOpen. A separate stateless public helper checks
domains, the issuer-supplied approved vector and state authentication. Controller
authorisation, proof verification, nonce/registration/allocation, approval and fresh
issuance reads remain surrounding work. The prior status suggestion to add control
checks is not treated as authority to move them into the private relation.

Frozen data records, strict encode/decode/Boolean boundaries, an explicit `auth_private`
circuit target and a mandatory complete `auth` entry are engineering choices. Every
serialised public field is encoded for later proof input; actual transcript binding is
unimplemented. Well-formed context mutations can change E(X) without falsifying a
predicate, and old signed roots can remain mathematically valid. Tests preserve these
boundaries instead of adding clocks or session stores to a relation.

[stage2_relations.md](stage2_relations.md) records 201 focused and 890 regression tests,
independent fixture provenance and the remaining Stage 2/Stage 3 boundary. Bounded
keygen/signing, DEP-001 quantitative validation and remaining DEP-002 pre-release/service
integration stay open. SPEC-001/002 and the manuscript remain unchanged.

## PROP-001 — Concrete-proof profile change proposed, not adopted

19 September 2026. The user authorised a source-review/change-proposal package,
not a replacement implementation or amendment of SPEC-001–004. The
[profile proposal](stage3_profile_change_proposal.md),
[separate draft wording](stage3_profile_spec_draft.md) and
[draft benchmark targets](benchmark_targets.md) are ready for review. This is a
proposed construction change, not a newly discovered manuscript contradiction or
an agreed SPEC-005.

Affected in-scope locations: II concrete comparisons; III proof building block and
assumptions; IV profile selection in lifecycle use; V Prove/Check instantiation;
VI extraction/privacy requirements; VII-A.6/.7 proof/compiler/admission/encodings
and closing proof-size equation; VIII-A–E concrete costs, extraction/simulation
losses and lifecycle composition. The draft `PQDID-R0S-EXP1` separates proof-profile
identity from existing signed credential-suite bytes and replaces BC-1/raw-view
proofs only for that proposed profile. Existing ML-DSA-65, application SHA3/SHAKE,
depth-20 tree, same-witness relation and freshness rules are retained.

Recommended next engineering candidate is RISC Zero v3.0.6 native Succinct STARK,
subject to source/privacy/security qualifications and explicit bounded experiment
review. None of the surveyed candidates currently establishes the complete required
contract. The proposed backend's documented ZK limitations, 96/99-bit component
estimates, quantum full-witness extraction and actual-history simulation/composition
are adoption blockers. No Groth16 wrapper, altered repetitions/seeded tapes or
unproved external private check is authorised.

Decisions pending: separate profile/receipt encodings, whether to run the engineering
experiment while security adoption remains blocked, draft numerical/network targets,
and future installation/build/resource envelope. The active specification/config,
manuscript and original proof conventions are unchanged. Stage 2 keygen/signing/
release/revocation/service work, DEP-001/002, full original authentication/proofs and
BC-1 conformance remain open. The 64M/2 GiB proposal stays inactive.

## PROP-002 — R0 design-review disposition and unadopted alternatives

19 September 2026. [R0-DESIGN-REVIEW-1](stage3_r0_design_review.md) is source analysis
and documentation only. Its [checked arithmetic](data/r0_design_review_1/calculations.json)
confirms 16,313,474 measured user cycles, 182 segments and a **35,615.572-second
forecast**, with the existing 50% allowance applied once to the whole subtotal.
Actual CredValid proving time and aggregate prover memory remain unmeasured. The
600-second resource deadline and the draft application targets are unchanged.

**Disposition:** keep current RISC Zero CPU proving paused. Two proof attempts
remain used and one unused; no new execution, proof, installation, limit increase
or replacement profile is authorised by this review. PROP-001's initial engineering
candidate recommendation is historical; the isolated experiments and this review
do not approve its proposed profile or numerical security assumptions.

**Unadopted relation-preserving proposals:** A, exact SHA3-384/SHAKE128/256 through
the pinned accelerated tiny-keccak adapter, requires a new guest/image/dependency
pin, constrained coprocessor claims and their proof/lift/assumption resolution.
B, public issuer-key preprocessing, requires independent bounded derivation and
binding to the expected key, using an explicit public auxiliary/journal schema or
an independently validated per-key image. Unchecked prover-supplied matrices are
unacceptable. Public cache/rotation/cold-start costs and exhaustion semantics must
be specified. Mathematical predicate equivalence does not preserve the existing
BC-1 schedule, R0 image or interfaces. Neither A, B nor their combination currently
has an evidenced complete latency/memory case.

**Two redesign comparators only:** the inspected zkDilithium prototype proves an
altered signature relation and lacks the required implemented ZK; it is not FIPS
ML-DSA-65. LaZer's small lattice credential showing changes issuance/signatures and
does not implement this holder/SHA3/disclosure/private revocation conjunction. Its
documented current hardware requirements are not met by the recorded WSL ISA.
Neither supplies a complete same-witness construction with the required quantum
extraction, complete-view privacy and historical-unlinkability justification.

Affected locations, subject to future review: II fair concrete comparisons; III
public parameters/building blocks/trust; IV issuer-instance and verifier lifecycle;
V exact joint relation and proof/public bindings; VI security/privacy games;
VII-A.6/.7 compiler/profile/receipt and auxiliary encodings; VIII-A deterministic
reuse and full cost accounting, VIII-B binding/tree premises, VIII-C extraction,
VIII-D simulation/history privacy and VIII-E lifecycle composition. A changed
signature/hash/tree requires new suite definitions and re-established arguments,
not a rename of ML-DSA or transfer of the original MITH loss bound. See the review's
concrete proposed change list and binding designs; no manuscript edit is made.

**One next-package proposal:** S2-VERIFY-STATE-1, a reference-only R-028 state model
with the existing R-017 logical epoch and SPEC-002 final atomic expiry/context check.
The review specifies success criteria, a smaller local envelope and stop conditions.
It must not expose placeholder proof success or claim completed PQ-DAA. This can
advance independently of backend adoption. SPEC-001–004, active parameters and
original fixtures remain fixed; full authentication, selective-disclosure/non-
revocation integration, BC-1, actual CredValid/authentication proofs, DEP-001/002,
bounded keygen/signing/release services and privacy/security review remain open.

## S2-VERIFY-STATE-1 — reference lifecycle implementation, not a new SPEC decision

19 September 2026. [Implementation/validation report](stage2_verifier_state.md) and
[reference module](../src/pqdid/verifier_state.py). The implementation was checked
against IV-A/B, V-B/C, VII-A.1/.4/.7 and VIII-E within the authoritative II–VIII
scope. No contradiction or ambiguity was found in the failed-verification rule,
logical epoch or SPEC-002: failed calls do not consume; an update after the final
ordered state read does not invalidate acceptance; the final locked expiry sample
must satisfy strict `now < texp`.

R-016/R-017/R-027/R-028 are **partially implemented**. Typed clock/store/trusted
provider/request signer/proof adapter interfaces, exact registered-context and
invoking-session checks, bounded authentication of `current` and `state` signatures,
public-statement construction and in-process atomic consumption are implemented.
Configured DID checks use only disclosed certified did/vD and validated specified
state; no hidden lookup or current controller-control requirement is introduced.
The default proof adapter is unsupported. Controlled test tokens and separate local
same-witness evaluation are not cryptographic receipts or remote knowledge proofs.

Engineering choices: immutable local records, strict proof-verdict enum, finite
in-memory store retaining all nonce reservations/tombstones, default capacity 100,
and at most eight audience-nonce draws per creation call (explicitly configurable
within the local allowance). The latter bounds IV-A's collision resampling; it is
not a changed cryptographic sampler/security parameter. Existing canonical ctx/X
and `current`/`state` signing bytes are reused without new fields. The local DID-check
flag and byte admission ceiling are not added to the signed/proved statement.

After ctx is registered, a signing failure leaves the unused reservation pending
and releases no request. No failed verification consumes it. Request delivery/crash
recovery, persistent nonce retention/eviction and replica consistency are not fully
specified as deployment mechanisms by the manuscript and are not implemented here;
production choices must preserve audience nonce uniqueness and at-most-once acceptance.
No freshness window, default application lifetime or cross-service atomic transaction
is invented. Provider latest-state ordering and trusted DID/issuer validation remain
assumptions; valid signatures alone do not establish currentness.

The 87-case focused/scoped-regression corpus, lint and formatting pass within the
256 MiB/no-swap, one-worker/two-core, 60 s per command/300 s aggregate proposal.
Ordinary native test-only signing creates ephemeral synthetic manager/request
evidence; bounded production keygen/signing, DEP-001/002, issuance/release/revocation,
real proofs and the privacy/security review remain open. Original source, vectors,
dependencies, manuscript and historical experiment evidence are preserved. CPU
proving remains paused at **two used/one unused attempts**. S2-UPDATE-WIT-1 is the
one proposed next bounded reference package, not work begun here.

## S2-UPDATE-WIT-1 — reference witness updates, not a new SPEC decision

19 September 2026. [Implementation/validation report](stage2_witness_updates.md) and
[reference module](../src/pqdid/witness_updates.py). IV-A/B/C, V-B/D and VII-A.1/.5/.8
within Sections II–VIII support the existing R-029–R-031 contract. No genuine
specification contradiction or ambiguity was found. SPEC-001–004 are unchanged:
the rupdate path remains one raw 960-byte payload, and its transport is never
substituted for the distinct update signing message.

R-031's bounded holder-local reference procedure is implemented and tested against
independent sparse-tree roots/paths. Every endpoint/carried state and update is
authenticated with the existing bounded verifier. Caller-pinned pp supplies issuer
instance, namespace and manager key. Missing/replayed/reordered/forked history,
false zero-to-one roots, invalid signatures and malformed records fail closed.
Authenticated own-identifier revocation returns no replacement witness.

Engineering choices: immutable whole-batch result, maximum 16 records / 178592
encoded update bytes (both lowerable), fixed typed reasons and no diagnostic private
data. Logical state identity is the specified reference (namespace, epoch, root);
different valid signature randomness does not create a different state. Every
transported signature remains checked. These choices add no signed/proved fields,
change no cryptographic cap and invent no duplicate-skipping or history repair.
The existing internal bounded-verifier diagnostic result retains exhaustion
separately from invalid signatures without a retry or fallback.

All public records must pass before a private result is returned; a bad later
record prevents reporting either partial success or revocation for that batch.
Failure preserves the caller's old witness/root/version together. That old
checkpoint is not currentness evidence. Explicit consecutive bounded calls can
retain previously successful checkpoints; wallet persistence/crash recovery and
public-log retrieval remain deployment obligations. The updater assumes a locally
validated credential; its identifier/path checks do not replace CredValid or full
authentication. Uniform-subtree paths can legitimately coincide for different IDs.

**70 focused and 25 scoped regressions pass** within the existing 256 MiB/no-swap,
one-worker/two-core, 60 s/300 s envelope, including genuine bounded-sampler exhaustion
and failure during both public and private processing. Controlled native test
signing and public proof adapters are not bounded production signing or proofs.

R-030 remains partial: issuer request authorisation, allocation/aborted issuance,
nonce replay protection, atomic tree/state/update publication and retrieval after
delivery failure need a manager-side service/reference transaction. Recommend the
separate bounded S2-REVOKE-STATE-1 reference state-machine package next; it has not
begun. Production wallet/verifier/issuance/release services, DEP-001/002, bounded
keygen/signing, full authentication circuits, selective-disclosure/non-revocation
proof integration, BC-1, actual CredValid/authentication proofs and privacy/security
review remain open. No proofs, zkVM runs, installs or profile changes occurred;
historical evidence and the **two used / one unused** ledger are preserved.

## S2-REVOKE-STATE-1 — manager reference state, no new SPEC decision

19 September 2026. [Contract/validation report](stage2_revocation_state.md) and
[reference module](../src/pqdid/revocation_state.py). Checked IV-A/B/C, VII-A.1/.5/.7/.8
within authoritative Sections II–VIII. No genuine ambiguity or new cryptographic
convention was needed. SPEC-001–004 and the active suite remain unchanged.

R-030's reference transition now authenticates the issuer's exact revreq message,
checks current reference, allocation, unused nonce and zero leaf, prepares/validates
both manager signatures and the public record, then atomically replaces the complete
local tree/state/nonce/history snapshot. Signing occurs outside the lock; final
snapshot identity comparison prevents publication against a concurrent obsolete root.
Duplicate/replayed requests do not create a new epoch. Post-commit delivery failure
leaves the record retrievable. No allocation, reuse, unrevoke or DID-deactivation
operation is introduced.

Engineering choices: trusted local checkpoint import; allocation represented by the
specified permanent prefix; immutable sparse maps/snapshots; lowerable limits of
32 newly committed history records, 64 total revoked IDs and 64 consumed nonces;
at most two active preparations and non-blocking conflict/busy outcomes.
Signature adapters default to unsupported and make at most two requests per
revocation or one per current read. Actual bounded signature verification retains
exhaustion separately; it does not turn an uncapped signer into a bounded one.

The manager's imported allocation/nonce state is trusted, not certified by the
root signature. Complete nonce retention and correct bootstrap provenance are caller
obligations; this does not implement Setup, genesis replay or persistent restoration.
A checkpoint is an explicit history base. Earlier/future/gapped history returns
UNAVAILABLE; no committed record or consumed nonce is evicted. The finite model
stops at capacity. Production recovery must preserve required history rather than
restart this model to bypass its storage or replay bounds.

Public retrieval is namespace/version-based and returns at most the existing
holder limit of 16 records/178592 bytes with explicit continuation. No hidden rid,
private witness or credential query is introduced. Current replies use the existing
signed current message and linearise at a final snapshot recheck. State certificates
contain no expiry field; strict SPEC-002 context expiry remains separately enforced
by the verifier. Valid historical signatures do not establish currentness.

**73 focused and 25 scoped regressions pass**, including independent trees, all
three verification boundaries' real bounded exhaustion, both signing stages' faults,
concurrent preparations, two full holder batches, delivery failure and full local
holder/verifier composition. Test-only native issuer/manager signing and controlled
proof tokens establish reference results only. Historical files, including the prior
witness-update audit failure/correction, are unchanged.

Remaining obligations: real bounded keygen/signing and DEP-001/002; permanent
allocation, issuance/certification-release integration; persistent/distributed
manager, wallet, verifier and DID services; complete authentication circuits,
selective-disclosure/non-revocation proof integration, BC-1, actual
CredValid/authentication proofs and privacy/security review. Recommend the bounded
S2-REVOKE-AUDIT-1 read-only preservation package next; it has not begun. The final
audit completed its content checks but reached the 256 MiB cgroup memory ceiling,
with 387 max events, zero OOM and guard exit 125. Validation stopped without retry
or a limit increase. This is a resource/audit issue, not a manuscript ambiguity or
failed credential test. Charged memory categories were not captured; a subsequent
bounded audit should establish the cause under the same ceiling before more
implementation work. The content result's success flag does not override the
guard's failure. Stages 2–3 remain open. No proofs, zkVM executions, installs or
profile changes; CPU proving remains paused at **two used / one unused attempts**.


## S2-REVOKE-AUDIT-1 — audit resource correction, no SPEC change

19 September 2026. [Audit report](stage2_revocation_audit.md) and
[exact scope](data/s2_revoke_audit_1/scope.json). The historical manager audit
completed content checks but failed its 256 MiB cgroup guard. This separate package
keeps that failure intact and corrects buffered file-cache retention and duplicate
manifest allocation under unchanged limits. The bounded diagnostic supports the
cache mechanism, not a retrospective measurement of the original peak. All 8,759
original paths retain SHA-256 checks; the historical final manifest adds a disjoint
30-file partition. The manager report is append-only with its original prefix
checked. The three original permitted documentation paths are unchanged as a set;
new audit/test/evidence paths are individually enumerated. Exact additions/removals
are also checked in five named source/configuration/documentation roots, with no
directory exclusion. The complete guarded audit now passes; see the final result below. R-030/R-031 behaviour
and prior 73 + 25 functional passes are reused, not reinterpreted. This package
introduces no cryptographic/protocol change or manuscript decision. Stages 2–3 and
all proof/security/integration obligations remain open; proving stays paused at
**two used / one unused**, with zero new proofs or zkVM executions.

**Final audit outcome:** [S2-REVOKE-AUDIT-1 result](data/s2_revoke_audit_1/final_checks/result.json)
passes with exit 0, **21,823,488 bytes (20.8125 MiB)** cgroup peak and **1.053191021 s**;
max/OOM/OOM-kill/swap events are zero. All 8,759 original plus 30 supplementary
historical entries, the original manager-report prefix and the 418-entry name
inventory pass; complete reporting and guard acceptance are recorded. **44 audit
fixture tests** and final lint/format pass; the initial B007 lint failure and its
STOP are retained alongside the documented correction and fresh final-check records.
The historical 256 MiB ceiling failure is not overwritten or reclassified. This
closes only the follow-up audit resource issue. No protocol/specification change,
proof or zkVM execution occurred. Stages 2–3, integration and privacy/security
obligations remain open; CPU proving stays paused at **two used / one unused**.


## S2-ISSUE-ENROL-1 — reference issuance, no new SPEC decision

19 September 2026. [Issuance/enrolment report](stage2_issuance_enrolment.md).
IV-B, V-C, VI-A/B and VII-A.5 within authoritative Sections II–VIII supply the exact
contract. No unresolved specification ambiguity was needed to implement this scope.
SPEC-001–004, the active suite and existing signature/statement/credential encodings
remain unchanged. Issuer authorisation checks and holder-secret possession remain
separate; no present-time DID-control requirement is introduced for authentication.

R-018/R-019/R-020/R-021/R-022 now have a bounded reference implementation: the manager
extends its same permanent allocation prefix without changing the root; the issuer
stores the approved public challenge, checks controller signature and proof verdict,
freshly rechecks current DID and manager state, bounded-verifies the generated
credential, and logs before effective release. Failed/aborted sessions retain every
completed allocation and recorded certificate, and never reuse their nonce/ID.
The holder verifies its local opening/intent, existing credential/state/path and
atomically stores credential and witness/state. Root consistency is not freshness.

Engineering choices: one trusted local issuer/store per instance, finite retained
64-entry sessions/nonces/certifications, at most two active preparations, authenticated
session IDs up to 256 bytes, default eight nonce draws (lowerable/configurable within
the existing 1–100 allowance), evidence capped at 64 KiB and opaque proof input at the
existing 10 MiB reference allowance. Exact duplicate sessions/challenges reject;
separate approved sessions for the same holder can issue more than one credential.
These are local admission/storage choices, not signed parameters or cryptographic
assumptions. Default signing/proof adapters fail closed. A trusted method resolver
must establish current active record/key authenticity, and the authorisation adapter
must validate evidence and channel controller authority; neither is replaced by a
local witness check or an unchecked holder-selected vector.

**64 focused and 30 selected regression cases pass**. An initial wrong-issuer fixture
used malformed iref bytes and failed during fixture construction; its failure/STOP
are preserved, the fixture now uses another canonical issuer reference, and a fresh
corrected run passes. Final lint/format pass after a recorded audit-key line-length correction; the
complete preservation audit also passes, with its measured result below.
Bounded production keygen/signing, signing-tail and DEP-001/002 validation, actual
proof verification, DID method services, persistent/distributed recovery, complete
authentication circuits/BC-1, selective-disclosure/non-revocation proof integration,
CredValid/authentication proofs and privacy/security review remain open. Recommend a
separate bounded S2-DID-STATE-1 publication/resolution reference package next. No proof
or zkVM execution; proving stays paused at **two used / one unused**. Stages 2–3 are
not complete.

**Final S2-ISSUE-ENROL-1 validation:** [package result](data/s2_issue_enrol_1/release_checks/result.json)
passes; **64 focused + 30 selected regression cases**, no final failures/skips;
final lint/format pass. One complete preservation audit exited 0 at **23,212,032 bytes
(22.13671875 MiB)** cgroup peak and **2.140307967 s** under the unchanged 256 MiB
ceiling, with zero memory-max/OOM/OOM-kill/swap events. All **8,827 historical paths**
are accounted for (8,825 content comparisons plus two distinct manifest identities),
with only the exact authorised manager extension and three documentation changes.
The 463-entry name inventory and every original manager method's AST comparison pass.
The initial fixture-construction and lint failures/STOPs remain preserved. No baseline
was regenerated, no complete audit retried and no resource limit raised. No new
proofs or zkVM executions; CPU proving remains paused at **two used / one unused**.
The next bounded recommendation is S2-DID-STATE-1; it has not started. Stages 2–3,
production backends/recovery/integration, BC-1 and privacy/security review stay open.

## S2-DID-STATE-1 — DID reference, no new SPEC decision

19 September 2026. [Report](stage2_did_state.md). Checked IV-A/B and VII-A.1–5/.7
within authoritative II–VIII against R-012–R-015/R-052. Rotation, terminal
deactivation and historical resolution are explicitly defined; none needs invented
semantics. The entire expected issuer/key/schema/namespace/suite and registry trust
configuration are independently pinned. DID version/current controller authority,
credential revocation, logical revocation epoch and strict expiry remain distinct.
Old certified DID/version is not migrated on rotation. The optional verifier DID
check uses disclosed historical fields; ordinary hidden-DID authentication performs
no holder DID lookup or present-controller possession check.

R-013/R-015 now have bounded local reference implementations with exact canonical
records, bounded ML-DSA authorisation, nonce-bound ordered complete-chain reads and
atomic append. R-012 supplies derivation/validation from supplied controller key/salt,
not independent secret sampling or bounded keygen. R-014 implements in-process
pending-record/key retention, explicit identical resend, conflict retirement and
confirmation after later deactivation; durable recovery remains open. Missing signers
fail closed, and an append acknowledgement cannot replace authenticated confirmation.
Only new source/test files are added; the existing issuer/verifier/manager and audit
implementation remain unchanged.

Engineering admissions reuse 32 retained records total, two in-flight operations,
64 retained resolver nonces and default eight bounded draws (1–100). Raw method
records are capped at 8192 bytes and read messages at 263,296 bytes; field sizes,
method index space and cryptographic caps are unchanged. Public tuples/frozen
records and local CAS prevent accidental mutation/lost updates. There is no cache,
nonce eviction, automatic retry, remote service or distributed-consistency claim.
The W3C mapping stays on the dated DID Core 1.0 Recommendation of 19 July 2022;
no standard ML-DSA verification-method type or full-conformance claim is invented.

**74 focused + 14 scoped regressions pass**, including real reference issuance and
two independent verifiers, pending operation changes, complete 32-record history,
concurrency, adapter/resource failures and instrumented privacy boundaries. These are
reference lifecycle tests using explicitly labelled ordinary native test signing and
public controlled proof verdicts. Historical audit failures and original baselines
remain intact. [Final audit record](data/s2_did_state_1/result.json) requires the complete
comparison, report and unchanged 256 MiB guard to finish successfully.

Open obligations: bounded production key generation/signing and signing-tail/DEP-001/002
validation; deployment trust, confidential authenticated issuance, persistence/restart
recovery and shared-state services; method/JSON interoperability; full authentication
circuits/BC-1 and selective-disclosure/non-revocation proof integration; actual
CredValid/authentication proofs and privacy/security review. No new protocol ambiguity
blocks this reference package. Recommend bounded S2-LIFECYCLE-REVIEW-1 next to review
cross-service failure/expiry/replay composition and identify durable state/recovery
requirements before a persistence design. No further package starts here. Stages 2–3
remain open; no proofs or zkVM executions; CPU proving paused at two used/one unused.

**Final S2-DID-STATE-1 validation:** [result](data/s2_did_state_1/result.json) passes.
All **74 focused + 14 regression** cases and final lint/format pass. The one complete
preservation audit exits 0 in **2.050973451 s** at **22,933,504 bytes (21.87109375 MiB)**
cgroup peak, zero memory-max/OOM/swap event, with comparison/report/guard completion.
All **8,872 historical paths** and **494 inventory names** are accounted for; precisely
three existing documentation files changed, no existing source change. Original
baselines and historical failures remain preserved; no retry or resource escalation.
The reference DID implementation obligation is closed at the scope above; production
signing, durable/distributed state, interoperability and Stages 2–3 proof/security
obligations remain open. S2-LIFECYCLE-REVIEW-1 is a recommendation only.

## S2-LIFECYCLE-REVIEW-1 — recovery gaps, no new SPEC decision

19 September 2026. [Full review](stage2_lifecycle_review.md),
[invariant/evidence matrix](stage2_lifecycle_review.md#lifecycle-invariant-and-evidence-matrix),
[structured findings](data/s2_lifecycle_review_1/review-findings.json).
Sections II–VIII and agreed SPEC-001–004 remain unchanged. The review found no
functional violation of the existing supported live-state lifecycle contract requiring
a source fix. **28 new focused + 50 existing regression cases pass**, including
explicit faults after reservation, signing/logging, holder acceptance and consumption;
real-service concurrency/expiry/read ordering; outages; and simulated reconstruction.
No pre-existing implementation/test file changes. This is reference correctness
and requirements work, not durability, production authentication or proof evidence.

| Gap | Demonstrated evidence / classification | Required disposition |
|---|---|---|
| REC-001: stale allocation bootstrap | The explicitly unsafe negative control reconstructs count 42 after ID 42 was issued; the signed root is identical at count 43, and the stale instance reserves 42 again. Violates trusted-checkpoint completeness, not the live reserve CAS | Block unverified restore. Persist all reservations/high-water before reply; require independently authoritative freshness/completeness. Root/epoch alone cannot recover count |
| REC-002: consumed-store rollback | The explicitly unsafe negative control reconstructs an old pending challenge without its later tombstone and accepts again. Violates shared atomic audience-state trust, not the live consume lock | Persist consumed/reserved state and fence old writers; reject activation without authoritative complete/fresh recovery evidence. A signed request cannot reveal later consumption |
| REC-003: incomplete restart images | IssuerSnapshot omits pending challenge/controller detail; ControllerSnapshot omits salt/private signer handles; manager constructor resets the retrievable history base to imported state. Damaged CLAIMED issuer phase cannot be safely resumed | Specify complete role-private checkpoints, validate before activation, preserve old public history and define conservative administrative reconciliation. Do not treat inspection snapshots as import/export formats |
| REC-004: commit versus delivery | An outer connection/resource failure can follow successful logging, acceptance or revocation; committed effects remain and normal retries reject | Keep terminal effects; distinguish unknown delivery from pre-commit rejection. Do not add automatic replay success or compensation that deletes allocations/logs/tombstones |

The two negative controls are **expected demonstrations of unsupported unsafe
reconstruction**, not passes for identifier uniqueness or at-most-once after arbitrary
restart. Safe complete in-memory reconstruction and missing/inconsistent-state failures
are tested separately. No process termination, power cut, database or storage engine
was tested. Recovering a complete old checkpoint cannot be detected using only a
local digest, valid signature or clock: the independent rollback/freshness authority,
evidence binding and writer-fencing design remain a concrete open deployment trust
question. No new trust choice or cryptographic checkpoint field is adopted here.

The report specifies durable transaction/checkpoint boundaries for permanent manager
allocation, issuer certification+nonce+response, DID history/pending keys, manager
revocation+history, verifier challenge/consumption and matching holder credentials/
witnesses. Recovery must stop on unavailable authority, uncertain commit or missing
private material. DID/controller changes after an ordered issuance read do not invent
a later global transaction; after-final-read revocation preserves the specified logical
verification epoch, while expiry is still strictly rechecked at atomic consumption.
DID deactivation, credential revocation, expiry and freshness remain separate.

**Integration decision:** proceed only with the bounded **S2-RECOVERY-ADMISSION-1**
reference package proposed in the report: typed complete checkpoints and pure bounded
fail-closed validation/activation with a default-unavailable injected recovery-authority
contract, no engine or new protocol encodings. The actual independent authority/fencing
policy needs concrete review before any production restart claim. The next package has
not started. Durable services, interoperability, bounded signing/DEP-001/002 and complete
private authentication/BC-1/proof/security obligations remain distinct and open.
[Final audit](data/s2_lifecycle_review_1/result.json) retains original baselines/history
under the unchanged 256 MiB ceiling. CPU proving stays paused; no proofs/zkVM
executions; two attempts used, one unused. Stages 2–3 remain incomplete.

**Final S2-LIFECYCLE-REVIEW-1 validation:** [result](data/s2_lifecycle_review_1/result.json)
passes. One complete preservation audit exits 0 in **2.049593098 s**, cgroup peak
**22,134,784 bytes (21.109375 MiB)**, zero memory-max/OOM/swap event. All **8,903
historical paths** and **525 inventory entries** are accounted for; content/report/
outer guard complete, original baselines/failures retained. Final lint/format and all
78 selected cases pass; the two unsafe-reconstruction controls do not close REC-001/002.
No source changes or cryptographic/protocol fixes were required within the supported
live-state contract. Recovery-admission/rollback trust, durable services, bounded
signing, interoperability and private-proof/security obligations remain open. Stages
2–3 remain incomplete; proving paused, two attempts used and one unused.

## S2-RECOVERY-ADMISSION-1 — guarded reference recovery; deployment blocker open

19 September 2026. [Report](stage2_recovery_admission.md) and
[structured findings](data/s2_recovery_admission_1/admission-findings.json).
No new SPEC clarification or cryptographic/protocol change. Typed local recovery
records and facade admission are engineering additions authorised by this package.
**59 new focused/scoped cases and 28 unchanged lifecycle cases pass.**

REC-001 and REC-002 now have fail-closed recovered allocation/verifier paths:
consistent but stale state cannot activate when an independent complete-role binding
disagrees. Default-unavailable evidence refuses activation. Allocation reservations
and consumption are explicitly covered, not inferred from revocation epoch/root or
a local checkpoint signature/hash. The existing unsafe constructors/controls remain
unchanged and are not approved for untrusted recovery. REC-003 gains seven role
schemas, bounded immutable validation, full history and association checks, gates
and explicit activation ordering. PREPARING/CLAIMED issuer outcome reconciliation
remains unsupported and rejects; REC-004 retains terminal effects and duplicate
rejection after lost delivery. No discard-pending/nonce-reset policy is implemented.

**Deployment recovery blocker remains open.** The reference authority protocol
requires an independently trusted latest-state comparison and exclusive writer grant.
Its deterministic test implementation is not a production rollback authority. Durable
transition coupling, authority rollback/availability assumptions, prior-writer fencing,
lease loss, replica coordination, confidential recovery and real crash tests need a
concrete approved design. Proposed next bounded package: S2-RECOVERY-AUTHORITY-DESIGN-1
for that design/review only. Do not infer production currentness from fixture tests.
Bounded signing/DEP-001/002, interoperability, full private authentication/BC-1,
selective-disclosure/non-revocation proof integration, proofs and security/privacy
review remain separately open. Stages 2–3 remain incomplete; no proofs or zkVM
executions; CPU proving paused, ledger two used/one unused. Prior failure evidence
and original baselines are retained for the unchanged 256 MiB preservation audit.

**Final S2-RECOVERY-ADMISSION-1 validation:** [result](data/s2_recovery_admission_1/result.json)
passes. One complete audit exits 0 in **2.072833665 s**, cgroup peak **21,762,048 bytes
(20.75390625 MiB)**, zero memory-limit/OOM/swap events. All **8,934 historical paths**
and the **566-entry inventory** are accounted for, with completed comparison/report/
outer guard. Only the exact three authorised existing documentation files changed;
new recovery implementation/tests and package evidence are explicitly inventoried.
Final lint/format and **87 executed cases** pass (59 new scoped + 28 unchanged
lifecycle cases, preserving both labelled unsafe controls). Independent durable
freshness/fencing and interrupted issuer reconciliation remain open. Stages 2–3
stay incomplete; no proof/zkVM executions; ledger two used/one unused.

## S2-RECOVERY-AUTHORITY-DESIGN-1 — local durability choice and explicit rollback limit

19 September 2026. [Design](stage2_recovery_authority_design.md) and
[structured plan](data/s2_recovery_authority_design_1/design.json). No new SPEC decision,
protocol byte change or implementation. Recovery deployment remains blocked.

- **REC-005, authority rollback domain (open):** select a role-owned SQLite authority
  co-committing complete checkpoint/head/outcomes for the local pilot. It is independent
  of service checkpoint copies, not of its own database rollback. A consistent old
  authority DB can restore stale allocation/consumption/generations undetectably.
  Process termination and stale service-cache tests cannot close this gap. An external
  non-rollbackable authority and its availability/privacy policy remain unselected.
- **REC-006, durable fencing integration (open):** positive signed-63-bit generations,
  authenticated replacement, exact expected heads/operation bindings and bounded
  per-commit/per-publication checks are specified. Current admission-only gates do not
  enforce these. Direct mutation, SQL/file and signer/publication bypasses must be closed
  by concrete adapters and OS ownership before any guarantee. No timed auto-takeover.
- **REC-007, interrupted issuance and delivery (design selected; implementation open):**
  issuer intent precedes an idempotent manager reservation; both retain the immutable
  operation mapping. Orphans remain spent. Interrupted signing with no committed
  certification is retired without a signing retry. Committed results can be retrieved
  as exact bytes only by a separately authenticated original recipient; ordinary finish
  remains REPLAY. Production recipient continuity across lost sessions/key rotation is
  unresolved; retrieval fails closed until that policy exists. Cross-store disagreement
  or unavailable authority quarantines, never recreates a reservation.
- **STORAGE-001, local SQLite candidate (design selected; validation open):** actual
  linked version 3.46.1 / Ubuntu 3.46.1-9ubuntu0.3. Upstream WAL-reset fix begins at
  3.51.3 with documented 3.44.6/3.50.7 backports; no installed backport was established.
  Choose DELETE/EXTRA, no WAL or upgrade. Correct SQLite flush assumptions do not prove
  WSL/VHD/host power-loss durability; process-crash tests are separately labelled.

The recommended S2-DURABLE-AUTHORITY-PILOT-1 has an explicit 256 MiB process-tree
ceiling and inherited time/output/concurrency limits, including the 1 MiB per-file
limit. It therefore proposes 512 KiB SQLite files and 64 KiB checkpoints as lower
pilot admissions, not larger resource limits. Sixteen future acceptance groups cover
fresh-process recovery, competing/superseded writers, operation conflicts, interrupted
issuance, unknown outcomes, clock/privacy and original unsafe controls. None ran here.
Other role adapters, production authority/admin/OS isolation, durable retention and
whole-store rollback remain open. Bounded signing/keygen/DEP-001/002 and the complete
private authentication/BC-1/proof/security/privacy obligations remain separate.
Source, dependencies, manuscript and historic evidence are preserved. No proofs or
zkVM executions; CPU proving paused; two attempts used/one unused; Stages 2–3 open.

**Final S2-RECOVERY-AUTHORITY-DESIGN-1 validation:** documentation/data checks and
final lint/format pass. [One complete preservation audit](data/s2_recovery_authority_design_1/final_checks/result.json)
exits 0 in **2.057240563 s**, cgroup peak **21,516,288 bytes (20.51953125 MiB)**,
zero memory-limit/OOM/swap events, with completed content/inventory/report/outer guard.
All **8,975 historical paths** and **607 inventory entries** are accounted for; exact
original baselines and old failures remain preserved. The initial formatting-only
E501 failure is retained alongside corrected final checks. All seven guarded invocations
share the unchanged budget and total 2.655893709 s. No production source/test/dependency
change, functional rerun, persistence/crash experiment, proof or zkVM execution.
The design is complete; durable implementation, deployment recovery and Stages 2–3
remain open. Recommended next: S2-DURABLE-AUTHORITY-PILOT-1; two proof attempts used,
one unused, CPU proving paused.


## S2-DURABLE-AUTHORITY-PILOT-1 — bounded local process-crash evidence

19 September 2026. [Report](stage2_durable_authority_pilot.md),
[implementation](../src/pqdid/persistence/lifecycle.py) and
[guarded evidence](data/s2_durable_authority_pilot_1/run-ledger.json).
**38 distinct focused cases and 28 unchanged lifecycle regressions pass**; three
non-resource development failures and their corrections remain recorded (69 total
case instances). Eighteen fixture-owned application-barrier SIGKILLs exercise fresh
process recovery; these do not establish power-loss durability or whole-store rollback
detection. Default policy denies; only the tests install synthetic operator identities.

REC-001/002 gain durable manager allocation and one-time verifier consumption for
separate audience stores, including stale same-root checkpoint refusal. REC-003/004,
REC-006 and REC-007 gain local checkpoint/head/outcome commits, per-transition and
publication generation/head fencing, conservative interrupted-issuer reconciliation,
permanent orphan reservations and exact original-recipient credential redelivery.
STORAGE-001 now has installed SQLite 3.46.1 DELETE/EXTRA readback, bounded SQL/storage
failures and application process-crash evidence. The APIs are narrow durable pilot
facades, not a complete restartable issuer/manager/verifier deployment.

Production admin/recipient/OS isolation and IPC, full durable begin/finish and other
role operations, bounded production signing/proofs, retention/backup, host flush
qualification and REC-005 whole-authority rollback remain blockers. Matching a head
inside the same rolled-back store is not rollback detection. The original unsafe
controls and historical failures remain unchanged. Full authentication/BC-1,
selective-disclosure/non-revocation integration, DEP-001/002 and security/privacy
review remain open. No proofs or zkVM executions; CPU proving paused, two attempts
used and one unused. Stages 2–3 remain incomplete. Recommend the bounded
S2-AUTHORITY-OWNER-BOUNDARY-1 design/test package before deployment.


**Final S2-DURABLE-AUTHORITY-PILOT-1 validation:**
[One complete preservation audit](data/s2_durable_authority_pilot_1/result.json) passes,
exit 0 in **2.111892061 s**, cgroup peak **24,236,032 bytes
(23.11328125 MiB)** under the unchanged 256 MiB ceiling; zero memory-limit/OOM/swap
events. All **9,016 historical paths** and the **690-entry inventory** are accounted
for with completed content/report/readback/outer guard. Only the exact three allowed
existing documents changed. Final lint/format and **38 focused + 28 unchanged
lifecycle cases** pass; development failures remain preserved. Fifteen guarded commands
share the unchanged budget and total **38.300096529 s**. Temporary stores are removed.
The pilot is complete; deployment recovery, Stages 2–3 and the named security/proof
obligations remain open. No proofs or zkVM executions; CPU proving paused, ledger
two attempts used and one unused. Next bounded recommendation:
S2-AUTHORITY-OWNER-BOUNDARY-1; no further work is launched in this package.


## S2-AUTHORITY-OWNER-BOUNDARY-1 — pilot permissions implemented; isolation open

19 September 2026. [Report](stage2_authority_owner_boundary.md) and
[validation ledger](data/s2_authority_owner_boundary_1/run-ledger.json).
Scoped random pilot capabilities plus kernel peer credentials now authenticate named
local owner operations. An explicit permission matrix separates administrator,
service writer, observer and issuance recipient. Fixed service/store identity,
existing expected-head/generation fencing, one-time consumption and immutable
recipient-bound logged delivery are retained through bounded IPC. **28 IPC cases
and 28 unchanged lifecycle regressions pass**; historical durable-pilot and corrected
auditor evidence remain preserved. No manuscript ambiguity is reopened.

These obligations are distinct and remain open:

- **Application authorisation:** trusted fixture provisioning supplies capability
  grants and approved session-to-recipient mappings. Production approval evidence,
  capability distribution/rotation/revocation and recovery-admin/recipient enrolment
  require an explicit policy. The mechanism is not PQ-DAA protocol authentication.
- **OS isolation:** owners/clients all run as UID/GID 1000. Mode 0700/0600 socket
  directories and peer checks do not stop that identity reading capabilities,
  directly accessing SQLite, replacing process code or bypassing signer/publication
  paths. Separate role accounts and exclusive paths are not deployed here.
- **Full lifecycle and signing:** internal direct-store/reference interfaces remain
  for trusted/test use; the complete durable issuer begin/finish and remaining role
  adapters are not integrated. Bounded production signing/DEP-001/002 remain open.
- **Durability/rollback:** existing local process-crash evidence is preserved;
  whole-authority rollback REC-005, power-loss/flush qualification, storage retention
  and backups remain unresolved. IPC authentication does not solve them.
- **Proof/privacy/security:** full authentication/BC-1, disclosure/non-revocation,
  actual CredValid proof and Section VIII/privacy/ZK/quantum-security reviews remain
  open. No persistent holder authentication requirement is added to presentations.

Three non-resource development failures and their corrections remain in the new
package evidence. Resource limits stay unchanged. No proof or zkVM execution;
CPU proving paused; ledger two attempts used/one unused. Stages 2–3 remain incomplete.
Recommend **S2-AUTHORITY-ISOLATION-PLAN-1**, a bounded provisioning/access-path design
review before host-account or deployment changes; not an automatic deployment.


**Final S2-AUTHORITY-OWNER-BOUNDARY-1 validation:**
[Complete preservation audit](data/s2_authority_owner_boundary_1/result.json) passes,
exit 0, **2.134272240 s**, cgroup peak **24,907,776 bytes (23.75390625 MiB)** under
unchanged 256 MiB. All **9,099 historical paths** and **773 inventory entries** are
accounted for; content/report/readback and outer guard complete, with zero
memory-limit/OOM/swap events. Final **28 IPC + 28 unchanged lifecycle cases**, lint
and formatting pass; 78 total case instances include the retained corrected fixture
failures and justified access repeat. Sixteen guarded commands total **55.803938689 s**;
maximum cgroup peak **114.01953125 MiB**, sampled tree RSS **173.59765625 MiB**.
No old source, tests, dependencies, manuscript, ledger or historical result changed.
Same-UID/direct-store access and test-only provisioning remain explicit limitations.
The package is complete; Stages 2–3, production authorisation/OS isolation, full
lifecycle, bounded signing and proof/privacy/security obligations remain open.
No proofs/zkVM executions; CPU proving paused, two attempts used/one unused.
Recommend S2-AUTHORITY-ISOLATION-PLAN-1; stop here without deployment changes.


## S2-AUTHORITY-ISOLATION-PLAN-1 — concrete deployment design, not protection

19 September 2026. [Plan and ownership matrix](stage2_authority_isolation_plan.md),
[uninstalled configuration/runbook](proposals/s2_authority_isolation_plan_1/README.md).
The demonstrated same-UID/direct-store and mutable-provisioning/runtime gaps now have
a bounded local design: 13 dedicated identities, four scoped IPC groups, root-owned
credential/configuration/release paths, fresh pinned runtime assembly and 22 required
actual-identity tests. Kernel-observed UID/primary-GID binding supplements existing
application permissions, expected-head/generation fences and recipient-bound delivery.

Open implementation gates remain explicit: current socket checks demand the caller's
UID and 0700/0600; the selected cross-UID 2750/0660 endpoint policy is **not implemented**.
Trusted preflight/launch/provisioning tools, a bounded system-manager coordinator,
actual numeric mappings, protected runtime import/linkage validation and actual-ID
access tests are absent. Static templates do not close OS isolation or production
application-authorisation issues. Grace's host sudo/adm access is a trusted operator
assumption; remapped tool/guard identities are not host ownership evidence.

Production approval and recipient credential lifecycle, full durable lifecycle
integration, bounded signing/DEP-001/002, whole-store rollback REC-005, host flush/
power-loss qualification, proof feasibility, BC-1/full authentication and privacy/
security review remain separately open. No account/service installation, activation,
existing permission change or dependency/source/manuscript change. No proofs/zkVM
executions; CPU proving paused; two attempts used/one unused; Stages 2–3 incomplete.
Recommend S2-AUTHORITY-ISOLATION-PILOT-1 only after the specified implementation gates
and explicit approval of the concrete privileged actions. No deployment starts here.


**Final S2-AUTHORITY-ISOLATION-PLAN-1 validation:**
[Static policy/unit checks](data/s2_authority_isolation_plan_1/static-accepted-validation.json),
final lint and formatting pass. The final installed-systemd syntax parser reports
no warnings. [One complete preservation audit](data/s2_authority_isolation_plan_1/result.json)
passes, exit 0 in **2.066424324 s**, cgroup peak **21,860,352 bytes (20.84765625 MiB)**
under unchanged 256 MiB. All **9,183 historical paths** and **851 inventory entries**
are accounted for; content/report/readback and outer guard complete. No memory-limit,
OOM or swap event. Thirteen guarded commands total **3.629145615 s**; temporary
stores are absent. Original code, tests, dependencies, manuscript and history remain
unchanged; only the exact three existing documentation files changed.
No functional/actual-ID tests or activation were performed. The plan is complete,
with deployment protections still **unimplemented**. Recommend only the gated
S2-AUTHORITY-ISOLATION-PILOT-1; full lifecycle, bounded signing, proof feasibility
and privacy/security obligations remain open. Stages 2–3 incomplete; CPU proving
paused, ledger two attempts used/one unused; no proofs or zkVM executions.


## S2-AUTHORITY-ISOLATION-PILOT-1 — implementation staged; approval boundary

[Implementation report](stage2_authority_isolation_pilot.md) and
[exact activation runbook](proposals/s2_authority_isolation_pilot_1/README.md): explicit
cross-UID endpoint policy, protected fresh-runtime provisioning, fail-closed launch,
fixed-identity clients, rollback and 22 prospective cases are implemented. Final
focused prerequisites: 28 passed; existing owner regressions: 28 passed; earlier
20 focused passes retained. Static parser passes with no warnings; original lint
and static failures/corrections retained, with no resource event or limit increase.
No privileged activation was authorised or performed. Actual IDs and all 22
real-identity outcomes are pending, not inferred from mocked/static evidence.
The unchanged 256 MiB envelope applies; final preservation results follow in the
report. Only exact IPC source changes and this package's new files/docs are allowed.

Request the user's §5 approval for the concrete runbook before creating accounts,
protected paths or system units. After actual isolation passes, recommend bounded
full lifecycle integration. Production bounded signing, DEP-001/002, complete
private-proof feasibility, integration and privacy/security review stay open.
Stages 2–3 remain incomplete; no proofs or zkVM executions; CPU proving paused,
ledger two attempts used/one unused.


**Final S2-AUTHORITY-ISOLATION-PILOT-1 validation:**
[Preservation](data/s2_authority_isolation_pilot_1/result.json) passes: one complete
run, exit 0, 2.163518033 s, cgroup peak **22,597,632 bytes (21.55078125 MiB)** under
unchanged 256 MiB. All 9,261 historical paths and 974 inventory entries accounted
for; content/report/outer guard complete, no memory/OOM/swap event. Exactly two
IPC source files and three existing status/traceability/issues documents may differ;
original manuscript, dependencies, vectors, historical results and ledger preserved.
Final lint/format pass; 28 focused prerequisites and 28 owner regressions pass,
with 20 earlier focused invocations retained. Twenty-one guarded commands total
35.443476731 s; five reviewed non-resource failures remain recorded.
Implementation is staged, **activation awaits explicit user section 5 approval**,
and all 22 actual-identity cases remain pending. Stages 2–3 remain open; CPU proving
paused, two attempts used/one unused, zero new proofs/zkVM executions. Next: approve
only the exact activation runbook; recommend bounded full lifecycle integration
only after actual isolation passes. Bounded signing and full private-proof
feasibility remain unresolved core obligations.


## S2-AUTHORITY-ISOLATION-PILOT-1 — activation preflight blockers

**Open implementation/deployment issues; not manuscript conflicts.** The user
approved the exact activation subject to preflight and required stopping on changed
privileged commands/effects. Approval is recorded, but the current sealed version
cannot activate. [Review and evidence](stage2_authority_isolation_pilot.md#conditional-activation-approval--preflight-stopped-19-september-2026):

- The guard reads a 155,989-byte historical ledger with the 65,536-byte default
  reader, after creating root-owned evidence. Use bounded complete ledger handling
  and admission before mutation; retain IPC limits, historical failures and all
  elapsed-time accounting. Do not truncate history or reseal to hide a mismatch.
- `/etc/sysusers.d` is absent; the installer requires it. Specify exact authorised
  parent creation and retention effects before changing the privileged implementation.
- Slice SIGKILL is supported by installed-systemd implementation evidence, but
  provisioning is outside that slice. Complete emergency coverage, checked stop/
  query results and descendant quiescence are required. Empty failed MainPID queries
  cannot establish shutdown; failed cases skip the success-path cleanup.
- Rollback's fixed configuration deletion/data-retention boundaries are sound on
  source inspection, but its shutdown dependency is unresolved. The installed
  controller cannot provide early partial-provision rollback before it exists.
  The approval marker is owner/mode checked, not digest-sealed in the creation ledger.

No privileged command ran and none of the 22 actual-ID cases ran. Source/fixture
seals match; the runbook and privileged source remain unchanged. Diagnostic
completion under 256 MiB is not isolation success. Preserve earlier validation
results and the newly recorded metadata-probe failures. Next is concrete correction
review within the unchanged budgets, not another approval request for this version.
Only after actual isolation succeeds should bounded full lifecycle integration be
recommended. Stages 2–3 stay open; production bounded signing, full private-proof
feasibility and privacy/security review remain unresolved. CPU proving paused;
two attempts used/one unused, no new proofs or zkVM executions.

## S2-AUTHORITY-ISOLATION-PILOT-1 — corrected version awaiting delta approval

The three preflight blockers have versioned implementations and **24 passed focused
invocations**: bounded purpose-specific ledger admission, explicitly recorded
absent-only shared-parent creation, and independent termination with strict query/
descendant checks and rollback refusal. See the
[correction report](stage2_authority_isolation_pilot.md#targeted-correction-pass--version-2-no-activation)
and [concrete changed actions](proposals/s2_authority_isolation_pilot_1/v2/README.md).
Original sealed code, runbook and failed diagnostics are preserved. Final quality,
preservation and seal identity are recorded in the report's closure.

Host effects remain **unactivated**: approval is needed only for the versioned
commands, absent shared-parent creation, inhibitor/lock resources, start inhibition
and corrected stop/maintenance behaviour. Original pilot-scope approval remains
valid. The 24 additional focused invocation allowance is spent; historical counts
are not reset. No actual-ID case or retry was added. OS isolation still needs the
original 22 cases under their outer guards. Unknown shutdown, a stale socket or
missing creation evidence still blocks configuration rollback by design.

These are implementation/deployment corrections, not manuscript conflicts.
Stages 2–3, bounded production signing, complete private-proof feasibility, full
lifecycle integration and privacy/security review remain open. CPU proving paused,
two attempts used/one unused, no proofs or zkVM executions.

**Version-2 final disposition:** implementation, 24 focused invocations, static
parsing, final quality and corrected complete preservation audit pass. Audit peak
33,054,720 bytes under 256 MiB; all 9,403 historical paths/1,084 inventory entries
accounted for, with original failure evidence retained. Corrected seal
`994327b3b0d32d22b6ce9aa09a5125ec798d509ebbdcfa79819bf2225f1a6c32`.
The three implementation blockers are corrected in this unactivated version.
Remaining approval is limited to the documented changed commands/effects; original
scope approval is not reopened. Actual-ID validation, full lifecycle integration,
bounded signing and complete private-proof feasibility remain open. Stages 2–3
are incomplete; proof ledger two used/one unused, no new proofs or zkVM executions.


## S2-AUTHORITY-ISOLATION-PILOT-1 — delta approved; operator authentication required

The version-2 host-effect approval is now explicit and bound to the matching
`994327b3b0d32d22b6ce9aa09a5125ec798d509ebbdcfa79819bf2225f1a6c32` seal.
[Live preflight](stage2_authority_isolation_pilot.md#version-2-approval-and-live-preflight--authentication-pending)
found no new sealed-input or real-host prerequisite discrepancy. The current tool
session cannot authenticate sudo interactively. The operator has been asked to run
the existing approved provision command once; no new approval or scope change is
requested. Preserve its result before any subsequent action. All 22 cases remain
pending, cumulative invocations 100; no shutdown or isolation success is claimed.
The historical failures remain intact. The five-second supplemental operator charge
leaves 250.22 s including the ten-second emergency reserve before activation.
The user now requires **S2-CONCRETE-SECURITY-ASSESSMENT-1** after the pilot attempt,
before lifecycle integration; await that task. Bounded production signing, complete
private-proof feasibility and Stages 2–3 remain open. No proofs or zkVM executions;
CPU proving paused, ledger two used/one unused. Only manuscript Sections II–VIII
remain authoritative; this is an operational access issue, not a manuscript change.


## S2-CONCRETE-SECURITY-ASSESSMENT-1 — initial findings, 24 September 2026

The [task schedule](../PQ_DID_Security_Assessment_Codex_Task.md) and
[initial report](stage2_concrete_security_assessment.md) distinguish assessment
completion from a justified security claim. Source inventory
`b2d0b57afe4b10c1ee6f41fc32ac031da96e332f79a98c6040aaebe1fd07c3a3`;
only manuscript II–VIII plus SPEC-001–004. Active configuration and production
source unchanged. Separate analysis budget; no estimator, proof, zkVM or deployment
execution. Proving remains paused, two attempts used and one unused.

| Issue | Status and missing evidence | Trigger/closure criterion |
| --- | --- | --- |
| SEC-001 — overall target and reduction budgets | Open. No agreed precise overall classical/quantum gate, depth, memory/QRAM, target, signing and lifetime workload contract; component advantages at T_red unresolved. No universal floor adopted. | Explicit property-specific target decision and quantified component/reduction resources; refresh at comparisons and final claims |
| SEC-002 — concrete outer SHAKE256 instantiation | Open. Ideal 1024-bit QROM inequalities reproduce, but SHAKE256 capacity is 512 bits; output length is no quantitative instantiation theorem. Neither ideal-theorem failure nor an attack is inferred. | Bounded primary-source/game review before proof-profile adoption; supported loss or explicit continuing assumption; no automatic hash/parameter change |
| SEC-003 — sampling and complete proof composition | Open, linked DEP-001/002. Four model tails reproduced, actual adaptive Delta_tail not zeroed. Complete BC-1 equivalence and oracle-relative target/history-preserving extraction/simulation remain unverified. | Bounded keygen/signing/release plus independent cap/workload analysis; complete relation and exact extractor/privacy game mapping before claims |
| SEC-004 — alternative-backend quantum knowledge/privacy | Open, linked PROP-001/002. Pinned Succinct/Poseidon2 enrolment receipt is experimental evidence; full STARK/Fiat–Shamir/recursion knowledge/privacy and concrete quantum assumptions unresolved. No pairing wrapper occurs in the selected path. | Separate assessed profile decision before adoption/freeze; do not transfer BC-1 bounds or vendor security labels |
| SEC-005 — complete lifecycle privacy/currentness boundary | Open. Reference predicates and state tests do not establish actual private authentication, production entropy/side-channel safety, deployment isolation or rollback protection. | Stages 4–5 joint-witness/public-output/freshness/adversarial integration review; preserve pending real-ID cases and existing recovery obligations |

| Trigger | Required security checkpoint |
| --- | --- |
| Current Stages 2–3 | Initial actual-profile/source/calculation assessment; completed with explicit unresolved terms, not an overall security claim |
| Stage 2 bounded key generation/signing/release | Randomness, caps, exhaustion, pre-release verification, lifetime invocation totals and `Delta_tail`; retain DEP-001/DEP-002 |
| Stage 3 before adopting/freezing any proof profile | Exact circuit/program, mode and recursion/compression; soundness/knowledge/ZK and quantum assumptions; refresh affected bounds |
| Stages 4–5 complete PQ-DAA/KYC integration | Same certified witness/holder/disclosures/rid, journal leakage, currentness/replay/revocation, side channels and deployment |
| Stages 6–8 baselines/comparisons/benchmarks | Exact comparator profiles, multi-key/target effects and lifetime nonce/cap counts; refresh parameter/dependency/proof-mode changes |
| Stage 9 reproduction/manuscript claims | Final revision/workload/current primary evidence against II–VIII; omit unsupported overall numbers |

Initial assessment completion is compatible with these open findings. It closes
no SPEC decision, dependency obligation, Stage 2/3, production-readiness or actual
isolation claim. Next bounded recommendation is S3-OUTER-HASH-SECURITY-REVIEW-1;
no further execution or activation is authorised by this entry.


Security-assessment validation closure (24 September 2026): eight independent
checks, lint and formatting passed. The single [complete preservation audit](data/s2_concrete_security_assessment_1/result.json)
passed comparison, report readback and the unchanged 256 MiB outer guard: 9,487
content paths, 9,500 identity-inclusive paths, no unexpected changes/removals;
2.310877172 seconds, 23,543,808-byte charged cgroup peak. Separate assessment
accounting is 8.593910845 / 300 seconds; this consumes no isolation/proof allowance.
Only the exact new analysis/evidence and append-only report updates were permitted.
Initial assessment complete with unresolved terms; no overall security number,
Stage 2/3 completion, deployment validation or production signing claim. No
estimator/proof/zkVM execution; two proof attempts used and one unused.


## S3-OUTER-HASH-SECURITY-REVIEW-1 — 24 September 2026

The [outer-hash review](stage3_outer_hash_security_review.md) is complete with an
explicit conditional-profile decision. ACMT arXiv:2504.16887v2 Theorem 7.22 supports
quantum domain extension in the random-permutation model. Fixed Keccak, the joint
internal/outer-hash game, DFMS compressed-oracle extraction and GHM adaptive
simulation still require distinct arguments. No additive concrete knowledge/privacy
loss or overall bit-security number is established; a weak bound is not an attack.

The existing ideal-QROM rows and model tails are preserved. New analysis records
canonical framing/block lengths and query/simulator mappings, with full-authentication
quantities symbolic. The theorem's unspecified constants are not set to one.
No profile change: retain current SHAKE256 only as a qualified research reference;
compare a joint-game contract revision and one unadopted balanced-sponge option.

Next bounded recommendation: **S3-OUTER-ORACLE-COMPOSITION-1**, a written typed
shared-permutation/game/extractor/simulator mapping for VIII-C/D before any proof
profile adoption. Deliver a compatible lemma or identify the exact incompatible
interface; no execution, deployment or profile change is inferred. SEC-001–005,
adaptive Delta_tail, component advantages at reduction budgets, bounded production
signing, complete private-proof knowledge/privacy and Stages 2–3 remain open.

Safe-stopped unactivated isolation, 100 historical invocations, 22 pending cases,
approval and 250.22 s including the ten-second reserve remain unchanged. No new
proof, zkVM, estimator, circuit generation, dependency installation or activation;
CPU proving paused, proof ledger two attempts used and one unused. Separate
security-analysis accounting carries forward 8.593910845 s of its 300 s allowance.
Final guarded validation/preservation measurements are appended after completion.

| Refined open obligation | Evidence and closure criterion |
| --- | --- |
| SEC-002 / Gap_KeccakModel | ACMT random-permutation theorem is not a reduction for fixed public Keccak; retain explicit model qualification before concrete claims |
| SEC-002 / Gap_jointGame | Map shared internal algorithms, canonical/adversarial message lengths, direct/inverse queries, advice, simulator query/time budgets and continuous adaptive state; prove the ideal endpoint matches the manuscript |
| SEC-002 / Gap_knowledgeExtractor | Construct a legal composed DFMS extractor preserving the original relation, target event, history and residual state; ordinary acceptance indistinguishability is insufficient |
| SEC-002 / Gap_privacySimulation | Establish compatible programmed/unprogrammed ideal endpoints or a valid endpoint triangle including stateful S and all continuation; no automatic epsilon addition |

These refine SEC-002, without closing SEC-003/004 or reopening SPEC-001–004.
The next source-only lemma package is the immediate Stage 3 checkpoint. After a
profile proposal changes oracle interfaces, lengths, parameters or backend, refresh
the affected argument and resource mapping before adoption; retain all previous
Stage 2 signing, Stage 4–5 integration and Stage 6–9 comparison/final-claim checks.


Outer-hash review validation closure: the [complete audit](data/s3_outer_hash_security_review_1/result.json)
passed comparison, report readback and the unchanged 256 MiB cgroup guard, exit 0:
9,543 content paths / 9,556 identity-inclusive paths; 2.349347859 s,
22,405,120-byte charged cgroup peak, no unexpected changes.
Four distinct mapping checks pass after one preserved non-resource harness failure
(five group invocations including the aborted first group); lint/format pass.
Continued security-analysis charge 16.956706719/300 s, remaining 283.043293281 s;
no isolation/proof allowance consumed. Historical baselines and report prefixes
remain intact. [Review and decision](stage3_outer_hash_security_review.md): retain
qualified current profile; next S3-OUTER-ORACLE-COMPOSITION-1. No quantitative concrete
knowledge/privacy guarantee, overall security number or Stage 2/3 completion.
No proof/zkVM/activation; ledger two used and one unused, proving paused.


Finalisation addendum: the first post-guard bookkeeping command exited 1 when the
write-once report helper correctly refused a second write to the newly created
closure record. The full audit and its report/readback/outer guard had already
completed successfully and were not repeated. The initial closure and unsealed
manifest placeholder are retained verbatim inside the final records, together with
the error and narrowly scoped finalisation. No resource breach or historical
record replacement occurred; the audit engine is unchanged.

An additional conservative five-second finalisation charge supersedes the preceding
accounting totals: **21.956706719 / 300 s charged,
278.043293281 s remaining**. This reduces the existing
security-analysis allowance; no ceiling is increased or isolation/proof time used.
The final evidence records one guarded validation-harness failure/correction and
one post-guard bookkeeping failure/finalisation. All four mapping checks, final
lint/format and the single complete preservation audit passed. The recommendation
and open obligations remain unchanged.


## S3-OUTER-ORACLE-COMPOSITION-1 — finite decision, 25 September 2026

The [composition review](stage3_outer_oracle_composition.md) completes the bounded
assessment with precisely stated missing lemmas. ACMT 7.22 supports a defined
ordinary bounded oracle-wrapper comparison. DFMS terminal extraction/event
restriction and GHM/raw-view privacy simulation remain supported in the stated
fixed-relation ideal-QROM model. Neither supplies the shared-permutation BC-1
relation, a legal shared-oracle extractor, or the complete joint privacy simulator.
No automatic indifferentiability-error addition or concrete Keccak security number
is made. The separated-primitive diagnostic model is explicitly not an adoption.

OC-REL, OC-EXT, OC-PRIV and OC-BUDGET refine SEC-002; A-K-MODEL remains an explicit
fixed-Keccak modelling assumption. These are finite findings, not a claim of attack
or impossibility. SHAKE256 remains the qualified research reference. Future proof
profile adoption/claims must resolve the applicable obligations, including complete
circuit equivalence and the separate RISC Zero knowledge/privacy questions.

**Next implementation recommendation: S2-BOUNDED-MLDSA-KEYGEN-SIGN-1.** Implement the
bounded fixed-parameter reference core, setup/import consistency and fail-closed
signer adapter, with sampler/attempt exhaustion and pre-release validation. Retain
DEP-001/002, conditional signing tails, adaptive Delta_tail, enlarged component
reduction budgets, randomness and production release/side-channel obligations.
This recommendation does not begin another package or activate signing/services.
No additional composition review is scheduled automatically.

Source, active parameters, dependencies, manuscript and all prior evidence remain
protected. Only II–VIII and SPEC-001–004 are authoritative. Stages 2–3 stay open;
no installations, circuits, estimator runs, proofs, zkVM executions or activation.
Isolation remains safely stopped unactivated: 100 invocations, 22 pending cases,
approvals/failures and 250.22 s including its ten-second reserve unchanged. CPU
proving paused, proof ledger two used/one unused. Analysis allowance carries forward
21.956706719007343 s charged / 278.04329328099266 s remaining, without borrowing
isolation/proof time. Final measured validation closure is appended below.

| Open item | Exact remaining obligation / closure trigger |
| --- | --- |
| SEC-002 / OC-REL | Define stable efficient shared-oracle relation and private-gate proof semantics; prove S-sound* reconstruction and two-view simulation, or justify a fixed-relation translation before stronger profile claims |
| SEC-002 / OC-EXT | For every permitted adaptive adversary/terminal predicate, construct legal sequential extraction preserving the same witness/history/Z; identify oracle-state control, costs and any truncation |
| SEC-002 / OC-PRIV | Public-only joint simulation with one continuing sponge-simulator state, programming/removal, all internal users and actual post-cutoff publications; prove b-independent ideal endpoint |
| SEC-002 / OC-BUDGET; SEC-001 | Finite full-output/prefix adapter, all q/ell/time/memory/advice and component reduction costs; numerical constants before numerical instantiation claims |
| SEC-002 / A-K-MODEL | Ideal permutation is not fixed public Keccak; concrete claim requires an explicit model assumption or property-specific concrete analysis |
| DEP-001/002; SEC-003 | Bounded keygen/signing implementation next; caps and pre-release failure semantics do not prove conditional tails or Delta_tail=0 |

The previous broad outer-oracle review recommendation is fulfilled by this finite
report. These obligations reopen when a concrete proof profile/claim is proposed;
they do not postpone independent fixed-algorithm bounded-reference implementation.
No SPEC clarification is reopened, no prior failure erased and no Stage 2/3,
production-signing, actual-isolation or full-proof obligation is closed.


Composition-review validation closure: one documentation-contract check and
lint/format pass. The single [complete preservation audit](data/s3_outer_oracle_composition_1/result.json)
passed comparison, inventory, report readback and the unchanged 256 MiB cgroup guard,
exit 0: 9,596 content paths,
2.155260734 s, 22,163,456-byte charged peak.
No new failure, resource breach or retry; historical failures and seals preserved.
Continued analysis accounting **29.818518832/300 s**, **270.181481168 s remain**;
no isolation/proof allowance consumed. Numerical/functional validation was reused.
Finite review complete with the specified missing lemmas; no concrete knowledge/
privacy transfer or overall bit-security claim. Next implementation recommendation
S2-BOUNDED-MLDSA-KEYGEN-SIGN-1, not started. Stages 2–3 and existing obligations
remain open; isolation unactivated, proof ledger two used/one unused.

## S2-BOUNDED-MLDSA-KEYGEN-SIGN-1 — DEP-002 reference-core disposition

[The implementation report](stage2_bounded_mldsa_keygen_sign.md) advances only the
reference-core subtask. The four caps exactly match R-033 and the unchanged suite:
1026 RejNTTPoly bytes, 512 RejBoundedPoly bytes, 256 SampleInBall total bytes and
1024 signing candidates. They are project limits, not exact FIPS-prescribed limits.
No specification/parameter discrepancy or protocol amendment was introduced.

- **DEP-002 reference keygen/sign/import: implemented and focused tests pass.**
  Exact FIPS encodings, pure message/context processing, nine-role fresh-randomness
  wrappers, strict candidate rejection and hint generation, bounded pre-return
  verification, explicit failure and no fallback. Expanded-key consistency does
  not prove entropy, authority or K provenance. Existing production adapters remain
  fail closed and unconnected to this module.
- **DEP-002 production/release obligations remain open.** All-role durable release,
  atomic state/nonce/log transitions, approved key import/storage, entropy assurance,
  constant-time execution, fault resistance and reliable erasure are not established
  by Python reference tests. Clearing owned mutable arrays does not erase every copy.
- **DEP-001 and SEC-003 remain open.** No tail/security probability is estimated from
  58 new passing tests. The corrected FIPS signing mean does not prove the adaptive
  conditional tail or Delta_tail=0. Count pre-release verification, explicit imports
  and internally signed but unreleased messages in reduction/lifetime workloads.
- **SEC-001–005 and the composition obligations remain open.** No change to the
  qualified SHAKE256 research profile, BC-1 proof model or experimental RISC Zero
  evidence; no complete private-proof knowledge/privacy claim follows.

Validation: 49 focused + nine final interoperability + 12 selected regressions pass;
nine preliminary interoperability invocations were retained after correcting an
unneeded optional C integration-context argument in the ctypes test harness.
Total 79/100 implementation test invocations, no functional test/resource failure.
The exact corrected ABI passed identical deterministic output comparisons. This was
an implementation-test harness finding, not a protocol or dependency defect.

One recommended next package, **S2-BOUNDED-SIGNER-RELEASE-CONTRACT-1**, should specify
and test isolated synthetic reference adapter failure/release accounting without
activating services or changing fail-closed production defaults. No next work has
started. Analysis allowance 270.181481168 s and isolation allowance 250.22 s remain
separate and unchanged; isolation safely stopped/unactivated with 22 cases pending.
Stages 2–3 remain open; no installations, circuits, proofs or zkVM runs. Proof
ledger two used/one unused, CPU proving paused. Final preservation closure follows.


Bounded-keygen/signing validation closure: lint/format and all selected tests pass,
79/100 implementation invocations including nine source-reviewed ABI repeats.
The single [complete preservation audit](data/s2_bounded_mldsa_keygen_sign_1/result.json)
passed content/inventory, report readback and the unchanged 256 MiB cgroup guard:
9,638 disjoint content paths,
2.330812694 s, 23,130,112-byte audit peak.
Maximum new-job peak 48,275,456 bytes; zero functional failures/resource breaches.
Separate implementation budget 11.616396493/300 s charged,
288.383603507 s remaining. Analysis 270.181481168 s and isolation 250.22 s
unchanged. New reference core only; original code, vectors, parameters and historical
evidence preserved. Production signing, DEP-001/002, Delta_tail and full proof
knowledge/privacy remain open; Stages 2–3 incomplete. Next recommendation
S2-BOUNDED-SIGNER-RELEASE-CONTRACT-1, not started. No activation/proofs/zkVM;
proof ledger two used/one unused, CPU proving paused.

## S2-BOUNDED-SIGNER-RELEASE-CONTRACT-1 — reference release disposition

[The report](stage2_bounded_signer_release_contract.md) closes the bounded
synthetic adapter subtask recommended above. It introduces no signing format,
parameter, dependency, manuscript or agreed-clarification change. All original
source, failed isolation evidence and historical security conclusions are retained.

- **DEP-002 reference role/key/release contract: implemented and tested.** Trusted
  fixed selection, all nine typed canonical operations, authorisation before and
  after signing, completed bounded-core verification-before-return, issuance
  reservation/log ordering, atomic in-memory revocation, DID deactivation/rotation,
  and durable issuer fencing/recipient-bound stored redelivery without resigning.
  Eighteen focused invocations pass, with no historical/native harness repeats.
- **DEP-002 production and remaining durable release: open.** The authority callback
  is a trusted owner dependency, default deny; Python private members are not a
  same-process isolation boundary. Actual-UID isolation is pending, not supplied
  by synthetic grants. Durable manager publication, all-role recovery composition,
  crash/power-loss validation, production key custody/entropy, reliable erasure,
  side channels and fault resistance are not resolved by temporary fixture tests.
- **DEP-001/SEC-003: open.** Exhaustion paths and allocation retention are tested;
  adaptive Delta_tail and reduction-budget component terms are not estimated.
  Unreleased signatures, bounded imports and pre-return verification still count
  towards workload/security budgets. No tail=0 or overall bit-security claim.
- **SEC-001–005 and OC-REL/EXT/PRIV/BUDGET: open.** The proof profile and separate
  experimental evidence are unchanged; full proof knowledge/privacy is unresolved.

Next implementation recommendation: **S2-BOUNDED-MANAGER-DURABLE-RELEASE-1**, atomic
bounded manager state/update publication, recovery and fencing on synthetic stores.
It is not started. Cumulative implementation tests are 97/100, three remaining;
future scope must fit that balance or have an explicit amendment. Analysis
270.1814811680233 s and isolation 250.22 s remain untouched. Isolation safely stopped/
unactivated, 22 cases pending; Stages 2–3 remain open. No activation, installations,
proofs or zkVM; proof ledger two used/one unused, CPU proving paused.


Bounded-signer release validation closure: lint/format and all 18 new tests pass,
97/100 cumulative implementation invocations, three remaining; no new repeats.
The single [complete preservation audit](data/s2_bounded_signer_release_contract_1/result.json)
passed content/inventory, report readback and the unchanged 256 MiB cgroup guard:
9,701 disjoint content paths,
2.286035420 s, 23,945,216-byte audit peak.
Maximum new-job peak 49,573,888 bytes; zero functional failures/resource breaches.
Continued implementation budget 30.539082389/300 s charged,
269.460917611 s remaining. Analysis 270.181481168 s and isolation 250.22 s
unchanged. New opt-in reference adapters only; original code, vectors, parameters and historical
evidence preserved. Production signing, DEP-001/002, Delta_tail and full proof
knowledge/privacy remain open; Stages 2–3 incomplete. Next recommendation
S2-BOUNDED-MANAGER-DURABLE-RELEASE-1, not started. No activation/proofs/zkVM;
proof ledger two used/one unused, CPU proving paused.

## S2-BOUNDED-MANAGER-DURABLE-RELEASE-1 — specific durable-publication disposition

[The manager report](stage2_bounded_manager_durable_release.md) fulfils the next
reference implementation subtask, with no architectural/specification amendment:
the existing single authority database already spans the required transaction.

- **R-030 / DEP-002 manager reference publication: demonstrated within the stated
  model.** Exact bounded state/update signing, complete checkpoint/history/nonce
  and outcome/head commit before release, concurrency/fencing checks at commit and
  public enqueue, exact no-signature redelivery and superseded-current rejection.
  Existing recipient-bound credential delivery remains unchanged.
- **Recovery evidence is conditional on independent admission.** Two actual process
  crashes complement simulated faults. Before COMMIT, old state and no outcome
  recover; after COMMIT, the complete result recovers against the head retained by
  the trusted test coordinator. The facade never refreshes admission merely from
  self-consistency. Missing independent freshness evidence, coordinated rollback,
  power/storage failure and complete crash coverage remain open.
- **Production/all-role release obligations remain open.** No service is activated;
  no real-ID isolation or cross-store transaction is claimed. Key custody, entropy
  assurance, reliable erasure, side-channel/fault resistance, bounded deployment and
  issuer/manager/verifier/holder integration still need separate evidence.
- **DEP-001, SEC-001–005 and OC-REL/EXT/PRIV/BUDGET remain open.** No adaptive
  Delta_tail estimate, reduction-budget component claim, concrete proof knowledge/
  privacy result or proof-profile change follows from these tests.

24 manager-specific invocations pass, including every parameter value and two actual
SIGKILL cases; no failures or repeats. User expressly amended the ceiling from 100
to 124; cumulative usage is 121, three remain. Original cumulative implementation
time continues; analysis 270.1814811680233 s and isolation 250.22 s unchanged.
Historical failures and seals are retained. Stages 2–3 stay open; isolation safely
stopped/unactivated with 22 pending cases; proof ledger two used/one unused.

One next implementation recommendation: **S2-DURABLE-ISSUER-MANAGER-INTEGRATION-1**,
temporary synthetic integration through the existing intent/reservation/reconciliation
contracts, without assuming atomicity across stores. Respect the three remaining
invocations or obtain an explicit amendment before expanding the matrix. Not started.


Bounded-manager durable-release validation closure: lint/format and all 24 new tests pass,
121/124 cumulative implementation invocations, three remaining; no new repeats.
The single [complete preservation audit](data/s2_bounded_manager_durable_release_1/result.json)
passed content/inventory, report readback and the unchanged 256 MiB cgroup guard:
9,754 disjoint content paths,
2.347716602 s, 23,076,864-byte audit peak.
Maximum new-job peak 59,478,016 bytes; zero functional failures/resource breaches.
Continued implementation budget 48.714120727/300 s charged,
251.285879273 s remaining. Analysis 270.181481168 s and isolation 250.22 s
unchanged. New opt-in durable manager only; original code, vectors, parameters and historical
evidence preserved. Production signing, DEP-001/002, Delta_tail and full proof
knowledge/privacy remain open; Stages 2–3 incomplete. Next recommendation
S2-DURABLE-ISSUER-MANAGER-INTEGRATION-1, not started. No activation/proofs/zkVM;
proof ledger two used/one unused, CPU proving paused.

## S2-DURABLE-ISSUER-MANAGER-INTEGRATION-1 — limited integration disposition

[The integration report](stage2_durable_issuer_manager_integration.md) closes the
specified reference issuer/manager subtask. No storage schema, distributed protocol,
signing format, active parameter, manuscript or dependency amendment is introduced.

- **R-018–021 / DEP-002 reference integration advances.** Permanent reservation,
  exact journal/enrolment/recipient binding, bounded certification before release,
  current-writer publication, conservative reconciliation and exact stored redelivery
  without signing/allocation are exercised together. Holder acceptance remains an
  atomic in-memory credential/witness update after its existing checks.
- **Real proof verification remains open and normally unsupported.** Positive tests
  explicitly inject only a test-side exact synthetic statement/token verifier;
  normal configuration fails closed. These results are not anonymous authentication,
  complete PQ-DAA or end-to-end cryptographic security.
- **Issuance-time ordering is preserved, not strengthened into cross-store atomicity.**
  A manager update before the final read aborts; one after it can coexist with a
  subsequently logged credential for the original state. Holder acceptance then
  proves neither current non-revocation nor current authentication eligibility.
- **Recovery qualifications remain.** Two actual application-barrier SIGKILLs use
  independently retained exact heads for both services. Incomplete work retires;
  committed certification redelivers. Lost independent evidence, power loss,
  coordinated rollback, malicious owner and general crash coverage remain unresolved.
- **Production and security obligations remain open.** Custody, entropy assurance,
  reliable erasure, side channels/fault resistance, real-ID isolation, durable holder
  and verifier integration, DEP-001 adaptive Delta_tail, reduction-budget component
  terms, SEC-001–005 and OC-REL/EXT/PRIV/BUDGET/full proof knowledge/privacy.

24 individually reported tests pass, including all parameter values and two real
crash cases; no failure/repeat. Explicit user amendment 124 → 148 preserves the prior
121 charges, yielding 145 used and three remaining. Original implementation time
continues; analysis 270.1814811680233 s and isolation 250.22 s remain separate.
All historical failures/seals remain. Stages 2–3 stay open; isolation safely stopped/
unactivated with 22 cases pending; proof ledger two used/one unused, CPU proving paused.

Next bounded package recommendation: **S2-DURABLE-VERIFIER-LIFECYCLE-INTEGRATION-1**,
synthetic bounded request/current and durable verification-consumption integration,
with normal proof failure preserved. Not started. Its matrix must fit the remaining
allowance or receive an explicit amendment before exceeding it.


Issuer-manager lifecycle validation closure: lint/format and all 24 new tests pass,
145/148 cumulative implementation invocations, three remaining; no new repeats.
The single [complete preservation audit](data/s2_durable_issuer_manager_integration_1/result.json)
passed content/inventory, report readback and the unchanged 256 MiB cgroup guard:
9,809 disjoint content paths,
2.369247573 s, 23,175,168-byte audit peak.
Maximum new-job peak 89,354,240 bytes; zero functional failures/resource breaches.
Continued implementation budget 85.601982479/300 s charged,
214.398017521 s remaining. Analysis 270.181481168 s and isolation 250.22 s
unchanged. New synthetic-proof lifecycle integration only; original code, vectors,
parameters and historical evidence preserved. Production signing, DEP-001/002,
Delta_tail and full proof knowledge/privacy remain open; Stages 2–3 incomplete.
Next recommendation
S2-DURABLE-VERIFIER-LIFECYCLE-INTEGRATION-1, not started. No activation/proofs/zkVM;
proof ledger two used/one unused, CPU proving paused.

## S2-DURABLE-VERIFIER-LIFECYCLE-INTEGRATION-1 disposition

No manuscript or profile correction is introduced. The
[implementation report](stage2_durable_verifier_lifecycle_integration.md) demonstrates
reference two-verifier lifecycle integration with synthetic proof acceptance only.
R-017 final-read semantics allow a later manager update before local consumption;
this is not globally atomic currentness or demonstrated private non-revocation.

Three test assertions initially expected the wrong existing rejection labels
(PUBLIC/MISMATCH, CONSUMED/FAILURE, service-binding/checkpoint-admission). Failures,
source versions, stop evidence and three targeted repeats are retained; no
implementation check was relaxed. All 24 distinct cases finally pass. The amended
implementation test budget is exhausted at **172/172**. Final resource/audit closure
is recorded below; analysis/isolation budgets are not borrowed.

The existing store forbids verifier acceptance redelivery; a lost post-commit reply
leaves a tombstone and UNKNOWN on replay. Downstream KYC business-action recovery
requires an explicit application contract, not another successful verification.
Production signing/custody/entropy, erasure, side channels, adaptive Delta_tail,
independent recovery freshness, durable holder state, actual-ID isolation and full
proof knowledge/privacy remain open. Stages 2–3 incomplete, proof ledger two used/
one unused, no activation or zkVM execution. Next recommendation is bounded holder
witness/revocation integration for the KYC lifecycle, with a new test allowance.


Verifier lifecycle closure: 24 distinct cases finally pass, three assertion failures
and targeted repeats retained; **172/172** cumulative invocations, zero remaining.
Lint/format and the single
[preservation audit](data/s2_durable_verifier_lifecycle_integration_1/result.json) pass:
9,865 disjoint content paths, complete reporting,
2.406519050 s, 23,465,984-byte cgroup peak
under unchanged 256 MiB. Maximum job peak 70,217,728 bytes; no resource breaches.
Implementation **116.659475644/300 s** consumed, **183.340524356 s** remain, including
failed tests and bookkeeping. Analysis/isolation unchanged. Synthetic proof acceptance
only; production signing/security and proof knowledge/privacy remain unresolved.
Stages 2–3 open; isolation safely stopped/unactivated; proof ledger two used/one unused.
Next recommendation S2-HOLDER-WITNESS-REVOCATION-INTEGRATION-1, not started; an explicit
new test allowance is required.

## S2-HOLDER-WITNESS-REVOCATION-INTEGRATION-1 disposition

[Holder lifecycle integration](stage2_holder_witness_revocation_integration.md)
requires no manuscript, canonical format or parameter change. Initial witness/state
come from the existing committed issuance result and HolderAcceptance, not a new
holder-specific retrieval service. Existing UpdatePage next_epoch/complete and
bounded consecutive-call semantics already provide explicit continuation.

REVOKED and errors supply no replacement: the last paired witness/state remains
stored, possibly valid only at its old root. Local new-root rejection is category B,
not a synthetic verifier rejection. The two-verifier category-C test step provides
no credential-authenticity, private-NR or knowledge/privacy proof. Holder atomicity
is in memory; no durable-wallet or global revocation/acceptance transaction claim.

22 cases passed without corrections/repeats, **194/199** invocations, five remain.
Original failures, dependencies, parameters and manuscript preserved. Production
custody/entropy/erasure/side channels, independent recovery freshness, Delta_tail,
component advantages, real proofs, services and KYC interoperability remain open.
Stages 2–3 incomplete; isolation safely stopped/unactivated; proof ledger two used/
one unused. Next recommendation S2-KYC-INTEROPERABILITY-CONTRACT-1, not started.


Holder integration closure: all 22 cases pass first run, **194/199** cumulative
invocations, five remain. Lint/format and the single
[preservation audit](data/s2_holder_witness_revocation_integration_1/result.json) pass:
9,958 disjoint content paths, completed reporting,
2.375583138 s and 24,059,904-byte audit
cgroup peak under unchanged 256 MiB. Maximum job peak 112,439,296 bytes; no functional failures,
repeats or resource breaches. Two lint diagnostics are retained.
Implementation **178.704218466/300 s** consumed,
**121.295781534 s** remain; separate analysis/isolation unchanged. Evidence A actual
bounded crypto, B complete local auth and C synthetic verifier acceptance remain
separate. No durable wallet or complete private-proof security claim. Stages 2–3
open; safely stopped isolation and proof ledger two used/one unused preserved.
Next: S2-KYC-INTEROPERABILITY-CONTRACT-1, not started.

## S2-KYC-INTEROPERABILITY-CONTRACT-1 interoperability decisions

The [contract](stage2_kyc_interoperability_contract.md) extends E-003 as an explicit
**proposal**, not a new active signed/proved format. No manuscript correction is
implied solely by lack of an application adapter or W3C securing specification.

| Issue | Open obligation / adoption criterion |
| --- | --- |
| KYC-INT-001 — issuer and claim vocabulary binding | Specify independently trusted refI issuer/key/schema ↔ globally unambiguous issuer URL mapping and immutable claim semantics. Arbitrary binary issuer IDs are not URLs. Determine which fixed vocabulary/type/status/validity assertions the securing algorithm may return without adding unsigned claims; if certified bytes must change, seek a separate specification decision |
| KYC-INT-002 — securing mechanism and proof container | Define a complete credential/derived-presentation securing specification, including verified output/graph coverage, exact canonical binding, proof format/admission size and fail-closed errors. No cryptosuite identifier, DataIntegrityProof, RISC Zero receipt substitution or conforming secured VC/VP is established here |
| KYC-INT-003 — DID method and key representation | Minimal exact DID JSON and authenticated method evidence exist locally; interoperable method specification, resolution metadata/error adapter, controller key/verification relationships and conformance validation remain unimplemented. Do not add a persistent holder-authentication key to anonymous presentations |
| KYC-INT-004 — private status and time mapping | Specify shared namespace/epoch/root status representation and its verification, without credential-specific index/URL exposing rid. Session texp is not credential validity. Any credential-validUntil dateTimeStamp projection must bind to the certified/disclosed schema claim and reject unrepresentable values |

Proposed transport conventions use strict bounded UTF-8 JSON, unpadded base64url,
minimal decimal integers, duplicate/unknown rejection, canonical equality and no
metadata passthrough. A production parser is not implemented or validated; the next
adapter must preserve fail-closed proof/method/signature boundaries and existing
commit/retrieval semantics. A valid parser round trip proves no W3C conformance.

Durable holder storage and downstream application action/reply recovery remain open.
The existing verifier acceptance tombstone cannot be transformed into repeatable
acceptance or a new successful redelivery endpoint. KYC integration remains reference
only. DEP-001/002 production obligations, custody/entropy/erasure/side channels,
adaptive Delta_tail, component reduction budgets, outer-oracle composition and full
proof knowledge/privacy remain unresolved. Stages2–3 open; isolation stopped/unactivated;
proof ledger two used/one unused. No live host action or parameter change.


KYC contract closure: four example checks pass, **198/199** cumulative invocations,
one remaining; lint/format pass. One preflight-helper typo failure and its corrected
follow-up remain charged and preserved. No functional repeat or resource breach.
The single [audit](data/s2_kyc_interoperability_contract_1/result.json) passes complete
content/inventory/reporting and unchanged256MiB guard:
10,030 disjoint content paths,
2.316034001s, 23,195,648-byte peak.
Implementation 187.316291120/300s consumed, **112.683708880s remain**;
analysis/isolation unchanged. Proposed container mapping, no W3C conformance or
secured-VC/VP claim. Production sources preserved. Stages2–3 open; isolation stopped/
unactivated, proof ledger2used/1unused. Next:S2-KYC-CONTAINER-ADAPTER-1, not started;
a new focused test allowance is needed for implementation validation.

## S2-KYC-CONTAINER-ADAPTER-1 disposition

The [implementation](stage2_kyc_container_adapter.md) selects a versioned **project-local
research transport**, as authorised, without changing canonical cryptographic bytes.
Strict byte/depth/collection preflight precedes JSON parsing. Duplicate/key limits
still operate after bounded key/value allocation; already allocated caller input and
retention of results are not covered by a parser-local memory guarantee. Protocol
integers deliberately use exact decimal strings; generic numeric/string coercion is
forbidden. All returned normal values are unverified input candidates.

KYC-INT-001–004 remain **open**. No registered vocabulary/issuer URL, cryptosuite,
proof transport, DID method/key representation or private-status semantics are chosen.
Ordinary proof submissions, DID resolution and client acceptance-outcome admission
fail closed. Fixture inspection has a distinct non-operational result type. Changing
synthetic metadata cannot manufacture a proof or acceptance flag.

The new24-case matrix passes, with222/223 cumulative invocations and one remaining.
Per-kind edge coverage, non-empty history conversion, malformed-Unicode campaigns,
actual channel read limits and application integration remain explicit follow-up
coverage obligations. No new parameter/specification correction is inferred.
Durable holder storage, downstream KYC-action recovery, production custody/entropy/
erasure/side channels, adaptive Delta_tail, component reduction budgets and complete
proof knowledge/privacy remain open. Stages2–3 open, safely stopped isolation and
proof ledger two used/one unused preserved. Next:S3-AUTH-PROOF-FEASIBILITY-PLAN-1 is
planning only and not started; no proof execution or backend adoption is authorised.


Container adapter closure: **24/24** distinct cases pass first run; lint/format pass,
**222/223** cumulative invocations, one remaining. No failure/repeat/resource breach.
The single [audit](data/s2_kyc_container_adapter_1/result.json) passes complete content,
inventory/reporting and unchanged 256 MiB guard: 10,100
disjoint content paths, 2.425557629 s,
23,527,424-byte audit peak. Implementation
195.863037117/300 s consumed, **104.136962883 s remain**; analysis/isolation unchanged.
Structural input conversion only; no authentication, proof or W3C conformance claim.
Existing code/parameters/evidence preserved; Stages 2–3 open, isolation stopped/
unactivated, proof ledger two used/one unused. Next recommendation:
S3-AUTH-PROOF-FEASIBILITY-PLAN-1, not started; no execution or proof attempt authorised.


## S3-AUTH-PROOF-FEASIBILITY-PLAN-1 disposition

**AUTH-FEAS-001 — open: complete private proof and admissible construction.**
The [bounded plan](stage3_auth_proof_feasibility_plan.md) completes the evidence
review with a negative adoption decision. No evaluated route establishes both the
full same-witness relation/security contract and proposed KYC envelope. Native
authentication is a holder-local reference predicate; R0 enrolment is not anonymous
authentication; CredValid execution omits private path/disclosure/auth-context and
is not a proof. Preserve capped BC-1 evidence and qualified cost forecasts.

VII-A.6 already assigns PubOK and Ppub to public verification. Preserving this
separation is not permission to externalise certification, opening or same-rid
non-revocation. Neither canonical wrapping nor separate unlinked proofs suffices.

The new research decision is replacement of both BC-1 lowering and raw-view proof
representation under a separately reviewed identity. Do not silently optimise
the frozen compiler, seed tapes, change repetitions or import a new transform's
security theorem. **S3-PRIVATE-HINT-LOWERING-PILOT-1** is the single next proposal:
eight cases, one bounded alternative hint decoder and full count/equivalence
evidence; no proof. Its proposed 223→231 invocation amendment and 30-second
allocation within implementation are inactive until approved. A passing component
cannot close AUTH-FEAS-001; a failed/capped experiment stops without escalation.

SEC-001–005, OC-REL/EXT/PRIV/BUDGET and A-K-MODEL stay open where unresolved, as
do component advantages at reduction workloads and adaptive Delta_tail. Completed
bounded synthetic signing/release packages do not close DEP-001/002 production
security, custody/entropy/erasure/side-channel obligations. KYC-INT-001–004, durable
holder storage and application action/reply recovery remain visible, outside scope.
Stages 2–3 open, isolation safely stopped/unactivated and proof ledger two used/one
unused. No newly discovered contradiction requires a manuscript/parameter change.


Authentication feasibility planning closure: helper lint/format and one documentation
consistency check pass. The single
[complete audit](data/s3_auth_proof_feasibility_plan_1/result.json)
passes 10,145 disjoint content paths, exact inventory,
report readback and unchanged 256 MiB outer guard: 2.283966482 s,
24,895,488-byte cgroup peak. Two E501 lint failures
are retained, with a final passing named check; no resource breach or full-audit retry.
Analysis 38.184259331/300 s charged, **261.815740669 s remain**.
Implementation unchanged **104.136962883 s, 222/223 tests**; isolation unchanged
250.22 s, safely stopped/unactivated. No cryptographic executions, new calculations,
builds, proof guests or proofs. No route/profile admitted. Stages 2–3 remain open,
proof ledger two used/one unused. Next proposed for authorisation only:
**S3-PRIVATE-HINT-LOWERING-PILOT-1**; no active lowering or allowance change.


## S3-PRIVATE-HINT-LOWERING-PILOT-1 disposition

**AUTH-FEAS-001 stays open.** The [isolated decoder pilot](stage3_private_hint_lowering_pilot.md)
finds a useful complete component:383,420 gates/203,142 ANDs, one generation probe
and eight differential cases pass. The13,329,306-AND difference from the historical
13,532,448-AND prefix is a conservative component cost gap for continuation of that
exact baseline recipe, not a comparison of two measured complete decoders.

**HINT-LOWER-001 — proposed lowering, integration open.** Narrow byte/bit comparison,
shared decoding prefixes and fixed-position membership violate the frozen BC-1
source-order/private-scan/CSE rules. They require a separately identified compiler/
profile with range and relation-equivalence review. No manuscript correction or
active compiler change is made. Scope's sticky active-path rejection is reused;
standalone active-scope testing does not establish all upstream composed behaviour.
Finite tests do not prove equivalence on every input, and rejected partial outputs
remain unusable. Future integration must preserve the same raw witness and final
validity, signed64 consumers and all malformed-input constraints.

Even the candidate component exceeds the frozen10MiB raw-view target's21,344-AND
threshold if its count embeds unchanged with that encoding. Changing only this
decoder therefore does not establish application feasibility. No R0 forecast,
security bound or complete-proof cost is revised. Propose only
S3-MLDSA-ARITHMETIC-LOWERING-REVIEW-1 to examine the next polynomial-arithmetic
representation bottleneck; do not run it automatically.

User-authorised cumulative ceiling231 is exhausted:222prior+1generation+8cases.
Actual time remains within the30-second package allocation from implementation;
analysis/isolation are untouched. SEC/outer-oracle/adaptive Delta_tail, production
custody/entropy/erasure/side channels, durable holder storage and KYC-INT-001–004
remain open. Stages2–3open, isolation safely stopped/unactivated; proof ledger
two used/one unused. No new proof, guest run, install or activation.


Private-hint pilot closure: **one generation + eight differential cases pass**,
**231/231** cumulative invocations, zero remaining. Candidate complete:
383,420 gates / 203,142 ANDs; original
13,532,448-AND result is a capped prefix, not a complete matched baseline.
A useful component candidate under a proposed new lowering, **not BC-1** or a
full-authentication/proof result. Lint/format and the
[single audit](data/s3_private_hint_lowering_pilot_1/result.json) pass:
10,205 disjoint paths,
2.423156706 s,
23,277,568-byte cgroup peak under256MiB.
Package 9.760450599/30 s charged, implementation
205.623487716/300 s used, **94.376512284 s remain**; analysis/isolation unchanged.
No failures, repeats or resource breaches. Active parameters/compiler preserved.
Stages2–3open, isolation stopped/unactivated, proof ledger2used1unused.
Next proposed only:S3-MLDSA-ARITHMETIC-LOWERING-REVIEW-1; not started.

## ARITH-LOWER-001 — proposed canonical-residue arithmetic refinement

**Open; source review complete, implementation/counting pilot unexecuted.**
[S3-MLDSA-ARITHMETIC-LOWERING-REVIEW-1](stage3_mldsa_arithmetic_lowering_review.md)
selects public-constant multiplication modulo q with a canonical23 invariant,
exact46 product and fixed25-bit restoring-subtraction schedule. A matching
signed64 baseline must include the same canonical guard and output/validity
requirements. Removing generic overflow/division work without that invariant would
change acceptance; the current Scalar domain tag does not establish the invariant.

This is a proposed compiler/profile change, not a newly agreed clarification of
BC-1. No production change or parameter/profile adoption. Montgomery was considered
and deferred because scaling, lazy ranges and conversion boundaries introduce
additional obligations. Preserve the original signed z norm and exceptional
centred decomposition. All signature formats/messages/contexts, sampler caps,
holder binding and same-certified-rid revocation linkage remain unchanged.

Next proposed only: S3-MLDSA-MODMUL-LOWERING-PILOT-1,16 named invocations,
≤30 charged implementation seconds, unchanged resource ceilings; all inactive.
Success needs both complete counts and every value/validity/control case, with
fewer gates and ANDs including conversions. No whole-transform/proof saving is
claimed. HINT-LOWER-001, AUTH-FEAS-001, OC-REL/EXT/PRIV/BUDGET, adaptive Delta_tail,
component advantages at reduction budgets and production-security obligations
stay open. Analysis allowance only; implementation94.376512284s,tests231/231,
isolation safe-stopped/unactivated and proof ledger2used1unused preserved.


Arithmetic lowering review closure: source/documentation checks and the
[single preservation audit](data/s3_mldsa_arithmetic_lowering_review_1/result.json)
pass, 10,250 disjoint content paths,
2.485872072 s, 23,232,512-byte
cgroup peak under the unchanged 256 MiB ceiling. Analysis charge
46.393514843/300 s; **253.606485157 s remain**. Implementation unchanged
**94.376512284 s; 231/231 tests**, no tests/probes/circuits generated. No failures
or retries. Canonical-residue 23-bit multiplication is selected for an inactive
S3-MLDSA-MODMUL-LOWERING-PILOT-1 proposal; no profile adopted. ARITH-LOWER-001,
HINT-LOWER-001, complete authentication/proof and security obligations remain open.
Stages 2–3 open, isolation safely stopped/unactivated; proof ledger two used/one unused.

## ARITH-LOWER-001 — modmul pilot implementation update

The [isolated pilot](stage3_mldsa_modmul_lowering_pilot.md) now implements the
reviewed canonical23/public-constant kernel and a matched fully guarded original
signed64 wrapper. Its two traces each contain independent baseline/candidate gate
segments; no hidden input/factor cross-product is tested. Named generation2,
differential10 and invalid-constant4 invocations exhaust the authorised16 amendment
if all complete. Measured disposition follows below; failures must remain visible.

Canonical input validation is essential; this is not a replacement for generic
signed64 arithmetic. Signed-to-canonical entry conversion and full transform
composition remain unmeasured. Gate reduction would justify only a bounded
composition experiment, with no full-proof/profile-adoption implication.
Production code/compiler/parameters and historical evidence remain unchanged.
Full authentication, profile conformance, knowledge/privacy, adaptive Delta_tail,
component reduction budgets and production-security obligations stay open.

Pilot disposition: sixteen first-run invocations pass, with complete matched
83,032→15,158 gates and34,550→6,161 ANDs at each tested public factor. Scalar evidence
supports separately bounded forward/inverse butterfly composition; ARITH-LOWER-001
remains open until conversion, composition and new-profile conformance obligations
are discharged. No private-by-private/whole-NTT/proof claim follows.


Modmul pilot closure: **merits-bounded-composition**. Two paired generation probes, ten differential
cases and four invalid-constant cases pass: **247/247** cumulative, zero remaining.
Both public-constant kernels have complete matched guarded counts in the
[report](stage3_mldsa_modmul_lowering_pilot.md); no full-transform/proof claim.
Lint/format and the [single audit](data/s3_mldsa_modmul_lowering_pilot_1/result.json)
pass 10,290 disjoint paths, 2.465593635s,
23,232,512-byte cgroup peak under256MiB.
Package8.827576857/30s; implementation214.451064573/300s used,
**85.548935427s remain**. Analysis/isolation unchanged. No failures/retries.
ARITH-LOWER-001 remains open for composition/conformance; Stages2–3open,
proof ledger2used1unused. Next proposed only: S3-MLDSA-BUTTERFLY-COMPOSITION-PILOT-1: separately bounded forward/inverse butterfly composition with exact entry conversions, guards and matched counts.


## S3-MLDSA-BUTTERFLY-COMPOSITION-PILOT-1 (26 September 2026)

Authorised isolated forward-butterfly composition; see the
[contract, individual outcomes and measured closure](stage3_mldsa_butterfly_composition_pilot.md).
The user adds16 invocations,247→263, with≤30 implementation seconds from
85.54893542698119s remaining. Analysis/isolation allowances are unchanged.
Existing generic signed64 input acceptance is retained through exact overflow
predicates and complete signed-to-canonical conversions; the two-node fragment
uses actual forward twiddles4808194 and3765607. The third frontier input is
explicit, not a generated full layer. No trusted-input or inverse-transform claim.
ARITH-LOWER-001 remains open for complete transform composition and proposed
compiler/profile adoption. Production arithmetic, active BC-1, parameters,
manuscript and historical scalar/hint evidence are preserved. Final measured
outcome and remaining balances follow in the closure below.
Stages2–3 remain open. Complete proof knowledge/privacy, adaptive Delta_tail and
production security remain unresolved. CPU proving paused; isolation safely
stopped/unactivated; proof ledger two used/one unused. No further package started.


Butterfly pilot closure: **supports-bounded-transform-experiment**. Two paired generation probes, twelve
differential cases and two invalid-twiddle cases pass: **263/263** cumulative,
zero invocations remaining. Full signed64 matched boundaries and the two-node
actual schedule fragment have complete counts in the
[report](stage3_mldsa_butterfly_composition_pilot.md). single forward butterfly: 66,213 fewer total gates (42.6076%), 27,724 fewer AND gates (45.1164%). two-node schedule fragment: 132,426 fewer total gates (42.6076%), 55,448 fewer AND gates (45.1164%).
Experimental lowering is not canonical BC-1 or a complete transform/proof result.
Lint/format and the [single audit](data/s3_mldsa_butterfly_composition_pilot_1/result.json)
pass 10,336 disjoint paths,
2.427376434s, 23,633,920-byte
cgroup peak under256MiB. Package10.171600435/30s;
implementation224.622665008/300s used; **75.377334992s remain**.
Analysis/isolation unchanged; no failures/retries. ARITH-LOWER-001 remains open
for transform composition/conformance; Stages2–3open, proof ledger2used1unused.
Next proposed only: S3-MLDSA-FORWARD-NTT-STAGE-PILOT-1: a separately authorised, bounded stage/transform counting and differential experiment with actual schedule, all conversion costs, explicit output invariants and unchanged gate/memory caps.


## S3-MLDSA-FORWARD-NTT-STAGE-PILOT-1 (26 September 2026)

Authorised dependency-complete four-lane fragment across forward lengths128/64;
see [contract and measured closure](stage3_mldsa_forward_ntt_stage_pilot.md).
Exact lanes0,64,128,192 and twiddle indices1,1,2,3. External signed64 acceptance
and overflow rejection are preserved. Only internal producer-validated canonical
representations bypass repeated normalisation; this remains experimental non-BC-1.
User amendment:16 invocations,263→279; at most30s from the exact
75.37733499205206s implementation balance, including checks/audit/bookkeeping.
Analysis and isolation allowances are unchanged. Four generation probes and
12 complete schedule cases; reference partitions cover A/B and C/D without overlap.
No full transform or entire128-butterfly stage, inverse experiment or proof is run.
ARITH-LOWER-001 stays open for full schedule/entry coverage and compiler conformance.
Stages2–3 and complete proof knowledge/privacy, adaptive Delta_tail and production
security remain open. CPU paused; isolation safely stopped/unactivated; proof
ledger two used/one unused. Final individual results and balances follow below.


Forward-stage pilot closure: **supports-bounded-full-forward-experiment**. Four generation probes and twelve
complete four-lane schedule cases pass, **279/279** cumulative, zero remaining.
Measured complete reference 621,868/246,058
total/AND gates; representation-reuse candidate
213,448/81,838. Four internal mod64 calls
are omitted only on producer-validated edges; all external/overflow checks remain.
[Report](stage3_mldsa_forward_ntt_stage_pilot.md) records complete partitions,
individual outcomes and limits. Lint/format and the
[single audit](data/s3_mldsa_forward_ntt_stage_pilot_1/result.json) pass
10,382 disjoint paths, 2.535323883s,
25,112,576-byte cgroup peak under256MiB.
Package14.112603900/30s; implementation238.735268908/300s consumed,
**61.264731092s remain**. Analysis/isolation unchanged;
one preserved lint-only failure was corrected;
no test/probe retry or resource breach.
ARITH-LOWER-001 stays open for full schedule coverage/compiler conformance;
Stages2–3open and security obligations unresolved; proof ledger2used1unused.
Next proposed only: S3-MLDSA-FULL-FORWARD-NTT-PLAN-1: a bounded source-only plan for complete schedule coverage, exact entry normalisation, invariant-preserving partition boundaries and separately authorised counting/differential resources.


## ARITH-LOWER-001 — full forward schedule plan, execution not admitted

S3-MLDSA-FULL-FORWARD-NTT-PLAN-1 records the
[implementation-ready plan](stage3_mldsa_full_forward_ntt_plan.md), including
entry normalisation of every signed64 representative, eight-stage range induction,
97 exact partitions and private alias/count coverage. This resolves the planning
question; it does not close actual transform validation or compiler conformance.
The generic raw butterfly's checked-overflow domain must not be imposed before
_ntt's full entry normalisation. No new arithmetic strategy/profile is adopted.

Resource admission is open: 279/279 invocations exhausted; implementation balance
61.264731091912836 s untouched. The sole inactive next request is107 invocations,
+74 implementation seconds and30M aggregate generated gates for
S3-MLDSA-FULL-FORWARD-NTT-PILOT-1. Partitioning must not reset gate/time accounting.
Retain the 2M per-trace and all memory/storage/process limits. Nominal27.04M gates
and101–132 s are source-based estimates with unmeasured twiddle/frontier effects.
No complete reference-circuit generation is required for the proposed candidate
correctness/count question; no complete-reference saving may consequently be claimed.

Full inverse NTT, private products/matrix accumulation, complete verifier and
authentication remain unestablished. HINT-LOWER-001, OC-REL/EXT/PRIV/BUDGET,
adaptive Delta_tail, component advantages at reduction budgets, DEP-001/DEP-002
production release, custody/entropy/erasure/side-channel obligations and complete
proof knowledge/privacy remain open. Stages2–3 open; no proof attempt, zkVM run,
installation or activation; isolation safe-stopped/unactivated, proof ledger2/1.


Full forward-NTT plan closure: source/documentation checks and the
[single preservation audit](data/s3_mldsa_full_forward_ntt_plan_1/result.json)
pass, 10,440 disjoint content paths,
2.442549156 s, 23,318,528-byte
cgroup peak under the unchanged 256 MiB ceiling. Analysis charge
54.576216841/300 s; **245.423783159 s remain**. Implementation unchanged
**61.264731092 s; 279/279 tests**, no tests/probes/circuits generated. No failures
or retries. The complete 97-partition plan requires a separately authorised
S3-MLDSA-FULL-FORWARD-NTT-PILOT-1; current resources do not admit execution.
Proposed only: 107 invocations, +74 implementation seconds and 30M aggregate
gates (2M per-trace ceiling retained); no profile adopted. ARITH-LOWER-001,
HINT-LOWER-001, complete authentication/proof and security obligations remain open.
Stages 2–3 open, isolation safely stopped/unactivated; proof ledger two used/one unused.


Full-forward pilot result: **Component composition/counting validated; NO-GO for integration with the unchanged raw-view proof encoding**. Complete partitions 97/97,
butterflies 1024/1,024; 386/386 invocations.
[Measured report](stage3_mldsa_full_forward_ntt_pilot.md) separates host partitioned
evaluation, logical alias/count accounting and actual circuit/proof construction.
No canonical BC-1 adoption or full-authentication performance claim. No retry.
Next recommendation only: S3-COMPACT-AUTH-PROOF-PROFILE-REVIEW-1: a bounded source-only review of compact transcript candidates, exact relation/security obligations and KYC resource admission, before more circuit integration. Stages2–3/security obligations remain open;
isolation safely stopped/unactivated; proof ledger2used/1unused.


## ARITH-LOWER-001 — complete forward component validated; raw-view integration no-go

S3-MLDSA-FULL-FORWARD-NTT-PILOT-1 completes the isolated full-forward component:
97 partitions,1,024 butterflies,256 initial normalisations and one final boundary;
all107 new invocations pass,386/386 cumulative. The source-backed private-alias
accounting yields27,044,356 total/10,679,298 AND gates. It remains experimental,
not canonical BC-1; a physically monolithic circuit/proof was not constructed.

The [report](stage3_mldsa_full_forward_ntt_pilot.md) records the conditional
raw-view auth projection2,568,395,104 bytes if the measured subgraph embeds
unchanged in the fixed480-round encoding. This exceeds the proposed10MiB target;
it does not bound all alternative lowerings/proof systems or demonstrate an attack.
Do not invest in further full-auth integration with that retained encoding.
The sole next recommendation is S3-COMPACT-AUTH-PROOF-PROFILE-REVIEW-1,
a separately scoped source-only construction/security/resource review, not started.

Full inverse/private-product/verifier/authentication integration and compiler
conformance remain open. No closure of OC-REL/EXT/PRIV/BUDGET, adaptive Delta_tail,
component advantages at reduction budgets, DEP-001/DEP-002 production security,
key custody/entropy/erasure/side channels, or complete proof knowledge/privacy.
Stages2–3 open; no proof/zkVM/installation/activation; isolation safely stopped;
proof ledger2used/1unused. Historical failures, measurements and seals preserved.


Full-forward pilot preservation closure: audit and report guard pass,
10,482 protected content paths,
2.438798105s and24,190,976-byte
cgroup peak under256MiB. Package93.441512754/135s;
implementation332.176781662/374s, **41.823218338s remain**;
invocations**386/386**. Analysis245.423783159s/isolation250.22s
unchanged. Outcome: Component composition/counting validated; NO-GO for integration with the unchanged raw-view proof encoding. No further package started.
See [complete report](stage3_mldsa_full_forward_ntt_pilot.md).
Stages2–3/security obligations remain open; proof ledger2used/1unused.


## COMPACT-PROFILE-001 — compact proof-layer construction decision (open)

26 September 2026, S3-COMPACT-AUTH-PROOF-PROFILE-REVIEW-1.
[Review](stage3_compact_auth_proof_profile_review.md) compares exactly gzkbpp
ZKB++, RISC Zero3.0.6 native Succinct/Poseidon2 and Aurora–BCS native ZK R1CS.
The measured NTT graph plus unchanged raw-view encoding conditionally projects
2,568,395,104 bytes, incompatible with the provisional10MiB target; this is not
a universal lower bound. Pause integration/optimisation under that encoding
unless new feasibility evidence changes the assessment. Historical ARITH/HINT
component success and all failed/capped evidence are preserved.

Recommend a user research-direction decision for **Aurora–BCS proof-layer
replacement without credential redesign**, not profile adoption. Concrete missing
capabilities: bounded binary-field/non-algebraic-hash ZK transcript serialisation
(inspected code has a stub), complete wire-byte accounting including positions/
salts/grinding, full same-witness R1CS mapping and finite parameter/theorem
correspondence. Inspected branch source identity must also be matched to the
identified commit/submodules before a build. CMS supplies a conditional QROM
route; it does not discharge the application's terminal-history extraction,
online continuing-view simulation or concrete BLAKE2b modelling obligations.

Only proposed next package: **S3-AURORA-AUTH-CONSTRUCTION-CONTRACT-1**, source-only
relation/wire/parameter/game contract, at most30 analysis seconds including checks
and audit with10s reserve and unchanged ceilings; zero experiments. Inactive
until user direction. Failure to support that exact contract ends in no-go; no
automatic broad survey, installation, profile adoption or reduced private relation.
VII proof registration/compiler/transcript and VIII proof-specific arguments
would change. Keep signed credential suite/messages/contexts intact; a distinct
proof-profile identity needs explicit admission rules.

SEC-001..005, OC-REL/EXT/PRIV/BUDGET, A-K-MODEL (historical BC-1), adaptive
Delta_tail, component advantages at actual reduction budgets, bounded production
signing/custody/entropy/erasure/side channels, durable holder storage and full
authentication proof knowledge/privacy remain open. Stages 2–3 remain open.
Implementation41.823218338s and386/386 invocations unchanged; isolation safely
stopped/unactivated, proof ledger two used/one unused.


Compact-proof review closure: documentation/static checks and the
[single preservation audit](data/s3_compact_auth_proof_profile_review_1/result.json)
pass, 10,680 disjoint content paths,
2.597733224 s, 23,707,648-byte
cgroup peak under the unchanged 256 MiB ceiling. Analysis charge
63.325249949/300 s; **236.674750051 s remain**. Implementation unchanged
**41.823218338 s; 386/386 tests**, no tests/probes/circuits generated. Two retained
formatting-only lint failures, manually corrected with two lint rechecks;
no experimental retries. **COMPACT-PROFILE-001 open**: recommend an Aurora–BCS
construction research decision, then only S3-AURORA-AUTH-CONSTRUCTION-CONTRACT-1
with the fixed relation/wire/security deliverables in the report. No profile,
installation or experiment approved. Raw-view integration/optimisation remains
paused; ARITH-LOWER-001, HINT-LOWER-001 and security obligations remain open.
Stages 2–3 open, isolation safely stopped/unactivated; proof ledger two used/one unused.


## AURORA-BRIDGE-001 — private transcript/parameter/transformation admission (open)

26 September2026, S3-AURORA-AUTH-CONSTRUCTION-CONTRACT-1.
The [proposed contract](stage3_aurora_auth_construction_contract.md) fulfils the
approved research-direction review, not adoption. COMPACT-PROFILE-001 no longer
awaits a direction decision; its implementation/security adoption obligations remain.

Required before a private Aurora prototype: byte-verified implementation/submodules
and field representation; ordered actual/virtual oracle and direct-message register;
complete query closure and joint masking/terminal-message exposure bound; finite
field/domain/FRI parameters without defaults, heuristic soundness or grinding credit;
correspondence of the proposed tagged, field-element Merkle leaves and challenge
expansion with BCS/CMS premises. The full CMS2020 PDF was unavailable; inspected
proceedings Theorem3 is informal. No precise missing constants are fabricated.
Source-version matching and original bit-leaf versus proposed packed-symbol privacy
must not be hidden behind a make_zk flag. This is a missing argument, not an attack.

The wire is a bounded proposal, not the library serializer or an accepted backend.
SectionVII would need proof registration/compiler/transcript changes; VIII needs
new finite proof-specific knowledge/privacy and composition arguments. Credential
suite/signatures/contexts, SHA3/SHAKE internals, accepted relation and caps are intact.
The original BCS privacy expression with512-bit oracle output does not alone certify
128-bit privacy; no overall numerical security target is currently adopted.

Recommend only **S3-AURORA-TRANSCRIPT-BRIDGE-1**, a finite source/mathematical
prerequisite, proposed20 charged analysis seconds with10s reserve, no executions;
not started. If the exact transcript/privacy bridge cannot be supplied, retain a
no-go for this draft instead of launching a nominally private proof experiment.

SEC-001..005, OC-REL/EXT/PRIV/BUDGET, historical A-K-MODEL, concrete BLAKE2b
modelling, full lowering, adaptive Delta_tail, component advantages at actual budgets,
production custody/entropy/erasure/side channels, durable holder storage and complete
proof knowledge/privacy remain open. Stages2–3 remain open; raw-view integration
and CPU proving paused, isolation safe-stopped/unactivated, proof ledger2used/1unused.


Aurora construction-contract closure: documentation/static checks and the
[single preservation audit](data/s3_aurora_auth_construction_contract_1/result.json)
pass, 10,739 disjoint content paths,
2.510384024 s, 23,289,856-byte
cgroup peak under the unchanged 256 MiB ceiling. Analysis charge
71.710894273/300 s; **228.289105727 s remain**. Implementation unchanged
**41.823218338 s; 386/386 tests**. One diagnosed preflight inventory-path failure
and its charged manual correction are preserved; no experimental retry or resource
breach. **AURORA-BRIDGE-001 open**: resolve the pinned oracle/query/mask manifest
and transformation correspondence before a private prototype. Proposed next package
S3-AURORA-TRANSCRIPT-BRIDGE-1 only; no experiment or profile adopted.
Stages 2–3 remain open; raw-view integration and CPU proving paused, isolation
safely stopped/unactivated, proof ledger two used/one unused.

## AURORA-BRIDGE-001 — transcript review, Decision 2 (still open)

The [completed bridge review](stage3_aurora_transcript_bridge.md) identifies an
actual pinned-source construction discrepancy, distinct from the earlier missing
source access: commit `a2ed2ec2f3e85f29b6035951553b02cb737c817a`,
`blake2b_hashchain::absorb_hash_digest`, constructs state plus digest but hashes only
state-length bytes. Root and direct-message contents cannot affect that state
update. Aurora's wrapper also lacks initial statement/relation binding. This is
source analysis, not an executed attack, and not a defect demonstrated in active
PQ-DID cryptographic code.

The report's TB-01–TB-10 register requires full framed absorption, trusted E(X)/IDs,
an actual no-PoW branch without work credit, paper-aligned masking or explicit
replacement lemmas, complete query/terminal disclosure accounting, commitment/port
and wire correspondence, degree metadata reconciliation and distinct BCS/CMS
knowledge/privacy premises. Source zero-sum masks/random coefficients and b=2q+1
do not discharge the theorem hypotheses. Concrete hash instantiation, adaptive
Delta_tail and application composition remain open.

No manuscript correction is applied: only Sections II–VIII remain authoritative.
No production source or profile is changed. Recommend **S3-AURORA-TRANSCRIPT-CORRECTION-CONTRACT-1**
as an inactive source-only next action, not a prover implementation. A private
prototype remains inadmissible until the corrected byte transcript and joint
simulator correspondence are established. Analysis opening 228.28910572698805 s;
implementation 41.82321833795868 s and 386/386 invocations untouched. Stages 2–3
remain open; isolation safely stopped/unactivated, CPU proving paused, proof ledger
two attempts used/one unused.


Aurora transcript-bridge closure: source/documentation checks and the
[single preservation audit](data/s3_aurora_transcript_bridge_1/result.json)
pass, 10,788 disjoint content paths,
2.542261570 s, 23,666,688-byte
cgroup peak under the unchanged 256 MiB ceiling. Analysis charge
80.005991822/300 s; **219.994008178 s remain**. Implementation unchanged
**41.823218338 s; 386/386 tests**, no tests/probes/circuits generated. No failures
or retries in validation; the preliminary source-read DNS failure is retained.
**Decision 2 / AURORA-BRIDGE-001 open:** pinned absorption ignores new digest
bytes; statement binding, no-PoW handling, algebraic masking and commitment/wire
correspondence require explicit correction. Recommend only the inactive
S3-AURORA-TRANSCRIPT-CORRECTION-CONTRACT-1 source package. No profile adopted;
complete authentication/proof and security obligations remain open.
Stages 2–3 open, isolation safely stopped/unactivated; proof ledger two used/one unused.

## AURORA-BRIDGE-001 — correction contract prepared, not applied

[S3-AURORA-TRANSCRIPT-CORRECTION-CONTRACT-1](stage3_aurora_transcript_correction_contract.md)
specifies a patch-ready experimental EXP2 transcript and the length-only diagnostic
repair separately. TB-01/TB-02 are **not implemented or validated**. The missing
binding finding concerns explicit initial statement/relation hashing in the selected
fresh BLAKE2b call chain. Primary-input algebraic checks exist; historical shorthand
must not be read as proof that the entire verifier ignores its statement.

EXP2 binds trusted protocol/parameter/relation identities and canonical public E(X),
with exact framing, message boundaries, phase/counter rules and atomic failure.
The pseudo-diff and independent future trace recipe are complete for a public-only
harness. Proposed **S3-AURORA-TRANSCRIPT-REGRESSION-1** requires16 additional cases
(386→402) and at most 25 seconds from the unchanged implementation balance, retaining
ten seconds for evidence/cleanup. The proposal is inactive; no further general
review is needed before that narrow authorised execution. It cannot return proof
acceptance or enable an old-version fallback.

AURORA-BRIDGE-001 remains open: query/masking, commitments, round-by-round/state-
restoration extraction, adaptive privacy/composition, concrete hash and Delta_tail
are not discharged by proposed framing or future deterministic regressions.
Production code, active profile, signed encodings, parameters and manuscript are
unchanged. Only Sections II–VIII remain authoritative. Stages 2–3 open; CPU proving
and raw-view integration paused, isolation safely stopped/unactivated; proof ledger
two attempts used/one unused. Implementation41.82321833795868 s and386/386 untouched.


Aurora correction-contract closure: source/documentation checks and the
[single preservation audit](data/s3_aurora_transcript_correction_contract_1/result.json)
pass, 10,856 disjoint content paths,
2.632140150 s, 23,830,528-byte
cgroup peak under the unchanged 256 MiB ceiling. Analysis charge
88.486544458/300 s; **211.513455542 s remain**. Implementation unchanged
**41.823218338 s; 386/386 tests**, no tests/probes/circuits generated. No failures
or retries in this package. **AURORA-BRIDGE-001 open:** proposed transcript EXP2
repairs are specified, not implemented/validated. Algebraic primary-input checks
are distinguished from absent explicit initial statement hash binding. Recommend
only inactive S3-AURORA-TRANSCRIPT-REGRESSION-1: sixteen counted cases (386 to 402),
at most 25 implementation seconds from the unchanged balance. No profile adopted;
complete authentication/proof and security obligations remain open.
Stages 2–3 open, isolation safely stopped/unactivated; proof ledger two used/one unused.


## S3-AURORA-TRANSCRIPT-REGRESSION-1 — isolated public EXP2 regressions

The [regression report](stage3_aurora_transcript_regression.md) records **16/16
authorised public cases passed**, including the individually counted TR-02 repeat
and the TR-16 old-omission negative control. Corrections are implemented/tested
only in the isolated Python reimplementation: no native upstream patch or Aurora
proof system was executed. The correction contract and source snapshot remain
preserved. Independent expected traces agree on full preimages, states/blocks,
canonical records, counters, mapped outputs and prover/replay results. Negative
cases retain prior state and release no partial value. Finite mutation results
are not collision-resistance or forgery evidence.

The qualified finding remains: explicit initial full-statement binding was absent
from the selected fresh hash-chain path, but algebraic primary-input checks exist.
**AURORA-BRIDGE-001 stays open** for native/IOP mapping, query/masking, commitments,
compiler/relation and adaptive extraction/privacy/concrete-hash obligations.
Adaptive Delta_tail and production-security obligations remain unresolved.

Invocations are now **402/402**, with no additional probe or automatic retry.
Implementation opened at 41.82321833795868 s; the measured closure below records
this package's charge. Analysis 211.51345554180443 s and isolation 250.22 s remain
untouched. Recommend bounded source-only **S3-AURORA-ROUND-PLAN-ADAPTER-CONTRACT-1**
to specify actual registration/round/query hooks and the no-PoW transition before
any native integration. It has not started; no private prototype is admitted.
Stages 2–3 remain open. Raw-view integration and CPU proving remain paused;
isolation safely stopped/unactivated; proof ledger **two used, one unused**.


**EXP2 package completion stopped — preservation prerequisite failed.** The
[regression report](stage3_aurora_transcript_regression.md) retains all 16/16 passing
cases, but the [scope-preparation diagnostic](data/s3_aurora_transcript_regression_1/prepare.log)
exited 1: required new experiment files were outside the inherited traversal roots.
They exist; this is an inventory-scope construction error. No full preservation
audit ran; no complete preservation or successful package closure is claimed.
The failed guard and STOP marker are retained; no retry or semantic change occurred.
Lint/format passed before case execution. Source identities remain those executed.

Charge **5.676312445 implementation seconds**, including the failed preparation
and reserved bookkeeping; cumulative **337.853094107/374 s**, **36.146905893 s
remain**. Tests **402/402**; analysis **211.513455542 s** and isolation **250.22 s**
unchanged. Maximum guarded cgroup peak **23,035,904 bytes** under 256 MiB; no resource
breach. AURORA-BRIDGE-001 and Stages 2–3 remain open; proof ledger two used/one unused.
Immediate next recommendation (superseding the conditional adapter step):
**S3-AURORA-TRANSCRIPT-PRESERVATION-REPAIR-1**, adding only the exact new experiment
root to the audit traversal, preserving every inherited root/required file and the
failure, then completing checks and the still-unexecuted audit without rerunning
cases. Not started; no additional invocation or limit increase is requested here.


**S3-AURORA-TRANSCRIPT-PRESERVATION-REPAIR-1 stopped; package incomplete.**
The [repair record](stage3_aurora_transcript_regression.md) adds only traversal root
`experiments/aurora_transcript_regression_1`. Corrected preparation passed
(2,596 names, no missing/unexpected); all four false reports
are resolved. The one complete audit attempt subsequently failed at the reused
case-evidence presence check: the repair adapter checked `repair-1/TR-01.json`
instead of the retained original path. The files and original failure remain
intact. No further attempt, evidence relocation or regression rerun occurred.
10,901 baseline content comparisons completed, but final inventory/reporting
and guard success did not; **preservation is incomplete**. This audit-adapter path
error is the remaining completion blocker, distinct from AURORA-BRIDGE-001.

Audit 2.539544389 s, peak 23,654,400
cgroup bytes under 256 MiB, no resource breach. Repair charge **7.931766078 s**;
combined **13.608078523/25 s**, **11.391921477 s** remain including the
protected ten-second reserve. Implementation **28.215139815 s**
remain; tests **402/402**. Analysis/isolation unchanged. Both failed attempts and
all 16 passed regressions are preserved. Stages 2–3 and AURORA-BRIDGE-001 open;
proof ledger two used/one unused, no activation/proofs/zkVM executions. Stopped.


Repair-2 stopped before preparation/audit: original 16 case references were verified,
but static lint failed on the new audit helper's overlong accounting string (E501).
[Failure and ledger](stage3_aurora_transcript_regression.md) retained; no retry.
Package remains incomplete. Added charge 5.153995360s, combined 18.762073883/35s;
package 16.237926117s remain including ten-second reserve; implementation
23.061144455s remain. Tests 402/402; analysis/isolation unchanged.
Original failures and EXP2 inputs unchanged. AURORA-BRIDGE-001/Stages 2–3 open;
proof ledger two used/one unused. No proofs, zkVM executions or activation.


E501-only repair continuation: **stopped at storage admission**, no helper change,
static rerun, preparation or audit. Retained package usage 262,101/262,144 bytes
left 43 bytes; the existing helper requires 1,100 bytes reporting headroom before
new evidence. The report pointer leaves 262,142 bytes. Earlier failure archives
and all 16 passed cases are unchanged. See the [admission and closure record](status.md#repair-2-stop).
Five-second established bookkeeping charge: combined 23.762073883/35 s;
package 11.237926117 s remain including ten-second reserve; implementation
18.061144455 s remain. Tests 402/402; no new invocations. Full audit,
final inventory/reporting and E501 correction remain outstanding; no completion
claim or limit increase. Stages 2–3/AURORA-BRIDGE-001 remain open; proof ledger
2 used/1 unused; analysis/isolation unchanged, CPU proving paused, no activation.


**Approved preservation continuation stopped at preparation; package incomplete.**
The E501-only helper correction passed one guarded lint/format pass and preserves
its entire parsed AST/runtime string. Inventory preparation exited 1: 2,622 names,
zero missing, one unexpected retained file:
`docs/data/s3_aurora_transcript_regression_1/repair-1/prepare.json`.
That file matches its historical seal; the inherited expected-name list omits it.
No preparation retry, audit or case rerun occurred. Complete baseline preservation,
final inventory and audit reporting remain unestablished; earlier 10,901 completed
comparisons are partial evidence only. See the [continuation outcome](stage3_aurora_transcript_regression.md#completion-continuation-outcome).

The approved 1,048,576-byte output and 40-second package caps are recorded separately;
all previous evidence counts and remains unchanged. Continuation charge
5.355415765 s = 0.355415765 guarded seconds + five established bookkeeping
seconds. Combined 29.117489648/40 s; package 10.882510352 s and implementation
12.705728690 s remain. The ten-second reserve remains inside that balance.
Cgroup peak 25,104,384 bytes under 256 MiB, no resource breach. Tests 402/402;
analysis/isolation unchanged. Only the inventory omission remains for a separately
authorised repair; the present stop rule prohibits another attempt.
Stages 2–3/AURORA-BRIDGE-001 open; EXP2 remains isolated Python evidence, not native
or proof-security validation. Isolation stopped/unactivated, CPU proving paused;
proof ledger two used/one unused. No proofs, zkVM executions or installations.


**Aurora transcript preservation finalisation complete.** The exact protected
`docs/data/s3_aurora_transcript_regression_1/repair-1/prepare.json` entry was restored;
its original digest and content seal are unchanged. Reconciliation of 88 retained
manifest names found no further omission. One preparation and one complete audit
passed, both exit 0. Audit: 8,759 primary entries (8,756 unchanged plus three
previously authorised documentation changes) + 2,142 unchanged supplemental
entries = **10,901 disjoint comparisons**, 10,936 identity-inclusive paths,
2,644-name inventory with no missing/unexpected entries. Final report/readback
and outer guard passed. Earlier failed records are retained; they are superseded
for package completion, not rewritten. See the [complete finalisation record](stage3_aurora_transcript_regression.md#inventory-finalisation-result).

Audit 2.834623713 s; cgroup peak 28,528,640 bytes
under 256 MiB, no resource breach. Finalisation charge 8.148349031 s including
five existing bookkeeping seconds; combined 37.265838679/40 s. Package
2.734161321 s and implementation 4.557379659 s remain. The reserve was used
inside the same cap as authorised. Tests **402/402**, all 16 prior cases reused;
analysis/isolation unchanged. Only the existing package is complete: Stages 2–3
and AURORA-BRIDGE-001 remain open; native correspondence and proof security are
unestablished. CPU proving/raw-view integration paused, isolation stopped/unactivated;
proof ledger two used/one unused. No new package, proof, zkVM execution, installation
or activation. Historical baselines, parameters and cryptographic inputs preserved.


## S3-AURORA-NATIVE-TRANSCRIPT-PILOT-1 — dependency-blocked

The [native pilot report](stage3_aurora_native_transcript_pilot.md) records **no native
patch, build or test**. The source snapshot at libiop
`a2ed2ec2f3e85f29b6035951553b02cb737c817a` passed 21 file/blob identity checks;
eight relevant files were copied unchanged into an isolated experiment. Sodium
development headers/pkg-config metadata, libff development/source closure and the
complete libiop header tree are unavailable. Transitive revisions remain unpinned.
The installed libsodium runtime does not establish those build prerequisites.
All TR-01–TR-16 native outcomes are unexecuted; independent Python expectations
were reused unchanged. Build attempts **0/2**; native invocations **0/24**;
cumulative **402/426**, no hidden probe or regression rerun.

The hard-coded `/usr/bin/rg` preflight launcher error and its source/results are
preserved and charged. Metadata completion used the installed tool; no native
code or negative control ran. Lint/format and the complete preservation audit
passed: **10,901 disjoint content comparisons**, 10,936 identity-inclusive paths,
2,688-name inventory, no missing/unexpected entries, report/readback and guard pass.
Audit 2.643288025 s; cgroup peak 30,203,904 bytes
under 256 MiB. Package charge 8.249009901/300 s, including failure and five
bookkeeping seconds; **291.750990099 package seconds** and
**296.308369758 implementation seconds** remain. The 30-second completion
reserve is inside the package balance; analysis/isolation untouched.

This closes the package with a dependency blocker and successful preservation;
it does not establish native transcript correspondence. AURORA-BRIDGE-001 stays
open for native callers, query/masking, commitment transformation, extraction/privacy,
concrete-hash and complete authentication. Stages 2–3 remain open. Next recommendation:
a bounded complete-source/dependency-lock and prerequisite-provisioning proposal,
not started. Production code, BC-1, manuscript, dependencies and old evidence remain
protected. Isolation stopped/unactivated; CPU proving/raw-view integration paused;
proof ledger two used/one unused. No proof, zkVM execution, installation or activation.


## S3-AURORA-NATIVE-DEPENDENCY-LOCK-1 — provisioning proposal

The [dependency report](stage3_aurora_native_dependency_lock.md),
[proposed lock](data/s3_aurora_native_dependency_lock_1/dependency-lock.json) and
[runbook](proposals/s3_aurora_native_dependency_lock_1/README.md) resolve the selected
libiop/libff/libfqfft revisions and exact sodium/GMP development-package identities.
Project-local acquisition/static linking is proposed; no host installation is
necessary. Native build admission remains pending acquired-checkout integrity,
archive-member/header/library/ABI checks and actual compiler/resource compatibility.
The runbook consolidates acquisition approval and a narrow artifact-file exception;
no provisioning or build was performed. The interrupted lookup and 7,203-byte output
overrun remain failures under their original ceiling. The authorised continuation
uses 12,386,485 cumulative bytes and the unchanged 2 MiB package cap. It reuses
successful metadata and the 16 Python regressions; the unfinished requests passed.
The current full-audit and resource outcome will be appended after finalisation.

DEP-001/DEP-002 and AURORA-BRIDGE-001 are not closed by dependency metadata.
The dependency-pin question for the selected native support path is answered at
the metadata layer; acquired artifacts, native EXP2/caller correspondence,
query/masking, commitment transformation, extraction/privacy and concrete-hash
composition remain gates. Stages 2–3 remain open. Isolation stays stopped/unactivated,
CPU proving/raw-view integration paused, proof ledger two used/one unused. Native
291.750990099 s, implementation 296.308369758 s, both build attempts and all 24 native
invocations remain unused; cumulative 402/426. Next step: approve only the concrete
local provisioning/resource proposal, then apply its admission checks.


Dependency-lock finalisation: focused checks, preparation and the one full audit
passed (exit 0; 10,901 disjoint comparisons; 2,790 inventory names; report/readback/guard
complete). Audit 2.655091408s and 33,660,928bytes
cgroup peak, below 256 MiB. Earlier 7,203-byte overrun remains preserved as failure.
Analysis package charge 31.717931544/60s; analysis balance 179.795523998s.
Current [closure](data/s3_aurora_native_dependency_lock_1/continuation-1/validation-closure.json)
records final output accounting. Proposal ready for its specified local acquisition
approval; actual archive/source verification and native build admission pending.
No provisioning/native execution occurred; 402/426 and all native/implementation
allowances unchanged. Stages 2–3 and AURORA-BRIDGE-001 remain open.


## Native provisioning integrity stop

Approved local provisioning stopped before dependency admission: pinned libiop
HEAD `a2ed2ec2f3e85f29b6035951553b02cb737c817a` and fsck passed, but its acquired
root tree `2e2588ccb085242dd2237875c3b9adf1a0fc958c` differs from the approved
lock's tree field (which equals the commit ID). Retained API metadata was interpreted
as a tree ID without object-type verification. This is a lock/metadata discrepancy,
not demonstrated checkout corruption. See the appended
[native report](stage3_aurora_native_transcript_pilot.md) and
[failure analysis](data/s3_aurora_native_transcript_pilot_1/provisioning-1/failure-analysis.json).
The proposal-readiness conclusion is superseded by this failed admission gate.
No pins changed, no retry, no archives or other repositories acquired; partial
libiop checkout retained in its approved isolated prefix. No native build or case:
0/2 builds, 0/24 native invocations, 402/426 cumulative. Next bounded recommendation
is source/tree identity reconciliation before a corrected lock or acquisition.
DEP-001/DEP-002 and AURORA-BRIDGE-001 remain open; Stages 2–3 open. Isolation
stopped/unactivated; CPU proving paused; proof ledger two used/one unused.
Final preservation result and resource balances follow after the audit.


Stopped native-provisioning closure: preservation passed (exit 0; 10,901 disjoint
content comparisons; 3,080 inventory names; report/readback/guard complete). Audit
2.636536615 s, 28,880,896 bytes cgroup peak under 256 MiB.
Partial checkout retained (2,030,216 bytes); no archives/builds/native cases.
Continuation charged 9.061018428 s; native balance 282.689971671 s and
implementation balance 287.247351330 s. Analysis/isolation unchanged; 402/426, two
unused builds, all 24 native invocations and proof ledger two used/one unused.
See [current closure](data/s3_aurora_native_transcript_pilot_1/provisioning-1/validation-closure.json).
Tree-identity reconciliation is the only recommended next step, not started.
Stages 2–3 and AURORA-BRIDGE-001 remain open.


## Verified dependency reconciliation and native build stop

The authorised commit/tree reconciliation passed with replacement-object substitution disabled. The libiop commit remains `a2ed2ec2f3e85f29b6035951553b02cb737c817a`; its stored tree header, `^{tree}` resolution and tree object agree on `2e2588ccb085242dd2237875c3b9adf1a0fc958c`. The same commit-versus-root-tree metadata error was verified and corrected for the selected libff and libfqfft commits. Only the three tree fields changed in a new lock version; the original lock, seals, failed acquisition and all gitlink commit IDs remain protected.

See the [v2 runbook](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/runbook-v2.md), [correction proof](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/lock-correction.json) and [provisioning result](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/provision-result.json). Corrected lock SHA-256: `0e33258c861764eacb8e4f04d21962425e7b7fedd7f27e79cecc4176deec1736`.

Project-local provisioning passed: all three selected source trees, all recorded gitlinks, 21 retained source snapshots and eight historical source copies matched. Both unchanged Debian archive hashes, members, destinations, header versions and static-library x86-64 ELF members passed inspection. Nothing was installed globally or into the existing Python/liboqs environment. Build compatibility was then tested and failed; static dependency readiness is not compilation success.

Both native build attempts are consumed. Build 1 stopped on private `bigint_repr()` access in an unused libff BLS12-381 source. The one authorised build-only correction narrowed `ff` to pinned binary-field/common sources. Build 2 built that target but stopped on non-existent `index`/`coeff` members in pinned libiop `relations/variable.tcc` (lines 63, 129, 171, 177–178). No native executable was produced. No native function/caller or negative control was executed, and no correspondence is established. The prepared patch/harness and both failures are retained. No further build was attempted.

All TR-01–TR-16 outcomes are individually [recorded as not run](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/native-case-outcomes.json). Native invocations remain 0/24; cumulative 402/426. Existing 16 Python results are reused, not rerun. DEP-001/DEP-002 and AURORA-BRIDGE-001 remain open. The exact acquisition prerequisite is now satisfied; compiler compatibility and native transcript correspondence remain unresolved.

Recommended next package: a bounded source-only native build-compatibility correction contract addressing the observed libff friend-access and libiop stale-member errors, with exact isolated changes and an explicit future build-attempt request. Do not substitute dependencies or start that package automatically. Stages 2–3 remain open; query/masking, commitment transformation, extraction/privacy, concrete hash and complete authentication obligations remain open. Only manuscript Sections II–VIII and agreed clarifications are authoritative. Isolation stays stopped/unactivated; CPU proving paused; no proofs or zkVM executions; proof ledger two used/one unused.

Final preservation/guard outcome and actual resource balances are appended below after completion.


Reconciliation/native closure: the complete preservation audit passed, exit 0,
with 10,901 disjoint baseline content comparisons, 10,936 identity-inclusive paths
and 4,884 inventory entries at audit time. Report generation/readback and outer
guard passed; audit 2.939619946 s, 30,527,488 bytes cgroup peak under
256 MiB. New artifact inventory covers 1,988 entries (1,983 regular files and five
exact symlink targets); retained artifact bytes 11,228,057 / 134,217,728. No baseline,
seal, historical failure or expected result was replaced. No resource breach.

Native builds: attempt 1 exit 1 in 1.371514156 s; attempt 2 exit 1 in
3.603540356 s. Largest native cgroup peak 258,568,192 bytes / 1 GiB;
largest sampled native tree RSS 211,906,560 bytes; sampled temporary-storage peak
669,692 bytes / 8 MiB. These are separate memory metrics, not sums. All launched
guarded workers exited and temporary work is empty. Local checkouts, archives,
static-library prefix, patched sources and partial builds remain isolated and
retained. Both build attempts used; all 24 native invocations unused; 402/426.
No executable, native transcript result, or successful caller comparison exists.

Provisioning/reconciliation sub-limit conservatively charged 18.156349560/60 s,
leaving 41.843650440 s without resetting the old charge. This continuation
charged 18.318097987 s: actual guard durations plus the existing five-second
bookkeeping convention. Native package total 35.628126316/300 s; balance
264.371873684 s, with its 30-second reserve preserved. Overall implementation
balance 268.929253343 s. Analysis 179.795523998 s and isolation 250.22 s unchanged.
The first static pass recorded E741/E501; the authorised cosmetic identifier and
string-wrapping corrections preserved runtime values, and the second lint/format
pass succeeded. Both diagnostic sets remain; static checks consumed no native cases.

The additive [closure and final output accounting](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/validation-closure.json)
and [seal](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/manifest.json)
record final inventory and bytes. Preservation is complete; the native pilot is
closed at a build blocker, not successful correspondence. A source-only compiler
compatibility correction contract is the sole next recommendation, not started.
Stages 2–3 and AURORA-BRIDGE-001 remain open. Proof ledger two used/one unused;
no proofs/zkVM, host activation or additional native work.


## S3-AURORA-COMPILER-COMPATIBILITY-CONTRACT-1

Source-only contract prepared; no acquired/experimental native source mutation,
configuration, compiler probe, build or native case. The ten logged `index`/`coeff`
errors affect four functional operators, not printing. The minimal separate patch
selects declared `index_`/`coeff_` members; eight proposed semantic cases are required
before unchanged TR-01–TR-16. This fits the existing 24 unused invocations but remains
inactive. Request one additional build attempt (2 → 3), no other allowance increase,
with a 150-second native/implementation subcap and existing finalisation reserve.
See the [contract](stage3_aurora_compiler_compatibility_contract.md) and
[inactive exact runbook](data/s3_aurora_compiler_compatibility_contract_1/runbook.md).

AURORA-COMPILER-001 remains open pending semantic validation and a successful build.
Related latent member errors in three other combination/free-operator paths are
recorded and left unchanged; no general relations-module correctness claim.
The libff target-selection workaround retains binary fields/common support but does
not repair prime-field friend/stream access. Historical wording “built that target”
is clarified: eight translation units compiled; the sealed build inventory has no
build-produced `.a` archive, and no link/native executable was completed. Both failed
builds and their original reports remain protected.

Balances remain native 264.371873684 s, implementation 268.929253343 s, provisioning
41.843650440 s; builds 2/2 used; native invocations 0/24; cumulative 402/426. Analysis
opens at 179.795523998 s, separate from those allowances; actual charge follows in
final contract closure. Stages 2–3 and AURORA-BRIDGE-001 remain open, including full
native caller coverage, query/masking, commitment transformation, extraction/privacy,
concrete hash, adaptive Delta_tail and production security. Isolation remains
stopped/unactivated; CPU proving paused; proof ledger two used/one unused.


Completed source-only contract: lint/format and all three textual patch-applicability
checks passed; no source mutation, compiler invocation or native test. The complete
preservation audit passed, exit 0, with 10,901 disjoint content comparisons,
10,936 identity-inclusive paths and 4,915 inventory entries at audit time. Final
inventory, reporting/readback and outer guard passed. Audit 3.020466007 s,
30,470,144 bytes cgroup peak under 256 MiB; sampled tree RSS 48,529,408 bytes.
Largest analysis-worker cgroup peak was 36,962,304 bytes. No resource breach or
retained temporary data. Historical build failures, original seals and native
source/artifacts remain preserved.

Analysis charge 8.535517291/30 s, including existing five-second bookkeeping
accounting; package residual 21.464482709 s and analysis balance 171.260006707 s.
Native 264.371873684 s, implementation 268.929253343 s, provisioning 41.843650440 s,
isolation 250.22 s, builds 2/2 consumed and invocations 402/426 remain unchanged.
Exact final byte accounting and the additive seal are in
[the contract closure](data/s3_aurora_compiler_compatibility_contract_1/validation-closure.json)
and [manifest](data/s3_aurora_compiler_compatibility_contract_1/manifest.json).

The functional patch's SHA-256 is
`8a28d44432c4dfd2ff41a07bb4affd1a154b52ae781289210410586b43e4c357`.
It remains unapplied. One extra build plus eight semantic cases and TR-01–TR-16
is an inactive request requiring approval; no broader resource increase is requested.
Stages 2–3 and AURORA-BRIDGE-001 remain open; proof ledger two used/one unused.


### Native functional-correction continuation: build 3 guard stop

The approved ten-reference patch and semantic target were applied only in the
fresh isolated `dependency-prefix-v1/compatibility-v1` subtree after seal checks.
Build 3 configured successfully, then stopped at 2.299439995 seconds under the
new-output guard: compiler temporary files were included in evidence accounting
(569,344 sampled temporary bytes versus the 393,216-byte reservation). The log
contains no compiler diagnostic; neither executable linked. No SEM-01–SEM-08 or
TR-01–TR-16 case ran. Builds are 3/3 used; invocations remain 402/426. No further
build or correction is automatic. Containment and the empty temporary directory
are recorded; the partial build and every earlier failure are retained.

See [the native report](stage3_aurora_native_transcript_pilot.md) and its
`docs/data/s3_aurora_native_transcript_pilot_1/compatibility-1` evidence. Required
preservation finalisation is recorded separately below; a passing audit cannot
establish compilation, operator semantics or native correspondence. Recommended
next work is a source-only compiler-scratch/evidence accounting correction
contract before a new build request. Stages 2–3 and AURORA-BRIDGE-001 remain
open, with query/masking, commitment transformation, extraction/privacy,
concrete-hash and complete-authentication obligations unresolved. Isolation
remains stopped/unactivated and CPU proving paused; proof attempts remain two
used and one unused. Analysis/provisioning allowances are unchanged.


### Final outcome of the third-build continuation: incomplete, stopped

Formatting/lint passed. Preparation passed over **5,907 inventory entries** with
no missing or unexpected paths. The sole full preservation audit exited **1**
after **3.082952 seconds**, at **29,663,232 bytes** cgroup peak
(**47,603,712 bytes** sampled tree RSS), under the unchanged **256 MiB** ceiling.
It completed **8,759 original + 2,142 supplemental = 10,901** disjoint baseline
comparisons, report-prefix checks and assessed/sealed input checks. These remain
partial evidence: final inventory, final documentation checks and complete report
readback were not reached.

The failure is `changed prior resource controls`: this continuation's
`checks.py::current_checks` included the authorised **1 GiB native preflight** in
the legacy `check_runs` list, whose resource validator requires **256 MiB**.
This is an integration error in the new audit wrapper, not a measured audit
memory breach or a demonstrated protected-content mismatch. The error, phases,
outer result and STOP record are preserved. No audit was repeated and no
comparison requirement was removed. **The package is not complete.**

**AURORA-NATIVE-GUARD-001 remains open:** review the compiler scratch/evidence
accounting boundary and make phase-specific validation explicit while retaining
all ceilings. This is the one recommended bounded next contract; neither a repair
execution nor another build begins here. Build attempt three remains consumed,
with no complete linking and **zero** semantic/transcript invocations. Each
SEM-01–SEM-08 and TR-01–TR-16 outcome is recorded as not run. The previous Python
results do not establish native correspondence or proof security.

Accounting: **11.543774/150 seconds** charged (five conservative bookkeeping
seconds plus **6.543774** measured guarded seconds); **138.456226**
remain under this stopped subcap. Native balance **252.828099 s**;
implementation **257.385479 s**. Analysis remains
**171.260006707 s**, provisioning **41.843650440 s**. Builds **3/3** used;
invocations **402/426**, all **24** native cases unused. The guarded workload
terminated; cleanup retained the empty assembler artifact and left no temporary
entries. New artifacts: **3,995,318 bytes / 956 entries**, aggregate artifacts
**15,223,375/134,217,728 bytes**.

Final retained new evidence and document appendices: **000000224338 bytes**;
cumulative **000011879147/12,386,485 bytes**, headroom
**000000507338 bytes**; native package evidence
**000001262780/2,097,152 bytes**. These retained totals do not erase the
build-time guard exceedance caused by temporary-file accounting. Exact records
are in `docs/data/s3_aurora_native_transcript_pilot_1/compatibility-1/validation-closure.json`.
The new manifest seals this incomplete outcome; it does not replace old seals or
claim a successful audit. No final inventory is claimed after the failure.

Stages 2–3, AURORA-BRIDGE-001, query/masking, commitment transformation,
extraction/privacy, concrete-hash and complete-authentication obligations stay
open. Isolation remains stopped/unactivated, CPU proving paused, and the proof
ledger two used/one unused. No proof, zkVM execution, installation or activation
occurred. Stop after this report.


S3-AURORA-RESOURCE-GUARD-REPAIR-1: eight tooling cases and one targeted rerun
passed (411/438); complete preservation pending. See the native transcript report.
Builds remain 3/3; all 24 native cases remain unexecuted.


Resource-guard repair complete: audit passed; 411/438 invocations, builds 3/3. See native report.

**AURORA-NATIVE-ADMISSION-001 — open.** The approved fourth-build runbook's
200,000-byte reservation is unsupported by retained build evidence: 344,971 bytes
under its unchanged classification, exceeding even opening cumulative headroom
by 77,318 bytes before finalisation. Admission stopped; no fourth build consumed.
Reconcile complete generated-output and finalisation budgets before resumption;
do not relax roles or remove retained files to fit. Resource-guard synthetic
validation remains valid; live compiler routing remains untested. Builds 3/4;
SEM/TR 0/24, cumulative ledger 411/438. AURORA-BRIDGE-001 and Stages 2–3 remain
open; no new security claim or proof attempt.


Fourth-build admission finalised: preservation passed (10,901 comparisons; final inventory 6008; report/readback complete), no build or cases launched. Charged 9.005019 s; native 233.290628 s, implementation 237.848007 s remain. Builds 3/4; ledger 411/438. Evidence-budget blocker and AURORA-BRIDGE-001 remain open; see native report.


Fourth-build storage resumption: 784,736 historically artifact-only bytes now
additionally charged once as evidence; 16 MiB cumulative/4 MiB native/2 MiB new
reservation reconciled without altering old ledgers. Preflight E501 stopped native
admission before copying/configuring/building. Formatting-only correction and
completion lint passed; no preflight retry. Builds 3/4, ledger 411/438; every SEM/TR
case not run. See native report and `build-4-resumption-1/` evidence. Storage gap
addressed; static-stop resumption remains pending. Stages 2–3/AURORA-BRIDGE-001 open.


Stopped preflight finalised: audit exit 0; 10,901 comparisons, final inventory 6041, reporting/readback complete. Charged 8.976094 s; subcap 82.018887 s, native 224.314534 s, implementation 228.871913 s remain. Builds 3/4, ledger 411/438; all native cases not run. Unchanged 55+30-second build/completion reservation no longer fits; resolve admission before resumption. Historical failures remain failures. See native report; Stages 2–3/AURORA-BRIDGE-001 open.


Fourth-build total amended prospectively to 120 s; 17.981113 s retained as consumed.
Source admission then found AURORA-NATIVE-SEAL-001: unchanged preflight uses older
full-file hashes for five legitimately appended reports. Current hashes match the
latest seal and historical prefixes are intact. Stop before preflight/build;
non-formatting validation correction is not authorised here. Native launcher and
worker unchanged; all SEM/TR cases not run, builds 3/4, ledger 411/438. See native
report and `build-4-time-admission-1/`. Stages 2–3/AURORA-BRIDGE-001 remain open.


Time-admission finalisation complete: audit passed, 10,901 comparisons, 6066 final inventory entries and report readback complete. Charged 9.044320 s; fourth-build 92.974568 s, native 215.270214 s, implementation 219.827594 s remain. No preflight/build/case launched. Builds 3/4; ledger 411/438. AURORA-NATIVE-SEAL-001 needs the explicit non-formatting preflight correction described in the native report. Stages 2–3/AURORA-BRIDGE-001 remain open.


AURORA-NATIVE-SEAL-001 corrected: explicit five-report allowlist, protected prefix
checks and pinned complete seals/lengths. Eight fixtures passed once; stable-snapshot
preflight passed. The authorised fourth build configured then failed compiling
`libiop/algebra/utils.cpp`: `utils.hpp:40` has undeclared `size_t`. No functional fix
or fifth build; AURORA-NATIVE-COMPILE-002 open for a bounded source-only correction
review. No native SEM/TR case ran; builds 4/4, ledger 419/448. All 24 native cases,
two new fixture reruns and three older tooling reruns remain unused. Historical
failures preserved; see native report and `seal-repair-1/` evidence. Stages 2–3 and
AURORA-BRIDGE-001 remain open; proof ledger two used/one unused.


Seal repair/fourth-build finalisation: preservation passed, 10,901 comparisons, 7073 final inventory entries, complete reporting/readback. Charged 18.074351 s; native 197.195863 s, implementation 201.753243 s, fourth-build subcap 124.900217 s remain. Eight seal fixtures/preflight passed; fourth build failed at utils.hpp undeclared size_t, all native cases unrun. Builds 4/4, ledger 419/448. AURORA-NATIVE-SEAL-001 resolved at this layer; AURORA-NATIVE-COMPILE-002 and AURORA-BRIDGE-001 remain open. See native report.


### AURORA-NATIVE-ARTIFACT-001 — exact harness-object registration and guard failure handling

Open. The registered output slots omitted CMake target-local `exp2_native.cpp.o` and `semantic_cases.cpp.o`; the former exceeded fallback ordinary/evidence per-file limit. `package_size` raises before the monitor enters its stop handler, leaving final outer metrics incomplete. This is an observed admission/monitoring defect, not permission to grant a wildcard binary exemption. Required next work is bounded exact-path reconciliation plus exception-safe containment/recording, with focused tooling validation and a complete audit. No policy fix, native rerun or extra build authorised/executed here.


Fifth-build continuation: the exact approved standard-size correction compiled and both targets linked; the outer monitor failed on an unregistered 1,387,120-byte CMake harness object. This is an incomplete guarded run. SEM-01–SEM-08 and TR-01–TR-16 are all not run; builds 5/5, ledger 419/448, all 24 native invocations retained. AURORA-NATIVE-COMPILE-002 is resolved at declaration/compilation level. AURORA-NATIVE-ARTIFACT-001 is open: exact CMake target-local object registration and exception-safe monitor termination/reporting need a bounded correction; no such correction was made here. Full preservation admission exited 1 before a worker, with zero fresh baseline comparisons. The previous 10,901 comparisons remain historical only. Final name inventory passed (8078 entries); failure reports/readback completed, not a successful audit.

Measured compiler body 6.052475 s; worker 6.115275 s and cgroup-v2 memory.peak 450,625,536 bytes under 1 GiB. Outer wall/RSS completion metrics are unavailable. Conservative charge 73.345883 s comprises preflight 1.345883, existing unfinished-run fallback 60, failed-audit reservation 7 and bookkeeping 5; it is not a measured 60-second build. Remaining: build continuation 51.554334 s; parent 59.478106 s; native 123.849980 s; implementation 128.407360 s. Analysis/provisioning unchanged.

Stages 2–3 and AURORA-BRIDGE-001 remain open: query/masking, commitment transformation, extraction/privacy, concrete-hash and complete authentication remain unestablished. Isolation remains stopped/unactivated; CPU proving paused; proof ledger two used/one unused. No native comparison, proof, zkVM execution, installation or activation occurred. Evidence and additive failure seal: `docs/data/s3_aurora_native_transcript_pilot_1/header-correction-1/`.

Final retained-byte accounting: new evidence 000002002278 bytes; combined reservation 000003622250/4,194,304, remaining 000000572054; cumulative 000015845249/18,874,368; native 000005228882/6,291,456. No bytes removed from prior charges. Aggregate artifacts 27,839,915/134,217,728 bytes, including all 8,253,592 new bytes; the existing per-file classification breach remains unresolved. See the additive failure seal and validation-closure.json; package is **not complete**.


AURORA-NATIVE-ARTIFACT-001: corrected at the exact registration/shared fatal-handler layer, five focused fixtures passed; previous failed guards remain failures. Native admission and all 24 comparisons passed. The remaining limits of handler/transport coverage and proof-security obligations are documented in the native report.


### Output registration/monitor repair and retained native execution

The consolidated continuation passed five tooling fixtures, then a complete pre-native preservation audit, then SEM-01–SEM-08 and TR-01–TR-16 once each. Native binaries were reused without rebuilding. Cumulative ledger is **448/450** (419 opening + 5 tooling + 24 native); two targeted tooling reruns remain unused and are not native retries. Builds remain **5/5**, with no new attempt. The first tooling command failed lint before admitting any fixture (two unused imports and an unbound loop-variable warning); the log and source snapshot are retained, the narrow correction passed lint/format, and no test was rerun.

The 22 retained compiler/linker output identities, target rules, dependencies, source overlays and successful link records were verified against the retained failure seal before execution. Exactly two CMake target-local harness object paths were added to the prospective registration. Logs/textual metadata and unregistered paths retain their evidence/fallback roles. All historical charges, including 1,844,237 bytes of build-tree evidence and the prior 73.345883-second charge, remain paid. The failed fifth-build outer guard is not retroactively marked successful.

The existing monitor now preserves a primary fatal error before containment, attempts bounded termination/reaping of its exact workload, and records cleanup/reporting errors separately. Unavailable timing/memory remains explicit; the established missing-time fallback remains 60 seconds. GUARD-04 exercised the shared fatal handler with an active harmless child, killed/reaped with exit -9; GUARD-05 exercised it after termination, retaining null measurements and a failed result. These are focused handler fixtures, not exhaustive transport/persistence fault injection or validation of the separate isolation controller.

Native results establish only the demonstrated patched-library public transcript correspondence and eight tested GF(2^192) operator behaviours. The common BCS caller, EXP2 state/round/challenge/finish paths, native public-record replay and original absorbed-digest omission control were exercised. Full Aurora proving/verifying, complete authentication, other field families and unrelated latent R1CS defects were not tested. TR-16 reproduces the original omission; it is not a forgery experiment. Existing algebraic primary-input checks remain distinct from the historical missing explicit hash-chain initialisation.

Stages 2–3 and **AURORA-BRIDGE-001 remain open**: query/masking, commitment transformation, extraction/privacy, concrete-hash composition, complete authentication and production-security obligations are unchanged. Isolation stays stopped/unactivated; CPU proving paused; proof ledger two used/one unused. No installation, configuration, compilation, proof or zkVM execution occurred in this continuation. Final preservation and exact balances are appended below after its single final audit.


Finalisation complete: the final audit exited 0 after **3.982068 seconds**, with **49,991,680 bytes** cgroup-v2 memory.peak under 256 MiB; sampled tree RSS 70,905,856 bytes. It repeated the complete 10,901 disjoint baseline content comparisons and 10,936 identity-inclusive paths with all frozen inputs/artifacts, without replacing them with prior partial evidence. Final audit inventory 8188; closure inventory 8193, no missing or unexpected paths. Both audit reporting/readback and outer guards passed. New report appendices are covered by the additive completion seal.

Charge **16.585722 seconds** = 11.585722 measured guarded wall seconds (including the retained initial static failure) + five conservative bookkeeping seconds. Remaining: continuation **94.968612 s**; parent **102.892385 s**; native **107.264258 s**; implementation **111.821638 s**. Analysis 171.260007 s and provisioning 41.843650 s remain unchanged. The old 73.345883-second conservative charge remains intact. No build reservation remains; builds 5/5 unchanged. All five tooling and 24 native cases passed once, ledger **448/450**, two narrowly reserved tooling reruns unused. The retained audit template's generic test fields are unpopulated; the individual fixture/native ledgers and closure record the actual 29 invocations.

This completes the isolated native public-input transcript pilot and its preservation continuation, not Aurora as a whole, complete authentication or proof security. AURORA-NATIVE-ARTIFACT-001 is resolved at the demonstrated repair layer; AURORA-BRIDGE-001 and Stages 2–3 stay open. No further work starts here.

Final exact evidence accounting: new 000000349206 bytes; retained-plus-new reservation 000003971456/6,291,456, remaining 000002320000; cumulative 000016194455/18,874,368; native 000005578088/8,388,608. No historic charges reclaimed. Artifacts remain 27,839,915/134,217,728 bytes; no new artifacts. Closure and additive seal: `output-guard-repair-1/validation-closure.json` and `manifest.json`.


### S3-AURORA-QUERY-MASKING-CONTRACT-1 — source contract

The [query/masking contract](stage3_aurora_query_masking_contract.md) separates the completed public native EXP2 pilot from untested private IOP/commitment code. Native continuation closed; 2,320,000 unused evidence-reservation bytes released without refunding consumption. No new functional invocations, builds or proof work.

TB-05 is refined by the full Aurora §4.7 shared-domain position convention: scalar disclosure totals are not its RS masking budget. TB-04 still requires a joint-view distribution correction/argument; TB-06 packed/selectively salted commitments and TB-09 classical restoration/quantum extraction/concrete-hash correspondence remain open. TB-01/02 are demonstrated only at the tested public native layer; TB-03/07/08/10 remain private-integration obligations. Recommend the source-only S3-AURORA-MASKING-CORRECTION-CONTRACT-1, with exact mask/message changes and a joint simulator mapping. No private prototype admitted.

Stages 2–3 and AURORA-BRIDGE-001 remain open. Isolation safely stopped/unactivated; raw-view integration and CPU proving paused; proof ledger two used/one unused. Analysis alone is charged; native107.26425821718294s and implementation111.82163787621539s remain unchanged. Preservation outcome follows in the package closure.

Finalisation: static checks and full preservation audit passed (exit0; 10,901 disjoint content comparisons; final inventory/readback complete). Audit 3.589761s, peak 48,013,312 bytes under256MiB. Package charged26.590041s; analysis remains144.669966s. No new invocations; native/implementation balances unchanged. Source contract complete; required construction corrections and all stated security gates remain open. See [closure](data/s3_aurora_query_masking_contract_1/validation-closure.json).


### AURORA-BRIDGE-001 — masking correction contract refinement

The [masking correction contract](stage3_aurora_masking_correction_contract.md) supports an exact ideal algebraic correction under explicit domain, degree, rate and query hypotheses. TB-04 now has proposed unrestricted sumcheck masks, their correlated direct sums and unit-pad combinations, with a joint conditional simulator. TB-05 has the corrected protocol's common-position projection argument including all quotient/fold/terminal messages; a finite private descriptor and actual source/parser closure remain open. The existing zero-sum/random-coefficient variant is not declared broken merely because this simulator does not apply to it.

TB-08 has an exact proposed folded-degree registration repair; no source patch, field certificate or full FRI execution is claimed. TB-01/02 retain only tested public native EXP2 correspondence. TB-03 no-PoW private integration, TB-06 complete commitment-view simulation, TB-07 concrete bytes/hash ports, TB-09 restoration/knowledge/quantum/concrete-hash composition, and TB-10 complete wire correspondence remain open. The algebraic simulator cannot itself emit binding roots for lazily determined tables; that precise commitment-transformation lemma remains required before a private prototype. Overall AURORA-BRIDGE-001 and Stages2–3 remain open.

Recommend only the inactive public synthetic S3-AURORA-SUMCHECK-MASK-CORRESPONDENCE-PILOT-1 with independent polynomial identities and actual native sumcheck calls. No builds/tests are authorised by this contract. Native/implementation balances unchanged; analysis and preservation charged separately. Adaptive Delta_tail, production security and complete authentication proof obligations remain unresolved.

Finalisation: complete audit exit0, 10,901 disjoint comparisons, inventory/reporting/readback passed; 3.894257s and 49,020,928 bytes cgroup peak under256MiB. One E501 static failure retained; formatting correction passed separately. Package charged18.392586s; analysis remains126.277380s. Native/implementation and448/450 invocations,5/5 builds unchanged. Contract complete, source proposals inactive and security obligations open; see [closure](data/s3_aurora_masking_correction_contract_1/validation-closure.json).


### OCT31-KYC-NATIVE-MILESTONE-1 — proposed execution and baseline decisions

The [consolidated milestone](october_implementation_milestone.md) proposes direct implementation, replacing a separate small sumcheck pilot. Native work is restricted to the supported masking contract; TB-06/TB-09 still needs a simulator for roots/salts/openings committed before challenges and adaptive openings without the hidden witness. Component success cannot close AURORA-BRIDGE-001 or admit full private authentication.

Proposed baseline `pqdid-mldsa-reference-1` is an explicit new, isolated research comparator: issuer signatures bind a persistent holder key; holder signatures bind the exact verifier request and credential/path. New fixed `PQ-DID-REF/*` contexts, strict framing and a baseline-specific issuer journal require this consolidated approval. Existing proof endpoints are not repurposed. Full attributes, holder key, rid and path are disclosed; W3C issuer/vocabulary, DID/key representation, securing mechanism, validity and status mappings remain open.

A prospective shared resource/correction policy retires completed-package microcaps without rewriting failures or consumption. No limit is raised now. Independent baseline/benchmark delivery continues after approval if the private route is blocked. Complete credential authenticity, holder-secret binding, selective disclosure and non-revocation remain jointly required for the eventual private scheme. Stages2–3, production security, adaptive Delta_tail and complete proof knowledge/privacy remain open.

Preparation complete, awaiting one consolidated execution approval: static checks and full audit passed,10,901 disjoint comparisons, final inventory/reporting/readback complete. Audit3.506725s/41,791,488B cgroup peak; preparation charged19.222742s; analysis remains107.054637s. Implementation/native balances and448/450 invocations,5/5 builds unchanged. Proposed resource amendments remain inactive; see [closure](data/october_implementation_milestone_1/validation-closure.json).

## OCT31 milestone implementation findings

**OCT31-NATIVE-ADMISSION-001 — open (tool admission).** Automatic approval review
rejected TR01–16 twice using the old24-case native ceiling. The milestone plan
allocates24 N plus16 TR and600 total new invocations. Direct confirmation requested;
no bypass/retries launched. Build3 N04 revalidation and C09 remain pending.

**OCT31-NATIVE-COVERAGE-001 — open at final binary.** Build2's N04 established
zero-polynomial/unit-mask behaviour at sumcheck. The compiled build3 harness adds
actual zero-triple lincheck calls; passing old-binary tests is not execution of that
addition. Full matrix revalidation is recommended within the existing correction
pool. General nontrivial R1CS and commitment/extraction/privacy obligations stay open.

**OCT31-BASELINE-001 — reference obligations demonstrated, production open.**
Real issuer/holder/verifier signatures, persistent synthetic keys/wallet, independent
A/B durable consumption, exact redelivery and authenticated revocation were tested.
No cross-store atomicity, process-crash/power-loss, production custody/erasure/side-
channel or external recovery-head claim follows. Adaptive Delta_tail remains open.

**OCT31-MEASUREMENT-001 — baseline measured, private proof unavailable.**276 local
trials completed with exact payload sizes, setup excluded from operation latency
but resource-charged, warm-ups retained and null proof metrics. No throughput/SLA,
PQ-DAA/private-authentication ratio, W3C conformance or complete PQ security claim.
Stages2–3/AURORA-BRIDGE-001 remain open; proof ledger two used/one unused.

OCT31 final preservation checkpoint: the full audit passed (exit 0), including
10,901 disjoint historical content comparisons, immutable/prefix checks and a
10,625-entry inventory. The first preparation exceeded the fixed 10,000-entry
traversal admission; its retained failure was corrected by complete disjoint-root
partitions without altering that per-partition limit or coverage. Guarded audit
time 6.058319 s; cgroup memory peak 51,773,440 B below 256 MiB. Native admission
and final-binary coverage remain open; overall milestone completion is not claimed.
See [final closure](data/oct31_kyc_native_milestone_1/validation-closure.json).

OCT31 final readback and exact-unit cleanup passed; no milestone worker remains.
Charged 381.396519 implementation seconds; 3330.425119 remain, with
826/1050 invocations and 8/13 builds used. Full preservation is complete while
final native validation remains blocked; see the execution report and closure.
Production, active profiles, historical evidence, proof/isolation ledgers and open
security obligations are preserved.

## OCT31 native finalisation — 29 September 2026

Direct user confirmation resolved **OCT31-NATIVE-ADMISSION-001** through normal
automatic review; neither rejection was bypassed. **OCT31-NATIVE-COVERAGE-001** is
resolved at the public component layer: 24 final-binary N cases, 16 retained-vector
TR cases and C-09 passed once (M1-0379–M1-0419). No build, expectation or cryptographic
source changed. Earlier results/rejections remain intact. Baseline/harness/276
measurements were reused. Ledger 867/1,050; builds 8/13. Final preservation follows
in [continuation evidence](data/oct31_kyc_native_milestone_1/native-finalisation-1/).

The bounded milestone's functional checks are complete. General Aurora correctness,
nontrivial R1CS/full authentication, query/masking and commitment transformation,
knowledge/privacy, concrete-hash, adaptive Delta_tail and production obligations
remain open. Stages 2–3/AURORA-BRIDGE-001 remain open; no proof or zkVM execution.
Isolation remains stopped/unactivated and CPU proving paused; proof ledger 2 used/1 unused.

## Final milestone closure — 29 September 2026

**OCT31-KYC-NATIVE-MILESTONE-1 is complete at its approved reference/component
validation scope.** All originally planned 392 distinct cases/trials are covered,
including all 41 pending final-binary/transcript/C-09 checks. There were no native
failures or new builds in this continuation. Baseline and all 276 benchmark results
were reused unchanged; earlier-binary results, failures and rejected admissions
remain separately preserved.

The continuation's complete preservation audit exited 0: 8,759 original plus
2,142 disjoint supplemental comparisons, 10,936 identity-inclusive historical paths,
complete prior seals/report prefixes and a 10,732-entry inventory with no missing
or unexpected names. Audit worker reporting/readback and outer guard passed.
Elapsed guard time was 4.872552 s (worker 4.203994 s); cgroup memory peak was
46,354,432 B under the unchanged 256 MiB ceiling, with no memory-event breach or
swap. Separately sampled summed process-tree RSS was 63,078,400 B; shared mappings
can be counted repeatedly in that metric. All 1,520 local link checks passed.

The first preparation reported the already-sealed `benchmarks/README.md` outside
its traversal root. Content matched its historical seal. Its helper, snapshots and
failure are retained in `native-finalisation-1/failed-preparation-1`; the correction
traverses `benchmarks` in place of its existing testbed subdirectory and retains all
expected names and hashes. Corrected preparation and affected lint/format passed.
No baseline or expected digest was regenerated, no content permission broadened,
and no functional test was repeated for this tooling correction.

Final report seals, final inventory/readback, exact-unit shutdown and all time and
storage accounting are recorded in the [completed continuation closure](data/oct31_kyc_native_milestone_1/native-finalisation-1/validation-closure.json).
The invocation ledger is 867/1,050 (419 milestone invocations; 181 milestone slots
plus two separate historical tooling slots remain). Builds remain 8/13. Analysis
and isolation allowances are unchanged; completion reserves remain inside unused
implementation/evidence balances.

The next bounded native validation target is a nontrivial public R1CS fixture
through the corrected components before considering private integration; no such
work is started here. Complete Aurora correctness, authentication/private-proof
feasibility, query/masking and commitment-transformation arguments, extraction/privacy,
concrete-hash composition, adaptive Delta_tail and production security remain open.
Stages 2–3/AURORA-BRIDGE-001 remain open; isolation stopped/unactivated and CPU
proving paused. No proof or zkVM execution occurred; proof ledger two used/one unused.

## OCT31 closure and full-relation proposal — 29 September 2026

OCT31-KYC-NATIVE-MILESTONE-1 remains complete within its approved scope and is
preserved in place as **OCT31-KYC-NATIVE-MILESTONE-1/v1**, including final native
coverage and all 276 benchmark trials. The existing closure/seals are unchanged.
[OCT31-AUTH-RELATION-INTEGRATION-1](oct31_auth_relation_integration.md) is one
inactive execution proposal for complete same-witness authentication lowering,
streamed counting/checking and nontrivial native R1CS correspondence. Its explicit
request reallocates 2,550 existing implementation seconds, 128 invocations and
three builds; proposes a bounded aggregate work-event cap; and requests zero proof
attempts. No implementation/test/build budget is consumed by this source review.

AUTH-REL-001 remains open: complete private ML-DSA verification (including capped
challenge and inverse transforms), holder/disclosure/same-rid Merkle composition,
compiler equivalence and complete counts are missing. AUTH-CAPACITY-001 records a
conditional no-go for direct one-gate/one-row resident Aurora lowering: one measured
forward NTT implies a >=24 GiB codeword in the corrected family. This is not a
full-authentication measurement or a claim against all compact representations.
A complete streamed descriptor and explicit capacity decision are required before
allocation; a small native fixture cannot close full relation validation.

TB-06/BCS committed-view simulation, private transcript/query correspondence,
state-restoration/quantum round-by-round knowledge, adaptive application extraction/
privacy, finite parameters/concrete hashes, adaptive Delta_tail and production
security remain open. AURORA-BRIDGE-001 and Stages 2–3 stay open; ordinary private
proof acceptance remains fail-closed. Isolation stopped/unactivated; CPU proving
paused; proof ledger two used/one unused. No private proof by 31 October is supported
by current evidence; the proposal identifies the concrete integration/no-go endpoint.
Preparation checks and actual analysis/storage charges are recorded in the new
[proposal closure](data/oct31_auth_relation_integration_1/validation-closure.json).

Proposal preparation preservation passed: one complete audit, 10,901 content
comparisons, 10,936 historical paths, 3.922663s and 43,925,504B cgroup peak under
256 MiB. The final proposal closure records inventory/report readback and exact
analysis-only charges. No implementation, case, build or proof was executed.

## Authentication relation integration — bounded endpoint, 29 September 2026

[OCT31-AUTH-RELATION-INTEGRATION-1 result](oct31_auth_relation_integration_result.md)
implements isolated same-witness source lowering, a streaming Boolean/gf192 R1CS
interface, actual native constraint loader and fail-closed proof boundary. The
75 bounded invocations passed their documented scopes; these include a labelled
2,000,000-gate prefix, not complete authentication. Two builds were used; the first
latent vector-constructor error and one lint failure are retained. Native loader
correction uses existing add_term on validated canonical terms without changing
pinned library code. Cumulative invocations942/1050; builds10/13.

AUTH-REL-001 remains partial: full private sampler, complete verifier and joint
rejection checks, full descriptor and frontier are unvalidated. AUTH-CAPACITY-001
rejects the direct resident route: one conditional codeword lower bound is24 GiB
before other working sets. No such allocation was attempted. The baseline/v1 and
276 measurements remain unchanged. No complete private proof by31 October follows.

Recommend one bounded compact-ML-DSA/R1CS representation contract with exact
semantics and simultaneous-buffer admission before generation; stop this backend
route if none fits. AURORA-BRIDGE-001, commitment simulation, extraction/privacy,
concrete hashes/finite parameters, adaptive Delta_tail and production security
stay open. Stages2–3 remain open; ordinary private-proof verification fail-closed.
Isolation stopped/unactivated; CPU proving paused; proof ledger2 used/1 unused.
Final preservation and exact remaining resources are recorded in the result and
[closure](data/oct31_auth_relation_integration_run_1/validation-closure.json).

Integration preservation audit passed:10,901 disjoint content comparisons,10,936
historical paths and10,999 inventory entries; guard5.595654s, cgroup peak54,116,352B
under256 MiB. Final readback/accounting is recorded in the linked closure; complete
private relation/proof admission remains blocked, independent of preservation.

## Compact authentication representation — 29 September 2026

[OCT31-COMPACT-AUTH-REPRESENTATION-1](oct31_compact_auth_representation.md)
implemented exact experimental GF192 affine XOR/NOT elimination with constrained
spills, free-bit guards and every original AND retained. All29 new invocations
passed:24 candidate fixtures, four actual-native comparisons and one resource
model. Existing native binary reused; no new build. Cumulative971/1050 invocations,
10/13 builds; work27,593,603/2^32 including prior consumption.

**Full resident admission fails.** The six required measured-core NTT embeddings
retain43,401,216 AND rows, giving a conditional48 GiB per codeword and192 GiB
for four simultaneously retained codewords, before other working structures.
The complete count is unmeasured; residual hashing, sampler, inverse arithmetic,
parsing/disclosure and same-rid Merkle costs are explicitly included symbolically.
The previous2M joint stop was its declared local probe cap, not a forced2M
count-only ceiling; raising it or streaming cannot resolve resident capacity.

AUTH-CAPACITY-001 remains open with a precise no-go for AND-preserving mapping.
AUTH-REL-001 remains partial; all21 outstanding full-relation checks stay unrun.
The guarded modmul's row count falls15,224→6,367 but nonzero terms grow51,888→135,198;
row reduction is not a measured prover-memory saving. No complete private
authentication by31 October is supported. A substantive arithmetic/representation
change with field/domain/masking correspondence is required, or stop this backend
route for that target; no further work is started here.

Comparison pointv1 and276 measurements are preserved. Stages2–3, AURORA-BRIDGE-001,
commitment simulation, extraction/privacy, concrete-hash/finite parameters,
adaptive Delta_tail and production security remain open. Ordinary proof acceptance
stays fail-closed; isolation stopped/unactivated; CPU proving paused. Proof ledger
two used/one unused; zero proofs/zkVM executions. Final preservation/readback and
remaining capacity appear in the [closure](data/oct31_compact_auth_representation_1/validation-closure.json).

Compact representation preservation passed:10,901 disjoint content comparisons,
10,936 historical paths, complete inventory/reporting; guard4.400144s and cgroup
peak46,227,456B under256 MiB. Final inventory/readback/accounting is in the linked
closure. This closes the bounded experiment, not complete private authentication.


## Arithmetic R1CS feasibility — 29 September 2026

[OCT31-ARITHMETIC-R1CS-FEASIBILITY-1](oct31_arithmetic_r1cs_feasibility.md)
closes the affine candidate unsuccessfully for resource admission, preserving its
code and results. One exact direct-integer candidate, INT-R1CS-FR254-1, is specified
with canonical ranges, no-wrap quotient/remainder constraints, signed overflow,
bit/byte links, fixed bounded sampling and the same joint authentication predicate.
**No arithmetic gadget implementation was admitted.** The required final SHAKE256
alone has 268,800 chi products; under the candidate's odd-prime hash mapping these
force at least 512 MiB per codeword and 2 GiB for four simultaneous codewords,
before positive remaining costs. XOR has explicit odd-prime constraints, not free
GF192 addition. Complete prime-field counts/peak memory remain unmeasured.

AUTH-CAPACITY-001 / AUTH-R1CS-HASH-001: arithmetic-only optimisation does not solve
this final-hash obstruction, before holder binding, full sampler and twenty Merkle
nodes. The reviewed paper-masking implementation also explicitly requires additive
domains, whereas the proposed field requires multiplicative subgroups. A compatible
masking implementation/argument is absent; the storage bound optimistically retains
the existing degree/rate envelope, not reduced security settings. Stop this route
for the 31 October target unless a substantive hash-representation and compatible
masking construction addresses both gaps. No new proof experiment is proposed.

One calculation/reporting attempt was incomplete due to an omitted new cases
directory. Its original output, diagnostic and conservative work charge are retained;
one explicit routine-correction rerun passed identically. Two invocations consumed,
cumulative 973/1050, builds unchanged 10/13. All 21 full-relation checks remain
unrun; no circuit or large instance was generated. Comparison point v1 and all
276 measurements remain unchanged. Stages 2–3, AURORA-BRIDGE-001, finite-parameter,
concrete-hash, extraction/privacy, adaptive Delta_tail and production obligations
remain open. Ordinary private-proof verification stays fail-closed; isolation
stopped/unactivated; CPU proving paused; proof ledger two used/one unused.

Final preservation and accounting are in the
[closure](data/oct31_arithmetic_r1cs_feasibility_1/validation-closure.json).


Preservation completed: the single full audit exited0 with 10,901 disjoint
content comparisons and 10,936 historical identity-inclusive paths.
It took 4.844211s including the guard (4.444965s worker),
with cgroup-v2 memory.peak 46997504B under256 MiB;
sampled summed process RSS was 63,692,800B and is a distinct metric.
All retained failure records remain present. Final inventory, report readback,
exact-unit shutdown and the authoritative remaining balances are recorded in
[validation-closure.json](data/oct31_arithmetic_r1cs_feasibility_1/validation-closure.json).
No resource admission for the complete representation follows from preservation.


## Joint hash/masking construction decision — 29 September 2026

[OCT31-JOINT-HASH-MASKING-DECISION-1](oct31_joint_hash_masking_decision.md):
**Decision C — close this Aurora route for the current October delivery plan.**
Preserve the arithmetic-only NO-GO. The exact 268,800-chi subset is the internal
ML-DSA SHAKE256(mu || w1Encode(w1),48), not the outer transcript hash.
JHM-FR254-PACKED-1 specifies one prime-field/direct-integer/Boolean-hash candidate
with multiplicative masks and packed salted commitments. Its optimistic resident
codeword/salt/tree payload floor is 7.5 GiB minus 128 bytes, before other relation
components; complete counts and peak remain unknown. This exceeds the existing
limits and observed available memory. No sufficient new resource envelope is
justified by that floor, and no amendment is proposed.

AUTH-JOINT-HASH-MASK-001: close the examined candidate unsuccessfully for delivery
admission. Aurora's multiplicative sumcheck remark supports local algebra; the
native additive-only guard is not a mathematical impossibility result. Full
prime-domain masking/knowledge and packed commitment/EXP2 correspondence remain
unestablished; AURORA-BRIDGE-001 and AUTH-CAPACITY-001 remain open obligations.
The decision is construction-specific, not an attack or universal impossibility.

The concrete delivery decision is to retain 31 October for the validated reference
KYC testbed/native correspondence/comparison dataset, excluding complete private
authentication, or revise scope/deadline and separately authorise a new integrated
construction. No further component optimisation/review or proof starts here.
One bounded calculation passed; retained lint failure plus formatting-only rerun
recorded. Cumulative invocations 974/1,050, builds unchanged 10/13. The 21 full
relation checks remain unrun. Comparison point v1 and all 276 measurements are
preserved. Stages 2–3, complete knowledge/privacy, concrete-hash/finite parameters,
adaptive Delta_tail and production security remain open. Private verification
stays fail-closed; isolation stopped/unactivated; CPU proving paused; proofs two
used/one unused. Final preservation/readback/accounting is in the
[closure](data/oct31_joint_hash_masking_decision_1/validation-closure.json).


Preservation: the single complete audit exited 0, with 10,901 disjoint content
comparisons, 10,936 historical identity-inclusive paths and complete inventory
and report generation. Guard time was 4.720063 seconds (worker 4.384852 seconds).
Cgroup-v2 memory.peak was 46,858,240 bytes, including descendants and charged
cache/kernel, under the unchanged 256 MiB ceiling; sampled summed process RSS
was 63,475,712 bytes, a separate metric. No resource breach occurred.
Final inventory, sealed report readback, exact-unit cleanup and final balances
are recorded in
[validation-closure.json](data/oct31_joint_hash_masking_decision_1/validation-closure.json).
This preservation result does not admit the proposed construction.


## Full-scope implementation consolidation — 29 September 2026

**User-confirmed scope unchanged:** the goal remains the complete privacy-preserving
PQ-DID scheme, KYC testbed and benchmarking. **31 October remains the target;
current evidence does not support committing to full completion by that date.**
No scope reduction or replacement construction has been approved. The previous
recommendation to exclude private authentication was not adopted. Preserve its
historical record; this scope confirmation supersedes that recommendation.

[Implementation consolidation](implementation_consolidation.md) indexes working
reference cryptography/lifecycles, synthetic proof gates, the disclosed/linkable
baseline, native components and incomplete private authentication. Every R-001–R-052
has an evidence/gap entry, not a blanket completion claim. W3C securing mechanisms,
issuer/vocabulary binding, DID method/key representation, private status mapping
and conformance remain unfinished. Complete private-proof measurements are null/
unavailable, never inferred from baseline signatures, component timings or journals.

The exact Aurora route is closed under its assessed construction/resource conditions
(AUTH-JOINT-HASH-MASK-001); this is not impossibility of PQ-DID. The full-relation,
security and simultaneous-resource [handover](data/implementation_consolidation_1/handover.md)
specifies the admission gates for a named replacement integrated construction.
Selection, exact profile deviations, supported security claims/remaining arguments
and a complete bounded resource/validation plan require the user's construction
decision before further private-proof implementation. No replacement is selected.
DELIVERY-SCOPE-001 records this unchanged original scope and unsupported date
commitment; it does not reduce requirements or change the target.

Comparison point v1, final binaries and all 276 measurements remain sealed and
unchanged. [Reproduction information](data/implementation_consolidation_1/reproduction.md)
consolidates exact historical commands/configs and failures without reruns.
Documentary preflight verified 362 dataset/evidence files, 21 source/binary files,
24 historical command records and exactly 52 indexed requirements. No functional
case, build, new circuit or proof ran; invocations remain 974/1050 and builds10/13.
The 21 full-relation checks remain explicitly unrun. Reference holder persistence,
production custody/entropy/erasure/side channels, adaptive Delta_tail, component
advantages, complete knowledge/privacy and concrete-hash/finite parameters remain
open. Stages 2–3 and the original implementation programme are incomplete;
AURORA-BRIDGE-001 remains open. Ordinary private-proof verification stays fail-closed.
Isolation remains stopped/unactivated, CPU proving paused, proof ledger two used/
one unused. Final preservation, readback and balances are recorded in the
[consolidation closure](data/implementation_consolidation_1/validation-closure.json).


Preservation completed: one full audit exited 0 with 10,901
disjoint content comparisons and 10,936 historical
identity-inclusive paths, complete inventory and reporting. Guard time was
4.656938 seconds; worker 4.345925 seconds.
Cgroup-v2 memory.peak was 47,390,720 bytes under
256 MiB, including descendants and charged cache/kernel. Separate sampled summed
process RSS peaked at 64,061,440 bytes. No resource breach occurred.
Final report seals, inventory/readback, cleanup and balances are in the
[closure](data/implementation_consolidation_1/validation-closure.json).
Only this consolidation is complete; the original programme remains incomplete,
with unchanged scope and 31 October target, not a supported completion commitment.


## B64-REPLACEMENT-001 — current candidate not admitted

[Decision](oct31_binius64_replacement_decision.md): **NO-GO for private authentication
at Binius64 commit441fbf51ff0bcb0bcd28f3f1b73f4954029e8577**. Its ZK APIs exist,
but the inspected wrapper publishes the private terminal oracle claim directly,
and the inner zero-padded witness path does not establish the Blueprint's required
q+2 randomisable support. These are source findings, not an executed attack.
Current native SECURITY_BITS=96/GHASH128/SHA-256 cannot establish the intended PQ
knowledge/privacy claims. The OtterSec public-input absorption correction is present
in current caller behaviour; the cited fix commit is not an ancestor, and a specific
adversarial public-input substitution regression was not identified in the inspected
coverage. No native test ran. Cargo's transitive dependency lock is unresolved.

[One conditional integrated plan](data/oct31_binius64_replacement_decision_1/implementation-proposal.md)
records exact relation mapping, native/privacy repair gates, field/hash/masking
obligations, complete live-storage accounting and an inactive consolidated envelope.
It is not an admitted private-proof milestone or adopted profile. Whole-authentication
counts/memory remain unmeasured; no sufficient new allocation is claimed. The user
must decide whether to fund correction of this named route before implementation.
No replacement was silently selected; the examined Aurora experiments remain closed.

The complete scheme, KYC testbed and benchmarking scope is unchanged;31October
remains the target without a supported full-completion commitment. W3C issuer/
vocabulary, DID/key, securing mechanism/private status mappings, holder persistence,
adaptive Delta_tail, component advantages, concrete hashes/finite parameters,
production security and complete quantum knowledge/privacy remain open. Stages2–3
and AURORA-BRIDGE-001 remain open. Ordinary private verification stays fail-closed.
Comparison pointv1/all276 observations and21unrun full-relation checks are preserved.
No tests/builds/proofs/installation/activation: invocations974/1050, builds10/13,
proof ledger2used/1unused. Isolation stays stopped/unactivated and proving paused.
Final preservation and exact balances are in the
[package closure](data/oct31_binius64_replacement_decision_1/validation-closure.json).

- **B64-ZK-001 (implementation + correspondence):** mask the inner private terminal
  oracle claim as Blueprint7.3 requires and constrain the linked key in the PCS and
  outer verifier. Existing plaintext-send path is not admission-ready.
- **B64-ZK-002 (implementation/theorem application):** establish complete randomisable
  support, q+2 inner coordinates, query-opening/claim masking and joint Merkle/FRI
  simulator conditions. Resolve code/Blueprint gamma convention. Library ZK naming
  is not evidence that these premises hold for our relation.
- **B64-PARAM-001 (theorem/possibly new argument):** finite GHASH/FRI/masking bounds,
  classical-to-QROM knowledge/adaptive privacy composition, concrete SHA-256 and PRG
  assumptions at agreed workload/advantage targets. No universal128-bit quantum
  target was agreed by the earlier assessment; its provisional status is preserved.
- **B64-LOCK-001 (reproducibility):** Rust1.98.1 and declared dependencies identified;
  no Cargo.lock or acquired transitive artefact checks. No fallback versions approved.
- **B64-RESOURCE-001 (implementation admission):** count the whole word relation,
  privacy wrapper and simultaneous live buffers before allocating/proving. Observed
  WSL headroom is not the physical16GB; proposed larger ceilings are inactive and
  do not assert sufficient capacity.

The internal source-byte estimate was exceeded by a bounded GitHub comparison
response; all retained metadata stays charged. No enclosing per-file/output ceiling
was exceeded. Further acquisitions stopped; completion uses the existing reserve.
The source-budget observation remains evidence rather than being silently reset.


Preservation completed: the full audit exited **0**, with **10,901**
disjoint original/supplementary content comparisons, **10,936** historical
identity-inclusive paths, no missing or unauthorised content, and completed inventory
and reporting. Outer guard **4.539334s**, worker
**4.203199s**, cgroup-v2 memory.peak
**47,255,552 bytes** under256MiB (worker,
descendants and charged cache/kernel); sampled process-tree RSS separately
**63,913,984 bytes**. No cgroup resource event occurred.
Scoped lint/format and documentary source/v1 checks passed; no native code ran.
[Final inventory, report readback, cleanup and exact resource balances](data/oct31_binius64_replacement_decision_1/validation-closure.json)
complete this source-decision package only. Metadata acquisition used bounded reads,
per-request timeouts and256MiB process address-space limits; it has no cgroup peak
measurement and must not be conflated with the measured audit worker.


## B64-ZK-001 / B64-ZK-002 — G0 disposition

Both remain open; [G0](oct31_binius64_g0.md) is a substantive construction NO-GO.
B64-ZK-001 is confirmed through the actual verifier's public equality. B64-ZK-002
is now a confirmed inner implementation gap: encode_masked preserves the original
packed row, while query openings reveal it alongside the independent random row.
No repair changes are silently adopted.

**B64-G0-COMPOSITION-001 (open):** establish a relation-preserving random-support
embedding in the actual RS basis, committed terminal-pad equality across the inner
oracle/outer constraints, and one joint simulator for all compiled observations
and actual oracle shapes. Include the native IntMul auxiliary path and exceptional
affine-gamma challenges. A count of q+2 coordinates, an OTP send change or marginal
privacy tests is insufficient. This requires a construction argument, not merely
new test evidence. It does not assert overall approach impossibility.

**B64-G0-RESOURCE-001 (open for later execution):** shared remaining evidence at
opening is 1,737,206 bytes, below the inherited 2,097,152-byte ordinary-job completion
reserve. No ordinary test job admitted; reserve not reset. Source diagnosis and
completion remain within actual caps. Future execution requires prospective nested
reservation reconciliation; extra space would not resolve the construction issue.

QROM/finite bounds, adaptive Delta_tail, production security and complete privacy/
knowledge remain open. Full original delivery scope unchanged; 31 October target
retained without an unsupported completion commitment. Proof ledger two used, one
unused. No backend replacement or G1–G3 authorisation is inferred.

G0 preservation checkpoint: complete audit exit 0; 10,901 disjoint original
comparisons, 44.875 MiB cgroup peak under 256 MiB. Final readback/shutdown and
charged balances are recorded in the G0 closure; construction NO-GO unchanged.


KYC-TESTBED-COMPLETION-1 opening: G0 NO-GO accepted. The pinned Binius64
route remains paused; no G1–G3, speculative repair or backend survey is admitted.
Reopening requires the specific committed-key/support/joint-view construction
and security correspondence in the G0 report. The newly authorised KYC workstream
retains full original scope; Stages 2–3 and private authentication remain open.
Execution plan and resource/mapping decision are recorded in
`docs/kyc_testbed_completion.md`; affected tests have not run.

KYC preparation checkpoint: isolated wallet draft and 72-case/observation plan
prepared; no new functional requirement marked satisfied. Static/identity checks
and complete preservation audit passed (10,901 historical comparisons). Execution
awaits the consolidated evidence reallocation/local-mapping decision; the original
workstream approval stands. Workstream incomplete; no new baseline/private proof
measurement, build or functional invocation. See KYC preparation closure for final
accounting. G0 NO-GO and all paused-route/security boundaries remain unchanged.

### KYC-TESTBED-SCALE-001 — bounded baseline storage scalability (open)

The authorised testbed continuation measured one-record catch-up and 18 genuine
presentations. R-1-4 failed before catch-up: the existing baseline issuer's complete
session inventory exceeded the 65,536-byte local encoding cap at certification.
Retained state has three CERTIFIED sessions, one SIGNING, with permanent allocation
preserved and no failed credential delivery. Independently, eight manager records
alone total 89,328 bytes before other checkpoint fields, so that case is unadmitted.
No limit increase, replacement storage design or substitute measurement is approved
implicitly. Larger-scale completion needs a versioned incremental authenticated
issuer/manager store with atomic outcome/head updates, fencing, independent recovery
and permanent ID retention, followed by bounded scale/failure tests. Preserve v1.
See [failure evidence](data/kyc_testbed_execution_1/failure-analysis.json).

KYC-INT-001–004: the user approved the precise **local** issuer/vocabulary table,
separate raw ML-DSA DID-key metadata and canonical-bound projections. Those local
choices are now implemented/tested; standards-level securing, externally recognised
key representation, issuer governance and private status mapping remain open.
Durable holder reference storage now has focused crash/recovery evidence, conditional
on independent tickets and trusted local custody. Power-loss/whole-store rollback,
encryption, production erasure/side channels and genuine private proofs remain open.
B64 G0 NO-GO remains recorded; no G1–G3. AURORA-BRIDGE-001 and the complete security
obligations remain open. No original scope reduction or supported full-completion
promise for 31 October follows from this workstream.

KYC continuation preservation: complete audit passed (10,901 disjoint historical
comparisons, 10,936 identity-inclusive paths), under the unchanged 256 MiB audit
ceiling. See the execution validation/resource closures for final readback,
shutdown and balances. Functional scaling failure remains open.


### KYC-ISSUER-INCREMENTAL-STORAGE-1

The isolated v2 issuer stores bounded per-session records and atomic digest-event/head
updates, with explicit origin-bound migration and independent freshness tickets.
35 storage/recovery cases, eight genuine bounded-ML-DSA application cases and three
new baseline scaling observations passed (46 invocations; 1,091/1,146 cumulative).
The retained v1 four-record failure is reproduced on a sealed copy, then resolved in
v2; actual four-record catch-up now passes. R-2-1 and R-2-4 are newly measured.
R-1-8/R-2-8 remain unrun: the unchanged manager aggregate checkpoint needs at least
89,296 update-payload bytes before other fields, exceeding 65,536; its observed
four-record database is already 475,136/524,288 bytes. The manager needs a separately
scoped incremental history/checkpoint/outcome design before larger-scale admission.
No manager architecture or limit was changed implicitly. See
[issuer storage report](kyc_issuer_incremental_storage.md) and its new evidence series.
Original 276 and subsequent 19 observations, v1, protected sources and failures stay
unchanged. Private authentication/security/standards obligations and Stages 2–3 remain
open; this is not completion of the KYC workstream or original programme. Binius64
remains paused, private verification fail-closed, proof ledger two used/one unused.

KYC-TESTBED-SCALE-001: issuer aggregate-encoding sub-issue resolved for the tested
v2 isolated stores; manager aggregate checkpoint/retained-storage sub-issue remains
open. Earlier failure and 89,328-byte framed estimate are preserved. The new 89,296
raw-payload lower bound is deliberately more conservative, not a passed eight-record
experiment. Migration/recovery assumes independently retained trusted tickets;
whole-store rollback, power loss and production custody are not established.


Preservation checkpoint: the single full audit **passed**, exit 0, with
10,901 disjoint historical comparisons and
10,936 identity-inclusive paths; no changed/missing
protected content or inventory discrepancy. Guard time 4.840s; worker
`memory.peak` 48,730,112 bytes (46.473 MiB), including descendants
and charged cache/kernel, below 256 MiB with no resource breach. Final inventory,
report readback, terminated workload and actual balances are recorded in
`docs/data/kyc_issuer_incremental_storage_1/validation-closure.json` and
`resource-closure.json`. Historical failures remain failures; two eight-record
measurements remain unrun, and no missing private-authentication result is supplied.


### KYC-MANAGER-INCREMENTAL-STORAGE-1

The isolated manager-v2 storage, bounded public-state paging and atomic holder
catch-up now pass 47 distinct checks (49 invocations including two retained, corrected
failures). R-1-8/R-2-8 completed: eight updates, two 55,041-byte responses, one final
wallet update; manager DB 450,560/524,288 bytes. Largest validated history is eight.
One/four-record affected measurements are also retained as a new series. Original
276, subsequent 19 and issuer-v2 three observations remain immutable. No larger-scale
capacity, private authentication or privacy-overhead claim follows. See
[manager storage report](kyc_manager_incremental_storage.md) and its individual outcomes.
Cumulative invocations 1,140/1,146; builds 10/13; proof ledger two used/one unused.
KYC-TESTBED-SCALE-001's tested four/eight-record obstruction is resolved for v2;
production custody/rollback/power-loss, larger capacity, standards-level interoperability
and full proof/security obligations remain open. Stages 2–3 remain open; private
verification fail-closed, Binius64 paused, proving/isolation paused. The full scope
and 31 October target remain unchanged without a supported completion commitment.


Preservation checkpoint: the single full audit **passed**, exit 0, with
10,901 disjoint historical comparisons and
10,936 identity-inclusive paths; no changed/missing
protected content or inventory discrepancy. Guard time 4.878s; worker
`memory.peak` 49,483,776 bytes (47.191 MiB), including descendants
and charged cache/kernel, below 256 MiB with no resource breach. Final inventory,
report readback, terminated workload and actual balances are recorded in
`docs/data/kyc_manager_incremental_storage_1/validation-closure.json` and
`resource-closure.json`. Historical failures remain failures; two eight-record
measurements remain unrun, and no missing private-authentication result is supplied.


### Retained evidence handover checkpoint

The completed issuer-v2/manager-v2/wallet/paged-history results are registered as
`KYC-BASELINE-ISSUER2-MANAGER2-WALLET-PAGED-1` in
`docs/data/private_proof_handover_1/comparison-point.json`; earlier datasets and
failures remain unchanged. Packaging the retained G0 evidence stopped at the
1 MiB per-file ceiling (1,065,684 bytes, 17,108 over). The failed archive and guard
record are retained; archive readback/full final audit remain incomplete. See
`docs/private_proof_handover.md`. No new analysis, functional cases, builds or proofs.
Binius64 stays paused, private verification fail-closed, Stages 2–3 open; original
scope and 31 October target unchanged without a supported completion commitment.


Private-proof handover continuation: the exact-path 2 MiB prospective exception
was approved. Retained v1 is complete and reused unchanged: 1,065,684 bytes,
112 safe members, exact payload hashes, complete compression readback. No v2 was
created. The original overrun remains a failure. Current identity is
`docs/data/private_proof_handover_1/continuation-1/archive-verified.json`; final
preservation/closing records govern handover completion. No functional tests,
builds, new security analysis or proofs; Binius64 paused and private verification
fail-closed. Original scope, 31 October target, Stages 2–3 obligations unchanged.


Preservation continuation: the single complete audit passed, exit **0**, with
10,901 disjoint historical content comparisons and
10,936 identity-inclusive paths; no missing or
unexpected inventory entries. Guard time **4.767 seconds**, worker
`memory.peak` **49,307,648 bytes** (47.023 MiB), including descendants
and charged cache/kernel, below 256 MiB. The final inventory, reporting readback,
workload shutdown and exact remaining balances are recorded in
`docs/data/private_proof_handover_1/validation-closure.json` and
`resource-closure.json`. The original failure and all earlier datasets remain
unchanged; this is completion of packaging only.


### S3-BINIUS-JOINT-OPENING-CONSTRUCTION-1

[Joint-opening construction decision](stage3_binius_joint_opening_construction.md):
**NO-GO for a native correction prototype on the established correspondence.**
The joint zero-target equation has a local same-commitment binding argument and a
conditional aggregate-mask coupling. It does not establish joint-view privacy.
New pinned NTT source resolves the earlier generic example: native `E(m)[0]=m[0]`,
so randomising a trailing support cannot hide a witness-dependent first symbol.
`B64-JOINT-001` requires the explicit embedding, support/image condition and
sequential commitment/opening simulator/extractor in JOINT-OPENING-LEMMA-1, across
all oracle shapes including IntMul. Its logup helper internals remain unacquired.
The exact specialist question is in the report; no implementation package is active.

The user-supplied independent review is retained unchanged. Ten necessary source
files were obtained at the unchanged pin, with verified tree blob IDs. The
acquisition's lifetime RSS diagnostic exceeded 256 MiB while its address-space
limit was installed; no before/after baseline or cgroup trace resolves that
observation. `B64-JOINT-RESOURCE-001` remains open: do not certify that acquisition
as resident-memory-compliant. No further acquisition/probe followed. Full
preservation and its completion-worker measurements are recorded separately.

No functional tests, builds, proofs, benchmarks or activation. Invocations remain
1,140/1,146, builds 10/13, proof ledger two used/one unused. Existing analysis
allowance alone is charged; implementation/KYC balances and reserves remain
unchanged. Comparison point v1, all 276 original measurements, later KYC datasets
and 21 unrun full-relation cases remain unchanged. Binius64/proving/isolation stay
paused; private verification fail-closed; Stages 2–3 open. Full project scope and
31 October target remain unchanged without a supported completion commitment.


### Preservation completion checkpoint

The single full audit passed, exit **0**: **10,901**
disjoint historical content comparisons and **10,936** identity-inclusive paths,
with no changed/missing protected content or inventory discrepancy. Audit guard
time was **4.635 seconds**; cgroup-v2 `memory.peak` was
**47,558,656 bytes**, including descendants and charged
cache/kernel, below 256 MiB. This certifies the audit worker, not the unresolved
source-acquisition lifetime-RSS observation. The first static run's E501 failure
and exact formatting correction are retained; the affected repeat passed. No
functional case was run. Final report seal, inventory/readback and exact closing
analysis balance are in `docs/data/s3_binius_joint_opening_construction_1/` `manifest.json`, `validation-closure.json`
and `resource-closure.json`. Historical baselines and previous failure records
were not regenerated or changed. This completes a construction decision and
preservation checkpoint, not a native privacy repair or proof-security claim.


## S3-BINIUS-EMBEDDING-CORRESPONDENCE-1 — preparation only

The proposed native-embedding addendum is assessed in
[the component report](stage3_binius_embedding_correspondence.md), with the inactive
execution plan in `docs/data/s3_binius_embedding_correspondence_1/`.
The retained bit reversal, interleaving and basis contracts support the proposed
even/odd embedding and its low-degree random-polynomial rank argument. This is
source/mathematical correspondence, not an executed native comparison. The
restricted joint-view lemma requires fixed operands/public aggregate, independent
fresh masks and nonzero gamma. It excludes commitment roots, online transcript
order and extractor access; individual mask claims cannot be substituted for
its aggregate claim. Terminal joint-opening, commitment simulation, extraction,
QROM/concrete-hash and finite-security obligations remain separate and open.

`B64-JOINT-001` is narrowed by an explicit embedding proposal, not closed.
`B64-ZK-001/002` remain findings about the unchanged implementation.
`B64-JOINT-RESOURCE-001` and every earlier failure remain retained. No new source
acquisition, functional test, build, proof or activation occurred in preparation.
The requested component is inactive: 200 existing implementation seconds outside
KYC, 25 fixed cases plus three correction reruns (28 total, requiring ceiling
1,146 to 1,168), and inspection of 15 exactly pinned missing source files. Native
comparisons remain unrun/unreserved; no build or dependency installation is sought.

Invocations remain 1,140/1,146, builds 10/13 and proofs two used/one unused.
Implementation 810.6179695621813 seconds and KYC 443.3903556420428 seconds remain
unchanged, including the KYC 300-second reserve. Only existing analysis capacity
funds preparation. Comparison point v1, all 276 original measurements and later
KYC datasets are preserved; the 21 full-relation cases remain unrun. Stages 2–3
remain open; private verification fail-closed; Binius64, proving and isolation
paused. Full project scope and 31 October target remain unchanged, without a
supported commitment to full completion. Final preservation/accounting is recorded
in the component report and its closure files.


### Preservation completion checkpoint

The single full preservation audit passed with exit **0**: **10,901**
disjoint historical content comparisons and **10,936** identity-inclusive
paths; no protected changes, missing files or inventory discrepancy. Guarded wall
time was **4.742 seconds** and cgroup-v2 `memory.peak` was
**48,177,152 bytes**, covering the worker and descendants plus charged
cache/kernel memory, below the unchanged 256 MiB ceiling. Static lint/format and
preparation also passed on their first runs. The report seal and final inventory/
readback are completed through the existing workflow; their definitive outcome and
exact closing balances are in `docs/data/s3_binius_embedding_correspondence_1/`
`validation-closure.json` and `resource-closure.json`.

This completes preparation and preservation only. All EC/N cases remain unrun;
the component implementation/allowance request remains inactive. Implementation,
KYC, invocation, build and proof balances are unchanged. Historical resource
qualifications remain open; this audit does not certify the earlier acquisition.


## S3-BINIUS-EMBEDDING-CORRESPONDENCE-1 — authorised attempt, representation stop

The approved 15 source blobs (176,779 bytes) were acquired at the unchanged pin;
length, Git blob and SHA-256 records are retained. Acquisition passed the new
256 MiB cgroup guard (25,866,240-byte cgroup peak); the earlier acquisition-memory
qualification remains unresolved. No additional source or dependency was acquired.

**B64-EMBED-REP-001:** the approved files invoke but do not define `binary_field!`.
The missing `crates/field/src/binary_field.rs` (24,075 bytes; tree blob
`d073d856abf2d1a2ad58b9a0dbe6b7a49460f1df`) prevents inspection of the exact scalar
associated-constant mapping required for Gao–Mateer/IntMul correspondence.
Metadata is verified from the retained tree; this file's content is unavailable.
Per the approved stop rule, no model/adapter was substituted and EC-01–25 are all
unrun. EC-08 remains a declared-layout check, not arbitrary vector recognition.
Native N-01–04 remain unrun. The component report records acquired logup shapes,
same-Y dual openings, prefix/suffix point ordering and unresolved proof obligations.

Prospective invocation ceiling is now 1,168; consumption remains 1,140. Builds
10/13, proof ledger two used/one unused. Implementation alone pays this attempt;
KYC/analysis balances and reserves are unchanged. Per-case outcomes, final audit
and exact closing balances are under
`docs/data/s3_binius_embedding_correspondence_1/execution/`.

Production, BC-1, all baselines/measurements and historical failures are preserved.
Stages 2–3, terminal joint-opening, commitment/online simulation, extraction,
QROM/concrete security and adaptive-tail obligations remain open. Binius64,
proving and isolation remain paused; private verification fail-closed. Full scope
and 31 October target are unchanged without a supported completion commitment.
No subsequent package is active. This is an evidence-dependency stop, not a
counterexample to the embedding lemma or a NO-GO for the overall PQ-DID approach.


### Execution preservation and retained tooling corrections

Full preservation passed, exit **0**, in **4.534 guarded seconds**:
**10,901 disjoint historical content comparisons**, **10,936 identity-inclusive
paths, and no missing/changed protected file or inventory discrepancy. Cgroup-v2
`memory.peak` was **48,721,920 bytes**, including descendants and charged
cache/kernel memory, below 256 MiB. The final inventory/report seal/readback and
precise closing ledger are in `execution/validation-closure.json` and
`execution/resource-closure.json`.

Three tooling failures are retained, separately from the unrun EC cases:

1. `quality`: E501 in a diagnostic string; splitting the literal preserved its
   exact runtime value and AST. The affected `quality-2` passed.
2. `prepare`: the new helper wrote its newly collected snapshot twice; the
   established auditor refused the second write. The original partial
   `checked-inputs.json` is preserved. The correction writes once to
   `checked-inputs-v2.json` after including the isolated README; no original
   expected entries, hashes or baselines changed.
3. `quality-3`: stopped before starting a worker because the reused resume helper
   recognised the initial lint stop but not the retained preparation stop. The
   correction admits only the exact three recorded failure phases and verifies
   their retained hashes/reasons; unknown stops or resource failures still stop.
   `quality-4` passed, then `prepare-2` passed. No functional invocation was used
   for these static/preservation checks. Every failed guard/log/stop record remains.

The single full audit then passed. Finalisation preserves the approved 1 MiB
package-output cap and 2 MiB shared completion reserve. No actual resource breach
occurred in this attempt. No component result, native correspondence or security
claim is inferred from preservation success. The outstanding construction still
needs same-object terminal joint opening, commitment/online simulation and
extraction correspondence; supplying the missing macro source alone would address
only this component's representation-admission evidence.


### S3-BINIUS-EMBEDDING-CORRESPONDENCE-1 — approved scalar-source continuation

The extra 24,075-byte `binary_field.rs` at unchanged commit
`441fbf51ff0bcb0bcd28f3f1b73f4954029e8577` passed retained-tree/blob/length checks;
SHA-256 `4907b827c90b585f110186524cdb5442e37e6b5f0ded79544a1c5f343c189390`.
The 15 original files/seals are reused. `B64-EMBED-REP-001` is resolved at the
scalar Python-model admission layer. The historical blocked attempt is preserved.

Isolated layout/encoder/reference/operand/query helpers implement the approved
component; EC-01–EC-25 all passed once, with no case corrections/reruns. EC-08
checks an explicit declared parity mismatch, not arbitrary-vector detectability.
Six complete small encoder outputs match independent polynomial arithmetic;
aggregate/individual-claim controls preserve the restricted lemma's qualifications.
Native N-01–N-04 remain unrun. Detailed individual outcomes and source correspondence
are in [the report](stage3_binius_embedding_correspondence.md) and
`data/s3_binius_embedding_correspondence_1/continuation-1/case-summary.json`.

Invocations: **1,165/1,168**; three corrective slots unused; builds **10/13**;
proofs **two used/one unused**. The same 200-second package and 1 MiB evidence cap
apply, with KYC/analysis allowances untouched. The narrow README evidence-accounting
fix and both passing static checks are recorded separately; no historical failure
was rewritten. Final preservation/result and exact ledger follow below and in the
continuation closure files.

Terminal same-object joint opening, commitment/online simulation, extraction,
exceptional-challenge soundness, quantum/concrete security and adaptive-tail
obligations remain open. The historical acquisition-memory observation is still
unresolved. Production/profile/baseline datasets are unchanged. Stages 2–3 remain
open; Binius/private proving and isolation remain paused, private verification
fail-closed. No full private-authentication or native-security claim is made.


### Continuation preservation and completion record

The full comparison audit and outer resource guard passed, exit **0**, in
**4.741370 seconds**, with cgroup-v2 `memory.peak`
**49,397,760 bytes**, below the unchanged 256 MiB
ceiling. Coverage was **10,901** disjoint original/supplementary content
comparisons and **10,936** identity-inclusive paths. Content, report prefixes,
seals, documentation and inventory checks passed; no unexpected/missing protected
files or overlapping partitions were reported.

A preceding launcher failed before the comparison auditor was entered because
its preparation omitted the required `scope_sha256`. This is retained as
`continuation-1/full-audit.json`, its log/service record, `STOP.json`, and the
byte-identical failed-result snapshot `audit-failure.json`. The routine correction
restored that required scope-hash check, retained the old helpers and preparation,
and used new `quality-3`, `prepare-2` and `full-audit-2` records. Both corrected
static/preparation phases passed. There were **two launcher attempts, one failed
before comparisons, and one complete comparison audit**; nothing was refunded or
retroactively labelled successful. No case was rerun and no resource ceiling was
increased. The failed result remains separate from the successful aggregate result.

Five additional conservative correction/bookkeeping seconds are charged, making
**50** operator seconds plus all guarded continuation times, on top of the
unchanged prior **61.68825586186722 seconds**. This replaces the provisional
45-second operator figure above prospectively. Final inventory, report seals and
readback are recorded in `continuation-1/validation-closure.json`; exact consumed
and remaining balances, including all failures, are in
`continuation-1/resource-closure.json`. Those closure records determine final
completion, rather than the comparison-only evidence.

EC-01–EC-25 are passed **Python-model results**; native comparisons remain unrun.
The component resolves scalar admission and supplies independent small-instance
embedding evidence. It does not discharge terminal same-object joint opening,
commitment/online simulation, extraction or quantum/finite-parameter security.
Stages 2–3 stay open, production verification fail-closed, Binius/proving/isolation
paused, and the proof ledger two used/one unused. No subsequent package is started.


## CV-ONLINE-SAME-OBJECT-1 — committed-view simulation and shared extraction

**Open; bounded S3-BINIUS-COMMITTED-VIEW-CORRESPONDENCE-1 attempt closed.**
[Report](stage3_binius_committed_view_correspondence.md), especially sections 4–7.
The proposed protocol fixes both transparent IntMul rows to one Y and distinct
slots of the same outer z, and replaces individual terminal targets with global
joint relations. This is an unadopted construction, not a source correction.

SIM-A cannot adapt ordinary early binding roots to later constraint-compatible
objects. SIM-B needs an online correlated outer-prefix simulator and a quantified
fresh-programming/conditional-entropy argument for the actual deterministic
Merkle/folding/hash view. CV-RANK-1 derives a conditional residual-rank criterion:
given complete V, a paired original/companion leaf does not provide two independent
field symbols. Neither m>q nor the stronger-view saturation example settles
privacy for the native projected/folded view.

A specialist result must construct that online simulator and a compatible
extractor returning the same inner objects and OZ across the relevant forks, or
give an actual-view counterexample identifying a required protocol change.
Classical ideal-oracle premises, native lift/permutation correspondence, finite
bounds and quantum/concrete-hash requirements must remain distinct. No native
prototype is admitted. Existing terminal-opening, commitment, extraction,
adaptive-tail, production-security and acquisition-memory issues remain open.
No parameters, manuscript text, encodings or production code are changed.


### Completed comparison audit and finalisation

The single complete preservation audit passed, exit **0**, in **5.025703 seconds**.
It completed **10,901** disjoint historical content comparisons and **10,936**
identity-inclusive paths; no content discrepancy, missing protected entry or
partition overlap was reported. The audit-time inventory contained **12,472**
paths. Documentation/link checks and report generation/readback within the audit
passed. The enclosing guard passed: cgroup-v2 `memory.peak` **48,558,080 bytes**,
sampled tree RSS **63,836,160 bytes**, swap peak zero, no memory-limit/OOM event,
under the unchanged **268,435,456-byte** ceiling. The cgroup metric covers the
worker and descendants, including charged anonymous, file-cache and kernel memory;
the external monitor is outside that cgroup. The two metrics have different
accounting scopes and must not be added or treated as interchangeable.

Static/lint/format and sealed-input checks passed in **0.327315 seconds**; inventory
preparation passed in **0.810629 seconds**. This is zero functional validation
invocations. The final inventory, sealed-report readback and termination evidence
are completed by the package's `validation-closure.json`; exact final resource
usage and remaining balances are in `resource-closure.json`. Neither earlier
comparison-only results nor this paragraph alone substitutes for that closure.

The construction result is an unresolved lemma, not a supported implementation
release. The completed embedding results and unresolved acquisition-memory
observation are preserved. No implementation/proof follows this package.


## KYC-TESTBED-DELIVERY-1 — current delivery evidence

[Delivery report](kyc_testbed_delivery.md) and
[interoperability limits](kyc_testbed_interoperability_limits.md) provide the current
reproduction entry points and requirement boundary. All 18 fixed invocations passed
once: 10 genuine baseline demonstrations, 4 export checks and 4 smoke observations.
No functional rerun occurred; one failed static pass and its correction are retained.
V2 recovery uses the versioned issuer interface, not historical Scenario.reopen.
Seven-update catch-up used two bounded pages; own revocation reached epoch eight.
The baseline wallet and private reference wallet remain different objects; the DID
registry remains an in-memory reference service.

Verified/exported 302 retained successful observations in separate 276/19/3/4
datasets, with seven historical failed invocations separately indexed; four new
runner-smoke observations remain separate. No distribution/capacity/private-proof
measurement is inferred. The earlier statements that benchmarks do not exist or
eight-record scaling remains unrun are superseded by the retained benchmark and
manager-v2 results; their historical text/evidence is preserved.

Ledger before finalisation: 1,183/1,190, four delivery correction slots and three
embedding-only slots unused, builds 10/13, proof ledger two used/one unused. The
20-second preparation charge and 80-second internal transfer are recorded once;
220-second package and 2 MiB evidence caps retain KYC's 300-second/shared 2 MiB
reserves. Exact checkpoint and balances are in data/kyc_testbed_delivery_1 closures.
KYC-INT-001–004 remain standards obligations; approved local projections are not
secured VCs/VPs or an invented cryptosuite. CV-ONLINE-SAME-OBJECT-1 remains unresolved
and its attempt closed. Full scope, 31 October target and Stages 2–3 remain unchanged;
no supported full private-authentication completion commitment follows. Private
verification is fail-closed; Binius64 proving/isolation paused. No next package.

### KYC delivery preservation correction and final checkpoint

All 18 fixed delivery cases passed once. The first preservation comparison rejected
the newly appended benchmark README because its exact documentation permission was
missing at the inherited primary layer. The retained 211-byte prefix seal matched;
the routine correction registered only that filename while retaining prefix checks,
immutable inputs and the failed attempt. Corrected static/preparation/full audit
passed: 10,901 historical content comparisons and 10,936 identity-inclusive paths.
See docs/data/kyc_testbed_delivery_1/validation-closure.json for final inventory,
readback and termination, and resource-closure.json for exact final balances.
No functional revalidation was needed for this tooling-only correction. Baseline
items alone are eligible for closure; KYC-INT-001–004 and CV-ONLINE-SAME-OBJECT-1,
private authentication/security and Stages 2–3 remain open. All pauses are unchanged.


## LIGETRON-CORRECTION-AND-ADMISSION-1 — CPU component result

The [component report](ligetron_correction_and_admission.md) records an isolated
six-path overlay against public commit 4b1cdef1bfdf4497fb3e38170db4541fba3f6c12.
Commit/tree records verify the 19 snapshot blobs plus the pinned BN254 source.
Checked entropy, seeded query blocks, bounded field rejection and separated
challenge streams are implemented in shared routines. One CPU build and all 35
fixed cases passed once; zero functional reruns. Full WebGPU/VM/proof paths remain
unrun. The retained dependency-index, static and pre-admission CLI failures are
recorded with their corrections; no historical evidence was overwritten.

LIG-PARAM-MASK-001, LIG-PUBLIC-EXPANSION-001, LIG-COMMIT-FS-001 and
LIG-KNOWLEDGE-PQ-001 remain open as detailed in the report. The strict privacy
parameter premise is not met by the unchanged direct mapping; separate-IV public
AES expansion and complete commitment/compiler correspondence are unestablished.
**Private-proof admission remains denied.** Passing components neither repairs
those construction gaps nor establishes complete authentication or a security level.

Final preservation and exact accounting are in
`data/ligetron_correction_admission_1/validation-closure.json` and
`data/ligetron_correction_admission_1/resource-closure.json`. The 30-second
preparation debit and 600-second/39-slot amendments are prospective and separately
recorded. KYC capacity/reserve and all prior reserved slots remain untouched.
Baseline datasets and failures remain preserved; Stages 2–3 stay open, Binius
correspondence stays closed/unresolved, verification fail-closed, proving/isolation
paused, proof ledger two used/one unused. No subsequent package starts.


### Final preservation result

The single complete audit passed, exit 0, in **7.187452 seconds**
(including guarded launch/completion). Audit-worker cgroup-v2 memory.peak was
**59,756,544 bytes**, below 256 MiB. It completed **10,901**
disjoint historical content comparisons and **10,936**
identity-inclusive paths. Audit-time inventory: **13,091**;
no missing/unexpected paths or partition overlap. The final inventory, complete
report seal/readback, termination and exact remaining balances are recorded in
the package validation/resource closures. No proof-security obligation is closed.


## LIGETRON-DOMAIN-MASK-CORRECTION-1 — component outcome

[Report](ligetron_domain_mask_correction.md): isolated coset/full-code-mask and
constrained linear/quadratic-mask overlay; 32 fixed cases passed once with no
corrective reruns. CPU build 1 failed before compilation (missing output parent);
build 2 succeeded. Both slots are consumed. Native field/RNG/witness-manager
checks and explicitly labelled CPU transform models are distinguished from
uncompiled/unrun GPU, VM and full prover/verifier paths. Earlier 35-case
randomness evidence and all baseline datasets remain unchanged.

The component uses k8192/ell7936/n32768, 256 padding/192 queries and a disjoint
7H_n code domain. Native public coefficient degree requires D_L=2k-1, rather
than the cited paper's k+ell-1; full theorem correspondence is not asserted.
LIG-PARAM-MASK-001, LIG-PUBLIC-EXPANSION-001, LIG-COMMIT-FS-001 and
LIG-KNOWLEDGE-PQ-001 remain open. No complete private-proof admission follows.
Prospective slot ceiling1265 and allocation360s outside KYC preserve consumption
and reserves. Exact closure: data/ligetron_domain_mask_correction_1. Stages2–3
remain open, Binius correspondence closed/unresolved, verification fail-closed,
proving/isolation paused, proof ledger two used/one unused. No next package.


## LIGETRON-FULL-PATH-ENGINEERING-1 — memory-gated continuation

The [engineering report](ligetron_full_path_engineering.md) records prospective
authorisation and the failed dual-environment memory gate: WSL3,926,478,848 bytes
available and Windows2,363,203,584 bytes free, each below4,294,967,296. No acquisition,
configuration, build, functional invocation, device workload or proof was admitted.
A separately sealed partial source overlay adds bounded file/gzip I/O, explicit
digest initialisation and offline CMake wiring; it remains uncompiled/unvalidated.
Complete statement/protobuf binding and native harness/path work remain unfinished.
E01–E40 are individually UNRUN. Builds13/17 and invocations1250/1313 retain all
historical consumption and reservations; the new synthetic-only proof attempt is
unspent alongside the original reserved attempt (two used, two separately reserved).
Final preservation/accounting: data/ligetron_full_path_engineering_1 closures.
The package is blocked, not complete; resume only after the unchanged4 GiB gate
passes in both environments. KYC383.7084432235879 seconds/reserve300, all datasets
and both completed Ligetron components remain preserved. Degree/masking,
commitment/compiler, challenge expansion, extraction/quantum obligations and
Stages2–3 remain open. Verification stays fail-closed, private proving/isolation
paused; Binius remains closed/unresolved. No automatic next package or restart.
