# S3-MLDSA-ARITHMETIC-LOWERING-REVIEW-1 — arithmetic representation decision

26 September 2026. **Select one experimental kernel for a separately authorised
pilot: multiplication of a private canonical residue by a public canonical
constant, using 23-bit operands, an exact 46-bit product and fixed restoring
reduction modulo q.** This is an implementation-ready design, not implemented
arithmetic or a measured improvement. It requires a proposed compiler/profile
change; it is not an optimisation admitted by frozen BC-1.

Recommend only **S3-MLDSA-MODMUL-LOWERING-PILOT-1** below. All proposed execution
allowances remain inactive. The completed hint candidate remains experimental and
non-BC-1; neither candidate admits a complete authentication/proof profile.

## Authority, identities and opening balances

Only manuscript Sections **II–VIII**, SPEC-001–004 and the
[current specification](implementation_spec.md) are authoritative. VII-A.5/.6
requires bounded signature verification and exact checked compilation; V-B fixes
the complete authentication relation; VIII-A separates correctness, capacity and
security losses. The [preserved section extraction](data/s2_concrete_security_assessment_1/sections-II-VIII.txt)
was reused. No claims or timings come from the excluded sections.

[Preflight](data/s3_mldsa_arithmetic_lowering_review_1/preflight-evidence.json)
verified the manuscript SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`,
all 53 assessed source/input entries and the preceding 48-file hint-pilot seal
`50943b9c35df830eeb8c23598c7a40c503b33ef36c21c997b56910b720ae5a13`.
[Reviewed inputs](data/s3_mldsa_arithmetic_lowering_review_1/reviewed-inputs.json)
pin the additional source/evidence used here. Source revision is a content
inventory, not a Git commit. These review pins do not replace an original baseline.

| Ledger at entry | Balance / permitted use |
| --- | --- |
| Analysis | 38.18425933085382/300 s consumed; **261.8157406691462 s remaining**. Only source/evidence/documentation checks and preservation |
| Implementation | 205.62348771607503/300 s consumed; **94.37651228392497 s remaining**, untouched |
| Test/probe invocations | **231/231**, zero available; no amendment in this review |
| Isolation | Safely stopped/unactivated; 100 historical invocations, 22 original identity cases pending, 250.22 s remaining; untouched |
| Proof ledger | **Two attempts used, one unused**; CPU proving paused |

The [sealed host closure](data/s2_concrete_security_assessment_1/host-closure.json)
and [activation disposition](data/s2_authority_isolation_pilot_1/activation-v2-session/session.json)
are reused. Safe termination is not successful identity validation. No host
observation campaign or activation occurred.

The existing analysis workflow charges guarded command wall time plus five seconds
of operator/final-bookkeeping allowance. It is not elapsed conversation time or
permission latency. Preserve 256 MiB cgroup-v2 memory, zero swap, a separate
256 MiB sampled aggregate RSS stop, one worker/two CPUs/four controlled processes,
60 s command/55 s child, 300 s cumulative analysis and a ten-second reserve.
Preserve 8 MiB temporary disk, 10 MiB cumulative evidence, 1 MiB/file, 60 KiB command
logs, 9 GiB storage stop, existing diagnostic stop and 2 GiB headroom. The required
audit uses the unchanged corrected streaming engine. No allowance is borrowed.

## Source map and actual verifier path

The [bounded verifier](../src/pqdid/bounded_mldsa.py) implements the original
ordinary-residue algorithm; see its [provenance report](stage2_bounded_mldsa.md).
The circuit fragments are [scalar_ring](../src/pqdid/circuits/scalar_ring.py),
[words](../src/pqdid/circuits/words.py),
[division](../src/pqdid/circuits/division.py),
[control](../src/pqdid/circuits/control.py) and
[signature decoding](../src/pqdid/circuits/signature.py). They do not yet compose
into a complete private verifier. The Python verifier's complete execution path
must not be described as an already generated Boolean circuit.

Primary specification provenance is [FIPS 204, August 2024](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf),
Algorithms 8, 36, 40–43 and Appendix A, read alongside the recorded DEP-001
clarifications. The standard fixes modular verification and transform conventions;
its equivalent-output implementation latitude does not override this manuscript's
more restrictive circuit profile. No standard-conformance/security certification
is claimed. The source/range conclusions below are also derived directly from the
pinned local functions, rather than extrapolated from a software timing.

Write q=8,380,417, n=256, k=6, l=5, gamma1=524,288,
gamma2=261,888, beta=196 and D=13. The polynomial ring is
`Z_q[X]/(X^256+1)`; NTT coordinates are not coefficient coordinates. The root is
1753 and the public twiddle schedule is `1753^BitRev8(m) mod q`. Forward lengths
halve from 128 to 1, with increasing public starts and indices. Inverse lengths
double from 1 to 128 and traverse reversed, negated twiddles. Neither operation
uses a secret-dependent host index in the proposed circuit.

| Ordered reference operation | Representation, range and mathematical obligation | Visibility / proposed scope |
| --- | --- | --- |
| `_decode_public_key`, `_decode_signature` | pk: rho and six t1 polynomials in 0..1023; z: five polynomials `gamma1-u`, u a 20-bit unsigned decode, hence -524287..524288; hints validated for order, endpoints/count≤55 and zero padding | pk/rho/t1 public; z, challenge seed and hints private. No new pk byte-pattern rejection |
| `_expand_a` | 6×5 polynomials of NTT coordinates, accepted masked 23-bit candidates strictly below q; independent 1026-byte caps | Public rho, but expansion/exhaustion still enforced. Partial output cannot enter arithmetic |
| tr/mu, `_sample_in_ball` | Same pure-message/context framing; challenge c has 49 coefficients ±1 and others zero if bounded sampling completes; 256-byte total cap | tr/public key public; message representative and c private; no sampler changes |
| `_ntt(z)` five times, `_ntt(c)` once | First canonicalise each input modulo q. For each butterfly, p=zeta*b mod q; outputs a+p mod q and a-p mod q, each 0..q-1 | Private data / public twiddles. Source stores right before left, reusing old left; retain that schedule |
| `_matrix_vector_product(A,z_hat)` | Each of six rows has 256 independently accumulated slots; five columns visited in increasing order; reduce product, then reduce accumulator+product every time | Public A times private z_hat. No unchecked five-term or 256-term lazy sum |
| `_ntt(t1*2^13)` six times | t1*8192 in 0..q-1; same ordinary-residue forward transform | Public and eligible for existing all-public folding; not six extra private transforms |
| `az - c_hat*t1_hat*2^D` as implemented | The factor 2^D is already in the t1 transform input. Multiply c_hat by that transformed input, reduce, subtract from az and reduce | Private c_hat / public transformed t1. Multiplying by 2^D a second time would be wrong |
| `_inverse_ntt` six times | Canonical a+b and a-b first; multiply difference by negative reversed twiddle, reduce; finish every coefficient with factor 8347681=256^-1 mod q | Private values/public constants. Forward butterfly count is not an inverse-transform count |
| `_decompose`, `_use_hint`, `_encode_w1` | Positive residue; centred mod 523776 with even tie retained; special q-1 bucket. High in 0..15, low normally (-gamma2,gamma2], exceptional bucket includes -gamma2. At q-1 the pair is (0,-1). Hint selects unchanged high or ±1 mod 16 according to low>0; encode each high in four bits | Private values. Preserve exact sign/tie and exceptional wrap; leave these signed helpers unchanged in first pilot |
| `_norm_ok`, final challenge compare | All original z satisfy strict abs(z)<524092; recomputed full 48-byte challenge equals decoded seed | Norm uses original signed z, not residue! Reference performs it at the end. No early norm rejection or altered accepted set |

There are twelve forward transforms in the reference (six private-data, six public)
and six inverse transforms, each with eight public stages. This is source-derived
control-flow information, not a gate count. Every stage visits 128 butterflies;
public-only folding and distinct twiddles prevent multiplying one measured
butterfly cost into a defensible complete-transform estimate. No dense schoolbook
polynomial convolution occurs in this path: polynomial products use coordinatewise
NTT multiplication and the inverse transform. No signing-only rejection loop,
Power2Round or MakeHint is added to verification.

All multiplications on this specialised verification path have a public factor
(A entry, twiddle, transformed t1 or final inverse constant). A private/private
modular multiply remains useful generic evidence, but would be a less representative
first pilot. The proposed kernel therefore measures public/private multiplication.

## Range invariants and the existing cost problem

A `Scalar` holds a 64-bit word plus COEFFICIENT/NTT domain. `_check` checks width,
wire ownership and domain; **it does not prove a canonical residue**. `multiply`
performs checked signed64 multiplication followed by checked mod64; add/subtract
also check integer representability before reducing. For arbitrary scalar inputs,
`multiply(-1,1)` can validly return q-1, whereas an overflowing signed product
rejects even if its mathematical residue would be small. Merely truncating such
inputs to 23 bits changes the gadget's acceptance language.

For the verifier's canonical arithmetic, stronger invariants are available:

- After every ring operation, 0≤a,b<q. Thus a+b≤2q-2<2^24,
  -(q-1)≤a-b≤q-1, and a*b≤(q-1)^2<2^46<2^63. Ordered accumulator addition
  has the same two-residue bound because each preceding sum is reduced.
- `_ntt` entry normalisation of decoded z needs at most one addition of q when
  negative, since the full **decoded** range lies strictly between -q and q.
  The same holds for c in {-1,0,1}. Do not use the smaller *accepted norm* as an
  entry assumption; out-of-norm signatures must still reach their rejection.
- t1*8192≤1023*8192=q-1. Public matrix coordinates are canonical only after
  bounded rejection sampling succeeds. Publicness does not bypass that condition.
- Every butterfly re-establishes canonical outputs. For inverse multiplication,
  normalise a public negative twiddle to q-zeta. Alternatively keep the old signed
  multiplication; do not silently cast a negative twiddle to unsigned23.
- Keeping the original signed z is essential: `norm_ok(z)` and decomposition's
  centred/exceptional values cannot be replaced by an unsigned residue comparison.
  Domain conversion is an operation boundary, not a relabelling of arbitrary bits.

These bounds justify the absence of integer-overflow faults **only on the proved
canonical domain**. They are insufficient to change `scalar_ring.multiply` for
all signed64 inputs. At every future call site, retain canonicalisation/guards or
provide a compositional proof that a guarded producer establishes the invariant,
including on adversarial signature bytes and all active paths.

The current signed multiplication emits 64 magnitude partial products, 128-bit
ripple additions, sign correction and narrowing checks (SPEC-003). Every mod call
uses all 64 descending magnitude steps, 65-bit subtraction/mux and the signed
floor correction, constructs both quotient and remainder and checks Q then R
(SPEC-004), even when only a remainder is consumed. Add/sub reductions repeatedly
pay this cost after a much smaller ring operation. Decompose additionally needs
centred reduction and division by 523776; UseHint uses mod16. Those operations
remain independent later obligations, not included in the first kernel saving.

### Existing measurements, with their exact scope

Use the **post-adoption**
[18 September SPEC-004 core record](data/stage3_spec004_core_measurements.json),
not the older report's then-provisional division identity. These complete core
counts include sticky rejection/checking and exclude equality-to-test-target
suffixes. Their retained fingerprints have not been regenerated.

| Recorded core | Complete gates / ANDs | Historical count-generation time | Python process peak RSS |
| --- | ---: | ---: | ---: |
| Two private signed64 NTT slots | **83,342 / 34,588** | 0.088815825 s | 26,189,824 bytes |
| Public left 25847 / private signed64 right | **82,757 / 34,393** | 0.086291618 s | 26,189,824 bytes |
| Forward butterfly with public 25847 and two private words | **155,272 / 61,321** | 0.168483568 s | 26,447,872 bytes |

These are count-only generation measurements under the recorded earlier envelope,
not circuit evaluation, proof time or current cgroup measurements. No current
measurement is added by this review. In particular, 25847 is the constant in that
historical gadget measurement; it is **not** the ordinary-residue first twiddle
of this Python transform. Its first used entry is 4808194. Preserve the historical
record and do not infer identical folding/counts for the new constant.

The [hint pilot](stage3_private_hint_lowering_pilot.md) completed 383,420 gates /
203,142 ANDs, while its original 13,532,448-AND baseline is a capped prefix.
Its experimentally shared decoding is not canonical BC-1. Response/norm and
message-preparation costs are separate previously measured components, not
additive evidence of the entire remaining verifier. Full bounded sampling,
NTT/matrix/inverse/decomposition composition and the private Merkle path have no
complete authenticated-circuit count here. No full-transform, full-verifier,
proof-size, speedup or RISC Zero forecast is inferred from the scalar records.

## Two representations considered

| Option | Benefit supported by source structure | Obligations / decision |
| --- | --- | --- |
| **A: canonical unsigned23, exact46 product, fixed restoring remainder** | Matches Python's ordinary residues and the existing high-to-low subtract/select idea. Replaces generic magnitude/sign/64-step work on a proved restricted domain; no twiddle scaling or inverse convention change | New lowering and invariant proof required. Widths suggest a worthwhile measurement; gate savings unmeasured. **Select only public-constant modular multiplication as first kernel** |
| **B: 32-bit Montgomery representation/reduction** | The pinned native source uses word truncations and exact division by 2^32 with explicit range contracts, avoiding general division in software | New circuit reduction, signed/truncation semantics, lazy-range proofs and scaling boundaries throughout transforms. Software/native speed does not predict Boolean gate cost. Defer; too many coupled changes for the first pilot |

For B, the inspected primary implementation is mldsa-native revision
`9b0ee84f4cf399043eca59eca4e5f8531ca1d61b`, vendored by liboqs commit
`5a1a854b0dc9f2141bdc771c555ee60c37950183`; identities and paths for `reduce.h`
and `poly.c` are in the reviewed-input seal and
[native dependency record](../native/dependencies.json). No native code was run.

Its reduction computes a*R^-1 modulo q for R=2^32, using QINV=58728449 and a
**signed lift** of the low 32-bit product. The documented call-site contract is
|a|<2^31*q, yielding |result|<q; final canonicalisation still matters. The signed
lift is essential to those bounds: blindly interpreting the low word as an
unbounded positive integer is not the same interval argument. DEP-001 already
records this Appendix-A issue; no new unqualified bound is substituted.

Scaling must be tracked by domain, not merely by coefficient bit width. If every
coordinate is stored as xR, multiplying two such values followed by Montgomery
reduction yields xyR; entering requires xR mod q, leaving requires reduction of
xR, and twiddles/final 256^-1 must use matching factors. The **inspected native
path instead** uses Montgomery twiddles with ordinary-scale forward inputs,
so twiddle multiplication preserves that input scale; base multiplication inserts
R^-1, and `invntt_tomont` finishes with Montgomery multiplication by R^2/256,
introducing R and cancelling the base-product factor. Its lazy forward/inverse
bounds differ from canonicalisation after each operation. Do not combine its
scaled constants/final inverse with Python's unscaled 8347681 blindly. A B pilot
would need matched conversion costs and independent bounds for each stage; this
review does not select or implement it.

## Selected kernel: exact interface and lowering recipe

Proposed isolated name: `experimental-public-modmul-q-v1` in a future
`experiments/mldsa_modmul_lowering_1/candidate.py`; **no such implementation is
created in this package**. This is a fixed-q kernel, not a generic compiler pass.

Proposed function:
`ntt_mul_public_q(scope, value: Scalar, factor: int) -> Scalar`.
The factor is a construction-time public integer 0≤factor<q, never a decoded
witness/advice parameter. Reject bool/non-int, out-of-range factors, wrong domains,
wrong-width/foreign wires at construction, as structural errors. The private
entry is exactly the original 64-bit, LSB-first arithmetic word in the NTT domain.

1. Establish `canon(value)` with all upper bits 23..63 zero **and** unsigned
   low23<q. Submit it through `Scope.require`; no host branching on private bits.
   Concretely, AND the NOT of each high bit; compare low23 against q by
   zero-extending both to 25 bits and using the sign of their full ripple
   difference. Equality with q is invalid.
   All input bits are checked, including sign and high bits. A width/type check
   alone is not this range check. Factor validity is checked separately as public
   construction data. The guard may share the *identical* input-check wires used
   by the matched baseline harness; sharing is explicit in the proposed design.
2. Multiply public factor23 by private low23. Start a public-zero 46-bit
   accumulator. For i=0..22 emit all 23 AND terms `factor[j] AND low23[i]`, shift
   them by i by wiring, and ripple-add the full 46-bit partial product in increasing
   i order, retaining terminal carry operations. Only all-public gates fold. No
   secret-controlled carry loop, lookup, witness quotient or native fallback.
3. The product is exact: every partial sum is non-negative and no greater than
   the complete product. Even for a noncanonical low23 admitted only speculatively,
   both bitstrings are <2^23, so product and every partial sum are <2^46. Thus
   the accumulator's carry-out is zero by induction, not by discarding a possible
   overflow. For guarded inputs the tighter bound is (q-1)^2. No magnitude/sign
   correction is necessary for this unsigned representation.
4. Scan product bits i=45..0. Start r=0 (23 bits). Form the 24-bit trial
   T=2*r+product[i] by wiring. Zero-extend T and q to 25 bits, ripple-subtract
   q including terminal carry, and set `take = NOT difference[24]`. Use the
   existing mux convention (true selects its third argument) to choose between
   zero-extended T and the difference. Retain the low23 of the selected word as
   the next r. This is an explicit **25-bit** signed-difference schedule; it
   must not be confused with interpreting T itself as signed24.
5. Restoring invariant: before each step, r is the processed prefix modulo q
   and 0≤r<q. Hence 0≤T≤2q-1<2^24 and
   -q≤T-q≤q-1, which fits signed25. The subtraction sign is exact; one subtraction
   suffices. Both choices produce 0≤r'<q<2^23. By induction after all 46 steps,
   r=(factor*low23) mod q. The removed high bits are zero by this invariant;
   no unchecked overflow/modular wrap is being used to justify a signed result.
6. Zero-extend r to signed64-compatible output wires. Preserve the existing
   rejection state, active-path masking and final scope predicate. Mask output
   values by `scope.active AND NOT scope.rejected`; inactive/rejected outputs
   are zero and unusable. The acceptance bit is `scope.output(())`, so an inactive
   invalid input does not create a new fault, but a pre-existing rejection never
   clears. A caller must retain the predicate, not mistake masked zero for success.
   Output masks/finalisation count as core gates; zero-extension is wiring.

The invalid low-word product/remainder is still constructed on a fixed schedule;
its numerical correctness does not authorise use after `canon` fails. No extra
witness bits, public disclosure, guessed carries, quotient advice or conditional
host evaluation are introduced. This recipe allows constant-count symbolic
construction independent of private values; it is not a claim about side-channel
security of a future prover implementation.

### Exact comparison domain and proof obligations

The matched reference kernel must add the **same canonical guard** to the unchanged
`scalar_ring.ntt_pointwise_multiply(scope, Scalar(constant(factor,64), NTT), value)`,
then apply the same output mask and scope finalisation. On canonical inputs the
original checked product is <2^46, so it fits signed64, the positive divisor q is
nonzero, and both divmod outputs fit. Its remainder is exactly the candidate's
result. This gives a restricted-domain refinement argument. The baseline's
quotient checks remain in its count; the candidate proves they cannot fail on
that domain rather than reimplementing an unused signed quotient.

On noncanonical words the added guard rejects both wrappers on active paths.
This does **not** establish equivalence to the unguarded generic scalar gadget on
those words. Full verifier integration must establish that every real caller
reaches the guard with canonical values, or retain the reference normalisation
before it. The decoded z/c entry conversions and all later invariant-preserving
outputs above supply the proposed argument, but the composed circuit does not
exist yet. No check is removed from the active implementation.

Integer norm/decomposition/index/counter checks, sampler masks and malformed hint
rejection remain unchanged. In particular, a malformed scalar's low bits must
never become an accepted residue merely because a modulo computation completes.
Public factor specialisation does not make the private multiplicand public.

## Relation, compiler and proof security are separate

**Implementation equivalence:** the kernel proof is exact unsigned multiplication
and restoring remainder on the guarded domain, plus validity/masking equivalence.
Further integration requires range propagation, original update order, all
constants, inverse normalisation, accumulator reductions and boundary conversions.
Finite differential tests would support, not prove, universal equivalence.

**Compiler/profile:** BC-1 R-034–036, SPEC-003 and SPEC-004 prescribe signed64,
128-bit magnitude multiplication and 64-step 65-bit division. This kernel changes
those widths and schedules, and replaces quotient production with a proved
invariant. Behavioural equivalence is insufficient for canonical identity. It
needs a new versioned lowering specification, separate compiler/trace identity,
prover/checker agreement, reproducible counts and independent conformance review.
Do not relabel existing BC-1 fingerprints or adopt the hint candidate by proximity.

**Authentication relation:** retain the same 42,632-bit witness, original hidden
signature and canonical attributes; recompute holder opening and the sole
`build_mcred` body from the same holder binding, instance and certified rid.
The credential context remains `PQ-DID/credential/v1`, with unchanged pure FIPS
prefix. Same certified rid feeds the depth-20 non-revocation path, and same
certified attributes feed disclosure. PubOK/Ppub remain required public checks;
manager-state authenticity, latest state, strict session expiry and atomic nonce
consumption keep their existing roles. No signature format, sampler cap, signing
attempt cap, role context, security parameter or accepted credential set changes.

**Proof knowledge/privacy:** arithmetic refinement alone proves none of these.
OC-REL/OC-EXT/OC-PRIV/OC-BUDGET, concrete Keccak/outer-oracle composition,
component advantages at reduction budgets and adaptive Delta_tail remain open.
Changing circuit identity also changes the object the proof must bind and extract;
a separate proof-format/security argument is required. The ideal-oracle analysis
and experimental RISC Zero backend remain distinct. No new proof-byte projection,
concrete bit-security number or revised R0 execution/proving forecast is made.
Production signing, custody/entropy/erasure/side channels, durable holder storage,
and complete proof feasibility remain unresolved. Stages 2–3 remain open.

## One proposed inactive experiment

**S3-MLDSA-MODMUL-LOWERING-PILOT-1**, public/private scalar kernel only. Use the
first ordinary-residue forward twiddle **4808194**, held public for both circuits.
Keep a symbolic private signed64 multiplicand, a private active bit and a private
prior-rejection bit: **66 private input bits** in each standalone harness. These
control bits are test harness inputs, not extra protocol witness advice. Wire the
scope identically; never choose a fixture at construction. One construction of
each circuit serves every named differential case below.

Baseline: unchanged `scalar_ring.ntt_pointwise_multiply` with the above public
factor, canonical entry guard, active/sticky semantics, output mask and final
predicate. Candidate: the proposed `ntt_mul_public_q` recipe, with the identical
external requirements. Include guard/conversion/masking costs in **both** counts.
The historical 25847 count is context only; do not compare it directly with a
new 4808194 circuit. No full butterfly or transform is generated.

Independent reference provenance: existing
[`tests/reference/scalar_oracle.py`](../tests/reference/scalar_oracle.py)
`floor_pair` uses exact `Fraction`/floor rather than the restoring algorithm;
its `trace_words` interprets output wires independently of the production evaluator.
For valid input x, expected output is `floor_pair(4808194*x,q)[1]`.
Expected invalidity comes from the declared signed64/canonical/domain contract,
not from either candidate's result. Observe the complete word and acceptance bit
with both the independent observer and normal evaluator in the same named case.
Reuse primitive/native evidence; do not call ML-DSA, the ABI harness or a full
credential verification to manufacture extra tests.

| Proposed invocation | Input / requirement |
| --- | --- |
| G1 | Generate and count the complete matched baseline once |
| G2 | Generate and count the complete candidate once |
| D1 | x=0, active, clean scope: accept and return zero |
| D2 | x=1, active, clean: return the public factor |
| D3 | x=2, active, clean: exercise modular wrap with that factor |
| D4 | x=q-1, active, clean: maximum canonical multiplicand |
| D5 | x=2^22, active, clean: high private bit and multi-step remainder |
| D6 | x=(q-1)/2, active, clean: a distinct large product/remainder boundary |
| D7 | x=q, active: reject despite fitting 23 bits |
| D8 | x=-1, active: reject signed/noncanonical input, not silently normalise |
| D9 | x=2^63-1, active: reject high bits and prevent integer-overflow release |
| D10 | x=-2^63, active: reject the signed minimum, not magnitude-truncate |
| D11 | x=q, inactive, clean: no active rejection; zero masked/unusable output |
| D12 | x=1, active, prior rejection set: rejection remains; zero output |
| C1 | Incorrect 63-bit multiplicand word: construction refuses before generation |
| C2 | COEFFICIENT input passed as NTT slot: construction refuses |

This is **16 proposed invocations**: two generation probes, twelve differential
cases and two structural construction refusals; every repeat/failure consumes an
invocation, with no hidden parameterised batches. Public-factor extremes, other
twiddles, full transform round trips and composition are explicitly outside this
first pilot. No claim of universal implementation equivalence follows from these
six valid samples or the finite negative/control coverage.

Proposed allowance, **not authorised here**: add 16 to the test ceiling
**231→247**, at most 30 charged seconds from the existing implementation balance
(including validation/audit/five bookkeeping seconds), reserve ten seconds for
evidence/cleanup, one worker/two CPUs/four controlled processes, no parallel probes.
Retain 256 MiB cgroup memory/swap0 and aggregate RSS stop, and additionally retain
the arithmetic emitter's 256 MiB address-space / 128 MiB sampled RSS limits.
At most two circuits, each ≤2,000,000 gates, ≤65,536 input bits, generation≤10 s,
evaluation≤5 s per case; aggregate retained traces≤8 MiB **in memory**, no trace
files. Preserve 60/55 s command/child maxima, 8 MiB temporary disk, 10 MiB cumulative
evidence, 1 MiB/file, 60 KiB logs, storage/headroom stops and the 256 MiB audit.
Stop admission when the remaining package allowance cannot fit the next operation
and required evidence. The unused 64M-gate/2 GiB proposal stays inactive.

Record complete total/AND counts, XOR/NOT counts, private inputs, outputs/validity,
fingerprints, trace bytes, generation/counting/evaluation time, process RSS and
cgroup peak separately, all guard outcomes, and any incomplete prefix. No trace
comparison may include test-target equality gates in only one side. A capped
baseline or candidate is **insufficient evidence** for this pilot, not a full-cost
comparison; do not automatically rerun or enlarge limits.

Success requires every specified value/validity/control observation and structural
refusal to agree, both counts complete under the same envelope, and the candidate
to have fewer **total gates and AND gates after all guards/conversions**. No
numerical speedup is promised. A failure stops with retained evidence; signing,
proofs, zkVM and installations remain prohibited. Report time/memory even if no
improvement is found. There is no authorisation for subsequent integration.

If successful, the staged route is: review the kernel/invariant evidence; separately
validate forward/inverse butterfly wrappers and entry conversions; then complete
transforms and ordered matrix products with every constant; then retain norm,
decomposition/hint, samplers/hash and same-message/path acceptance in the full
relation. Those later stages have no allowance here. Smaller scalar arithmetic
could matter because the source repeats it extensively, but the magnitude of a
complete-authentication benefit is unknown. Hashing, bounded samplers, the hint
candidate's remaining cost, proof representation and security remain independent
barriers. The feasibility plan's KYC target is not shown attainable by this design.

## Decision and issue disposition

**ARITH-LOWER-001 — open:** implementation-ready canonical-residue public modular
multiplication candidate; authorise only the 16-invocation, ≤30 s isolated pilot
above if a measurement is desired. No lowering/profile adoption or whole-proof
benefit is established. Required closure evidence is complete matched counts,
value/validity agreement, range invariants and subsequent separately reviewed
composition, not a successful scalar example alone.

HINT-LOWER-001 and AUTH-FEAS-001 stay open. DEP-001/002 production obligations,
SEC-001–005, outer-oracle composition and full proof knowledge/privacy are not
closed by this review. All previous failures, counts, parameters and fingerprints
are preserved. The following measured closure records documentation/static checks
and preservation only; it must not be read as execution evidence for the proposal.


## Measured documentation and preservation closure

The review is complete: canonical-residue multiplication is ready for a separately
approved component pilot; no profile or execution allowance is activated.
Helper lint/format and documentation/static consistency checks pass. No test,
circuit generation, arithmetic probe, build, estimator or cryptographic execution ran.
The single [preservation audit](data/s3_mldsa_arithmetic_lowering_review_1/result.json)
completed content/inventory comparison, report readback and outer guard, exit 0.
Coverage: 10,250 disjoint content paths;
10,275 identity-inclusive paths.
Original baselines and historical document prefixes are preserved.

| Measurement | Result |
| --- | --- |
| Audit wall time | 2.485872072 s |
| Audit cgroup-v2 memory.peak | 23,232,512 bytes |
| Audit sampled process-tree RSS | 41,050,112 bytes |
| Maximum guarded-job cgroup peak | 24,018,944 bytes |
| Maximum separately sampled tree RSS | 41,050,112 bytes |
| Guarded commands | 7, 3.209255512 s |
| New analysis charge, including five bookkeeping seconds | 8.209255512 s |
| Cumulative analysis charge | 46.393514843/300 s |
| Analysis remaining | **253.606485157 s** |
| Implementation unchanged | **94.376512284 s**, **231/231 tests** |
| Temporary disk observed peak | 0 bytes; zero retained |
| Evidence bytes at audit completion | 320,773 |

No failures, retries or resource breaches. The unchanged 256 MiB cgroup guard
covers the worker and descendants, including charged file-cache/kernel memory;
swap is zero. Sampled RSS is a separate metric. Final bounded bookkeeping uses
256 MiB address space, five-second CPU/alarm, two CPUs and 1 MiB/file inside the
five-second charge; it does not repeat content comparisons.
The [closure](data/s3_mldsa_arithmetic_lowering_review_1/validation-closure.json)
and [additive seal](data/s3_mldsa_arithmetic_lowering_review_1/manifest.json)
record the exact balances. Isolation remains safely stopped/unactivated with
250.22 s and 22 original cases pending. Stages 2–3 remain open; proof ledger
**two attempts used, one unused**, CPU proving paused.
