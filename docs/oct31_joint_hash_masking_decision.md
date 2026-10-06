# OCT31-JOINT-HASH-MASKING-DECISION-1

**Decision C: close the examined Aurora route for the current October delivery
plan.** The arithmetic-only NO-GO is accepted and its evidence remains immutable.
One combined candidate, **JHM-FR254-PACKED-1**, is specified in the
[construction contract](data/oct31_joint_hash_masking_decision_1/contract.md).
It preserves the intended predicate but has neither resource admission nor a
demonstrated complete masking/knowledge correspondence. This decision closes a
delivery route, not the possibility of a different future construction.

This package performs source analysis and a bounded parameter calculation only.
It does not construct a circuit, instantiate a native field, run a proof or adopt
a profile. Only manuscript Sections II–VIII and SPEC-001–004 are authoritative.
The existing executable reference and comparison point v1 remain the baseline;
all 276 measurements are retained. This is **not complete private authentication**.

## Exact obstruction and its provenance

The call is `verify_signature` in
[`mldsa_verify.py`](../experiments/auth_relation_integration_1/mldsa_verify.py):
`encoded = encode_w1(scope, high)` followed by
`reconstructed = shake256(e, mu + encoded, 48)` and exact comparison with the
decoded 48-byte challenge. Its inputs are the 64-byte FIPS message representative
and 768-byte encoded reconstructed high parts. This implements the internal
challenge recomputation in FIPS 204 Algorithm 8, line 12. It is unrelated to the
outer proof transcript oracle. [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)

For SHAKE256, the 832-byte input, 136-byte rate, suffix 0x1f and final padding bit
require seven absorption permutations. The 48-byte output needs no further
squeeze permutation. Each Keccak-f[1600] permutation has 24 rounds, 25 lanes of
64 bits and one chi product per bit: `7*24*25*64 = 268,800`. The production
[`keccak.py`](../src/pqdid/circuits/keccak.py) fixes this schedule and bit order.
All seven permutations involve the hidden reconstructed `w1`; treating `mu` as
public in an isolated measurement does not make this hash public in Rauth.

Retained M-16, [AR1-0054](data/oct31_auth_relation_integration_run_1/cases/AR1-0054.json),
completed the final hash/equality component with public `mu` and private `w1`:
1,096,322 XOR, 269,187 AND, 386 NOT, 1,365,895 total gates, and 1,372,041 rows in
the old GF(2^192) lowering. These are measured component counts, not new prime-field
counts. The candidate's odd-prime XOR requires a product constraint; GF(2) linearity
cannot be transferred. A chi product is one retained auxiliary and R1CS row **by
this representation's definition**, not a universal lower bound for every hash
arithmetisation. Public folding does not eliminate these retained private products.

The proof backend's retained EXP2 transcript uses BLAKE2b-512/libsodium. The
manuscript's ideal outer oracle/concrete SHAKE256 question remains separately
conditional under the previous composition decision. Replacing an outer hash
would not remove this internal ML-DSA cost. No hash or ML-DSA parameter changes here.

With R constraints, V auxiliary/input columns, M=ceilpow2(R), N=ceilpow2(V), and
t=max(M,N), the chi subset alone gives M,N>=2^19. Each xy=z has at least one
nonzero coefficient in each of A,B,C: 806,400 coefficients, 25,804,800 bytes at
32 bytes each, before indices and containers. This is a matrix payload floor;
dense conversion rows elsewhere can have 65 terms. The old measured GF192
row/term ABI is not asserted for the new field.

Retaining the masking/rate envelope, even the optimistic **bound parameter** b=1
gives Dconstraint>=2^20+1 and S=ceilpow2(8*max(D,Dconstraint))>=2^24. It does not
set the actual query/masking parameter to one. One 32-byte-element codeword then
costs at least 536,870,912 bytes. Four base codewords cost 2 GiB before other
objects. The degree, rate and rounding deductions are conditional on the specified
candidate; the simultaneous retention deduction depends on its resident schedule.
The native `r1cs_rs_iop.tcc::submit_witness_oracles` builds the four base columns,
and `iop.tcc::submit_oracle` retains real oracle evaluations. A generator loop is
not evidence that those retained vectors cease to exist.

## Complete relation and public preprocessing

The target is the joint `emit_private` relation, not a list of separately accepted
components. One 42,632-bit parsed witness supplies secret, attributes, signature,
certified identifier and siblings throughout. The statement and expected parameters
bind issuer key, instance, schema, policy/disclosure, authenticated state, nonce and
context using existing canonical encodings. No container acceptance flag is trusted.

| Required component | Candidate treatment and remaining cost |
| --- | --- |
| Public parameter/key/instance/context/state checks and policy | Reuse trusted `PubOK`/`Ppub`, canonical statement and verifier-recomputed constants; lifecycle freshness/atomic consumption stays outside the proof as specified |
| Private parsing, 1,024-byte attributes and disclosure linkage | Exact byte/range/padding constraints, same attribute columns, no new coercions |
| Holder binding | SHA3-384 of canonical holder record with the private 32-byte secret; digest linked into the certified body |
| Signature response and hints | 1,280 response coefficients, strict norm, 61-byte hint encoding, ordered indices/count/padding, 1,536 hint outputs |
| FIPS `mu` | SHAKE256(tr || pure-mode/context framing || exact Mcred,64), computed from the same holder/attribute/rid values |
| SampleInBall | Exact private 256-byte SHAKE stream, 248 candidate scans, fixed selection/order and exhaustion rejection |
| Forward transforms | Six transforms, each 256 signed64 entry conversions and 1,024 butterflies, canonical intermediate invariants |
| Matrix products | 7,680 public-constant products and accumulation, plus 1,536 challenge*t1 products and subtraction |
| Inverse transforms | Six transforms, 1,024 butterflies each and 256 final factor products; distinct inverse semantics retained |
| Decompose/UseHint/w1 | 1,536 coefficients; all boundary cases and 768 output bytes, with exact representative and links |
| Final challenge | Seven SHAKE permutations and exact 48-byte equality, as above |
| Non-revocation | Twenty SHA3-384 node hashes with private siblings/directions, same certified rid, levels and public-root equality |
| Final rejection | All active checks conjunctively linked; invalid outputs unusable, no unconstrained acceptance witness |

Public `tr=H(expected_key,64)`, t1 decoding, bounded ExpandA from expected rho,
canonical headers, the unrevoked leaf and public-only prefix blocks can be
independently recomputed. The declared matrix/tr cannot be chosen by the prover.
An optional public-prefix optimisation must match the exact fixed encoding/state;
the estimates below do not silently apply it. Hidden holder, attributes, signature,
rid and path checks stay inside. Credential validity and session expiry retain
their distinct rules. This component inventory is complete **source coverage**;
complete rows, columns, nonzeros and witness size for the new lowering remain unknown.

## One joint candidate and the limits of its correspondence

The contract gives the full equations, distributions and message order. Salient
choices are a 254-bit prime scalar field, canonical 32-byte little-endian fields,
bit/byte links, direct bounded integer arithmetic and unchanged Boolean SHA3/SHAKE.
Signed 64-bit entries, exact 65/128-bit intermediates and bounded quotient/remainder
witnesses preserve overflow/rejection; no-wrap bounds are below the prime.
AND is xy=z, XOR is (2x)y=x+y-z, NOT is 1-x. All constraints remain degree two
after naming products before conditional guards. Kernel completeness and soundness
follow from Booleanity, ranges, no-wrap and unique quotient arguments; applying
them to every reference operation remains an unimplemented composition obligation.

The field modulus is
21888242871839275222246405745257275088548364400416034343698204186575808495617.
No elliptic-curve proof assumption is introduced by using its scalar field.
Multiplicative domains use the pinned root of order 2^28, bit-reversed exponent
order and L=5H_S; public K-point interpolation is nested in N. The bounded
calculation checks the root order and coset separation, not native FFT correctness.

Joint base masks are independent uniform coefficient polynomials of degree<b,
multiplied by the appropriate vanishing polynomials. Sumcheck masks are independent
uniform degree<Dlin polynomials including their constant coefficients; beta=sum_H r
is disclosed before dependent challenges. On a multiplicative H of size t,
sum_H f=t*f(0) for degree<t. Thus the masked remainder uses beta/t as its constant
and divides the remainder difference by X, rather than using an additive-domain
top coefficient. The quotient and virtual column remain correlated with that mask.
Each LDT reducer has one independent unit pad of degree<D, exactly 2J challenges
for J=3a+5 handles, and binary x/-x folding. Full terminal coefficients are included
in the view; they cannot be omitted from a privacy argument.

Packed, salted binary-coset trees commit each round's ordered real columns. Exact
leaf/node framing binds profile, statement, domain, position and order. This is an
**inactive commitment-format proposal**, not correspondence established by the
native public tests. All leaves, including quotients and folds, carry independent
128-byte salts; BLAKE2b-512 output is 64 bytes. EXP2 order/counters remain required.
Fp challenge sampling and fresh coefficient entropy with bounded failure remain
unimplemented; biased modulo reduction and seeded tapes are not authorised substitutes.

For opened position unions u_j<=min(2q,S/2^j), the candidate opens
(4+2a+P)u_0+IP*sum(j>=1,u_j) scalar fields, discloses a+IP*Df direct fields, and
requires the algebraic projected query union B_RS=|S_0|<=b. Counts of scalar
fields, query positions, terminal coefficients and outer-oracle queries Q_H are
different. The full transcript includes roots, salts, paths, beta, terminal vectors,
indices and all dependent challenges. Conditional closure of all those views is
required; the contract's rank/translation observations do not by themselves prove it.

| Result or retained evidence | Applicable condition and current conclusion |
| --- | --- |
| Aurora Remark 5.6 | Multiplicative sumcheck algebra is explicitly contemplated; it supports the local constant-coefficient replacement, not a full changed protocol theorem |
| Aurora Theorem 7.4/Protocol 7.5 | Bounded-query ZK RS-IOP conditions include disjoint domains and random low-degree extensions; verify joint query bound and all modified public polynomials |
| Aurora Theorem 8.5/Protocol 8.6 | Reduction needs the stated low-degree/proximity and polynomial honest-prover conditions, complete masking distribution and messages; library support is insufficient |
| Aurora Theorem 9.2 | Stated for binary fields; not directly a theorem for this prime-field construction |
| Retained masking contract/native milestone | Establishes specified additive-domain algebra/native cases; native additive-only guard remains closed for the proposed port |
| Retained BCS commitment/Fiat–Shamir assessment | Still requires the applicable joint commitment simulator and actual transcript/query bound; packed correlated openings and explicit salts are not automatically covered |
| Retained quantum/CMS/outer-oracle assessment | Required quantum knowledge/extraction, adaptive games, concrete-hash composition and finite constants remain open; native algebra cannot discharge them |

Primary theorem locations were checked in the 8 May 2019 version of
[Aurora](https://eprint.iacr.org/2018/828.pdf), especially Remark 5.6 and Theorems
7.4, 8.5 and 9.2. Other obligations reuse the
[construction](stage3_aurora_auth_construction_contract.md) and
[masking correction](stage3_aurora_masking_correction_contract.md) assessments.
We do not derive numerical security from unspecified asymptotic constants.

The precise missing result is a full applicable soundness/knowledge and joint
simulation correspondence for this prime-domain RS-IOP/reducer/folding plus the
specified commitments and EXP2 challenges at the actual query budgets. Some local
steps follow existing algebra; whether all remaining steps are an application or
a new theorem is not established. **Decision C does not assert that a new
fundamental mathematical result is necessary.** Even a successful future proof of
that correspondence would not remove the independently demonstrated storage failure.

## Complete resource accounting and scheduling

The machine-readable [calculation](data/oct31_joint_hash_masking_decision_1/decision.json)
records canonical shape lengths and sponge permutations for the retained alpha
fixture. This uses public framing sizes only; zero placeholders denote lengths,
never accepted credentials. It supplies a constructive hash-core row upper bound
for this mapping, including odd-prime theta/chi XORs, before public preprocessing.
It excludes parsing/ranges, controls, equality and all non-hash work; it is **not**
a complete-relation row bound or a generated measurement.

For a complete implementation the resource model must include the following
simultaneously live objects; unresolved terms cannot be replaced with zero:

| Object | Accounting and status |
| --- | --- |
| R1CS matrices | 32*nnz coefficient payload plus index/row/container storage, copies and serialisation; full nnz unknown. A possible 40-byte indexed term is an ABI estimate, not measured |
| Assignment and products | >=32N for padded assignment; >=96M for Az/Bz/Cz when retained; raw witness/packing/validity columns and compiler maps additional |
| Masks and quotient coefficients | 32*(4b+aDlin+PD) sampled coefficient bytes before derived quotient/folding coefficients; fresh entropy and generation work also count |
| Retained real codewords | 32E, E=S(4+2a+P)+IP*sum(j=1..r-1,S/2^j); base, sumcheck, quotient, reducer pad and folded words all included |
| Packed commitments | T=S+sum(j=1..r-1,S/2^(j+1)) leaves, r+1 trees; 128T salt bytes and 64*(2T-(r+1)) digest bytes if full trees retained |
| Temporary buffers | FFT/interpolation work vectors, virtual rowcheck/lincheck/reducer evaluations, hashing batches and allocator overhead; unmeasured exact lifetimes |
| Output | Roots, descriptor/statement, a beta fields, IP*Df terminal fields, opened fields/salts/paths; finite q/r/I/P not settled, complete encoded size unknown |

For a=P=1 as lower-bound values, before any additional fold layer, E>=7S and
T>=S. At S>=2^24, codeword payload is at least 3.5 GiB, salts 2 GiB, and tree
digests 2 GiB minus 128 bytes: **8,053,063,552 bytes (7.5 GiB minus 128 bytes)**.
This is a conditional **resident payload floor for this candidate**, not a measured
peak, a universal proof lower bound, or a sufficient allocation. Rows from all
other components and positive buffers can increase domains again. Finite security
parameters can only increase this optimistic subtotal; they have not been lowered.

The current limits are 1 GiB/native worker, 2 GiB aggregate, 128 MiB artifacts,
32 MiB per designated artifact, and required 2 GiB free headroom. Even one codeword
exceeds the entire artifact cap. The calculation records observed total/available
WSL memory and disk availability; available host capacity is not permission to
consume it. No complete native peak or total execution-time estimate exists.

Exact recomputation could preserve a transcript only by retaining the same random
coefficients/salts and reproducing identical values, ordering and roots. Resampling
or replacing independent masks with a short seed changes the distribution/model.
For scale, a particular naive Horner replay of only four base codewords costs
4*S*M>=2^45 coefficient steps, versus the existing 2^32 work-event cap. This is
not a lower bound for all schedulers. An external FFT/recomputation schedule would
need full peak/work/storage accounting and privacy correspondence; none is
demonstrated by streaming the existing generator. No such additional candidate
or hidden resource amendment is admitted here.

There is therefore **no supported prospective resource amendment**. A floor cannot
justify a sufficient new ceiling, and the resident floor already exceeds the
observed available memory. A different hash arithmetisation or proof construction
would need a jointly justified field/masking/security design and a complete upper
resource model. Another arithmetic component optimisation would not address this
hash/commitment/domain obstruction.

## Decision, delivery scope and evidence

Close JHM-FR254-PACKED-1 and this Aurora route for the current delivery plan without
adoption or further experiments. This is not a cryptanalytic attack or a universal
impossibility claim. The bounded mathematical analysis, native component evidence
and reference KYC work remain useful, versioned results.

The concrete user decision is whether **31 October means delivery of the validated
reference KYC testbed, native component correspondence and comparison dataset,
explicitly excluding complete private authentication**, or whether to revise the
deadline/scope and separately authorise a replacement integrated construction.
There is no evidence-backed promise of complete private authentication by that date.
Do not turn remaining implementation capacity into another isolated review or proof
attempt. No new package is started by this decision.

All 21 outstanding checks remain **unrun**: M-01–M-03, J-01–J-16 and Q-02–Q-03.
Ordinary private-proof acceptance stays fail-closed. Stages 2–3, AURORA-BRIDGE-001,
commitment simulation, complete knowledge/privacy, concrete-hash and finite-parameter
obligations, adaptive Delta_tail and production security remain open. Isolation
stays stopped/unactivated; CPU proving is paused. Proof ledger: two used, one unused.

Opening accounting: 2,838.5076846957927 implementation seconds; 973/1,050
invocations; 10/13 builds; 77,593,603/2^32 work events, including the retained prior
failure reservation. Cumulative evidence was 26,554,061 bytes; shared new-evidence
headroom 4,978,828 bytes, inside the 32 MiB cumulative cap. Artifacts were
58,966,547 bytes. The 300-second/2 MiB completion reserves remain inside balances.
One bounded calculation completed and is counted; static/admission/audit operations
are recorded separately. No build or circuit work events are authorised. The
80.91750274339225-second analysis balance and isolation allowance remain unchanged.
Measured command time and the retained conservative operator-accounting convention
are recorded separately, without resetting any historical usage.

## Preservation

Use the established complete auditor at 256 MiB, inheriting every original
comparison, historical repair artifact, source seal and name inventory. The only
new roots are this experiment and its data; the report is new, while status,
traceability and issues are append-only. The arithmetic-only report/contract,
active production code, parameters, dependencies, manuscript, v1 and all 276
measurements remain immutable. Final results and balances are appended below and
recorded in the package closure only after audit, inventory, readback and shutdown.


### Completed calculation and source checks

D-01 passed once (JHM1-0001), 0.381427 seconds including the guard,
0.060878 seconds worker, cgroup peak 23,162,880 bytes. No hash/circuit evaluation,
new arithmetic gadget, native field instantiation or large allocation occurred.
The retained alpha shape has metadata 386 bytes; holder preimage 457 bytes
(5 permutations), mu preimage 1,612 bytes (12), SampleInBall prefix 48 bytes
with 256 output bytes (2), final challenge preimage 832 bytes (7), and twenty
528-byte Merkle node preimages (120). Total: 146 sponge permutations before
public preprocessing. A literal odd-prime hash-core construction uses at most
22,657,600 rows for these shapes: 153,600 rows per permutation plus at most
1,600 per absorbed block. This upper bound omits all non-hash constraints and
is not a complete resource-admission estimate.

Observed WSL memory was 8,126,111,744 bytes total and 4,132,270,080 available;
observed free filesystem capacity was 1,011,226,124,288 bytes. Swap availability
is irrelevant: guarded work retains memory.swap.max=0. The conditional resident
minimum nearly fills physical RAM and exceeds available RAM before the required
2 GiB headroom or remaining components. No larger envelope is proposed.

Preflight verified historical inputs and completed. The first scoped lint pass
reported three E501 lines in the new helper; its diagnostic remains retained.
One authorised formatting correction and scoped rerun passed lint/format. No
cryptographic or historical test was repeated. Harmless missing-path source-read
diagnostics are recorded separately from test outcomes. Invocation ledger is
974/1,050; builds remain 10/13 and work events remain 77,593,603. All 21 full
relation cases are explicitly unrun, not failed or replaced by this calculation.


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
