# S3-AURORA-MASKING-CORRECTION-CONTRACT-1

**Decision: a precise algebraic correction is supported by the published
construction and the joint argument below, for the explicitly restricted ideal
IOP family.** Propose an isolated, public synthetic sumcheck correspondence pilot
next. No source patch is applied here, no private prototype is admitted, and no
claim is made that the current native library already realises this family.
Concrete field validation, source correspondence, commitments, Fiat–Shamir and
knowledge/privacy of complete authentication remain separate gates.

The selected route is Aurora's general RS-encoded construction and unit-pad LDT
transformation, rather than claiming byte-for-byte identity with its optimised
Figure 5. This keeps all currently tested polynomial handles and their degree
checks. It avoids needing a new simulator for the existing zero-sum/random-pad
variant. The decision concerns the algebraic correction, not profile adoption.

## Authority, immutable snapshot and scope

Only manuscript Sections II–VIII and SPEC-001–004 govern the scheme. The manuscript
SHA-256 is `d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The active BC-1 construction, parameters, source, binaries and dependencies remain
unchanged. Aurora is still an alternative research construction.

Reuse the completed [query/masking contract](stage3_aurora_query_masking_contract.md)
and [native pilot](stage3_aurora_native_transcript_pilot.md). The former's final
manifest is `887421bc7b58261c7fe207a9a2b9791ef8e12976245ffa685484f033c978c960`.
Its completed package is closed and its 919,201 unused reservation bytes released;
no historical consumption is refunded. The native continuation was already closed.
Its eight SEM and sixteen TR successes establish public EXP2 correspondence only.
No mask, private IOP, FRI or commitment execution is added to that evidence.

Source locations below are relative to
`experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1/guarded-build-v2/work/libiop/libiop/`.
Commit `a2ed2ec2f3e85f29b6035951553b02cb737c817a`, tree
`2e2588ccb085242dd2237875c3b9adf1a0fc958c`, and the retained EXP2, ten-reference,
size-type and libff overlays are unchanged. The reviewed hashes and inherited
historical seals are recorded in
[reviewed inputs](data/s3_aurora_masking_correction_contract_1/reviewed-inputs.json).

The primary result used here is the [Aurora paper](https://eprint.iacr.org/2018/828.pdf),
8 May 2019, 64 pages: §4.6–4.7, Protocol 5.8, Theorem 7.4/Protocol 7.5,
Theorem 8.5/Protocol 8.6, and Theorem 9.2/Figure 5. Full paper text was inspected;
the earlier unsuccessful screenshot requests remain failures. This package does
not infer quantum or concrete-hash security from that classical algebraic result.

## Findings: errors, different constructions and absent evidence

| Finding | Established by inspection | Classification and consequence |
| --- | --- | --- |
| Folded degree registration | `protocols/ldt/fri/fri_ldt.tcc:350–399` advances the localisation sum before registering the current folded oracle. For binary folds it labels the first folded word with D/4 instead of its mathematical D/2 bound | A source/degree-contract mismatch. The registration correction below is necessary. No executed rejection, attack or end-to-end consequence is claimed |
| Sumcheck masks and coefficients | `protocols/encoded/sumcheck/sumcheck.tcc:198–204,287–355,395–407` samples a zero-sum mask and combines mask/lincheck using two challenges | Demonstrably differs from the selected published distribution. Missing privacy justification is not a demonstrated privacy defect; this contract elects to restore the published construction |
| Reducer coefficient map | `protocols/ldt/ldt_reducer_aux.tcc:26–173` prepends one to the coefficient vector, but the pad is the last input, not input zero | Literal unit-pad correspondence fails. The pad can receive zero. No attack is inferred; the proposed unit-pad formula removes the need to prove this variant |
| Early LDT pad | `protocols/aurora_iop.tcc:335–351`, `ldt_reducer.tcc:242–254` submit it before the first challenge | Not a demonstrated error. General Protocol 8.6 permits an early independent pad; its simulator handles pre-challenge pad queries. Keep this timing |
| Unsalted quotients/folds and packed leaves | Existing source flags/encoding differ from the draft commitment proposal | Algebraic simulation alone does not justify the actual commitment view. TB-06 remains open |
| Field, entropy, full EXP2 schedule | GF(2^192), private dimensions, fresh sampler behaviour and complete caller correspondence are not certified by public TR cases | Explicit implementation/admission obligations, not demonstrated defects |

In particular, scalar openings exceeding b do not refute Aurora's masking theorem:
it counts common-domain positions. Conversely, `b=2q+1` alone is not a complete
privacy proof for the unchanged source variant. Both earlier statements retain
their evidence with this distinction made explicit.

## A nonempty, explicit admissible family

All polynomial bounds mean degree **strictly less** than the bound. Work over a
binary field F=GF(2^kappa), with a fixed verified field basis. Let M,N,K,t be powers
of two, 1 <= K < N, t=max(M,N) >= 2. Nested linear systematic domains H1,H2 have
sizes M,N; the public domain Hpub is a size-K subspace of H2. Set H=H1 union H2,
so |H|=t. L is an affine domain disjoint from H; all quotients evaluated on L have
nonzero systematic vanishing denominators. A concrete construction is
`H1,H2,Hpub = initial basis spans`, `L = e_d + span(e_0,...,e_(d-1))`, with
`|L|=2^d >= t` and kappa >= d+1. This includes the affine shift; it must not be
silently dropped by vector evaluation.

Choose positive integers a,P,I,q,r and b. The intended binary localisation has
eta_j=1 for all r folds. Define:

```text
Dlin = 2t+b-1
Dtest = max(Dlin, M+2b-1)
Dconstraint = max(Dlin, 2M+2b-1)
D = 2^r * ceil(Dtest / 2^r),  Df = D / 2^r
J = 3a+5                              # tested polynomial handles, excluding pads
sigma* = D/|L|, rho* = max(D,Dconstraint)/|L|
|L| >= 8 max(D,Dconstraint), b >= B_RS, B_RS <= min(2q,|L|)
delta = 1/4
```

Thus the general reducer condition
`delta < min((1-2sigma*)/2, (1-sigma*)/3, 1-rho*)` is strictly satisfied:
the three lower bounds are 3/8, 7/24 and 7/8. The rate and dimensional constraints
are requirements of this proposed family, not alterations to an active profile.
If a later deployment fixes another delta or rate, it must redo this admission.
For malicious oracle queries, B_RS is their complete projected union, bounded by b;
the `2q` bound pertains to the specified verifier, not unlimited external queries.

A purely algebraic consistency example is M=N=8,K=2,b=2,q=1,a=P=I=1,r=2:
Dlin=Dtest=17, Dconstraint=19, D=20,Df=5, |L|=256 and kappa>=9 satisfy these
inequalities. This is hand-checked parameter arithmetic, not an execution, test
vector, security level or proposed production workload. The source's GF(2^192)
can represent the required domains only after its field polynomial/basis and
encoding are independently validated. No finite authentication dimensions,
soundness repetition selection or field certificate are claimed here.

The mathematical hypotheses are therefore satisfied for this defined family;
the implementation must establish membership before using the theorem. The
library's heuristic defaults or public harness descriptor do not do so.

## Complete algebraic view and proposed definitions

Write Z_A for the monic vanishing polynomial of domain A, and
`Lambda(f)=sum(u in H, f(u))`. For linear H, let xi be the nonzero coefficient of
X in Z_H. If f=Z_H h+g with degree(g)<t, then
`Lambda(f)=xi*g[t-1]`. The following objects are related views, not independently
simulatable messages simply because some marginals are uniform.

| Object | Current definition and proposed definition | Bound / randomness / correlation |
| --- | --- | --- |
| Four base columns | Keep `fz = fz_base + Z_H2 Rw`, `fw=(fz-fpublic)/Z_Hpub`; keep `fAz=fAz_base+Z_H1 RA`, and similarly B,C | Rw,RA,RB,RC independent uniform coefficient vectors of length b. Bounds fw:N-K+b; A/B/C:M+b; fz:N+b. Their systematic values come from the same witness |
| Rowcheck | Keep `(fAz*fBz-fCz)/Z_H1` on L | Virtual; bound M+2b-1 on valid witnesses. Constraint numerator bound 2M+2b-1. No independent pad or extra real oracle |
| Lincheck ell_i | Keep the existing matrix identity `ell_i = sum(j=A,B,C, s_ij*(f_j*p_alpha_i - fz*p_alpha_i^j))` | Alpha_i and the three s_ij are verifier coins after early oracles. The matrix-derived p polynomials are public. Bound Dlin; Lambda(ell_i)=0 for a valid R1CS assignment. All a repetitions share the four base columns |
| Sumcheck mask r_i | Current: `Z_H v_i+u_i`, u_i[t-1]=0. Proposed: same bijection with unrestricted u_i, `r_i=Z_H v_i+u_i` | u_i uniform in F[X]_<t, v_i uniform in F[X]_<Dlin-t; all independent of base and other masks. The bijection makes r_i uniform in F[X]_<Dlin |
| Direct beta_i | Absent currently. Proposed: beta_i=Lambda(r_i)=xi*u_i[t-1], one direct field before alpha_i and s_i | Correlated with r_i; not a fresh unrelated field, not a witness input, not another oracle position |
| Combined p_i | Current: gamma_i*r_i+tau_i*ell_i, target zero. Proposed: p_i=r_i+ell_i, target beta_i | Remove the two extra sumcheck coefficients only in the new branch. Unit mask coefficient cannot disappear under a malicious zero challenge |
| Quotient h_i and virtual g_i | Proposed h_i is quotient of p_i by Z_H; `g_i=p_i-Z_H*h_i-(beta_i/xi)*X^(t-1)` | h_i bound Dlin-t=t+b-1; g_i bound t-1. Their exact correlation with r_i, beta_i and base columns is required. Retain the existing stricter quotient bound; it follows by division, while Figure 5 permits a looser t+b bound |
| Reducer mask z_p | Keep independent uniform z_p in F[X]_<D, committed early | Independent across P, and from all four base and a sumcheck masks. The same z_p participates in all I FRI repetitions for that reducer output |
| Reduced word W_p | Proposed `W_p=z_p+sum(j=0..J-1, (u_pj+v_pj*X^(D-d_j))*O_j)` for tested handles O_j with bounds d_j | Exactly 2J independent verifier fields per p. Include both terms even when d_j=D, giving exponent zero. z_p has fixed coefficient one and no second random coefficient |
| FRI words F[j,i,p] | Keep native folding equations/challenges and quotient domains; F[0,i,p]=W_p. Correct degree registration, not the fold arithmetic | Bound D/2^j. Folds across I share W_p and have separate verifier coins. No independently resampled fold masks |
| Terminal coefficients | Keep the complete ordered vector of Df coefficients for each i,p, including the existing specified zero padding | IP*Df direct fields, determined by the same W_p and fold challenges. They are not omitted from the simulator or hidden behind a commitment |

The tested-handle order stays exactly the source order: `(r_i,h_i,g_i)` for each i,
then fw,fAz,fBz,fCz,rowcheck. There are J=3a+5 handles. Their distinct degree bounds
are retained. Protocol 8.6 uses both each column and its degree-raised counterpart;
the proposed formula implements that general matrix explicitly. It does not claim
the Figure 5 optimisation that raises only g columns, or its shorter challenge
vector and exact specialised soundness expression.

For precision, the current reducer has n=J+1 inputs including the last pad.
It accepts 2n random fields y, forms `c=(1,y)`, and uses c_j on maximal-degree
input j. Submaximal input j uses `c_j+c_(n+s(j))*X^(D-d_j)`, where s(j) is its
ordinal in the submaximal-index list. This differs from both indexing by j and
the proposed complete 2J map; some supplied coefficients are unused. The proposal
does not silently reinterpret an old transcript as the new map.

## Exact inactive edit contract and order

This is an edit specification, **not an applied patch**. Introduce one explicitly
opted-in experimental non-holographic binary-field branch. Reject branch selection
for non-ZK, multiplicative-domain, multiple-attached-claim or nonzero-attached-claim
sumchecks. Leave other library modes and the public EXP2 harness unchanged.

| Edit | Exact source anchors | Required proposed change |
| --- | --- | --- |
| SC-1 | `protocols/encoded/sumcheck/sumcheck.hpp` class members; `.tcc:198–204,287–323` register/submit mask | Add one prover-message handle for beta_i and the explicit branch selector; register length one alongside the early mask. In the branch stop overwriting u_i[t-1], compute xi*u_i[t-1], submit it with r_i. Preserve rejection of invalid domains/dimensions |
| SC-2 | `sumcheck.tcc:204` register challenge; `:237–275` register proof; `:326–355,395–407` target sum and both states | No extra sumcheck challenge registration in this branch. Set the existing random-linear-combination coefficients to exactly [1,1] for [r_i,ell_i] in both states. Obtain beta_i through the existing prover-message API, require one field, and set g's claimed sum to beta_i. Keep h and g degree constraints |
| SC-3 | `protocols/encoded/lincheck/basic_lincheck.tcc:182–237,250–285` | Opt in only for the selected branch; keep alpha/triple registration and ell_i's attached zero claim. Remove only the nested registration/consumption of the obsolete pair through SC-2; maintain registration direction and round order |
| SC-4 | `sumcheck.tcc:363–384` DEBUG remainder bookkeeping, `sumcheck_aux.tcc:1–35`, sumcheck g vector/point evaluation | Document that the remainder's top coefficient is beta/xi, not beta. Any proposed DEBUG display of an actual sum must multiply by xi. The current local value is unused, so this is not a new verifier check. Preserve the affine shift in vector evaluation; use the same beta/xi formula on both paths |
| LD-1 | `protocols/ldt/ldt_reducer.tcc:165–225,266–294`; corresponding class declarations | Separate J tested handles from the final mask; register exactly 2J coins per p; carry J and d_j explicitly into the virtual oracle. Keep early mask creation/submission at `:135–155,242–254` |
| LD-2 | `protocols/ldt/ldt_reducer_aux.tcc:1–173`; corresponding header signatures | In the new branch initialise result with the last pad's value; add all J weighted terms using u[j] and v[j]. Remove the prefixed-one/ordinal coefficient convention for this branch. Require exactly J+1 constituent inputs and 2J coins; enforce identical point/vector formulas and lengths |
| FR-1 | `protocols/ldt/fri/fri_ldt.tcc:350–399` | Initialise total localisation to eta_0 as now. In loop i register using the current total (eta_0+...+eta_(i-1)); advance by eta_i at the loop end. Preserve final Df computed after all r localisations, domains, challenges, folds and query order. Reject nondivisible D, inconsistent dimensions and invalid bounds at branch admission |
| IO-1 | `protocols/aurora_iop.tcc:312–351`; `iop/iop.tcc:151,344`; `iop/iop.hpp:413` | Register early beta messages using existing prover-message facilities before changing to verifier registration; submit every beta before signalling round zero done. Do not change the early independent LDT pad timing. Include beta in the full future public transcript before its dependent challenges |

The general random-linear-combination helper at
`protocols/encoded/common/random_linear_combination.tcc:11–74` already implements
supplied [1,1] exactly and needs no semantic change. The field coefficient sampler
at `algebra/polynomials/polynomial.tcc:231` supplies one `FieldT::random_element`
per coefficient; the mathematical argument assumes ideal independent uniform
fields. It is not entropy assurance, a side-channel claim, or permission for
deterministic/reused tapes. Required leading coefficients may be zero.

Proposed timing, retaining every real and direct message:

1. Register the complete public statement, domains, bounds, handle/coin order and
   branch/version identity. No silent extension of the tested public descriptor.
2. Sample four base masks, a unrestricted r_i and P independent z_p. Submit the
   early base/r/z oracles and a beta_i. A future commitment port must bind all of
   these before deriving the a alphas and 3a matrix coefficients.
3. Compute p_i,h_i and submit h_i; derive virtual g_i from the same beta_i. Bind
   that round before obtaining the P vectors of 2J reducer coins and first FRI coins.
4. Compute W_p, successive FRI words and terminal vectors under the unchanged fold
   order. Bind each message before its dependent challenge. Fix all terminal
   vectors before deriving the verifier's query positions.
5. Open the existing complete dependency closure at the scheduled positions. A
   future serializer must reproduce this exact view, including beta and terminal
   coefficients; it may not expose extra private entries or accept omitted ones.

Roots, salts, paths and the complete private EXP2 driver remain deliberately
unimplemented. No new cryptographic transcript identifier or byte format is
silently deployed by this specification.

## Joint simulation: an explicit algebraic argument

The claim in this section is **perfect equality of distributions** for a
straight-line classical algebraic verifier whose projected position union is at
most b, and a satisfiable public R1CS instance. It concerns ideal polynomial
oracles and public field messages, not the current hashed native transcript.
It has no computational assumption and adds no unspecified statistical error.
Sampling from affine spaces below is a mathematical simulator operation, not an
implemented entropy routine.

Public inputs to S are the field/domains, matrices, primary input, full descriptor,
and access to the adversarial verifier's interactive messages/query requests and
public state. S may query its own lower-level simulated oracles. It never receives
the witness, credential, signature, holder secret, rid, Merkle path, honest prover
mask coefficients, or an oracle returning hidden witness values. S outputs the
public coins/messages and consistent requested field answers, including derived
folds and full terminal vectors. Validity of the statement is the usual ZK-domain
promise, not a witness supplied to S.

### S0: four base columns

Keep a lazy table T indexed by distinct u in L. On first use sample four independent
uniform field elements; on repeated use return exactly the cached quadruple.
At any v<=b distinct points, the v-by-b evaluation Vandermonde matrix has row rank
v. The mask factors Z_H1 and Z_H2/Z_Hpub are nonzero on L. Multiplying rows by
them preserves rank. Therefore the four real masked columns have exactly these
joint values, regardless of the hidden assignment. Conditional uniformity after
each adaptive request proves the lazy-table argument by induction, not merely for
fixed queries. Compute fz, rowcheck and ell_i at a requested point from that same
quadruple and public polynomials. Never sample these virtual answers independently.

### S1: mask, disclosed sum, quotient and related base queries

For each i, initially sample a dummy uniform r0_i of bound Dlin, send
beta_i=Lambda(r0_i), answer any early mask queries from r0_i, and record their
points U_i. Once alpha_i and the matrix triple are received, evaluate ell_i(u)
using S0 at each u in U_i. Sample p_i uniformly subject to:

```text
degree(p_i) < Dlin
p_i(u) = r0_i(u) + ell_i(u)   for every u in U_i
Lambda(p_i) = beta_i
```

These constraints are feasible with their stated rank: U_i is disjoint from H
and Dlin=2t+b-1 >= t+|U_i| for t>=1. Interpolation on U_i union H shows that Lambda
adds one independent condition to evaluations on U_i. Thus no inconsistent
conditioning is concealed. Compute h_i and g_i from this p_i and beta_i. For a
later r_i query return `p_i(u)-ell_i(u)` using the same S0; all h/g/combined queries
use the same p_i. The simulator knows p_i's coefficients but not ell_i globally.

For a valid witness Lambda(ell_i)=0. Translation `r_i -> p_i=r_i+ell_i` is a
bijection on the appropriate affine coefficient space, preserves its uniform
measure, preserves each cached mask answer and sends the sum condition to beta_i.
This proves equality of the entire r/beta/h/g/base joint view. Public challenges
may be adversarially chosen, including zero triples; the pad coefficient remains
one, so there is no exceptional zero-pad event to subtract. Independence between
fresh r_i makes the argument valid across a repetitions conditional on their
shared T and transcript. This specialises the conditioning argument underlying
Aurora Protocol 5.8 and its Theorem 7.4 base-column simulator.

### S2: early pads, adaptive queries and complete LDT messages

For each p sample a dummy uniform z0_p of bound D, answering and caching pre-coin
pad queries V_p. When the 2J coins arrive, let
`C_p(u)=sum_j (u_pj+v_pj*u^(D-d_j))*O_j(u)`.
Obtain every required O_j(u) at u in V_p through S0/S1, at those same positions.
Sample a uniform polynomial W_p of bound D constrained by
`W_p(u)=z0_p(u)+C_p(u)` for u in V_p. Distinct point constraints have full rank
since |V_p|<=b<=D. Subsequently answer z_p(u) as W_p(u)-C_p(u), retaining all
previous answers. For every real underlying assignment the equalised C_p has
degree <D, so translation by C_p bijects the uniform pad space. This is the
unit-pad conditioning step of general Protocol 8.6, with the paper's non-ZK LDT
allowed to act on the simulated, known W_p.

Run the honest algebraic FRI message computation on the known W_p and the actual
verifier's fold challenges. Use the same W_p across its I repetitions. This gives
the whole folded polynomials and therefore every requested fold answer **and all
IP full Df-coefficient terminal vectors**, with their correlations intact. P pads
are independent conditional on the common lower-level transcript; process their
conditioning and subsequent adaptive requests in causal order. Fresh independent
dummy polynomials do not mean independently sampling related terminal messages.

The argument is an induction on the actual interactive history: every conditional
translation preserves prior answers, future requests are answered by the same
tables/polynomials, and each lower-level request occurs at the very point queried
in an upper L0 oracle. Queries to folds/terminal messages are answered from W_p,
not by inspecting the hidden witness. For the specified verifier the projected
union is consequently S0, the union of opened L0 cosets. This proves the required
projection closure for this corrected algebraic protocol. It does not count each
column answer as a new domain point or assume that the unchanged source variant
has this simulator.

### Scope of the simulator and repeated presentations

The local rank/bijection arguments discharge the algebraic joint-view steps for
the defined family. They do not prove that unexecuted C++ edits implement them.
Formal refinement must connect both point and vector paths, exact ordering,
malformed-message handling, field arithmetic, quotient domains and sampler calls.
Failure of any such correspondence prevents use of the claim for that program.

Fresh presentations require fresh independent base, sumcheck and reducer masks.
Conditioning on a previous classical session's public history leaves the next
session's masks independent. Replacing sessions in chronological order therefore
gives equality for sequential presentations in the stated ideal model, including
adaptively selected valid public statements. Public disclosures remain public.
This does not establish concurrent-session, quantum-query, state-restoration or
Fiat–Shamir composition. Reusing a polynomial across presentations violates the
freshness hypothesis; resending the same proof is not a fresh presentation.

The unresolved commitment lemma is precise: construct a simulator for the chosen
root/salt/opening encoding that binds before challenges, answers all permitted
adaptive openings consistently, and implements this algebraic simulator without
the witness, under the selected commitment/oracle model and budgets. The algebraic
simulator lazily determines oracles; hashing their entire real tables would not
be justified by its construction. Packed raw-field leaves, unsalted h/fold trees
and all direct messages must be included. No commitment error term is appended
without that transformation. This remains TB-06/TB-09, not a new lemma needed for
the ideal algebraic correction itself.

## Query, communication, soundness and relation preservation

With Sj the union of cosets opened at FRI layer j, `uj=|Sj|<=min(2q,|Lj|)` for the
binary scheduled verifier. The proposed scalar disclosure count is:

```text
E_open = (4+2a+P)*u0 + IP*sum(j=1..r-1, uj)
M_direct = a + IP*Df
V_explicit = E_open + M_direct
B_RS = |S0| <= b                 # proved projection, not V_explicit
Q_H = adversarial hash queries   # a separate transformation budget
```

Real oracle counts remain 4+a+P in the early round, a quotient columns, and IP
per later fold layer. Add a direct beta_i fields. Initial explicit verifier
messages change from 6a to 4a fields; reducer messages from P(6a+12) to P(6a+10).
The Ir fold coins and terminal vectors remain. If a future GF(2^192) canonical
24-byte field encoding is selected, the beta payload alone is 24a bytes before
framing; this is not a measured proof size. Roots, salts, indices, authentication
paths, lengths, counters, statement and query description are additional view data.
No scalar count is substituted for b or Q_H.

Unit padding preserves honest degree correctness. Removing the two extra sumcheck
coins is justified for the specified one-ell, zero-claim branch by the published
alpha/triple lincheck structure, not by deleting constraints. All four base bounds,
rowcheck, every r/h/g bound, raised-degree tests, FRI checks and primary-input
consistency remain. Degree rounding and corrected intermediate metadata must agree
with fold domains and final coefficient lengths. Parameters outside the stated
family are rejected rather than silently rounded into another profile.

For soundness, use the RS-encoded consistency argument with the general reducer
and a separately justified FRI proximity test at the stated strict slack. Do not
reuse Figure 5's exact optimised finite bound after choosing a different tested
matrix, or credit the removed random coins. Numerical a,P,I,q, reduction errors,
restricted state-restoration, knowledge and finite authentication dimensions remain
unresolved. This is not a concrete security-level assessment.

For eventual authentication, the unchanged relation in
[the specification](implementation_spec.md) still requires the same certified
message/attributes, issuer key/context/instance, bounded ML-DSA verification,
holder binding `Y=H(enc_holder(suite,mu,xH))`, certified rid and its zero-leaf
non-revocation path, disclosed fields from the same canonical message, and all
public state/freshness checks. None moves to a host-side unauthenticated check.
The proposed changes wrap a satisfiable R1CS encoding; they do not establish the
missing complete compiler-to-authentication equivalence. No signature, encoding,
sampler cap, policy or accepted credential set is changed in the repository.

## Obligation decisions and one inactive next package

| Obligation | Disposition after this contract |
| --- | --- |
| TB-01/02 | Public native EXP2 evidence retained; full private schedule, new beta messages and descriptor binding unimplemented |
| TB-03 | No-PoW full driver remains required; a legacy zero-work setting is not assumed to disable it |
| TB-04 | Ideal algebraic correction and joint simulator specified above. Existing zero-sum/random-pad variant remains unproved; no claim that it is broken. Native correspondence for the proposed branch remains open |
| TB-05 | Common-position projection established for the proposed unit-pad ideal construction. Scalar/direct disclosures fully enumerated. Finite private dimensions and source/parser query closure still open |
| TB-06 | Packed or scalar commitment transformation, salt policy and adaptive root/opening simulation open |
| TB-07 | Concrete hash ports, canonical field bytes, expansion and full private EXP2 integration open |
| TB-08 | Fold registration correction precisely specified, not applied. Field/basis certificate, all fold/vector correspondence and finite parameters open |
| TB-09 | Classical restoration/knowledge, quantum extraction, concrete hash and complete adaptive proof privacy open; no transferred numerical claim |
| TB-10 | Wire/parser must bind every oracle, beta and terminal coefficient in the chosen future descriptor; unimplemented |

**Recommend only S3-AURORA-SUMCHECK-MASK-CORRESPONDENCE-PILOT-1 next.** It would
implement SC-1–SC-4 and the minimal IO registration needed to reach the actual
native sumcheck, in a new isolated copy with public synthetic assignments. It
would not implement the reducer, run Aurora proofs or use real private witnesses.
Propose eight counted cases and at most two builds, a 60-second implementation
subcap with 20 seconds for finalisation, 1 GiB native/256 MiB audit limits, and the
existing artifact ceiling. These are inactive requests; builds are presently
exhausted and the two unused tooling invocations are not native allowances.
Require a fresh nested evidence-headroom check with at most 512 KiB new evidence,
128 KiB reserved within it for completion; no automatic increase of an enclosing
limit. If those resources cannot fit, do not launch.

The proposed eight distinct checks are: unrestricted mask coefficient mapping and
beta; non-unit xi sum identity; zero lincheck triple with unit mask; nonzero triple
with exact quotient/remainder identities; honest prover/verifier point agreement;
shifted-domain vector/point agreement; wrong beta changes the required top-term
condition; malformed beta length/domain/branch admission as one specifically
enumerated parser case (each additional parameterised input must count separately).
The final case must select one concrete malformed input before admission; the
other malformed variants remain untested, not hidden inside that invocation.
Expected results must come from independent exact polynomial arithmetic, with
prescribed public coefficient vectors, never outputs of the candidate under test.
No empirical distribution test is a substitute for the coefficient-space argument.

Acceptance requires both native paths, preservation of all related messages,
correct nonzero beta handling, exact public polynomial identities, rejection of
the specified malformed input, zero unexpected failures, and a complete guarded
preservation audit. Report finite coverage honestly. Stop on the first unexpected
result or resource breach. Even success admits neither a private prototype nor
the reducer/FRI/commitment integration; their contracts remain subsequent gates.
This is a concrete next implementation request, not another general review.

## Resource and preservation record

Opening analysis balance is 144.66996550441067 seconds, verified against the prior
completed ledger; this package cap is 60 seconds with ten reserved for completion.
Read-only literature lookups charge 8.392 seconds (5.392 directly timed plus a
conservative three-second charge for the first grouped lookup). The established
five-second local source-review/bookkeeping charge covers preparation and final
additive reporting; guarded commands add their measured durations. Native
107.26425821718294 seconds, implementation 111.82163787621539 seconds, provisioning
41.843650440103374 seconds and isolation 250.22 seconds remain unchanged.

Opening cumulative evidence is 16,323,830/18,874,368 bytes, with 2,550,538 bytes
available. The new reservation is 1,048,576 bytes, including 262,144 for completion;
it fits after closing the preceding package's unused reservation. Historical
consumption is not removed. No artifacts are generated. The inherited 256 MiB
analysis/audit cgroup guard, zero swap, one worker, two CPUs, process, time,
temporary-storage and diagnostic stops remain unchanged.

Only this report, its evidence and appendices to status/traceability/issues are
new. Historical reports, repair artifacts, baselines and complete source/binary
seals remain protected. The previous working auditor supplies the same disjoint
baseline comparisons, full inventory, strict hashes and append-only checks.
Static/documentation checks are not functional test invocations. Detailed guard,
coverage, final inventory/readback and additive seal results are appended below.

No new tests/builds/native executions/proofs/zkVM runs/installations/activation:
invocations 448/450, builds 5/5, proof attempts two used/one unused. Stages 2–3 and
AURORA-BRIDGE-001 remain open. Isolation is safely stopped/unactivated, raw-view
integration and CPU proving paused; adaptive Delta_tail, production security and
complete proof knowledge/privacy are unresolved.

### Retained documentation-check correction

The first static phase failed on one E501 diagnostic: a descriptive audit string
occupied 102 columns. Its log, resource record, STOP record and pre-correction
helpers/configuration are retained. Splitting adjacent string literals preserves
the exact runtime string. A separately named, manually diagnosed `quality-2`
phase then passed lint and format checks; no resource breach or functional retry
occurred. The wrapper acknowledges only that exact retained lint STOP/digest; a
different stop still blocks admission. Both durations remain charged and no
failure is relabelled. See `format-correction.json` in the package evidence.

### Complete preservation and final accounting

The corrected static phase, preparation and the single complete audit passed.
The original E501 failure remains recorded (no integrity or resource breach).
Audit exit **0**, outer guard passed, and report-generation/readback completed.
All **10,901 disjoint baseline comparisons** completed: 8,759 primary and 2,142
supplemental, zero overlap; identity coverage 10,936 paths. The in-audit inventory
covered 8254 names with no missing/unexpected entries.
The post-report final inventory and full-file seal are in
[closure](data/s3_aurora_masking_correction_contract_1/validation-closure.json) and
[manifest](data/s3_aurora_masking_correction_contract_1/manifest.json); the baseline
was not regenerated. The retained native sources/binaries and every earlier repair
remain protected. Only the three authorised existing documentation files changed.

| Phase | Outcome | Charged wall seconds |
| --- | --- | ---: |
| quality | failed (exit 1) | 0.303696 |
| quality-2 | pass (exit 0) | 0.276489 |
| prepare | pass (exit 0) | 0.526144 |
| full-audit | pass (exit 0) | 3.894257 |

Audit memory was **49,020,928 bytes (46.750 MiB)** of cgroup-v2
`memory.peak` under the unchanged 256 MiB ceiling. Its scope includes the worker,
descendants and charged anonymous/file-cache/kernel memory; the external monitor
is outside that cgroup. Separately sampled aggregate tree RSS was
64,368,640 bytes. Temporary storage was zero.

Guarded work charged 5.000586s; with 8.392s literature and
5s local review/bookkeeping, package consumption is **18.392586/60s**.
Analysis remains **126.277380s**; native **107.26425821718294s** and implementation
**111.82163787621539s** remain unchanged. The unused time is not a new allowance.
Invocations **448/450**, builds **5/5**, proofs **two used/one unused** are unchanged.
The final byte totals below count retained cumulative evidence and every new
report/metadata byte, including this finalisation.

Source/documentation package complete. The recommended sumcheck pilot is inactive;
no private prototype or further integration started. Stages 2–3 and
AURORA-BRIDGE-001 remain open.

Final evidence: new package 000000175194/1,048,576 bytes; cumulative 000016499024/18,874,368; cumulative headroom 000002375344. Final inventory 8259 names; no missing/unexpected entries.
