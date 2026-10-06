# JHM-FR254-PACKED-1: single candidate examined, not adopted

This specification joins the retained direct-integer relation proposal to one
multiplicative-domain masking and packed commitment proposal. It is a decision
artifact, not a new circuit, native patch or proof profile. Only manuscript
Sections II–VIII and SPEC-001–004 govern the authentication predicate.

## Relation, field and exact representations

The field is Fp, p =
21888242871839275222246405745257275088548364400416034343698204186575808495617,
the pinned libff alt_bn128 **scalar** field, not its different base field.
Each external field value is exactly32 little-endian bytes encoding an integer
<p; reject noncanonical values rather than reducing them. Native Montgomery
storage is not a wire encoding. Field operations do not replace integer semantics.

Reuse the complete kernel equations and no-wrap arguments in
`docs/data/oct31_arithmetic_r1cs_feasibility_1/contract.md`. Private bytes have
eight constrained bits; unsigned and signed packed integers are linked to those
same bits. Each bit satisfies b(b-1)=0. Ranges are established by decomposition
and complement equations; mod-q outputs satisfy 0<=r<8,380,417 and bounded k in
x=cq+r. Wide65/128-bit arithmetic preserves signed64 overflow rejection.
Input normalisation accepts the existing signed64 entry domain. Quotients,
carries, byte links, inactive outputs and validity flags cannot be free advice.
Degree stays at most two by naming a product before any conditional guard.

Hash bits use AND xy=z, XOR (2x)y=x+y-z, NOT1-x and rewiring for rotations.
Every private chi product is retained; no hash lookup, custom gate, cross-round
fusion or field-native replacement hash is introduced. This does not retain one
row per Boolean arithmetic AND: polynomial integer/modular operations use direct
equations. It does retain the exact SHA3/SHAKE Boolean predicate. ML-DSA-65,
its7-permutation final hash, bounded ExpandA/SampleInBall, malformed signatures,
hints, norms, context framing and sampler exhaustion remain unchanged.

One parsed witness supplies xH, attributes, signature, certified rid and path.
The same bytes feed holder binding, credential authenticity, disclosure and
same-rid non-revocation. Public inputs are the existing canonical parameters and
authentication statement, including instance, expected issuer key, context and
authenticated state. No prover-supplied mu, holder digest, matrix or acceptance
flag is trusted. Relation/descriptor identity binds the public statement bytes,
field, all matrices, ordering, ranges, domain/masking/query settings and versions.
Compiled statement constants are independently recomputed by the verifier.

Kernel completeness/soundness is the retained bounded integer/bit induction.
Full composition additionally needs every reference check and branch linked to
the same assignment. No full compiler, matrices or equivalence tests exist for
this candidate. This is an explicit proof obligation, not an assumed predicate.

## Domains and order

Let Omega be the recorded primitive2^28 root of unity. For power-of-two s<=2^28,
H_s={Omega^(2^28/s*j):0<=j<s}. Use bit-reversed exponent order, so the first K
variable positions form H_K for power-of-two K dividing N. Pad rows/variables
deterministically with zero constraints/columns; preserve the constant column
and ordered primary public values. Every padding auxiliary is fixed, not advice.
H1=H_M, H2=H_N, Hpub=H_K, H=H_t, t=max(M,N). Choose L=5H_S, S a power of two
at least t. Explicitly verify the root's order and 5^S!=1. Then L is disjoint
from H and excludes0. Z_Hs=X^s-1. This mapping needs new native correspondence;
the binary additive basis/vanishing formulas cannot be reused by renaming types.

M,N,K,S and all counters are validated finite descriptor values. Failure to find
admitted finite values rejects construction; the descriptor is not a request to
the verifier to search or allocate. No finite authentication descriptor is chosen
by this decision. The existing public primary count would give K=2, including
the constant and acceptance value, with the full statement bound separately.

## Joint masks and related disclosures

All degree bounds mean strictly less. Let b bound the projected common-domain
query union. Independently sample Rw,RA,RB,RC uniformly from Fp[X]_<b.
Interpolate fz0 on H2 and fA0/fB0/fC0 on H1 from the **same** assignment.
Set fz=fz0+Z_H2 Rw, fw=(fz-fpublic)/Z_Hpub, and fA=fA0+Z_H1 RA, etc.
Bounds are N+b, N-K+b and M+b respectively. Rowcheck is the virtual quotient
(fA*fB-fC)/Z_H1, bound M+2b-1 on satisfying assignments. It is not freshly masked.

For alpha_i and matrix mixing fields s_ij, define public polynomials on H:
Palpha(h)=the H1 Lagrange evaluation weight at alpha_i if h in H1, zero otherwise;
Palpha^j(h)=sum over H1 rows of matrix_j[row,h]*weight(row), if h in H2, zero
otherwise. Interpolate these tables with degree<t. Define
ell_i=sum_j s_ij*(f_j*Palpha-fz*Palpha^j). This gives sum_H ell_i=0 by the matrix
identity. Its bound is Dlin=2t+b-1. This explicit definition avoids relying on
an additive-only implementation of public polynomial evaluation.

For each repetition independently sample r_i uniformly from Fp[X]_<Dlin.
Equivalently r_i=Z_H v_i+u_i, with independent uniform coefficients of u_i
(length t) and v_i (length Dlin-t), including possibly zero leading terms.
Disclose beta_i=sum_H r_i=t*u_i(0) before alpha_i and s_ij. Set p_i=r_i+ell_i;
divide p_i=Z_H h_i+g0_i. The virtual
g_i=(p_i-Z_H h_i-beta_i/t)/X has bound t-1; h_i has bound Dlin-t.
Division is polynomial division because g0_i(0)=beta_i/t. Point evaluation is
safe since X!=0 on L. Using the additive top-coefficient formula would be wrong.

Keep a,P,I,q,r positive, binary folding, J=3a+5 tested handles in the retained
order (r_i,h_i,g_i),fw,fA,fB,fC,rowcheck. Set
Dtest=max(Dlin,M+2b-1), Dconstraint=max(Dlin,2M+2b-1),
D=2^r*ceil(Dtest/2^r), Df=D/2^r, and S>=8*max(D,Dconstraint).
No b, rate, repetition or security target is weakened. Finite settings must
meet the retained proximity/rank and actual soundness obligations.

Each reducer pad z_p is independently uniform in Fp[X]_<D, committed early.
After all tested commitments, obtain exactly2J independent field challenges and
form W_p=z_p+sum_j(u_pj+v_pj X^(D-d_j))*O_j. Pad coefficient is exactly1.
For binary multiplicative folding, decompose f(X)=fe(X^2)+X*fo(X^2), and set
the next word at X^2 to fe(X^2)+challenge*fo(X^2). The two required values are
at X and -X; fe=(f(X)+f(-X))/2 and fo=(f(X)-f(-X))/(2X).
Fold challenges are distinct per repetition; I repetitions share W_p, not newly
sampled pads. Every full Df-coefficient terminal vector, including its specified
padding, is disclosed before query positions. No oracle correlation is discarded.

This specifies ideal independent uniform coefficient distributions. A concrete
fresh-entropy sampler and a bounded rejection-to-Fp procedure remain required;
mod-p reduction of arbitrary bytes is not declared uniform. No new sampler cap
or entropy assurance is silently supplied. The existing work/time limits would
have to accommodate all draws; exhaustion must abort without a partial proof.
Presentations require fresh independent masks and salts. No seeded/reused tapes.

The base-mask Vandermonde rank argument extends to distinct points outside H.
For sumcheck, evaluation constraints on U subset L together with sum_H add
independent conditions when Dlin>=t+|U|. Translation r_i->r_i+ell_i preserves
uniform conditional distributions and beta because sum_H ell_i=0. For the
reducer, translation by the degree-<D combined word preserves the uniform pad;
full folds and terminal messages are derived from that one masked word. These
are local algebraic arguments. They do not establish the full modified
knowledge/soundness theorem, native correspondence, commitment simulation or
quantum/application security. The retained additive guard stays closed.

## Exact proposed disclosure/commitment boundary

E is the existing canonical record encoding (length-prefixed tag, field count,
length-prefixed fields). Integers in metadata are fixed unsigned big-endian64,
except a version field unsigned32. Field vectors use canonical32-byte elements,
with their count explicitly bound. No raw native struct serialisation.

Use one packed tree for each registered round/domain, with binary-coset leaves:
round0 packs (fw,fA,fB,fC,r_1..r_a,z_1..z_P), round1 packs (h_1..h_a), and
each later folded layer packs its IP real columns. Each leaf contains the two
positions' fields in registered order and one fresh128-byte salt. Leaf hash is
BLAKE2b-512(E("jhm-leaf",(profile,statement_binding,round,domain,leaf_index,
ordered_field_bytes,salt))). A parent hashes E("jhm-node",(profile,round,domain,
level,index,left_digest,right_digest)); root registration binds tree size/order.
All trees, including h/fold trees, are salted. This is an explicit inactive
change from both native raw packed leaves and the earlier scalar-tree draft.

Use the agreed EXP2 framing/order/counters to absorb the complete descriptor,
statement, each ordered root/message and beta values before dependent challenges.
Prime-field challenge extraction and these new typed leaf domains are unimplemented
ports; native public EXP2 tests do not validate them. No proof-of-work branch.
Disclosures include statement, descriptor, roots, beta_i, all terminal coefficients,
ordered opened fields/salts/sibling paths, indices/counts and all challenges.
Parser bounds must be derived from the finite descriptor; missing/extra fields,
noncanonical fields, wrong contexts/order, counter overflow and unsupported
profile identities reject. Ordinary verification remains fail-closed.

Let S_j be the actual opened coset-position union at layer j, u_j=|S_j|<=min(2q,S/2^j).
Scalar openings are (4+2a+P)u_0+IP*sum(j=1..r-1,u_j). Direct fields are
a+IP*Df. For the proposed conditional algebraic simulator the projected base
query union is B_RS=|S_0|<=b; that closure must hold for the complete transcript.
Scalar entries, terminal coefficients, q, b and outer oracle queries Q_H are
different quantities. Opening additional packed entries or reusing masks changes
the conditions. Separate salts/paths count towards transcript storage and the
commitment proof, not additional algebraic points by fiat.

## Decision gate

This single candidate is semantically specified but not an admitted construction.
The known final-hash subset alone violates resident limits, and the complete
prime-domain knowledge/privacy and commitment correspondences remain open.
Do not implement isolated gadgets, execute a private proof or allocate a larger
instance. The accompanying decision chooses C and closes this Aurora route for
the current delivery plan, preserving all previous results.
