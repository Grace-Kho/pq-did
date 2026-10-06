# S3-OUTER-ORACLE-COMPOSITION-1 — finite composition decision

25 September 2026. **Review complete: additional, precisely specified lemmas are
required for the full shared-permutation knowledge/privacy claim.** The existing
ideal-QROM argument remains a conditional research reference. An ordinary bounded
oracle-game comparison is justified below; a concrete Keccak extractor or privacy
theorem is not. No profile change or overall classical/quantum security level is
claimed. The next implementation priority is **S2-BOUNDED-MLDSA-KEYGEN-SIGN-1**,
not another automatically scheduled composition review.

## Authority, identity and evidence reuse

Authority is only manuscript **Sections II–VIII**, SPEC-001–004 and the
[implementation specification](implementation_spec.md). Manuscript SHA-256:
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The unchanged source inventory revision is
`b2d0b57afe4b10c1ee6f41fc32ac031da96e332f79a98c6040aaebe1fd07c3a3`
(content identity, not a Git commit). [Preflight](data/s3_outer_oracle_composition_1/preflight-evidence.json)
verified all 56 files in the preceding review seal, SHA-256
`28a2f7384dffeb0e4a89cdd0c8c7f164773c08455e1dd0e1930d726caeccc290`,
and the 53 source/input entries before manuscript-dependent changes.

Reuse the [security assessment](stage2_concrete_security_assessment.md),
[outer-hash review](stage3_outer_hash_security_review.md),
[exact bounds](data/s2_concrete_security_assessment_1/bounds.json) and
[query mapping](data/s3_outer_hash_security_review_1/query-mapping.json).
No numerical calculation, cryptographic functional test or old test suite was
repeated. Primary theorem interfaces were reread for this narrower question;
[source locators](data/s3_outer_oracle_composition_1/sources.json) and the
[machine-readable game contract](data/s3_outer_oracle_composition_1/games.json)
record the review. They are analysis records, not executable proofs of the lemmas.

The manuscript BC-1 construction is distinct from the partially implemented
reference predicates/circuits and from experimental RISC Zero Succinct/Poseidon2
evidence. There is no complete BC-1 authentication prover/checker implementation.
Neither this argument nor the ideal BC-1 numbers establish quantum knowledge or
privacy for the alternative backend. SEC-004 and full circuit equivalence stay open.

Isolation is safely stopped and **unactivated**, using the sealed
[closure evidence](data/s2_concrete_security_assessment_1/host-closure.json) and
unchanged user disposition. No host queries or mutations were needed. Its original
failures, approvals, 100 executed invocations, 22 pending identity cases and
250.22-second allowance including the ten-second reserve are preserved.

## Objects and interfaces

Write K for the fixed public 24-round Keccak-f[1600] algorithm, P for a uniformly
random 1600-bit permutation, and U_J for ordinary coherent XOR-query access to a
function J (including a length register for variable inputs). A forward/inverse
permutation interface is the corresponding reversible oracle interface; inverse
access is not an inverse of an external signing, registration or revocation service.
Classical function evaluation is a restricted use of this interface. Domain,
padding, response-register and inverse conventions must be included in an adapter.

Define `H_J(x)=prefix_1024(Sponge_J,pad_SHAKE256(x))`, r=1088, c=512.
F denotes the ideal full sponge functionality used by ACMT, with consistent output
prefixes; F0 is its 1024-bit outer restriction. Write **S_perm** for the ACMT sponge
simulator, **E_DFMS** for the online extractor, and **Sim_proof** for the
manuscript's privacy simulator. These are three different algorithms.

Let W contain the adversary A, the sequential honest services, the entire classical
history Hist, a current-state/clock/nonce-consumption service, and a final efficient
test on the public output and residual adversarial state Z. No extra authority
collusion, hidden witness disclosure, network leakage or rollback capability is
introduced. Parameterise its lifetime by budgets, not by measured implementation
test counts. W has an initial state independent of the freshly sampled ideal
primitive, unless a separately stated advice model supplies a justified bound.

| Actor | Ordinary access | Privileged capability, ownership and limit |
| --- | --- | --- |
| Adversary A | Classical Section VI protocol calls; quantum outer queries; local coherent evaluation of public K where K is fixed. In P-games also quantum forward/inverse P ports | No program/read access to a random-oracle table or honest secret. Fixed public K computation costs time/gates, not an ideal-outer query |
| Honest parties and reference verifier | Classical service messages, actual witnesses locally, classical outer evaluations; internal hashes as specified for the game | No oracle programming. External classical services are forwarded in order, with no reset, rewind or inverse access |
| E_DFMS | Runs the adversary/environment and final proof checker, answering all ideal outer queries itself | Owns the compressed F0 database; after final verification measures it and recovers commitment preimages. This is not an ordinary U_F0 operation and is not supplied by ACMT's public ports |
| Sim_proof | Public statement/kind/authorised leakage; constructs selected opened views and uniform unopened commitments | Uses a programmable ideal outer oracle in analysis. Has neither witness, selected index, future revocation data nor permission to rewrite retained credentials or service history |
| S_perm | Ordinary quantum queries to F; offers simulated forward/inverse primitive ports; maintains private quantum workspace | Owns its simulator databases, not an extraction interface for F. ACMT §7.1 uses its own h/k/k' databases to find a tail, then queries f. The proof's compressed representation of f does not grant arbitrary inspection/programming of f to S_perm |

All ordinary F calls made through S_perm count. The implementation of S_perm may
have internal coherent database operations; confusing those with a right to read
the shared F database would improperly give E_DFMS's capability to another actor.
Similarly, a call named `program` in a privacy proof is not implemented by hashing
an input, replacing a cached digest, or altering a concrete permutation response.

## Exact games and relation treatment

Each game below includes all permitted classical service calls and a single
continuing adversary state. For extraction the terminal output includes
`(X,pi,Hist,Z,accept)`; for privacy use the Section VI left–right bit and a final
guess after all permitted continuation. This names games even where the full
proof construction for a proposed oracle model has not yet been supplied.

| ID | Outer and primitive interfaces | Hashing inside the credential/authentication relation | Status |
| --- | --- | --- | --- |
| **G-K** | Outer H_K; public K/K-inverse code, no independent ideal oracle | Fixed executable SHAKE/SHA3 code, bounded FIPS verification and canonical BC-1 lowering f_X^K | Intended concrete manuscript instantiation; implemented only in components |
| **G-M** | Ideal F0 for outer commitments/challenge; public K code remains available | The same fixed f_X^K; internal computations are not F0 oracles | Manuscript VIII-A's hybrid model, used by VIII-C/D |
| **G-P** | Outer H_P and forward/inverse P; every Keccak-derived component uses that same P | Reference predicates become R^P. Replacing a BC-1 Keccak subcircuit with an oracle gate is an additional construction, not the existing f_X^K | Shared-permutation protocol skeleton; full BC-1 version requires OC-REL |
| **G-S** | Outer F0 and primitive ports S_perm^F, with one continuing S_perm state | Internal algorithms use the simulated primitive; their evaluations are oracle-relative and can affect its state | ACMT ideal endpoint for a defined G-P wrapper; not G-M |
| **G-SEP-P** | Outer H_P, public P ports, but internal algorithms retain fixed K | Fixed f_X^K | Diagnostic separated-primitive model only, not an adopted instantiation |
| **G-SEP-S** | Outer F0 and S_perm^F ports; internal algorithms retain fixed K | Fixed f_X^K; simulated primitive is an extra interface for the environment | Diagnostic endpoint, useful for locating the shared-relation gap |

In G-K/G-M the relation is an ordinary polynomial-time relation at the admitted
parameter family: CGen independently compiles **known fixed algorithms**, under
the prescribed gate order. It does not contain a call to the outer proof oracle.
`relations.auth_private` in [relations.py](../src/pqdid/relations.py) reconstructs
one credential and uses its same attributes/rid for CredValid, disclosure and the
non-revocation path. The fixed-hash implementations in
[bounded_mldsa.py](../src/pqdid/bounded_mldsa.py),
[binding.py](../src/pqdid/binding.py), [merkle.py](../src/pqdid/merkle.py) and the
partial [Keccak circuit](../src/pqdid/circuits/keccak.py) support that intended
meaning. They do not establish complete circuit equivalence or a proof system.

In G-P, allowing oracle queries to P inside a private relation gives a different
object: a relativised verifier. DFMS §3 defines a polynomial-time relation
`R_lambda subset I_lambda x W_lambda`, with the random oracle used by the proof
algorithms. It does not itself supply this project's MPC protocol for a private
random-permutation gate. XOR-sharing a permutation input does not make separate
permutation calls on the shares compute shares of the correct output. A random
permutation has no given succinct public circuit to substitute for the existing
24-round K circuit. Counting it as a free deterministic Boolean gate, supplying
an unbounded truth table, or accepting prover-supplied hash-output advice would
change the protocol or bypass a private check. None is done here.

G-S creates another issue: S_perm is a stateful oracle algorithm. A relation whose
truth changes with oracle history is not automatically the fixed R_lambda of the
commit-and-open theorem. One cannot declare S_perm's whole private state to be
public instance data or a witness to repair the type mismatch. OC-REL must specify
a stable relation and the legal operations of its proof and extraction algorithms.

### Shared hash calls and domain separation

Reuse the exact two outer encodings: 1,440 commitments to framed `view` records
and one framed `challenge` containing A and a fresh 64-byte nonce. Their distinct
tags/arities, suite, kind, instance, repetition and party indices are injective
and separate the two outer domains. Restrictions of **one ideal random function**
to these disjoint input sets have independent tables; both still use one coherent
query interface, including superpositions over the domains. No independence of
different challenge trits is assumed; the modulo map and p_star are retained.

That fact says nothing by itself about independence from these concrete users:

| Component | Shared use of K/P | G-M versus shared games |
| --- | --- | --- |
| ML-DSA verification and future bounded keygen/signing | SHAKE128 matrix expansion; SHAKE256 tr, mu, challenge, secret/mask expansions and capped challenge sampling, with their FIPS inputs/output lengths | Fixed algorithms in G-M. Primitive calls in G-P/G-S must count against P budgets; do not replace each function by an independent random oracle |
| Holder/binding and Merkle/record computations | SHA3-384, different suffix/rate but same 1600-bit permutation | Component collision/preimage assumptions remain distinct; an outer domain tag does not establish primitive separation |
| Outer view/challenge | SHAKE256 with a 1024-bit output | Same-byte-input SHAKE256 results of shorter length are prefixes, not independent outputs. No feasible valid cross-domain collision or attack is asserted |

Within G-M, independence of F0 from fixed K is a **model assumption**, not a
consequence of the byte tags. Moving to G-SEP-P keeps that separation deliberately;
it must not be relabelled a result about the actual shared construction.

Here **A-K-MODEL** names the additional assumption that the property-relevant
behaviour can be assessed in the stated joint ideal-permutation abstraction, with
the same lifetime interfaces and all preprocessing charged. It is a generic-model
qualification, not literal indistinguishability of an oracle for known public K
from a random permutation: comparison with K's code would distinguish those two
oracles. Structural attacks using the concrete algorithm are not excluded by an
ideal-permutation theorem. Even adopting this qualification would leave OC-REL,
OC-EXT/OC-PRIV and OC-BUDGET to be established for the selected property.

## Primary results and justified transitions

The following is the bounded theorem-applicability table. The manuscript's
Theorems 6–9 are the target extraction/simulation statements; Theorems 10–11 inherit
their obligations. Direct certification and Merkle reductions (Theorems 4–5) do
not resolve these outer-proof questions.

| Source | Exact hypotheses/interface and conclusion used | Application and remaining condition |
| --- | --- | --- |
| [ACMT arXiv v2, 13 May 2025](https://arxiv.org/html/2504.16887v2), Definition 3.9, Theorem 7.22 | There exists an efficient S_perm such that every bounded q-query quantum distinguisher, with maximum block length ell, has real/ideal probability difference `O(ell^2*sqrt(q^9*2^-min(r,c)) + ell^3*(q^5*2^-min(r,c))^(1/4))` | Applies to ordinary primitive/construction ports, not database inspection or programming. Requires a defined wrapper and measured theoretical budgets, not only a protocol name |
| ACMT §7.1, §7.5, Definition 3.14/Claim 3.15 | Stateful simulation, valid padding, coherent lengths and output-extension adapters; computational simulation can introduce a quantum-PRP assumption, statistical query-bounded simulation has polynomial overhead | Keep chosen simulator construction, state, adapter costs and hidden constants symbolic. Its PRP is not concrete unkeyed Keccak |
| [DFMS v1, 28 February 2022](https://arxiv.org/pdf/2202.13730v1), §3, Definitions 3.1/3.5, Theorem 4.2 | Fixed efficiently computable relation; S-sound* ordinary commit-and-open; exists online E for all adaptive P*, preserving `(inst,pi,Z,v)` with simulation error zero and bounding accepting invalid extraction. E runs a compressed oracle and finally measures its database | Applicable to the fixed-relation ideal construction; not by itself to private P-gates, programmable proofs supplied to an attacker, or externally supplied permutation state |
| [GHM ePrint 2020/1361](https://eprint.iacr.org/2020/1361.pdf), Theorem 1 and Fig.2 | Any quantum query-bounded distinguisher issuing adaptive programming distributions; loss `sum_r(sqrt(qhat_r*pmax_r)+qhat_r*pmax_r/2)`. Coordinate mass is conditioned on preceding behaviour; all continuing ordinary queries are covered | Supports the specified ideal F0 hybrids with fresh coordinates. It does not assert b-independence of a different oracle-relative relation or give a concrete permutation programming operation |
| Manuscript VII/VIII-D; [ZKBoo Proposition 4.1](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_giacomelli.pdf), mapping reused from the assessment | Two-view simulation for the prescribed Boolean computation; here raw fresh tapes, canonical packing and complete checked relation | The fixed-circuit raw-view argument is retained. No oracle-gate sharing/simulation theorem or complete implemented-authentication equivalence is inferred |

No hidden big-O constant is set to one. The formal ACMT 7.22 expression is retained,
not replaced by its different informal Theorem 1.2 summary. This review uses
ACMT's quantum definition directly for the next elementary wrapper argument;
a classical composition theorem is not substituted for a quantum one.

### J-BIT: a supported ordinary-game comparison

Fix an algorithm W whose **only** access to the primitive/construction is through
the legal ports `(P,P_inverse,H_P)`, whose initial state and fixed code are
independent of P, and whose entire interaction plus final efficient bit test uses
at most `(q_W,ell_W,T_W)`. All honest/reference computations must be implemented
inside W or forwarded through explicitly charged compatible ports. W retains all
history and state across adaptive sessions and the historical-privacy cut-off.

Use that very W as the ACMT distinguisher, adapting only the canonical padding and
1024-bit output. Its real execution is W with `(P,H_P)`; its ideal execution is
the same W with `(S_perm^F,F0)`. Definition 3.9 and Theorem 7.22 give:

```text
abs(Pr[W^(P,H_P) = 1] - Pr[W^(S_perm^F,F0) = 1]) <= Delta_ACMT(W)
Delta_ACMT(W) = O(ell_W^2*sqrt(q_W^9*2^-512)
                 + ell_W^3*(q_W^5*2^-512)^(1/4))
```

This is a justified probability comparison for **ordinary, fully specified W**.
It allows adaptively chosen public statements and a final test on Z; “adaptive”
does not invalidate the definition. It applies equally to a legal bounded reference
predicate experiment, or the diagnostic G-SEP-P/G-SEP-S pair. It does not complete
the unspecified G-P proof protocol. Setting the final test to “accept” compares
acceptance; setting it to “extraction failed” is legal only if an extractor with
the required access has already been constructed within W. ACMT supplies no such
database-read port. No signing-service inverse, reprogramming port or oracle-state
measurement can be smuggled into W.

The prior coherent prefix adapter uses an unused `|+>` response register, preserving
superpositions; merely discarding unused output bits is insufficient. An ideal
1024-bit oracle has a uniform marginal under this adapter, but the simulator's full
ideal-function queries/tail must also be represented and counted. A compatible
full-output/prefix simulator is part of OC-BUDGET below, not free query work.

## Extraction: what is supported and what is missing

### J-EX: the fixed-relation ideal argument

For G-M take the protocol's actual canonical committed messages (including salt
and view) as the 1,440 DFMS messages. The advertised outputs and nonce are extra
first-message data, handled as in DFMS Remark 3.8; the base statement freshness
test still applies to X, not to an augmented `(X,aux)` instance. Domain separation
matches Remark 3.7. The deterministic full-message extractor tests the three
adjacent party pairs within a repetition and reconstructs the same witness if all
three choices pass. Its Boolean gate reconstruction is the manuscript's
S-sound* premise, not an extraction test implemented in this package.

For the modulo challenge retain the assessed weighted bad-set probability
`p_star=(2/3)^480+2^-544`: use the probability calculation in DFMS Lemma 4.1's
proof, not a false claim that trits are exactly uniform. With n=1024,
l_com=1440 and kappa=960, the ideal extraction bound is the previously checked
`epsilon_ex(Q)=min(1,31740*Q^3/2^1024+20*Q^2*p_star)`.

Quantifiers matter: for the S-sound* fixed-relation protocol, there is an online
E_DFMS, valid for **every** adaptive dishonest prover with the budget. It answers
queries while the prover runs, lets the final verifier make its classical queries,
then measures the compressed database and runs E* on the recovered preimages.
Its definition preserves the joint marginal `(inst,pi,Z,v)`; w is additional
analysis output. This is not extraction from an accepted transcript alone or
ordinary query access to somebody else's already instantiated oracle.

The target/history step can be made explicit without a new loss. In the ideal
model, include the real honest execution and its permitted classical services in
the prover environment, using actual witnesses for honest proofs. Retain Hist and
Z, forward external component calls once in order, and let
`T = fresh(X,Hist) AND S(Hist,X)` be the permitted terminal predicate. Simulation
error zero preserves the probability of `T AND accept`; accepting invalid
extraction remains at most epsilon_ex. Therefore:

```text
Pr[T AND accept AND R_fixed(X,w)]
  >= [Pr_G-M[T AND accept] - epsilon_ex(Q)]_+ .
```

This is event restriction of the cited bound, conditional on a correctly wrapped
fixed relation and its witness projection; it does not condition on T and divide
by its probability. All public checks and the same certified attributes/rid/path
must be preserved. Terminal extraction does not establish repeated extraction
before later protocol calls. In particular it does not silently supply VI-B3's
optional issuance-emulation table; the construction's certification reduction uses
direct message linkage instead.

Runtime remains `T_A+T_hon+T_gen+O(Q^2)*poly(1024,B_bits)+O(480*|f_X|)` with B_bits
covering every encoded oracle input and all verifier calls included in the chosen
conservative Q. Full authentication `|f_X|`, simulator cost and component signing
budgets are unknown. An expected-time replacement extractor would additionally
need an explicit truncation rule/loss; none is assumed.

### Why G-S is not already covered

If a simulator only makes ordinary F queries, it can in principle be included in
a larger query algorithm; its private work is not inherently forbidden by DFMS.
For a **fixed** relation, that observation makes G-SEP-S a useful diagnostic route,
once its full-output/prefix oracle and query costs are normalised. It does not
give the extractor privileged access through the public simulated-permutation port.

For the shared G-S endpoint, however, private relation evaluation uses the
stateful simulated primitive. The deterministic E* and the relation it must
satisfy have not been supplied for those oracle gates. E_DFMS's measurement of F's
database cannot simply be inserted into the real/permutation half of J-BIT: W
does not possess that register. A new emulation must specify which primitive
interfaces the extractor may replace, while keeping all external classical
services and target history consistent. OC-REL and OC-EXT state the exact missing
construction/lemma. No `epsilon_ex + Delta_ACMT` knowledge claim is asserted.

## Privacy: a separate composition problem

### J-PRIV: retain the full ideal simulation and restrictions

The G-M hybrids from VIII-D are retained: real proofs; fresh-nonce programmed
challenges; uniform unopened commitments using fresh-salt programming and its
removal; then the witness-free two-view distribution. Fresh 512-bit coordinates
give the conditional mass bound needed by GHM only when their stipulated
independence/erasure holds. Challenge programming uses a domain disjoint from view
commitments. Programmed challenges preserve the exact modulo distribution. No
protocol operation later opens a hidden view, and ordinary queries throughout the
continuation are charged. The reused loss is
`delta_ZK(N,Q)=min(1,481*N*(sqrt(Q/2^512)+Q/2^513)+960*N*Q/2^256)`.

The programmed values are fresh uniform values as required by the hybrid; this
does not grant an adversary arbitrary biased programming. Any ordinary query used
by the simulator to obtain a programmed value must also be included in Q.

For the fixed Boolean circuit the two-view simulator replaces the complete
observable proof, including lengths, while keeping actual persistent records. This
is a model-level argument under the admitted circuit's correctness/simulation
premises, not a completed private-proof implementation.

The following VI restrictions are part of the game, not optional assumptions to
drop during composition:

* Classical sequential protocol calls and one global left–right bit. Both
  credentials are accepted, honestly issued, uncorrupted, current, eligible,
  unrevoked and have valid updated witnesses. Both approve the same supported
  policy; metadata, disclosed positions/values, context and public outcomes agree.
* Contexts are fresh by audience/session/nonce; maintain Qshow and fresh **base X**.
  Policies, colluding verifiers and background corruptions can vary adaptively.
  Named OShow calls remain allowed under other fresh contexts. No challenge holder
  is ever corrupted; issuer/manager/current-state integrity and the specified
  service assumptions remain in force. No authority–verifier collusion is added.
* Leakage is the authorised `(mu,ctx,rs_e,D,m_D)` and fixed public deployment
  metadata, plus the required joint proof/transcript distribution. Proof bytes,
  lengths and residual Z cannot be declared harmless extra leakage. Cumulative
  disclosures may identify a holder; the theorem does not remove that information.
* During challenge access neither candidate may be revoked. At the adaptive
  cut-off challenge access closes permanently; at least one challenge credential
  must subsequently be revoked. Publish the actual identifiers, old sibling paths,
  states and metadata. Retain all named updates/presentations and permitted
  corruptions, but no later presentation using the hidden selected index.
  S_perm and adversary state cannot be reset at this cut-off. There is no
  post-compromise, timing/network or availability privacy claim.

The required final view is `(Hist_b,RevPub_after_cut,Aux_b)`, including Z and the
entire permitted oracle continuation. In G-M, replacing each world's proofs by
the public-only simulator gives a b-independent remaining execution, under those
restrictions. The guessing advantage is half the difference of the two output-bit
probabilities; use that convention, not an extra factor of two.

### Exactly where a composed privacy proof stops

S_perm emulates the primitive. Sim_proof simulates public proofs using programming
of F0. They are not interchangeable, and ACMT does not claim indifferentiability
for an arbitrary sequence of externally programmed ideal functions.

Nevertheless, statefulness alone is **not** a proof that composition fails. GHM
already permits an arbitrary query algorithm with private state. If all access
through S_perm is expanded into ordinary queries to one appropriately represented
F, that work can be charged within its distinguisher. Reprogramming effects on
that query algorithm are then covered by the GHM experiment; one need not reset
S_perm or demand an impossible perfectly consistent concrete permutation after
each programming instruction. This addresses an interface-level possibility,
not the complete joint-game lemma.

What still has to be proved is that the resulting ideal hybrid is the one whose
proof-view distribution and b-independence were established. In G-S, private
credential/circuit evaluation may make witness-dependent primitive calls and alter
S_perm's persistent state. Removing or replacing a private proof computation may
therefore change future simulated-primitive responses. The fixed-circuit G3=G2
argument alone does not identify those joint distributions. Public eligibility
checks on both candidates help enforce VI's rules but do not automatically remove
all private relation/prover calls on the selected witness.

One valid route, **if OC-REL/OC-PRIV/OC-BUDGET are proved**, is to use J-BIT only
on each *unprogrammed real endpoint* of the privacy game, then prove all ideal
hybrids with S_perm included. If those constructed endpoints obey
`abs(p_b^P-p_b^S)<=D_b` and `abs(p_b^S-p_common)<=Z_b`, the elementary triangle
inequality would give guessing advantage at most
`(D_0+D_1+Z_0+Z_1)/2`. This conditional algebra specifies the required quantities;
it does not assign D_b or Z_b to the old bounds. In particular, `Z_b=delta_ZK`
has not been established for the shared G-S experiment. There is no reported
concrete or full-protocol `delta_ZK+Delta_ACMT` bound.

## Transition and resource ledger

All theoretical budgets are separate from this review's wall-time/memory allowance.
Reuse `L=2^32-1`, `Bmax=8590196734` bytes, the canonical view/challenge framing and
the bound of fewer than 2^26 padded absorption blocks. These bound canonical
messages only. Full authentication g, `|f_X|`, actual statement size and all new
simulator/direct-primitive budgets remain symbolic. The 65,536-byte circuit
development guard is not a bound on an adversary's raw oracle-query domain.

| Transition / ID | Justification or required assumption | Resources and unresolved condition |
| --- | --- | --- |
| **T-K**, G-K to an idealised model | **A-K-MODEL**, an explicit additional modelling assumption about fixed public Keccak and the entire exposed interface | No concrete indistinguishability number is supplied. Treating K as a keyed random PRP or silently keeping a K bypass while replacing only its name by P is unjustified |
| **T-BIT**, defined G-P wrapper to G-S wrapper | J-BIT from ACMT Definition 3.9/7.22; supported for ordinary finite wrappers | `q_W=Q_outer+P_direct+P_internal+P_wrapper`, counting forward and inverse calls once. Do not charge a construction call's absorption calls a second time in this convention. Full proof wrapper blocked by OC-REL |
| **T-SEP**, G-SEP-P to G-SEP-S | Same J-BIT; explicit separated-primitive diagnostic | K is fixed local computation on both sides; P is independent of it. Does not model the implemented shared primitive |
| **T-EX**, G-M to fixed-relation extraction emulation | J-EX, DFMS 3.1/3.5/4.2, fixed circuit and weighted challenge mapping | All outer queries, honest/final verifier work and post-history selection included; `O(Q^2)*poly(n,B_bits)` plus E*/CGen/honest work. Full implemented equivalence remains open |
| **T-PRIV**, G-M to public-proof simulation | J-PRIV, GHM 1, manuscript raw-view argument and VI restrictions | N replaced proofs; fresh-coordinate mass, hidden-view erasure, complete continuation in Q. Component authenticity/service losses remain separate |
| **T-S-EX**, G-S to shared-relation extraction | **Unresolved OC-REL + OC-EXT** | Must supply a legal emulator, stable relation, event/history preservation and enlarged query/time budget; no additive loss currently licensed |
| **T-S-PRIV**, G-S to b-independent joint simulation | **Unresolved OC-REL + OC-PRIV** | Must include S_perm's continuing state, all internal users, programming/removal and actual post-cutoff publications; no additive loss currently licensed |

More precisely, define `Q_F = Q_direct_F + Q_Sperm_F + Q_honest_F + Q_hybrid_F`,
with disjoint categories and full-output/prefix adapter calls included. The
ACMT external-query budget q_W is **not** Q_F. Its stateful simulator contributes
unknown `Q_Sperm_F(q_W,ell_W)`, time `T_Sperm`, memory and auxiliary-randomness
cost. The statistical query-bounded construction and computational PRP variant
must not be conflated; the latter brings its own explicit assumption/loss. A
classical byte hash costs `floor(M/136)+1` permutation calls; a clean coherent
implementation can need compute/copy/uncompute. Use that alternative accounting
only when actually compiling a construction call into primitive-only access.

`ell_W` must cover maximum lengths in the support of all superpositions and output
extensions; `B_bits` for DFMS must cover simulator/adversary as well as canonical
inputs. Relation/oracle adapters must bound their own lengths. Fresh ideal
initialisation does not authorise arbitrary free P-correlated advice: count
preprocessing in the lifetime budget or supply a precomputation theorem matching
this multi-block/rate>capacity profile. Two chronological privacy phases can stay
in one continuous W; no simulator state is discarded between them.

The previous `Q=2^64/2^80, N=2^32` rows and monomial scaling are reused, **not
relabelled** with q_W or Q_F. No agreed numerical overall target exists; preserve
the assessment's provisional property/corruption/leakage/lifetime/gate/depth/
memory/QRAM/target budget definition. `T_A<=2^80` with unspecified cost unit does
not bound all these quantities. Adaptive Delta_tail and component advantages at
the enlarged reduction budgets remain explicit independent obligations.

## Finite decision and exact remaining work

The labels below refine SEC-002 rather than inventing numerical error terms.
They are precise deliverables required **if a stronger proof/profile claim is
later pursued**; this package does not schedule another review automatically.

| Obligation | Exact missing construction or lemma | Narrow claim until it is supplied |
| --- | --- | --- |
| **OC-REL** (Gap_jointGame) | Specify an efficiently representable relation and complete commit-and-open protocol for the selected shared-oracle model. Prove deterministic full-view extraction and two-view simulation for every added oracle operation, with a projection preserving the same certified attributes/rid, current root, public checks and admitted CGen identity. Alternatively supply a justified relation/game translation to the fixed-circuit model. No unconstrained hash-output advice or unbounded P truth table | The fixed-K Boolean relation is specified and partly implemented; a shared-P relation is only a skeleton. No theorem for private oracle gates is inherited from existing Boolean gates |
| **OC-EXT** (Gap_knowledgeExtractor) | For every admissible adaptive A and terminal predicate S, construct a legal sequential E_shared with explicit oracle-control rights. Bound joint observable-emulation distance and accepting-invalid-witness probability, retaining `(X,pi,Hist,Z,v)` and the original witness projection; give query/runtime/truncation costs. Explain how needed database access is obtained in the emulation without measuring an externally supplied oracle or rewinding external services | DFMS yields the stated terminal guarantee in the fixed-relation ideal model. Ordinary acceptance indistinguishability is not a knowledge guarantee for G-K/G-P |
| **OC-PRIV** (Gap_privacySimulation) | For each b, construct public-only online Sim_proof composed with one continuing S_perm. Prove closeness of the full `Hist,RevPub,Aux` view through programming/removal and internal shared-hash calls, then prove the resulting simulated worlds b-independent under VI. Identify the exact full-output oracle representation and conditional coordinate masses | Ideal G-M simulation remains supported under its premises. The shared G-S privacy distribution, including primitive state, is not yet identified with it |
| **OC-BUDGET** | Give an explicit finite adapter/simulator/query-length/preprocessing/time/memory accounting for each valid transition, with the chosen version and numerical constants if a numerical instantiation bound is claimed. Component reductions need these enlarged workloads, not the original adversary budget | Symbolic asymptotic ordinary-game comparison only; no evaluated concrete transfer loss or overall security level |
| **A-K-MODEL** (Gap_KeccakModel) | Any claim about G-K must state its concrete fixed-algorithm modelling assumption and scope, or supply a property-specific reduction/analysis that replaces it. A random-permutation theorem alone cannot discharge it | SHAKE256 remains an explicitly qualified research reference, with no demonstrated attack inferred from weak/inconclusive reductions |

| Intended claim | Classification | Decision |
| --- | --- | --- |
| J-BIT for a defined bounded ordinary oracle wrapper | **Supported under the stated model and cited results** | ACMT comparison only, with symbolic loss and legal ports |
| J-EX terminal extraction/event restriction in fixed-relation G-M | **Supported under the stated model and cited results** | Requires the S-sound* canonical construction; not completed implementation equivalence or multi-extraction issuance emulation |
| J-PRIV ideal proof-view simulation with VI restrictions | **Supported under the stated model and cited results** | Fixed-circuit/raw-tape premises and fresh-coordinate conditions retained; all continuation included |
| Treating the concrete shared K construction as that ideal abstraction | **Conditional on explicitly named A-K-MODEL** | Model qualification, not a numerical concrete-security claim |
| Full shared-P knowledge / full shared-P privacy | **Unresolved because specified lemmas/constructions are missing** | OC-REL/OC-EXT and OC-REL/OC-PRIV respectively; OC-BUDGET for any quantitative transfer |
| Production authentication/private proofs, including RISC Zero alternative | **Unresolved because construction/equivalence/security evidence is missing** | Keep SEC-003/004/005, complete authentication feasibility and Stages 2–3 open |

This is a completed negative applicability finding, not an assertion that
composition is impossible or that the primitive is insecure. The reference
implementation may continue fixed FIPS algorithms, bounded local predicates,
canonical formats, exhaustion semantics and component tests while making these
limitations explicit. It must not expose local private-witness evaluators as
remote proof verifiers, advertise dummy tokens as proofs, weaken private checks or
claim complete authentication security from component validation.

## One next implementation package

Recommend **S2-BOUNDED-MLDSA-KEYGEN-SIGN-1**: implement and validate the separate
bounded ML-DSA-65 **reference key-generation/signing core**, with explicit
setup/import consistency and a fail-closed signer-adapter boundary. Keep the pinned
ordinary backend only as a differential reference. This is a recommendation,
not execution authorisation in this package.

The concrete scope should preserve FIPS 204/August 2024 and the adopted contexts,
formats and parameters; enforce matrix/short/challenge sampler ceilings of
1,026/512/256 bytes and at most 1,024 signing attempts; distinguish exhaustion
from malformed/invalid input; perform bounded pre-release verification; and emit
no partial key/signature, uncapped fallback or automatic retry after exhaustion.
Record randomness and hedging inputs and consistency checks without logging live
secrets. Production entropy, side channels, erasure, all-role durable release and
service activation require their own evidence and remain open.

Validation should use finite deterministic differential fixtures and injected
boundary/exhaustion conditions, reusing unaffected verification evidence. Carry
forward **DEP-001/DEP-002 and SEC-003**: model tails beta_T/B/C/S, the actual
conditional signing-tail premise, adaptive Delta_tail, and invocation counts
across the distinct component reductions. The changed published average/minimum
retry guidance does not justify a geometric tail or replacing the cap. Neither
observing no test failures nor implementing the cap proves Delta_tail=0. Maintain
the coupling through the first cap event, including internally signed but
unreleased messages in the signature reduction. A precise unresolved tail term is
compatible with completing the bounded reference core; it is not a licence for
production signing/security claims.

Outer-oracle obligations reopen at a concrete proof-profile adoption/claim trigger,
not as a prerequisite for that fixed-algorithm reference work. Preserve the
existing Stage 2 signing, Stage 3 proof-profile, Stage 4–5 lifecycle and Stage 6–9
comparison/final-claim checkpoints. No further package is started here.

## Validation and preservation plan

Changes are restricted to this report, its exact evidence directory and append-only
status, traceability and issue updates. The original streaming preservation auditor
is reused unchanged, with the original baseline and ordered later seals, adding
the preceding review manifest. No historical baseline, calculation or failed
diagnostic is regenerated or overwritten. Newly authorised paths are explicit;
content partitions and addition/removal inventory checks retain full coverage.

The only new focused validation checks the documentation/game-contract consistency;
it is not a mathematical theorem prover. Reuse all prior numeric, functional,
isolation and cryptographic validation. Lint/format apply only to new scripts.
The final audit requires completed comparisons, report readback and a successful
outer guard. One complete audit only; a failed/resource-limited audit is retained
and is not repeated.

The [configuration](data/s3_outer_oracle_composition_1/config.json) carries forward
**21.956706719007343 seconds charged**, leaving **278.04329328099266 seconds** of
the existing 300-second analysis allowance at admission. Five new conservative
operator/bookkeeping seconds plus measured jobs are charged; isolation/proof
budgets stay separate. Resource limits remain 256 MiB charged cgroup memory, zero
swap, two CPUs, one worker, 60-second command/55-second child, 8 MiB temporary,
10 MiB package output, 1 MiB per file, 60 KiB diagnostic stop and existing 9 GiB
experimental-storage stop. The external monitor separately samples aggregate
process-tree RSS; it is not substituted for cgroup `memory.peak`.

Commands and resource records are retained in the
[run ledger](data/s3_outer_oracle_composition_1/run-ledger.json). Source/literature
reading is not a local execution benchmark. No dependency installation, estimator,
circuit generation, proof, zkVM execution or host activation occurred. CPU proving
is paused, with **two attempts used, one unused**. Stages 2–3 remain open.
The measured closure follows after the one guarded preservation audit.


## Measured validation closure

The [complete preservation audit](data/s3_outer_oracle_composition_1/result.json)
passed content/inventory comparison, report readback and the final unchanged
resource guard, exit **0**. It covered 8,759 original
and 837 supplementary
content paths: **9,596 disjoint content paths**,
9,610 identity-inclusive paths. There
were no unexpected changes, removals or additions. Exactly three existing reports
received append-only updates; their original prefixes remain intact. The baseline,
prior seals, original failures, production code and parameters are unchanged.

| Measurement | Result |
| --- | --- |
| Complete-audit wall time | 2.155260734 s |
| Audit cgroup memory.peak | 22,163,456 bytes, ceiling 268,435,456 |
| Audit sampled process-tree RSS | 40,165,376 bytes; a separate metric |
| Maximum new-job charged cgroup peak | 22,163,456 bytes |
| New guarded jobs | 7, all passed, 2.861812113 s total |
| New validation | One documentation-contract consistency check; lint/format pass |
| Repeated calculations/functional suites | Zero; previous evidence reused |
| Failures / resource breaches / retries | 0 / 0 / 0 |
| Continued analysis allowance | **29.818518832 / 300 s charged; 270.181481168 s remain** |
| Temporary data | 0 observed peak bytes, zero retained |
| Package output at outer guard completion | 277,510 bytes |

Charged cgroup memory includes the worker, descendants and charged file-cache/kernel
memory. The external RSS sample can count shared pages more than once. Neither is
an estimate of proving memory. The above charge includes prior 21.956706719007343 s
and five operator/bookkeeping seconds. The final bookkeeping is separately bounded
by 256 MiB address space, CPU/alarm five seconds, two CPUs and 1 MiB files; it only
checks new outputs, exact names, links and report prefixes, then writes the new
closure/seal once. It does not repeat the protected content comparison.

[Final evidence seal](data/s3_outer_oracle_composition_1/manifest.json) and
[validation closure](data/s3_outer_oracle_composition_1/validation-closure.json)
record the complete disposition. No overall security number, production signing,
actual identity isolation or complete private-proof claim is made. Stages 2–3,
OC-REL/EXT/PRIV/BUDGET, A-K-MODEL, Delta_tail and component reduction advantages
remain open. Isolation stays stopped/unactivated with 22 cases and 250.22 seconds
preserved; proof ledger two used/one unused, CPU proving paused. The single next
implementation recommendation is **S2-BOUNDED-MLDSA-KEYGEN-SIGN-1**; it is not started.
