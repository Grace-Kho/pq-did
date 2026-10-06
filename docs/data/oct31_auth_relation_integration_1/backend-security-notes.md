# Backend and security findings for OCT31-AUTH-RELATION-INTEGRATION-1

Source inspection only. No build, test, circuit generation, native execution or
proof was performed. This note reuses the completed milestone's final appendices,
not its earlier incomplete checkpoints. Only manuscript II–VIII and the agreed
clarifications define the application relation.

## What the native evidence establishes

The [final native report](../../stage3_aurora_masking_native.md#final-binary-validation--29-september-2026)
records 24 corrected masking/FRI cases, 16 EXP2 cases and current-binary integration
C09 passing. Its [closure](../oct31_kyc_native_milestone_1/native-finalisation-1/validation-closure.json)
preserves the separate baseline, benchmark and complete-audit evidence. The
isolated branch preserves the historical source and patches; it is not active
BC-1 and does not implement the application proof relation.

The exact coverage boundary remains material:

- `experiments/aurora_masking_milestone_1/overlay/masking_native.cpp:82–84`
  constructs eight `0*0=0` rows, one public and six auxiliary variables. N20's
  actual lincheck uses those zero matrices. N21 at line 158 reaches Aurora and
  encoded-R1CS constructors, registration and early beta layout, not complete
  witness submission and verification of a nontrivial relation.
- N01 independently checks the selected `GF(2^192)` modulus and representative
  native field products. It is stronger than an unverified field label, but is
  not universal arithmetic, entropy or side-channel validation.
- The corrected SC/LD/FR branch implements the reviewed unrestricted sumcheck
  mask plus beta, fixed unit-pad reducer and correct folded-degree registration.
  The finite independent comparisons do not prove every input, FRI schedule or
  full joint transcript.
- EXP2 validates native public framing and common callers against retained
  independent expectations. Full private Aurora round enumeration, roots,
  opening encoding, beta/terminal-message absorption and no-PoW driver remain
  to be connected and checked together.

## Remaining security gates and their classification

| Gate | Exact remaining condition | Classification |
| --- | --- | --- |
| Same-witness relation | One constrained 5,329-byte witness; complete bounded ML-DSA verification, holder opening, same certified attributes/rid, disclosure and depth-20 non-revocation; trusted public wrapper and lifecycle checks | Implementation plus both directions of compiler/relation equivalence |
| Algebraic masking correspondence | Actual nontrivial matrices; independent fresh base/sumcheck/reducer randomness; all related oracle/message values and malformed paths match the corrected construction | Implementation refinement of the existing classical ideal-oracle argument |
| Finite field/domain/degree/query descriptor | Actual `m,n,k,s,a,P,I,q,r,b,D,Df`; systematic/codeword disjointness; degree rounding, quotient dimensions and complete opening projection | Finite theorem application and parameter accounting, not supplied by toy fixture dimensions |
| Commitment privacy, TB-06 | Simulator emits roots before challenges and consistently answers all allowed adaptive salt/value/path openings while using the lazy algebraic simulator without a witness | Missing transformation argument for the selected encoding; also implementation work |
| Classical non-interactive knowledge/privacy, TB-09 | Exact BCS construction correspondence, restricted state-restoration soundness/knowledge, encoded IOP length, programmable-oracle simulator and query costs | Theorem application if all premises can be supplied; construction-specific bridge otherwise |
| QROM knowledge/privacy | Formal applicable round-by-round knowledge/soundness and HVZK statements for the selected IOP/FRI/BCS variant, complete extractor resources and finite losses | Unresolved theorem application/argument; ordinary algebraic knowledge and finite native tests do not supply it |
| Application adaptive extraction/privacy | Preserve the terminal statement, accepted event, service history and residual state; public-only online simulation through later revocations/corruption and repeated presentations | New application composition argument, OC-EXT/OC-PRIV with OC-REL/OC-BUDGET |
| Concrete hashes | Model the new outer BLAKE2b ports and their shared encoding; retain fixed internal SHA3/SHAKE relation; count all enlarged reduction/simulator budgets | Explicit additional assumptions plus valid game composition; no justified additive instantiation term currently available |
| Production operations | Fresh entropy, key custody, erasure, side channels, component advantages at reduction budgets and adaptive `Delta_tail` | Separate unresolved production/component-security obligations |

The [masking correction](../../stage3_aurora_masking_correction_contract.md#joint-simulation-an-explicit-algebraic-argument)
gives a joint, straight-line classical algebraic simulator with ideal polynomial
oracles and at most `b` projected common-domain positions. Its sequential-session
argument requires fresh independent masks and adaptively selected valid statements.
It expressly does not establish concurrent, quantum-query, state-restoration or
Fiat–Shamir composition. This is supported progress; it should not be downgraded
to merely independent uniform marginals, or upgraded to hashed-proof privacy.

The corrected general reducer uses `J=3a+5` handles, `2J` coins per reducer and a
unit last pad. Its admissible family has
`Dlin=2t+b-1`, `Dtest=max(Dlin,M+2b-1)`,
`Dconstraint=max(Dlin,2M+2b-1)`, `D=2^r*ceil(Dtest/2^r)`,
`Df=D/2^r`, and `|L|>=8*max(D,Dconstraint)`.
For `delta=1/4`, its general-reducer strict slack is established symbolically.
The specialised Figure 5 finite soundness expression cannot simply be reused
after choosing this different tested matrix. Finite soundness repetitions remain
unselected for authentication.

The [query contract](../../stage3_aurora_query_masking_contract.md#commitment-and-challenge-correspondence)
locates the current packed raw-field, round/domain Merkle encoding and selectively
salted trees. Those are different from the draft's one canonical 24-byte field
per leaf, tagged scalar trees, 64-byte hashes and fresh 128-byte leaf salts.
Neither choice is automatically the BCS bit-leaf construction. Binding alone
does not imply privacy or knowledge. Direct beta fields and complete terminal
coefficients remain part of the simulated view. `B_RS=|S0|<=b` counts projected
positions, not all scalar openings; `Q_H` is a separate hash-reduction budget.

The [construction's applicability table](../../stage3_aurora_auth_construction_contract.md#theorem-applicability-and-unresolved-application-arguments)
records classical BCS errors `s_sr`/`kappa_sr + 3*(Q_H^2+1)*2^-ell` and privacy
`z+p*2^(-ell/4+2)` only under its premises. With `ell=512`, the latter symbolic
term is `z+p*2^-126`, not an established 128-bit bound. The inspected CMS
proceedings give the informal quantum route
`O(Q_H^2*epsilon_rbr + Q_H^3/2^ell)`; unspecified constants and missing formal
extractor/application correspondence preclude a numerical claim. No new
literature lookup or calculation campaign was undertaken here.

## Complete-relation interface and backend footprint

Keep the exact public `X=(pp,mu,ctx,rstate,D,mD)` and sole
`encode_auth_statement`; trusted configuration fixes proof family, relation and
keys. Keep the private layout `xH[32] || Esch(m)[1024] || rid[4] || sigma[3309]
|| path[960]`, 42,632 bits. Auxiliary values must be constrained, with shared
wire identities or explicit equalities across subgraphs. A returned host ML-DSA
acceptance flag is not a circuit implementation. Public `PubOK`/`Ppub` and final
freshness/one-time-consumption checks retain their established separate roles.

Available production components are Boolean emitters, checked scalar arithmetic,
SHA3/SHAKE, witness/disclosure parsing and message preparation. In particular,
`src/pqdid/circuits/scalar_ring.py:1–5` explicitly excludes a complete transform
or signature verifier; `signature.py` supplies signature decoding/norm components,
not the entire bounded verification relation. Complete Merkle linkage and full
authentication composition remain missing. The isolated hint and forward-NTT
experiments are proposed lowerings with their own guards and representation
contracts, not canonical BC-1 or an Aurora constraint compiler.

Native `libiop/relations/r1cs.hpp:118–164` supplies primary/auxiliary field
vectors, explicit constraints, validity/satisfaction operations and sparse
matrix interfaces. It does not supply PQ-DID, FIPS SHAKE or checked-integer
gadgets. `aurora_iop.tcc:268–308` copies the constraint system into its member and
a separate shared object. `r1cs_rs_iop.tcc:485–613` materialises assignment,
interpolation and multiple complete codeword vectors. These are real integration
interfaces and storage costs, not evidence of a streaming full-authentication
backend. The repeated identical input-dimension check in `aurora_iop.tcc:275–282`
does not validate every required dimension; admission must explicitly validate
the reviewed descriptor without guessing which different check was intended.

The draft's conservative characteristic-two translation constrains free bits by
`u(u+1)=0`, AND by `ab=c`, XOR by `(a+b)*1=c`, and NOT by `(1+a)*1=c`. Booleanity,
integer carries/ranges, sticky invalidity, canonical encoding and equality of the
single final acceptance bit all need explicit coverage. Native field addition
cannot replace signed64 or modulo-8,380,417 arithmetic.

There is a concrete **conditional storage no-go** for directly materialising
that conservative translation in the current native worker. The measured
[forward-NTT component](../../stage3_mldsa_full_forward_ntt_pilot.md#complete-cost-breakdown-and-evidence-interpretation)
has 27,044,356 logical Boolean gates. If translated unchanged at one constraint
per gate, its padded row count alone is `M=2^25`. For positive `b`,
`Dconstraint>=2M+2b-1>2^26`; the reviewed family and power-of-two codeword domain
therefore require `|L|>=2^30`. A native `gf192` stores three 64-bit words
(`libff/algebra/fields/binary/gf192.hpp:99`), so **one codeword's field payload
alone is 24 GiB**. Matrix copies, other codewords, masks, FFT work and Merkle data
are additional. This conditional arithmetic is not a measured R1CS size, a
whole-authentication estimate, or an impossibility result for compact/affine
lowerings. It rules out admitting the naive materialisation into the existing
1 GiB worker. Public-only folding and a different proved lowering could change
the premise; they require their own counts and equivalence argument.

The old 97-partition circuit evaluation does not solve this backend problem:
those boundaries were host-managed private state, not independently proved
subrelations. Summing fragment rows cannot make partition boundary values
authenticated, and independently committing partitions changes the proof
construction and query/masking obligations. The recorded Boolean counts are not
R1CS sparsity or Aurora proof-size measurements.

## Concrete admission decisions

1. **GO for a bounded public nontrivial-R1CS relation/compiler integration pilot**
   once separately authorised: use actual native matrices/operators, independent
   assignment/constraint expectations, one shared canonical statement/witness
   schema and explicit validity checks. A small synthetic relation can exercise
   nonzero A/B/C, primary-input binding, witness submission and rejection without
   being called a complete authentication circuit or a private proof.
2. **Conditional classical ideal-model claim only:** the existing algebraic
   simulator supports its stated corrected family after implementation and
   finite-descriptor correspondence. Such a research pilot may be labelled
   classical/ideal-polynomial-oracle; it does not replace the PQ goal. A hashed
   private prototype additionally requires TB-06, even if the only intended
   claim is classical rather than quantum.
3. **NO-GO for full private authentication admission now:** no complete lowering,
   finite security/resource descriptor or committed-view bridge exists. Stop if
   integration would offload hidden checks, accept unconstrained boundary advice,
   use test-only deterministic masks, expose hidden witness material as public,
   rely on toy parameters as security settings, or require changing hashes,
   cryptographic parameters, accepted inputs or proof construction without a
   concrete approved specification.
4. **NO-GO for a concrete PQ claim** until round-by-round/restoration hypotheses,
   complete transformation, adaptive application games and explicit reduction
   budgets are established. The assessment records no adopted overall numerical
   target: proposed workload and KYC performance targets remain provisional.

An executable integration proposal should separate the complete relation ledger
from admission to materialise/prove it. It should first obtain a bounded compact
constraint representation and nontrivial native correspondence, then demonstrate
that its actual complete dimensions fit the intended backend. It must stop with
an honest unsupported-capacity result if they do not. Neither a toy success nor
relabelling the classical ideal model closes AURORA-BRIDGE-001, Stages 2–3,
adaptive `Delta_tail` or production-security obligations.
