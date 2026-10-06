# S2-CONCRETE-SECURITY-ASSESSMENT-1 — initial assessment

Assessment date: 24 September 2026. **The available evidence does not justify an
overall classical or quantum bit-security number for the current PQ-DID profile.**
The standard signature component, the manuscript's conditional reductions and the
implemented reference behaviour provide different kinds of evidence. The numerical
Section VIII examples are reproducible; important concrete terms remain unresolved.
This completes the applicable initial source/calculation assessment, subject to the
validation closure below, without completing Stages 2–3 or adopting a profile.

## Authority, revision and prerequisite

The available task file is [PQ_DID_Security_Assessment_Codex_Task.md](../PQ_DID_Security_Assessment_Codex_Task.md),
including its execution schedule and Sections 1–10. The requested `(2)` filename
was not present. The assessed file's SHA-256 is
`ffc641501306a2e05d80b287baa199b8826c9c5401da697fe5c5f9d75295364a`.
It is the task specification because the user explicitly instructed its use.
[AGENTS.md](../AGENTS.md), [the implementation specification](implementation_spec.md),
[the active manifest](../configs/suite.json), SPEC-001–004 and **only manuscript
Sections II–VIII** govern the construction. The manuscript digest remains
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The section-bounded extraction is retained in
[sections-II-VIII.txt](data/s2_concrete_security_assessment_1/sections-II-VIII.txt).
Bibliography entries are locators for the cited primary papers, not authority for
claims from excluded sections. No manuscript text was changed.

There is no Git checkout. The [source inventory](data/s2_concrete_security_assessment_1/source-revision.json)
has canonical inventory digest
`b2d0b57afe4b10c1ee6f41fc32ac031da96e332f79a98c6040aaebe1fd07c3a3`.
It pins every current `src/pqdid` Python file, authority inputs, active manifest,
proof ledger and approved isolation seal. The new
[security_profile.json](../analysis/concrete_security/security_profile.json) is
analysis-only; the active suite remains unchanged. The old `n=32,m=64` prototype
is historical evidence and supplies no parameter or security claim here.

Before numerical analysis, the [host-closure record](data/s2_concrete_security_assessment_1/host-closure.json)
used the existing strict version-2 systemd property parser on the fixed pilot
units and checked their jobs, cgroups and descendants. Queries completed; no pilot
workload or proposed resources existed. The isolation attempt is **safely stopped,
unactivated**, not a successful isolation validation. Privileged authentication
remains unresolved; the original 22 identity cases remain pending. Its approval,
100 cumulative invocations and separately recorded **250.22 seconds**, including
the ten-second emergency reserve, are unchanged. No shutdown or activation action
was necessary. The earlier failures and authorisation are preserved in the
[isolation report](stage2_authority_isolation_pilot.md).

## What the quantities mean

`lambda=128` is a protocol label; 256-bit secrets, 512-bit salts and 1024-bit hash
outputs are lengths. Neither establishes overall strength. Category 3 describes
ML-DSA-65 under the NIST evaluation framework, whose category comparator is
AES-192 key search; it is not an exact 128-bit quantum claim for this system.
[NIST criteria](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-%28evaluation-criteria%29).

No agreed system target specifies all necessary adversary resources. Proposed,
**not adopted**: record a separate contract for each property as
`(property, corruption/leakage model, lifetime workload, classical/quantum gates,
depth, memory/QRAM, targets, oracle/signing budgets, maximum advantage)`.
Report modelled known-attack costs at success at least one half, with the exact
cost model, separately from theorem advantage bounds at a fixed budget. Numerical
acceptance thresholds require a later target decision. This assessment establishes
neither a universal 80-bit floor nor a new overall 128-bit quantum target.

The illustrative Section VIII-E budgets are `T_A <= 2^80`, outer-oracle quantum
queries `Q=2^64` or `2^80`, replaced proofs `N<=2^32`, system keys plus the separate
certificate reduction `|K_sys|+1<=2^20`, and read nonces `q_n<=2^32`. The sum of
capped-call counts **across the distinct reductions in the chosen bound** is at
most `2^64`. These are illustrative assumptions, not observed deployment totals.
The manuscript does not fix an elementary unit for `T_A`, memory/depth budgets,
per-key signing queries or values of `n_K,n_S,n_V,n_A`. Those fields remain null.
`Q` includes honest checker/prover queries, hybrid queries and the complete future
continuation; classical service/signing queries are additional, separate budgets.
Benchmark trial counts cannot replace lifetime workloads.

## Component, property and implementation matrix

| Component and authoritative parameters | Property/assumption | Actual implementation and evidence | Remaining obligation |
| --- | --- | --- | --- |
| ML-DSA-65: `R=Z_8380417[X]/(X^256+1)`, `(k,l)=(6,5)`, `eta=4,d=13,tau=49,beta=196`, `gamma1=524288,gamma2=261888,omega=55` | Quantum EUF-CMA with classical signing access; bounded/standard coupling | [bounded_mldsa.py](../src/pqdid/bounded_mldsa.py), pinned native parameters, [bounded verifier evidence](stage2_bounded_mldsa.md) | Production bounded key generation/signing, adaptive cap discrepancy, component advantages at reduction budgets |
| Public key 1952, expanded secret 4032, signature 3309 bytes; 48-byte challenge seed; 32-byte key/hedging seeds; 64-byte `tr,mu` | Final FIPS parameter/encoding compatibility | Separate bounded verifier; ordinary fixture adapter liboqs/liboqs-python 0.16.0, native commit `5a1a854b0dc9f2141bdc771c555ee60c37950183` | Ordinary signing has 13,106-attempt limit and uncapped samplers, not the 1,024-attempt suite signer |
| Signature contexts `PQ-DID/{credential,state,update,did-record,did-read,control,request,current,revreq}/v1` | Domain-separated issuer, revocation, registry, controller and request authentication | Exact nine strings in profile and active manifest; canonical messages; bounded checks before reference commit/release | Count actual keys and all signing purposes per key, not nine independent keys; production release integration |
| `Y=SHA3-384(enc_holder(suite,E(mu),x_H))`; `B=(Y,E_schema(m))`, 32-byte `x_H` | Opening binding needs collision resistance; secret recovery needs preimage/search resistance on its actual entropy domain | [binding.py](../src/pqdid/binding.py) validates length and exact opening; attributes are directly certified in `B` | Production entropy, erasure and compromise assumptions; voluntary sharing excluded |
| `enc_cred(suite,E(mu),E(B),I2OSP(rid,4))`; padded attributes exactly 1,024 bytes | Injective encoding plus signature binds instance, attributes and certified identifier | [codec.py](../src/pqdid/codec.py), [credentials.py](../src/pqdid/credentials.py), issuer log-before-release | External approval of real-world evidence remains trusted |
| Depth-20 SHA3-384 tree; 1,048,576 identifiers; four-byte identifier; raw 960-byte path | Collision-based non-revocation soundness, ordered position binding | [merkle.py](../src/pqdid/merkle.py) hashes leaf status with suite/instance, not identifier; nodes include level and ordered children; path bits select position | Authenticate latest root and epoch; an old valid path is not current-state evidence |
| Witness updates apply authenticated sequential state/deltas | Maintain the same certified position under current root | [witness_updates.py](../src/pqdid/witness_updates.py), manager/lifecycle reports reused | Recovery admission, rollback resistance and real identity isolation remain operational obligations |
| Enrolment witness 256 bits; authentication witness 42,632 bits | One full credential witness, not separate unrelated proofs | [relations.py](../src/pqdid/relations.py) reconstructs one binding/certificate/credential, verifies issuer signature, projects its attributes, and uses its certified `rid` for the path | Complete private authentication prover/verifier and circuit equivalence remain unimplemented |
| BC-1, three parties, 480 repetitions, 1,440 commitments, 960 openings; raw fresh tapes; 512-bit salts and proof nonce | Complete-witness knowledge and online privacy in ideal QROM | Circuit foundations/partial signature and message preparation, SPEC-003 gate order and SPEC-004 arithmetic preserved | No complete BC-1 implementation, full authentication circuit identity or proof result |
| Outer SHAKE256 output 1,024 bits; challenge integer modulo `3^480` | Ideal 1,024-bit random-oracle reductions, plus separate concrete instantiation assumption | Output length/profile fixed; internal SHA3/SHAKE remain concrete algorithms | Quantitative SHAKE256 instantiation loss unresolved |
| Request/read nonces 256 bits; expiry unsigned 64-bit UTC seconds, strict `now < texp` | Freshness, anti-replay and current-state ordering | `SystemNonces` uses `secrets.token_bytes(32)`; final time/currentness recheck and atomic challenge consumption in [verifier_state.py](../src/pqdid/verifier_state.py) | Trusted clock, entropy across clones/restarts, authenticated current state and durable transaction boundaries |

Secret vectors ideally have independent coefficients uniform in `[-4,4]`; the
matrix has 30 polynomials expanded with SHAKE128. Mask coefficients lie in
`[-gamma1+1,gamma1]`; a challenge has 49 signed nonzero coefficients. Signature
acceptance requires `||z||_infinity < 524092` and the exact FIPS hint checks.
These match the standard component, not the old prototype.
[FIPS 204, Table 1 and Algorithms 6–8](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf).

Reference issuance, verifier and DID interfaces default to unsupported production
signer/proof adapters. Deterministic test tokens, local witness evaluators and
synthetic RISC Zero adapters are not private authentication receipts. The local
authentication predicate joins `PubOK`, the one-witness private relation and
public policy; it does not prove knowledge to a remote verifier. Existing state,
issuance, durable admission and recovery tests are reused, not repeated. Larger
keys would not repair stale state, replay, authority collusion or rollback.

## Signature evidence, caps and the estimator decision

FIPS 204 is the August 2024 standard. NIST's current page flags potential updates
dated 31 July 2026. The previously recorded errata workbook digest
`5bc93ce63bc647e6d1d456cb2d3a171426c15aca4a7a0e0edd40d08b7a34c793`
and DEP-001 dispositions are retained; no dependency/profile update is performed.
The corrected signing average/minimum guidance does not prove a conditional
geometric rejection bound. [NIST FIPS 204 status](https://csrc.nist.gov/pubs/fips/204/final).

Under the manuscript's stated model, define `F(n,p,k)=sum(i=0..k)
binom(n,i)p^i(1-p)^(n-i)`. The arithmetic results are:

| Term and interpretation | Formula | Approximate `-log2` of model probability | Exact checked inequality |
| --- | --- | ---: | --- |
| `beta_T`, 256 coefficients within 1,026 bytes | `F(342,8380417/2^23,255)` | 594.898250 | `<2^-594` |
| `beta_B`, 256 short coefficients within 512 bytes | `F(1024,9/16,255)` | 304.341184 | `<2^-304` |
| `beta_C`, 49 accepted indices after eight sign bytes | `F(248,13/16,48)` | 325.479172 | `<2^-325` |
| `beta_S`, 1,024 signing rejections under the conditional model | `(41/51)^1024` | 322.430297 | `<2^-322` |

The SampleInBall acceptance probability is bounded below by `208/256`; its
binomial expression is a conservative model bound, not an assertion that every
index draw has exactly that probability. A mean signing time alone cannot justify
`beta_S`. No independence between separate calls is needed **if the conditional
tail bounds given their adaptive histories hold**. This condition is unresolved
for the actual deterministic SHAKE inputs and signing simulation; `Delta_tail`
is not set to zero.

`c_T<=30(n_K+n_S+n_V+n_A)`, `c_B<=11n_K`,
`c_C<=1024n_S+n_V`, `c_S=n_S`; hence
`C<=41n_K+1055n_S+31n_V+30n_A` and
`delta_cap(E)<=Delta_tail(E)+sum_j c_j beta_j<=Delta_tail(E)+C*2^-304`.
Count all roles, setup and pre-release honest verification; reused cached
expansions count once only when actually cached. Adversarial malformed signatures
are rejected, not counted as honest cap failures. A signature reduction uses
`epsilon_Sigma(B)=Adv_qEUF-CMA_MLDSA65(B)+delta_cap(B)` so an internally signed
but unreleased message is not silently considered a fresh forgery. Do not add the
same cap loss again after including it in `epsilon_Sigma`.

The unchanged standard component does not justify a new cryptanalytic campaign.
No Sage executable, local pinned estimator or separate estimator allowance was
available. **Estimator runs: zero; installation: none.** The
[prepared inputs](data/s2_concrete_security_assessment_1/estimator-plan.json) and
[unexecuted commands](data/s2_concrete_security_assessment_1/estimator-not-executed.md)
record the source-reviewed upstream commit
`53da5982597709ba0fdf94ea37a84d822310fd84`, absent local version, models and caveats.

Three possible future surrogates are explicitly distinguished:

| Objective | Unexecuted scalar instance | Limits of the mapping |
| --- | --- | --- |
| Enhanced-information key recovery | LWE `n=1280,m=1536,q=8380417`, secret/error uniform `[-4,4]` | Flattens degree 256, ranks 5/6; grants full `t=A*s1+s2`. Actual public `t1=Power2Round(t,13)` omits low bits; its effective noise is correlated. This is not a direct rounded-key attack. |
| Ordinary forgery relaxation | Infinity-norm SIS `n=1536,m=3072`, bound `max(524092,2*261888+1+4096*49)=724481` | Six equation polynomials and `5+6+1` unknown polynomials. Generic SIS ignores sparse challenge/hash fixed-point conditions of SelfTargetMSIS. |
| Strong forgery relaxation | Infinity-norm SIS `n=1536,m=2816`, bound `max(1048184,1047554)=1048184` | Different objective and module relation. Observed Dilithium3 preset uses `m=3072,bound=1048576`; it must not be silently substituted. |

All flattenings omit possible structural attacks and protocol leakage. No custom
lattice assumption was inferred from historical prototype dimensions. A generic
SIS solution need not yield a signature forgery; the manuscript requires EUF-CMA,
not an unexplained minimum over weak and strong forgery estimates.

For context, the primary Dilithium v3.1 **historical** tables report level-3
Core-SVP logarithmic costs: MLWE classical 182/quantum 165; ordinary SIS forgery
186/169; strong forgery 176/159. Its refined classical MLWE gate estimate is 216.7
with memory exponent 138.7 bits. These are distinct attack objectives and resource
models, not PQ-DID bits. The old signature is 3,293 bytes, whereas final ML-DSA-65
is 3,309; challenge hashing/encoding and standard changes require explicit mapping.
The paper's alternative loose challenge bound also lowers its classical level-3
forgery estimate to 172. These published estimates are not a fresh minimum over
every modern attack. [Dilithium v3.1, Tables 1/4, §6 and Appendix C](https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf).

The reviewed estimator's full default uses MATZOV/GSA; LWE rough uses ADPS16/GSA,
and the relevant infinity-norm SIS rough path uses ADPS16/LGSA. Quantum reduction
cost does not automatically make surrounding guessing, search and memory access
quantum-correct. The recipes import the ADPS16 class explicitly; `RC.ADPS16` is an
already-instantiated model. Failed pinned-preset retrieval is recorded, not treated
as a verified preset. Any future run must report cost units, success assumptions,
algorithms, lattice dimensions/block size, memory, unsupported/failed attacks and
the cheapest result **within one consistent model**.
[Pinned estimator source](https://github.com/malb/lattice-estimator/tree/53da5982597709ba0fdf94ea37a84d822310fd84).

Published QROM reductions for Dilithium's self-target problem have additional
parameter conditions and nontrivial losses. Theorem 2 of the inspected primary
paper requires `2*gamma*eta*n*(m+k)<floor(q/32)`; its modified-parameter result
cannot simply be applied to this profile. This is a missing applicability argument,
not evidence of an attack on final ML-DSA-65.
[Evaluating the security of CRYSTALS-Dilithium in the QROM](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=956883).

## Hashes, randomness and repeated targets

SHA3-384 has rate 832/capacity 768 and 384 output bits; SHAKE256 has rate 1,088,
capacity **512**, and variable output. Both use 24-round Keccak-f[1600]. An output
of 1,024 bits does not make SHAKE256 a 1,024-bit-strength primitive.
[Keccak specifications](https://keccak.team/keccak_specs_summary.html).
FIPS 202 remains the 2015 standard; its page announces a revision and an editorial
Appendix B correction, not a replacement algorithm adopted by this package.
[FIPS 202 status](https://csrc.nist.gov/pubs/fips/202/final).

For an ideal 384-bit hash, generic constant-success collision search has classical
birthday scale `2^192` evaluations and a quantum black-box collision algorithm at
order `2^128` evaluations with a large table and coherent lookup assumptions.
That is a query-model illustration, not a realistic gate/depth/memory guarantee
for SHA3 or a system-level claim. [Brassard–Høyer–Tapp](https://arxiv.org/abs/quant-ph/9705002).
A uniformly generated 256-bit holder secret with a known binding has generic
classical domain-search scale `2^256` and quantum search scale `2^128` reversible
predicate evaluations at constant success. Gate cost includes SHA3 and encoding;
quantum depth and parallel memory trade-offs are not fixed here.
[Grover](https://arxiv.org/abs/quant-ph/9706033).

Those secret-search statements require actual 256-bit entropy. The API's 32-byte
length check cannot establish it. Issuer nonces, DID salts, namespaces and proof
salts likewise need appropriate generation, independence and erasure. Synthetic
fixtures/deterministic test sources provide no entropy evidence. Fresh raw tapes
and 512-bit proof salts/nonces are protocol requirements, not an implemented
production proof generator. Corruption, side channels, VM cloning, wallet access,
memory dumps and network correlation remain outside these ideal calculations.

For `t` targets under one searchable predicate, an idealised multi-target search
may cost order `sqrt(2^256/t)` quantum queries. Distinct instance domains and target
lookup resources must be included; subtracting a target exponent without a model
is invalid. Collision reductions, by contrast, seek *any* pair of distinct
canonical inputs with equal output. Binding and tree soundness use that collision
property, not merely preimage resistance. The tree's depth is capacity, not
20-bit cryptographic strength. Canonical lengths, suite/instance domains, ordered
children and level encodings are necessary to output a genuine collision.

The read-nonce union bound is `q_n(q_n-1)/2^257`, clipped at one; at `q_n=2^32`
it is strictly below `2^-193`. Explicit unused-nonce sets and atomic consumption
can reject reuse, but do not silently remove the theorem's independent-read-nonce
term or prove freshness after rollback. Every count must be lifetime-scoped.

The proof theorems below are about an **ideal 1,024-bit outer QROM oracle**.
Instantiating it with concrete SHAKE256 requires additional quantitative evidence;
the 512-bit capacity alone neither supplies that evidence nor disproves the ideal
theorem. We do not replace 1,024 by 512 in the equations and claim a new theorem or
an attack. Internal signature SHAKE and holder/tree SHA3 computations remain
concrete subroutines, separate from the modelled outer oracle. SEC-002 records the
uninstantiated loss that prevents a concrete overall claim.

## Proof hypotheses and reproduced arithmetic

The authoritative protocol takes a 1,024-bit challenge word modulo `3^480` and
opens two cyclically adjacent views per repetition. It does not sample a perfectly
uniform challenge vector. For each vector, the exact maximum mass is
`ceil(2^1024/3^480)/2^1024 <= 3^-480+2^-1024`. At most `2^480` vectors fail
extraction for a false witness under the local three-pair argument. Thus
`p_star=(2/3)^480+2^-544`. The unmodified base error is not quantum soundness.

The following is a source-level applicability review, not a completed specialist
proof or an executed extractor:

| Step | Checked applicability and explicit limit |
| --- | --- |
| Three-view local argument | XORing the three BC-1 AND equations cancels tapes and gives AND of reconstructed wires. If all three pair checks pass in one repetition, deterministic reconstruction produces the complete private input. It still requires faithful `CGen(kind,X)` and the accepted-output condition; circuit foundations are not full implementation equivalence. |
| Commit-and-open extraction | DFMS Definition 3.5 requires an efficient deterministic extractor from all committed messages. Theorem 4.2 gives `(22*l+60)q^3/2^n+20q^2*p_triv`, with perfect simulation and a non-rewinding extractor. Here `l=1440,n=1024`; adaptive instances and auxiliary quantum output are included. Its Lemma 4.1 proof tracks the probability of the bad challenge set; the manuscript's weighted modulo bound is the needed substitution, not an assumption of uniform trits. |
| Complete target/history preservation | The manuscript wraps real honest algorithms and real witnesses, retaining issuance logs, revocation history and the final target event. Classical external oracles are forwarded once in order, not coherently inverted or rewound. A transcript-only extractor would not establish this result. A formal oracle-relative composition of that exact wrapper and terminal predicate remains a specialist checkpoint. |
| Online privacy | GHM Theorem 1 charges each adaptive reprogramming by `sqrt(q_hat*p_max)+(q_hat*p_max)/2`. Fresh 512-bit nonce/salt coordinates give the claimed `p_max<=2^-512` only conditioned on the relevant prior side information. The manuscript additionally accounts for unopened-salt queries, erases hidden material and includes the complete continuation in `Q`. |
| Two opened views | The raw-tape simulator samples the two input shares/tapes and second party's AND outputs; the first party's gates are computed and the missing output share enforces acceptance. This is the manuscript's raw-randomness adaptation of the ZKBoo two-view decomposition, not permission to add an unanalysed PRG. |
| Subsequent revocation | Simulation retains actual public revocations/paths. The challenge candidates must have common authorised leakage, with no later hidden-index-dependent oracle and no compromise of the protected holder secret. Historical privacy is not post-compromise secrecy or protection against excluded authority collusion/network correlation. |

Primary checks: [DFMS, Definitions 3.1/3.5, Lemma 4.1, Theorem 4.2](https://arxiv.org/pdf/2202.13730),
[GHM, Theorem 1](https://eprint.iacr.org/2020/1361.pdf),
[ZKBoo, Proposition 4.1](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_giacomelli.pdf).
DFMS was inspected as arXiv v1 dated 28 February 2022; the manuscript cites the
CRYPTO publication. Version and locator differences are recorded in the source
notes; no unstated theorem from another protocol is substituted.

The calculator implements exactly the Section VIII-C/D expressions:

```text
p_star = (2/3)^480 + 2^-544
epsilon_ex(Q) <= min(1, 31740 Q^3 / 2^1024 + 20 Q^2 p_star)
alpha(Q) = sqrt(Q / 2^512) + Q / 2^513
delta_ZK(N,Q) <= min(1, 481 N alpha(Q) + 960 N Q / 2^256)
```

The first privacy hybrid reprograms a fresh proof nonce; 480 commitment hybrids
add fresh-salt programming and hidden-salt query costs. The final raw-view
simulation supplies the same opened-view distribution. The manuscript's privacy
advantage is its stated guessing advantage; no extra factor of two is inserted
by confusing that convention with a full probability difference.

| `Q`, with `N=2^32` | Approx. `-log2(epsilon_ex)` | Exact conservative bound | Approx. `-log2(delta_ZK)` | Exact conservative bound |
| --- | ---: | --- | ---: | --- |
| `2^64` | 148.460072 | `<2^-148` | 150.093109 | `<2^-150` |
| `2^80` | 116.460072 | `<2^-116` | 134.093109 | `<2^-134` |

All four manuscript inequalities hold; no arithmetic discrepancy was found.
`Q=2^80` is an oracle budget, not 80-bit security. An extraction-error bound of
`2^-116` is a probability upper bound at that budget, not a 116-bit attack cost.
[Raw exact fractions and upward-rounded displays](data/s2_concrete_security_assessment_1/bounds.json)
retain every term, modulo mass and conditional cap/nonce results.

The [calculator](../analysis/concrete_security/security_bounds.py) uses integer
binomial numerators and exact fractions. Square roots use a checked integer
dyadic ceiling; 90-digit Decimal output is rounded upwards. Logarithms are only
annotations. Independent checks use a probability recurrence, direct Decimal
evaluation at 120/160 digits, finite miniature modulo enumeration, domain
rejections, clipping and exact comparisons of printed upper bounds.

The gate-independent authentication proof size is already 5,363,104 bytes;
each additional million AND gates adds 240,000,000 bytes under the exact padded
formula `64+480*(515+2*ceil((d+2g)/8))`. These are encoding calculations, not a
new circuit synthesis, practical proof-size measurement or security estimate.

### Reduction costs and composition

Section VIII-A sets `Bmax=2*(2^32-1)+2^18=8,590,196,734` bytes and

```text
T_red <= T_A + T_hon + T_gen
         + O(Q^2) poly(1024,8*Bmax) + O(480*|f_X|).
```

The `Q^2` factors alone are `2^128` or `2^160` before polynomial factors. Their
hidden constants, actual circuit cost, honest simulation workload and signing
budgets are not instantiated. Direct signature/collision reductions omit the
extractor overhead. Component advantages must be evaluated at each applicable
reduction's runtime and queries, not copied from an attack estimate at `T_A`.
A loose reduction is not evidence of an attack.

Using Section VIII notation:

```text
epsilon_sys = sum(k in K_sys) epsilon_Sigma(B_k)
              + Adv_qCR_H(B_record) + q_n(q_n-1)/2^257
p_good >= [epsilon_accept - epsilon_sys - epsilon_ex(Q)
           - epsilon_Sigma(B_cert) - Adv_qCR_H(B_tree)]_+
Adv_priv/Adv_historical <= delta_ZK(N,Q) + epsilon_sys
```

Certification separately obeys `Adv_cert<=epsilon_Sigma(B_cert)`; opening binding
obeys `Adv_bind<=Adv_qCR_H(B_bind)`; the tree's inconsistent opening yields a hash
collision under its authenticated-instance/history conditions. Service signatures
are aggregated by actual key. Certificate and service reductions remain distinct,
with their actual simulation budgets, even if their accounting must consider a
shared underlying role/key. All advantages are clipped to their permitted ranges.
For the illustrative aggregate cap count, the bound is
`2^-240 + sum Delta_tail`, not `2^-240` alone.

The lower bound on `p_good` does **not** bound every authentication acceptance
probability. To obtain an upper bound for a particular violation event, define
that event so an extracted authorised unrevoked complete witness is impossible,
and prove the extractor preserves that very event/history. Then `p_good=0`, so
the displayed lower bound implies `epsilon_violation<=sum(losses)` (or the trivial
bound one). Without that disjointness and event-preservation argument, this
conversion is unavailable. Legitimate acceptance is not a failure event.

## Separate RISC Zero evidence

The existing [enrolment report](stage3_r0_enrol_po17.md) and pinned source describe
SDK **3.0.6**, commit `1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`,
`risc0-zkp 3.0.5` and rv32im/recursion circuits 4.0.5. The successful path is
**Succinct STARK/Poseidon2**, three segment proofs, three lifts and two joins.
It contains **no Groth16 wrapper**. An optional elliptic-curve/pairing wrapper
would need a separate quantum assessment; it is not inferred to be present here.

The profile records the complete hashes: image
`66e4c8e0c468edaea2bbef55ac470fab92de3c59e8c0f352905b8a741bac160c`,
receipt SHA-256
`2c711beaa6144968aac66421eba10dff1f883133f4d5ec3e1256e3b68e529cc5`,
verifier-parameter digest, allowed control root and final join control ID. The
independent host verifier checks operation/profile, exact expected journal,
Succinct kind/hash suite and registered parameters, then calls full receipt
verification against the expected image. The underlying verifier checks proof and
circuit versions, allowed control inclusion, STARK validity and claim outputs.
Integrity-only checking or trusting a self-declared image would be insufficient.

The 15,380-byte journal contains the diagnostic operation/profile and **full public
enrolment statement**, including suite/issuer metadata, attributes, binding,
certified identifier and enrolment nonce/state data. Exact journal comparison
binds those values in this fixture. It does not establish authentication policy,
audience/session, current revocation root or selective disclosure: those belong to
another complete relation that was not proved. Public enrolment attributes are
visible to the enrolment participants; this fixture is not anonymous presentation.

Historical evidence: one independently verified 238,485-byte receipt; eight tamper
rejections; 343.898929933 seconds for the pipeline including recursion, and
1,535,385,600 bytes peak cgroup memory. These are prior experiment measurements,
not this assessment's consumption, and not complete-authentication feasibility.
No attempt, receipt verification campaign or guest execution was repeated.

Source-level parameters are BabyBear `p=2013265921`, degree-four extension;
Poseidon2 width 24/rate 16/capacity eight/digest eight field cells, S-box degree
seven, eight full and 21 partial rounds; FRI 50 queries, inverse rate four,
fold 16 and minimum degree 256. Digest words are constrained field elements,
not 256 independent random bits. SHA-256 also participates in identity/claim
digests; a hash-suite label does not enumerate all assumptions.

The pinned `zkp/src/prove/soundness.rs` distinguishes toy, conjectured proximity-gap,
proven list-decoding and unique-decoding models. Its comments give 97 conjectured
bits at `2^20` cycles and 95 at `2^24`; these are not a recomputed complete bound
for this selected segment/recursion pipeline or quantum knowledge/privacy. The
current vendor security page describes a zero-knowledge target without a published
mathematical argument. A vendor quantum-safe label or a verified receipt cannot
supply the missing composition and leakage analysis.
[RISC Zero security model](https://dev.risczero.com/api/security-model).

Classification: **unresolved for complete PQ-DID quantum knowledge and privacy**;
supported only as the recorded experimental enrolment verification result under
its exact pinned implementation. BC-1's 480-repetition theorems do not transfer.
No backend is selected or profile frozen here. This is a source review, not a
full audit of the STARK, Fiat–Shamir, recursion, runtime or side channels.

## Conclusions by property and bounded next decision

| Property | Supported conclusion | Unresolved term or required evidence |
| --- | --- | --- |
| Certification/authentication | Canonical certificate and role checks exist; manuscript certification reduces to component forgery plus bounded-operation loss | `Adv_qEUF-CMA` at actual reduction workloads, bounded production signer/keygen and `Delta_tail`; real complete authentication backend and event-preserving extraction |
| Holder binding | One encoded opening and SHA3-384 collision reduction; same credential witness in local evaluator | Concrete quantum collision advantage, secret entropy/compromise assumptions; no protection against voluntary sharing |
| Revocation soundness | Ordered Merkle path at certified identifier; authenticated sequential reference update/currentness checks | Hash advantage, authentic latest service state, durable recovery/isolation and actual complete proof integration |
| Presentation privacy | Checked ideal-QROM simulator bounds under stated restrictions | Concrete outer-hash instantiation, fully matched implementation/simulation, honest authority/leakage and runtime assumptions |
| Historical privacy | Same conditional privacy bound including actual subsequent revocations and full continuation | Protected holder remains uncompromised, common leakage and no hidden-index oracle; not post-compromise secrecy |
| Experimental enrolment | Existing pinned Succinct receipt verified under exact image/journal/parameters | Complete authentication unproved; quantum knowledge/privacy of the composed backend unresolved |

**Overall answer: no numerical overall level is justified.** Missing concrete
component advantages at reduction time, adaptive sampling discrepancy, quantitative
outer-hash instantiation, complete proof/equivalence/composition evidence and a
declared lifetime adversary/resource contract prevent that conclusion. Merely taking
the minimum of unrelated error, Core-SVP, digest-length and query exponents would
be invalid. Absence of a demonstrated attack is not a security proof.

Wording suitable for the manuscript or monthly meeting:

> The current reference profile uses ML-DSA-65, SHA3-384 and the specified BC-1
> construction. Its illustrative ideal-QROM extraction and privacy inequalities
> were independently reproduced. This initial assessment leaves concrete hash
> instantiation, adaptive bounded-sampling loss, production signing and complete
> private-proof obligations open; it establishes no overall classical or quantum
> bit-security level. The separate RISC Zero result proves only its recorded
> experimental enrolment statement.

Recommended next package: **S3-OUTER-HASH-SECURITY-REVIEW-1**, a bounded source-only
review of the precise SHAKE256-to-outer-QROM assumption and the applicability of
the extractor/reprogramming games, before any proof-profile adoption or substantial
lifecycle integration. Deliver an explicit property/resource contract, supported
quantitative instantiation evidence or a precisely stated impossibility of deriving
it from current sources, and a decision memo. No profile replacement, extra proof,
estimator campaign, activation or automatic implementation change is proposed.
Any proposed parameter/hash alternative requires separate approval and recalculation.

## Persistent checkpoints and validation scope

The task's full schedule is recorded in status, traceability and SEC-001–005:

| Trigger | Required refresh and evidence |
| --- | --- |
| Current Stages 2–3 | This initial profile, primary-source review, arithmetic and explicit gaps |
| Stage 2 bounded keygen/signing/release | Randomness, all caps/exhaustion/pre-release checks, totals and `Delta_tail`; DEP-001/002 remain open |
| Stage 3 before proof-profile adoption/freeze | Exact program/circuit, parameters, recursion/compression, soundness/knowledge/privacy and quantum arguments; refresh affected calculations |
| Stages 4–5 PQ-DAA/KYC integration | Same complete credential witness, disclosure/rid binding, public leakage, freshness/replay/revocation, side channels and deployment |
| Stages 6–8 comparison/benchmark work | Each comparator's exact profile and assumptions; lifetime multi-key/target, nonce and cap accounting; refresh changed dependencies/modes |
| Stage 9 reproduction/manuscript claims | Reconcile final revision, workloads and current primary evidence with II–VIII; omit unsupported overall levels |

These are tracked triggers, not background automation or authority to spend other
budgets. Reuse unchanged evidence; unrelated infrastructure edits do not demand
a fresh security package. Assessment completion does not close DEP-001/002,
recovery/isolation, production readiness or backend privacy/knowledge obligations.

The new [configuration](data/s2_concrete_security_assessment_1/config.json) uses the
existing ancillary/preservation guard with a **separate** 300-second numerical
budget: one worker, two CPUs, 60-second command/55-second child, 256 MiB cgroup-v2
memory including charged file cache/kernel memory, zero swap; external aggregate
tree RSS observation is also retained. Limits remain 8 MiB temporary storage,
10 MiB package output, 1 MiB per new output file, 60 KiB command diagnostics and
the existing 9 GiB experimental-storage stop. The guard requires 2 GiB WSL memory
headroom beyond its ceiling. No network route is available inside analysis jobs.
The lightweight preceding host observer used its separately recorded address-space
limit; it is not misreported as a cgroup preservation audit.

Commands and effective limits are in the
[run ledger](data/s2_concrete_security_assessment_1/run-ledger.json). Eight focused
analysis checks and relevant Ruff/data/documentation checks replace no historical
functional evidence. One corrected full preservation audit is admitted only after
those pass. It uses the unchanged streaming auditor and original 8,759-entry
baseline plus the ordered historical seals, verifies exact coverage/inventories,
and permits only new analysis/evidence and append-only changes to this report's
four existing tracking/isolation documents. The old reports' complete prefixes,
original seals, failures, production code, manuscript, dependencies, parameters and
proof ledger remain protected. New evidence seals do not replace old baselines.
Content completion is insufficient until report readback and the outer resource
guard also complete. Final measured results are appended below after that guard.


## Validation closure — complete, 24 September 2026

All **eight independent analysis checks passed**, with no repeated production
functional tests. Ruff lint passed and all seven new Python files passed the
format check. The [single full audit result](data/s2_concrete_security_assessment_1/result.json)
records **exit 0**, complete content comparison, report write/readback and a
successful outer resource guard. Original historical failures remain preserved.

| Measured item | Result |
| --- | --- |
| Original baseline | 8,759 paths: 8,756 unchanged, only the three expressly permitted tracking documents changed |
| Historical supplemental content | 728 paths: 727 unchanged, only the append-only isolation report changed |
| Complete content coverage | 9,487 unique paths; zero overlap, missing paths or unexpected content changes; 9,500 paths including baseline identities |
| Name inventory at audit comparison | 1,146 paths; no unexpected additions/removals; exact pending closure filenames separately declared |
| Content bytes hashed in those two partitions | 300,410,702 bytes; baseline/source/seal/prefix checks additional |
| Documentation | 417 local links checked; all four historical report prefixes preserved |
| Full-audit wall time | 2.310877172 seconds |
| Full-audit cgroup-v2 memory.peak | 23,543,808 bytes (22.45312 MiB) / 256 MiB |
| Full-audit observed aggregate process-tree RSS | 40,034,304 bytes (38.17969 MiB); separate from cgroup charged memory |
| Whole assessment's maximum guarded cgroup peak | 45,047,808 bytes (42.96094 MiB); occurred during section extraction |
| Guarded local command wall time | 3.530317744 seconds across nine sequential jobs |
| Separate charged assessment allowance | 8.593910845 / 300 seconds, including host observer plus five-second operator/bookkeeping charge; 291.406089155 seconds remain, with no further workload planned |
| Temporary data | Audit 0 bytes; largest sampled temporary use across jobs 181,080 bytes; final temporary directory empty |
| Output at full-audit guard completion | 634,844 bytes; final new evidence inventory/size recorded in validation-closure |
| Resource events | No memory.max/oom/oom_kill event, swap, timeout, diagnostic or storage stop; two CPUs, one worker, no retries |

Each command was `.venv/bin/python -I -B
 docs/data/s2_concrete_security_assessment_1/run_checks.py NAME`, with literal
names in order: `extract`, `sections`, `calculate`, `source-format`, `quality`,
`format`, `validate`, `prepare`, `full-audit`. The ledger records the exact
systemd invocation and effective cgroup settings for each. The audit used the
original SHA-256 baseline and unchanged streaming/cache-advice engine; no work was
moved into unmonitored hashing helpers. `validation.json` deliberately retains
its historical content-only `pending-outer-finalisation` meaning; `result.json`
is the completed outer result and does not rewrite that earlier phase.

Final changes are the new report, analysis profile/calculator and exact package
files recorded in [manifest.json](data/s2_concrete_security_assessment_1/manifest.json),
plus append-only updates to `docs/status.md`, `docs/traceability.md`,
`docs/spec_issues.md` and `docs/stage2_authority_isolation_pilot.md`. Post-audit
bookkeeping adds this measured closure and a new evidence seal; it does not
repeat the full content comparison or replace a historical baseline.
[Primary-source/version notes](data/s2_concrete_security_assessment_1/sources.json)
and [closure accounting](data/s2_concrete_security_assessment_1/validation-closure.json)
complete the reproduction record.

No estimator, proof, zkVM/guest execution, activation, dependency/profile change or
cryptanalytic attack occurred. CPU proving stays paused with **two attempts used,
one unused**. Stages 2–3 and SEC-001–005 remain open; the initial assessment is
complete with unresolved terms. The next recommendation remains the bounded
source-only S3-OUTER-HASH-SECURITY-REVIEW-1 described above.
