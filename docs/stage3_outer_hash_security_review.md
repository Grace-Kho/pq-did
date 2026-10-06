# S3-OUTER-HASH-SECURITY-REVIEW-1 — outer-oracle profile decision

24 September 2026. **Retain the current profile as a conditional research reference;
do not freeze it as a quantitatively justified concrete knowledge/privacy profile.**
The reviewed quantum sponge result supports the domain-extension construction in
an ideal-permutation model. It supplies neither a concrete Keccak reduction nor the
missing protocol-specific composition argument. Its published asymptotic loss also
does not certify a useful numerical instantiation loss at the assessment's large
illustrative workloads. This is a limitation of the available justification, **not
a demonstrated attack**. No profile change is made.

## Scope, baseline and completed work reused

Authority is the pinned manuscript **Sections II–VIII** and SPEC-001–004 only.
Its SHA-256 remains
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The [completed assessment](stage2_concrete_security_assessment.md),
[analysis profile](../analysis/concrete_security/security_profile.json) and
[calculation evidence](data/s2_concrete_security_assessment_1/bounds.json) are reused.
The previous evidence manifest SHA-256 is
`6cf03dd4495521e2027961303ab0e7d9033445a005f0f8a640fc73d0e52c1be2`;
the unchanged content source revision is
`b2d0b57afe4b10c1ee6f41fc32ac031da96e332f79a98c6040aaebe1fd07c3a3`
(content inventory, not a Git commit). [Preflight](data/s3_outer_hash_security_review_1/preflight-evidence.json)
verified that seal and its inputs before new analysis.

The prior strict [host closure](data/s2_concrete_security_assessment_1/host-closure.json)
and sealed disposition establish safely stopped, **unactivated** isolation. No new
host operation occurred. Original failures, approvals, 100 executed invocations,
22 pending identity cases and 250.22 seconds including the ten-second reserve are
preserved. This report does not claim successful identity isolation.

Three objects remain distinct:

| Object | What is established here |
| --- | --- |
| Manuscript BC-1/raw-view MPC-in-the-head construction | Specified 480 repetitions, three parties, 1024-bit ideal outer oracle, 512-bit salts/nonce; conditional Section VIII arguments |
| Implemented reference components | Canonical encodings, SHA3/SHAKE circuit components and partial private verification; no end-to-end typed outer proof prover/checker or complete authentication circuit |
| Experimental RISC Zero profile | Existing Succinct/Poseidon2 enrolment evidence and CredValid feasibility results only; a different proof system with its own open knowledge/privacy assumptions (SEC-004). No BC-1 bound transfers to it |

The assessment records **no adopted overall numerical security target**. Preserve
its proposed property/corruption/leakage/lifetime/resource tuple: quantum and
classical gates, depth, memory/QRAM, targets, query budgets and advantage must be
specified together. `Q=2^64,2^80`, `N=2^32`, `T_A<=2^80` with unspecified cost unit,
system key/certificate reductions `<=2^20` and aggregate capped calls `<=2^64` are
illustrative workloads, not an adopted 80-bit or 128-bit security floor.

## Exact outer-oracle dependencies

The mapping follows [specification R-037–043 and R-049–051](implementation_spec.md),
the [active manifest](../configs/suite.json) and VII-A.7–A.8/VIII-C–D.

| Use | Canonical input and result | Claim depending on it |
| --- | --- | --- |
| View commitments | `c[j,i]=HRO(enc_view(suite,kind,E(X),[j]_2,[i]_1,salt[j,i],V[j,i]))`; 1,440 128-byte digests | Commit-and-open extraction of all shares/tapes/gate messages, three-pair witness argument, and hence complete authentication knowledge conditional on other reductions |
| Fiat–Shamir challenge | `u=HRO(enc_challenge(suite,kind,E(X),nu,A))`; `OS2IP(u) mod 3^480`, least-significant base-3 digit first | Adaptive statement/challenge soundness, modulo-bias bad-set probability, challenge programming in proof simulation |
| Fresh hidden coordinates | 64-byte independent salts per view and fresh 64-byte proof nonce, inside the preceding encodings | Adaptive reprogramming, unopened-view hiding/query removal, online and post-cutoff historical privacy |
| Domain separation | Literal `view`/`challenge` tags, arities 7/5, suite `PQ-DID-MITH-1`, kind `enrol`/`auth`, canonical public instance, repetition/party indices | Disjoint commitment/challenge domains; prevents ambiguous encoding or proof-kind/instance substitution in the ideal argument |

There is no additional outer oracle for seeded tapes: the construction uses fresh
raw uniform tapes. Nor does the outer oracle itself certify credentials, bind the
holder, compute Merkle roots, authenticate service state, or provide nonce entropy.
Those are separate components/assumptions feeding the composed authentication and
privacy statements. The 256-bit request/read nonces are distinct from proof nonce
`nu`; the earlier read-nonce collision calculation is unchanged.

Specifically, VIII-A idealises only HRO and leaves internal SHA3/SHAKE as specified
algorithms. VIII-C **Theorem 6** supplies the extraction contract for VI-B4's
adaptive terminal predicates. VIII-D **Theorems 7–9** cover online simulation,
adaptive presentation privacy (VI-C) and post-revocation unlinkability (VI-D2).
VIII-E **Theorems 10–11** inherit those outer-oracle obligations for lifecycle
authentication/privacy. VIII-B Theorems 4–5 concern certification/holder binding
and Merkle non-revocation; their direct component reductions are separate from
outer-proof security. No claim outside Sections II–VIII is used.

The reused ideal expressions are:

```text
p_star = (2/3)^480 + 2^-544
epsilon_ex(Q) <= min(1, 31740*Q^3/2^1024 + 20*Q^2*p_star)
alpha(Q) = sqrt(Q/2^512) + Q/2^513
delta_ZK(N,Q) <= min(1, 481*N*alpha(Q) + 960*N*Q/2^256)
```

At `N=2^32`, extraction is `<2^-148` / `<2^-116` and privacy `<2^-150` /
`<2^-134` for the two illustrative Q rows. These are **ideal-oracle advantage
bounds**, conditional on the manuscript's complete relation and game assumptions;
they are not attack costs or measured security of the partial implementation.
Replacing `1024` by sponge capacity `512` inside these expressions is unjustified:
the commitment range/challenge distribution still has 1024 bits. Conversely,
using `1024` as the capacity in a sponge theorem would analyse another primitive.

## FIPS parameters, encodings and shared primitive

[FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf), August 2015,
§§5–6/Algorithm 9 and Appendix B, specifies Keccak-p[1600,24], rate 1088 and
capacity 512 for SHAKE256. The suffix is `1111`, followed by `pad10*1`.
The [current standard page](https://csrc.nist.gov/pubs/fips/202/final) lists a
revision plan and a non-normative Appendix B typo; no replacement algorithm is
adopted here. The full primary PDF was accessible in this review, resolving the
preceding assessment's retrieval limitation without altering its historical record.

[codec.py](../src/pqdid/codec.py) uses four-byte big-endian LP lengths and field
counts. `enc_tag(fields)=LP(ASCII(tag)) || [count]_4 || LP(field_1) || ...`.
Views pack `d+2g` bits MSB-first, with zero unused low bits. Protocol integers and
the final challenge integer are big-endian; this does not change FIPS's bit order
within each byte. [keccak.py](../src/pqdid/circuits/keccak.py) reverses byte-bit
order at the sponge boundary and performs all 24 rounds. For a byte message of
length M, its padding has `136-(M mod 136)` bytes, first byte `0x1f`, last byte
ORed with `0x80` (a one-byte pad is `0x9f`). Thus:

```text
a(M) = floor(M/136) + 1 absorption permutations
output = 128 bytes = 1024 bits < 1088-bit rate
extra squeezing permutations after final absorption = 0
```

Even a multiple of 136 bytes requires a further padding block. The padded map is
injective and its final block is nonzero: remove the final padding 1, intervening
zeros and delimiter 1, then the fixed suffix to recover the bit message. Our
byte-domain restriction preserves that property. The local development component
has a **65,536-byte** admission limit; it is neither evidence of implementation of
the entire canonical message domain nor permission to narrow the manuscript game.

| Computation | Parameters/source | Relationship to the outer model |
| --- | --- | --- |
| Outer commitments/challenge | SHAKE256, r=1088,c=512, 128 bytes; generic arities plus primitive components exist | Two framed domains of one ideal oracle in the manuscript |
| ML-DSA internal hashes | SHAKE256 `tr(pk)`/`mu` 64 bytes, challenge 48 bytes, SampleInBall stream prefix; SHAKE128 matrix expansion r=1344,c=256; [bounded_mldsa.py](../src/pqdid/bounded_mldsa.py) | Separate FIPS algorithms; not additional outer proof calls |
| Holder/binding, Merkle leaf/node and record hashes | SHA3-384 r=832,c=768, suffix `01`/byte `0x06`; [hash_domain.py](../src/pqdid/hash_domain.py), [binding.py](../src/pqdid/binding.py), [merkle.py](../src/pqdid/merkle.py) | Separate collision/preimage and protocol-domain obligations |

All these concrete functions use the **same public Keccak-f[1600] permutation**.
Different rates/suffixes do not establish independent ideal primitives. SHAKE output
length is not an input separator: for an identical byte input, a shorter SHAKE256
result is a prefix of the longer result. The outer tags separate its own two
domains, but do not prove disjointness from every untyped internal FIPS input.
This observation establishes a modelling obligation, not a feasible cross-protocol
attack. No actual colliding valid instance is asserted.

## Parameter and query mapping

Let `S=|E(X)|`, `V=ceil((d+2g)/8)`, `L=2^32-1`, and `k=|kind|` (5 or 4).
Both S and V must be at most L. Keep the complete authentication AND count `g`,
circuit size `|f_X|`, actual S and reduction invocation totals symbolic.
Canonical admission implies `g<=floor((8L-d)/2)`; this is a capacity bound only.

| Quantity | Derived value (bytes unless indicated) |
| --- | --- |
| One commitment input | `S + V + 120 + k` (40 framing bytes, then suite/indices/salt/fields) |
| Commitment/output block A | `480*(3 + 3*128) = 185760` |
| Challenge input | `S + 185760 + 114 + k` (37 framing bytes plus suite/nonce/fields) |
| Maximum canonical view input | `2L+125 = 8589934715`; at most **63,161,285** absorption blocks |
| Maximum canonical challenge input | `L+185879 = 4295153174`; at most **31,582,009** blocks |
| Manuscript strict coarse bound | `M < Bmax = 2L+2^18 = 8590196734`; `a(Bmax-1)=63163212 < 2^26` |
| Authentication zero-gate formal minimum | `d=42632`, V=5329, view input `S+5453`; this is algebra, not a viable authentication circuit |
| One honest proof / one complete check | 1,441 / 961 outer calls; one of each totals 2,402 |

[New arithmetic](data/s3_outer_hash_security_review_1/query_mapping.py) and
[machine-readable mapping](data/s3_outer_hash_security_review_1/query-mapping.json)
derive these without allocating large messages or generating circuits.

The theorem's length parameter must bound the **longest message in the support**
of every superposition query, including relevant output extension. Canonical input
limits bound honest outer messages, not automatically arbitrary raw adversarial
oracle queries or simulator inputs. A finite-domain game must explicitly impose
the bound on all such queries. Until then `ell=max(ell_honest,ell_adv,ell_sim)` is
unresolved. An unspecified `T_A` cost unit cannot supply that missing length bound.

| Budget | Required interpretation; no silent identification |
| --- | --- |
| Manuscript Q | All outer queries of the experiment, including honest/hybrid work and the entire post-cutoff continuation; count failed proof attempts and checks as well as N successful proofs |
| ACMT q | Total external queries to construction and forward/inverse permutation in the wrapped experiment: `Q_H + P_direct + P_internal + P_wrapper`. Count each query once; do not again count internal absorption calls of a construction-oracle query |
| Primitive-only collision/preimage q | Compile construction queries into permutation queries. A classical outer call costs a(M); a clean quantum evaluation can use compute/copy/uncompute with at most 2a(M) calls, plus direct accesses. This is a different accounting convention |
| Ideal endpoint Q_F | Include outer calls plus simulator queries `S_F(P_direct+P_internal+P_wrapper)` and any newly exposed honest/hybrid work. The current rows do not bound S_F or simulator time |
| Programming | N nonce coordinates and 480N hidden-view coordinates in the stated privacy hybrids; reprogramming/removing entries is privileged oracle manipulation, not an ordinary H query |
| Reduction runtime | Existing `O(Q_F^2)*poly(1024,8Bmax)+O(480*|f_X|)` and honest/CGen costs, plus simulator overhead; no gate/memory claim without quantified factors |

Count offline preprocessing against the lifetime budget, or explicitly specify
permutation-correlated advice and a theorem allowing it. A bounded-query theorem
with independently initialised oracle and adversary is not a claim against free,
unlimited preprocessing for the fixed public algorithm. No fresh workload or
advice restriction is adopted in this review.

## Theorem-applicability matrix

Primary source versions and locators are retained in
[sources.json](data/s3_outer_hash_security_review_1/sources.json). Write
`m=min(r,c)` and use `ell` for sponge blocks; DFMS's commitment-count parameter is
instead written `l_com` below.

| Primary result and exact version | Hypotheses, interface, lengths and bound | Applicability/disposition |
| --- | --- | --- |
| [ACMT v2, 13 May 2025](https://arxiv.org/html/2504.16887v2), Definition 3.9, Theorem 7.22 (§7.5; printed p.71) | Random permutation and inverse, quantum construction/primitive access, stateful simulator; q queries of block length at most ell. Advantage `O(ell^2*sqrt(q^9*2^-m) + ell^3*(q^5*2^-m)^(1/4))` | Candidate **QIPM** domain-extension result. Formal theorem used; informal Theorem 1.2 instead displays `O(ell^3*(q^9*2^-m)^(1/4))`. Neither supplies an explicit constant here |
| ACMT Definition 3.14, Claim 3.15, Lemmas 3.7/5.4 and §7.5 proof | Injective valid padding with nonzero final block; length-controlled quantum queries; single squeeze extended to XOF. Ideal XOF outputs are prefix-related. Simulator efficiency construction includes a PRP or sufficiently independent permutation approximation | Padding/length/output adapters and their costs must be included; simulator construction is not an assertion that Keccak is a keyed PRP |
| ACMT Corollaries 6.13–6.14 (via Theorem 6.11/Corollary 6.12) | Random-permutation primitive queries; `ell<=q`; full r-bit single-squeeze collision/uniform-target preimage probabilities `O(q^5*(r+c)*2^-m)` | Does not directly bound collisions of a **truncated** 1024-bit prefix, or knowledge/privacy. Not applied numerically |
| [DFMS v1, 28 February 2022](https://arxiv.org/pdf/2202.13730), Definitions 3.1/3.5, Theorem 4.2; cited CRYPTO 2022 | Adaptive commit-and-open relation, deterministic full-message extractor, n-bit random function; q quantum queries. Error `<= (22*l_com+60)*q^3*2^-n +20*q^2*p_triv`, perfect simulation. Extractor accesses/measures compressed-oracle state | `l_com=1440,n=1024`; weighted bad-set bound via Lemma 4.1 proof gives p_star. No direct permutation or concrete-hash extractor follows |
| [GHM, ePrint 2020/1361](https://eprint.iacr.org/2020/1361.pdf), Theorem 1 (printed p.7), cited ASIACRYPT 2021 | Adaptive reprogrammable random function: sum over events of `sqrt(q_hat*p_max)+q_hat*p_max/2`, conditional maximum coordinate mass, cumulative preceding queries | Fresh 512-bit salt/nonce coordinates support the ideal hybrids under their entropy conditions. No programming interface for concrete Keccak is provided |
| [Ristenpart–Shacham–Shrimpton, 22 June 2011](https://eprint.iacr.org/2011/339.pdf), Theorem 3.1/§8 | Classical single-stage compatible game; probability transfer with indifferentiability loss; `t_B<=t_A+q_A*t_S`, `q_B<=q_A*q_S`; game must use the construction interface appropriately | Composition diagnostic, not a quantum knowledge theorem. Multiple chronological phases are not automatically disjoint adversarial stages |
| [Carolan–Poremba–Zhandry, 2024/1727](https://eprint.iacr.org/2024/1727.pdf), Theorem 7, Corollaries 2–3 | One-round sponge, `r<=c`, r-bit input/output; quantum/classical reset/precomputation variants, error `O(2^-r/2)`. Shared-randomness strong variant; weak statistical variant needs one bit of simulator advice | Current r>c and multi-block inputs violate hypotheses. Even the balanced option below remains multi-block; this theorem does not close its advice gap |

The applicable ACMT listing is v2 (v1 was 23 April 2025); HTML and PDF formal
statements were compared. The malformed probability bracket in the formal display
is read as Definition 3.9's distinguishing advantage, without changing its RHS.
Earlier random-**function** sponge results are a different primitive model: a
public invertible Keccak permutation cannot be silently replaced by such a
function. No numerical claim from that family is used.

For the present fixed output, restricting the full random r-bit output to its first
1024 bits yields a uniform 1024-bit function on the injectively padded domain.
A coherent prefix-query adapter can place the unused 64 response bits in `|+>`;
XORing them leaves that state unchanged, so one full query implements the prefix
query without input-dependent garbage. Discarding ordinary unused response bits
would not justify that claim. Conversely, completing F_1024 to F_1088 requires an
independent random tail G_64 and a compatible simulator. These elementary adapters
justify the marginal output distribution, **not** the complete game/extractor
composition or unchanged simulator query budget.

## What the asymptotic loss says at the recorded workloads

The two formal monomials have base-2 exponents
`2 log2(ell)+(9/2)log2(q)-m/2` and
`3 log2(ell)+(5/4)log2(q)-m/4`.

| m | Illustrative log2(q) | Assumed log2(ell) | Two monomial scales, with constants suppressed |
| --- | --- | --- | --- |
| 512 | 64 | 0, optimistic one-block case | `2^32`, `2^-48` |
| 512 | 80 | 0, optimistic one-block case | `2^104`, `2^-28` |
| 512 | 64 | 26, canonical coarse envelope | `2^84`, `2^30` |
| 512 | 80 | 26, canonical coarse envelope | `2^156`, `2^50` |
| 800, unadopted option | 64 | 27 | `2^-58`, `2^-39` |
| 800, unadopted option | 80 | 27 | `2^14`, `2^-19` |

These are exact arithmetic evaluations of **monomials**, not evaluated probability
upper bounds. Unknown constants are not set to one, and negative exponents are not
security-bit guarantees. The rows optimistically identify q with Q before charging
direct/shared-primitive queries. They do not establish ell for arbitrary adversarial
inputs. Even the one-block comparison shows why this published asymptotic form does
not substantiate the desired small concrete loss at the stated large Q values.
No complete threat-budget estimate or successful distinguisher follows.

## Transfer analysis: the missing argument is property-specific

There are three different endpoints to relate:

```text
implemented fixed Keccak and all internal algorithms
    -- unproved concrete modelling assumption -->
joint random-permutation experiment, outer Sp^phi, internals using phi
    -- ACMT, if a compatible bounded experiment is constructed -->
outer F, simulated primitive S^F, and internals using S^F
    -- protocol/game/extractor compatibility obligation -->
the manuscript's ideal outer-oracle knowledge/privacy statements
```

The first arrow is an idealisation of a fixed public algorithm, not a keyed PRP
reduction with an available numerical `epsilon_Keccak`. Comparing a fixed publicly
computable permutation with a random permutation as interchangeable black boxes
does not prove computational indistinguishability against its own code. Generic
QIPM results describe that model; they do not exclude structural attacks on Keccak.

For the middle arrow, wrap the **entire** experiment as a bounded quantum
distinguisher using the authorised interfaces. Public transcript validation,
classical service queries and the post-cutoff continuation belong inside it. Keep
one simulator state across all adaptive phases. A continuous adversary retaining
state may fit this structure; the word "adaptive" alone neither proves nor
disproves compatibility. A bounded final bit test can then use the distinguishing
definition. This establishes an endpoint comparison only once q, ell, runtime and
the exact internal interfaces are supplied.

The last arrow is not presently established:

* **Shared primitive and relation:** modelling internal ML-DSA/SHA3 via phi charges
  P_internal, but on the ideal side those algorithms use S^F. The resulting
  oracle-relative verifier/relation may differ from the fixed deterministic f_X
  independently compiled by CGen. Freezing internal concrete Keccak while
  randomising only the outer primitive also needs justification; it discards a
  real shared interface. Prove the joint endpoint correspondence and retain the
  same certified witness, current state, target/history and authorised leakage.
* **Knowledge:** the DFMS extractor's compressed-oracle inspection is more than
  ordinary black-box query access. Construct a legal composed extractor and prove
  its output witness and auxiliary state satisfy the original game. Applying
  indifferentiability merely to a final acceptance bit cannot establish knowledge.
  Relation evaluation, oracle access and simulator runtime must fit its theorem.
* **Privacy:** show the ideal endpoint is exactly the distribution treated by the
  GHM/raw-view hybrids, including S's state when F is programmed/unprogrammed and
  subsequent primitive queries. Alternatively prove a valid real/ideal endpoint
  triangle through those hybrids, without assuming S remains consistent after
  arbitrary programming. Concrete SHAKE need not itself be programmable for such
  a transfer, but the relevant endpoint simulation lemma is missing. Preserve the
  manuscript guessing-advantage convention when combining distinguishers.
* **Workloads/advice:** bound all simulator/direct/internal queries and lengths,
  preprocessing, and component advantage at the enlarged reduction runtime. A
  proof-query count is not a primitive-query count or an elementary-gate count.

Keep `Gap_KeccakModel`, `Gap_jointGame`, `Gap_knowledgeExtractor` and
`Gap_privacySimulation` as **unresolved obligations**, not established additive
epsilon terms. No formula `epsilon_concrete=epsilon_ideal+epsilon_sponge` is claimed
for extraction/privacy. If a future compatible ordinary bit game is exhibited,
its two endpoint probabilities can be compared using that game's distinguishing
loss; the relation to the final protocol property must still be proved.

| Supported claim | Continuing condition/limit |
| --- | --- |
| Correct parameter, framing and padding correspondence for specified outer calls | Partial implementation and development bounds; complete BC-1 execution remains absent |
| Earlier ideal-QROM arithmetic and formal model-tail inequalities reproduce | Ideal assumptions, fresh conditional entropy, complete relation and relevant game restrictions |
| A primary quantum indifferentiability theorem exists for the multi-block random-permutation sponge | Length/query/simulator costs, output adapter and joint-game hypotheses; no fixed-Keccak guarantee |
| Current profile remains usable for clearly labelled conditional research | No supported overall concrete security number or production proof-profile adoption |

`Delta_tail`, component forgery/collision/preimage advantages at reduction budgets,
bounded production signing and complete proof knowledge/privacy all remain open.
Improving outer-hash justification would not close these independent terms.

## Profile options and bounded decision

| Option | Gap addressed | Changes and remaining obligations | Engineering implications |
| --- | --- | --- | --- |
| **Retain current profile, explicitly qualified** | Makes the existing assumption boundary reviewable without claiming to resolve it | No active specification, parameters, wire format, source or experimental backend change. Require the missing joint-game/extractor/privacy argument and concrete model qualification before adoption | No new runtime/circuit work; continue using existing reference evidence. Recommended disposition now |
| Revision 1: explicit joint-permutation oracle/game contract, same hash | Resolves which interfaces, lengths, preprocessing and simulator/extractor access a construction claim actually covers | Proposed security-argument/specification revision; prove endpoint correspondence or expose a precise impossibility. No hash substitution. Any required relation/compiler change needs a separately reviewed proposal; fixed-Keccak and quantitative-loss questions remain | Primarily formal work; no predicted speed-up, proofs or wire change. Unknown full-authentication quantities stay symbolic |
| Revision 2: custom balanced outer sponge r=c=800, still 1024 output bits | Improves m to the maximum possible for width 1600; addresses only part of the displayed generic loss | **Not SHAKE256**, not adopted. Requires a new suite/version, exact padding/domain specification, argument/calculation revision, vectors, outer hash adapter and eventual proof identity updates. Same-permutation, composition, constants and component gaps remain | 100-byte rate: up to 85,901,968 absorption blocks under Bmax, plus one extra squeeze permutation; use ell<2^27. Estimated long-message permutation ratio 136/100=1.36, not a measured runtime ratio. The Q=2^80 scale still fails to justify a small loss |

Adding tags alone does not supply primitive independence, and requesting more
SHAKE256 output does not enlarge its capacity. Increasing capacity beyond 800 at
fixed width reduces `min(r,c)` again. The balanced option is a comparison to guide
a decision, not a proposed immediate patch or a security guarantee.

Existing [feasibility evidence](stage3_feasibility_review.md) remains decisive for
engineering scope: raw-view proof bytes are
`64+480*(515+2*ceil((d+2g)/8))`. For auth the formal g=0 floor is 5,363,104 bytes;
one million additional ANDs adds 240,000,000 bytes. The previously counted
13,532,448-AND prefix gives a **conditional** 3,253,150,624-byte projection, not a
verified complete authentication count. An outer-hash change does not remove the
raw views or establish inclusion of that prefix. It implies no RISC Zero proving
cost improvement, and this package makes no new performance measurement.

**One next package: S3-OUTER-ORACLE-COMPOSITION-1.** Bound it to a written, typed
game/extractor/simulator mapping for VIII-C/D with the existing profile: define the
joint shared-permutation interfaces and lifetime budgets, construct the continuous
adaptive endpoint, and either prove the necessary composition lemma or identify
the exact incompatible interface. Separate knowledge extraction from the privacy
endpoint triangle. Keep unknown costs symbolic and fixed-Keccak idealisation
explicit. No profile adoption, circuit generation, execution or activation is
implicit in that recommendation. A lemma would improve the construction argument;
it would not by itself produce an overall concrete bit-security number.

## Validation, resource accounting and preservation

Only this report, the new exact evidence directory and append-only updates to
status, traceability and issues are authorised changes. Production code, suite,
dependencies, manuscript, historical calculations, failed diagnostics, isolation
sources/seals and proof ledger are protected. The corrected streaming auditor is
reused unchanged against the **original** baseline and ordered historical seals,
adding the preceding assessment seal; no baseline is regenerated or large file
excluded. Explicit paths and disjoint content partitions preserve coverage.

Four new finite checks cover source/profile constants, independently framed input
lengths and invalid field domains, padding boundaries/coarse symbolic lengths,
and exact monomial exponents without converting them into probabilities. Earlier
eight analysis checks and all functional tests are reused. These four are analysis
checks, not additional identity cases. Commands/results are in the
[run ledger](data/s3_outer_hash_security_review_1/run-ledger.json); configuration is
[config.json](data/s3_outer_hash_security_review_1/config.json).

The initial `validate` invocation failed during its first group because
`ast.literal_eval` encountered the unrelated `did-chain: (0,1<<16)` codec entry.
No group completed and no resource event occurred. The
[reviewed correction](data/s3_outer_hash_security_review_1/correction-validation.json)
retains the original script, log, guard record and STOP marker; it selects only the
two relevant literal AST entries. `validate-corrected` then passed **4/4** groups.
This is five group invocations including the aborted first one, four distinct
checks, one reviewed harness correction and no automatic retry. The failed job's
time/memory remain in cumulative accounting; no production source or limit changed.
Final Ruff lint and formatting passed for all seven new Python files, including
the preserved initial script. No functional/identity test was repeated.

Each command uses the existing guard, e.g.:

```sh
.venv/bin/python -I -B docs/data/s3_outer_hash_security_review_1/run_checks.py mapping
.venv/bin/python -I -B docs/data/s3_outer_hash_security_review_1/run_checks.py validate-corrected
.venv/bin/python -I -B docs/data/s3_outer_hash_security_review_1/run_checks.py full-audit
```

The guard measures cgroup-v2 charged `memory.peak` of its worker and descendants,
including file cache/kernel memory: **256 MiB**, zero swap, two CPUs, one worker,
60-second command/55-second child. Its external monitor separately samples
aggregate tree RSS. Existing 8 MiB temporary, 10 MiB package, 1 MiB file, 60 KiB
per-command log and 9 GiB experimental-storage stop remain. No network in workers;
primary literature was read through the browser, not installed or downloaded into
the execution environment. Resource accounting carries forward **8.593910845 s**
against the existing separate 300-second security-analysis allowance, adds five
seconds of operator/bookkeeping charge and measured new jobs. It does not debit
or reset isolation/proof allowances. Human/source-reading elapsed time is not a
local execution benchmark. One complete audit only; a resource/report failure
would remain incomplete and stop the package without a retry.

The final measured closure below distinguishes comparison, report readback and
outer resource-guard success. Stages 2–3 stay open; no dependency installation,
estimator run, circuit generation, proof, zkVM execution or host activation.
CPU proving stays paused: **two attempts used, one unused**.


## Measured validation closure

The single [complete preservation audit](data/s3_outer_hash_security_review_1/result.json)
finished with exit **0**, completed content/inventory comparison and report readback,
and passed the final unchanged resource guard. The primary partition covered
8,759 paths and the disjoint supplementary partition 784: **9,543 content paths**,
9,556 identity-inclusive paths, no unexpected additions, removals or content changes.
The audit name inventory covered 1,200 entries; closure's new evidence filenames
are checked separately against the predeclared exact optional list. All prior report
prefixes are intact. Only the three documented append-only updates changed existing
files. The original baseline and preceding assessment seal remain unchanged.

| Measurement | Recorded outcome |
| --- | --- |
| Complete-audit wall time | 2.349347859 s |
| Complete-audit charged cgroup memory.peak | 22,405,120 bytes (21.36719 MiB), ceiling 256 MiB |
| Complete-audit sampled aggregate process-tree RSS peak | 40,329,216 bytes; separate sampled metric, may count shared pages more than once |
| Maximum charged cgroup peak across new jobs | 22,405,120 bytes |
| Maximum sampled tree RSS across new jobs | 40,329,216 bytes |
| New guarded jobs, including preserved failure | 10 invocations, 3.362795874 s |
| Continued security-analysis allowance | 16.956706719 / 300 s charged; **283.043293281 s remain** |
| Temporary storage | 0 observed peak bytes; zero retained |
| Package bytes at outer audit completion | 319,969; final seal/closure add only bounded metadata |
| Focused validation | 4/4 distinct groups passed after one reviewed harness correction; five group invocations including the aborted initial group |
| Quality | Ruff lint and formatting pass, seven new Python files; original functional suites reused |
| Resource breaches / full-audit retries | 0 / 0 |

The five-second operator/bookkeeping charge is included above. Final bookkeeping
uses a separate 256 MiB address-space, five-second CPU/alarm, two-CPU and 1 MiB file
limit; it records these results, checks exact names/links/report prefixes and seals
new evidence only. It does not repeat the protected-file content comparison or
substitute address space/RSS for the audit's cgroup measurement.

[Final evidence seal](data/s3_outer_hash_security_review_1/manifest.json) and
[validation closure](data/s3_outer_hash_security_review_1/validation-closure.json)
preserve the original validation failure and the corrected result together.
Review completed with explicit unresolved terms. Recommendation remains
**S3-OUTER-ORACLE-COMPOSITION-1**, before profile adoption. No active hash/profile,
production code, manuscript, dependency or historical-result change. Stages 2–3,
Delta_tail, component advantages, bounded signing and full proof knowledge/privacy
remain open. Isolation stays safely stopped unactivated with its original 22 cases
and allowance preserved; proof ledger two used/one unused, CPU proving paused.


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
