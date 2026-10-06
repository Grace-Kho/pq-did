# S3-AURORA-TRANSCRIPT-BRIDGE-1

26 September 2026. **Decision 2: specific construction corrections are required.**
**AURORA-BRIDGE-001 stays open; no private prototype or profile adoption is admitted.**
At the exact selected libiop commit, hash-chain absorption omits the new digest
from the hash input. The Aurora wrapper also omits initial statement binding.
These are source-demonstrated failures of correspondence to the required
commit-before-challenge construction, even with an ideal hash. They are not an
executed forgery or a claim of credential compromise. Separate algebraic masking,
query-budget and security-transformation obligations remain after correcting them.

This closes the requested **review**, not the bridge. The earlier
[construction contract](stage3_aurora_auth_construction_contract.md) remains
historical and inactive. Its source-access limitation is now narrowed by exact
commit-addressed text retrieval; its implementation and security claims are not
silently upgraded. The recommended next step is one source-only corrected
transcript contract, specified below, not a private prover.

## Authority, exact object and resource admission

Only manuscript Sections II–VIII, agreed SPEC-001–004 clarifications and the
[current specification](implementation_spec.md) govern the authentication scheme.
The [preflight](data/s3_aurora_transcript_bridge_1/preflight-evidence.json) verifies
the manuscript digest
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`,
53 assessed source identities and the previous 52-file construction seal
`1ad2ca3eb7d49c67f572422cb355b9410a6d8062196f08f2bdf265c2bfbcfb52`.
The [security assessment](stage2_concrete_security_assessment.md),
[outer-oracle decision](stage3_outer_oracle_composition.md),
[compact-proof review](stage3_compact_auth_proof_profile_review.md) and their
calculations are reused. No probability campaign or performance measurement ran.

| Opening ledger | Preserved treatment |
| --- | --- |
| Analysis | 71.71089427301195/300 s charged; **228.28910572698805 s available** |
| Package | Retain the proposed 20 charged seconds and ten-second evidence/cleanup reserve; measured documentation jobs plus five operator/bookkeeping seconds |
| Implementation | **41.82321833795868 s untouched**, 332.1767816620413/374 s charged |
| Invocations | **386/386**; no additional tests, probes, builds or evaluations |
| Isolation | Safe-stopped/unactivated evidence reused; 100 historical invocations, 22 original cases pending, 250.22 s untouched |
| Proof ledger | **Two attempts used, one unused**; CPU proving and raw-view integration paused |

The unchanged analysis guard enforces 256 MiB cgroup memory, zero swap, one
worker, two CPUs, four controlled processes, 60 s command/55 s child maxima,
8 MiB temporary storage, cumulative 10 MiB evidence, 1 MiB/file, 60 KiB command
diagnostics and the existing 9 GiB experimental-storage stop. Smaller job
reservations and the ten-second reserve apply. Primary-source text reads were
separately bounded by 256 MiB address space, two threads/CPUs, short alarms and
100,000 bytes/read, inside the five-second bookkeeping charge. Address space
and cgroup memory are different metrics; the preservation audit retains its
original cgroup enforcement. No implementation/isolation budget transfer occurs.

The reviewed object is **libiop commit
`a2ed2ec2f3e85f29b6035951553b02cb737c817a`**, specifically non-holographic Aurora,
`make_zk=true`, additive binary domains, proven FRI/reducer analysis, binary
localisation. The proposed profile is **PQDID-AURORA-AUTH-DRAFT1**, not an enabled
library configuration: GF(2^192), rate 1/8, no PoW, unkeyed BLAKE2b-512, independent
24-byte field leaves, 128-byte leaf salts, no batching/pruning. Dimensions,
repetitions and final degree remain symbolic. The field-polynomial certificate,
transitive dependency pins and complete authentication R1CS do not exist yet.

Twenty-one MIT-licensed source texts, including the licence, were retrieved from
immutable commit URLs into inert `.txt` evidence. [Source hashes](data/s3_aurora_transcript_bridge_1/sources.json)
and [supplemental hashes](data/s3_aurora_transcript_bridge_1/sources-supplement.json)
record URLs, SHA-256, computed Git blob SHA-1, lengths and read outcomes.
These establish the reviewed bytes, not an independently authenticated Git tree,
complete checkout or build. No source was installed, compiled or executed.
The earlier sandbox DNS failure is retained; the subsequent authorised network
read obtained the exact pin. Moving-branch descriptions are not used as pin evidence.

## Source-to-theorem correspondence and concrete blocker

All source paths in this report are relative to that commit; the local
[source-text directory](data/s3_aurora_transcript_bridge_1/sources) is preserved.

| Source location / function | Actual construction | Correspondence finding |
| --- | --- | --- |
| `snark/aurora_snark.tcc`, prover/verifier wrappers | Registers protocol from R1CS; supplies primary input to witness generation or predicate construction | No absorption of canonical public input, matrices or relation/profile identity into initial hash state |
| `bcs/hashing/blake2b.tcc:51–65`, `absorb_hash_digest` | Constructs `internal_state || new_input`, hashes only `digest_len_bytes` input bytes | **New input is ignored**; fails commitment/message binding independently of any cryptanalytic assumption |
| `bcs/bcs_common.tcc:551–615` | Absorbs roots in registration order; hashes direct messages concatenated after a zero field element; squeezes challenges | Root and message absorptions both enter the defective routine. Message framing lacks the draft's IDs/lengths |
| `bcs/bcs_prover.tcc`, final `signal_prover_round_done`; `bcs_verifier.tcc` | Always derives/checks a PoW challenge in the non-holographic path | No explicit disabled branch; answer is stored/checked but not absorbed into subsequent query state |
| `protocols/encoded/{r1cs_rs_iop,lincheck,sumcheck}` | Four randomised base oracles; zero-sum sumcheck masks; extra random mask/combined-sum coefficients | Structurally related to Aurora, not literally Figure 5's mask distribution/messages |
| `protocols/ldt/ldt_reducer.tcc` | General degree-equalising combinations and one independent random codeword per combination | Random coefficient on mask, early mask commitment and extra shifts differ from the fixed-mask presentation of Protocol 8.6 |
| `protocols/ldt/fri/fri_ldt.tcc`, registration/query/production | Shared coset positions; multiple polynomial/interaction columns; direct terminal coefficients | Full disclosure accounting below; no transcript field may be omitted |
| `bcs/{bcs_common,bcs_prover,merkle_tree}.tcc` | One tree per round/domain, coset leaves across columns, selective salts, pruned multipaths | Draft's independent salted scalar leaves require a new commitment/view correspondence |

Let `D=ceil(2s/8)` for hash-chain security argument `s`, and `S` be its D-byte state.
The critical function builds a 2D-byte concatenation for a D-byte digest `u`, but
passes input length D to `crypto_generichash_blake2b`. Thus its actual update is
`S_next = BLAKE2b_D(S)`, independent of `u`. Initial state is D space bytes;
the squeeze counter starts at zero in `blake2b.hpp`. For fixed registration and
call ordering, all roots and direct messages produce the same state sequence.
Field-message absorption first hashes the vector, then loses that digest in the
same way. Challenges depend on call indices and public shape rather than the
committed contents. This conclusion follows from byte lengths and callers; no
hash computation, collision search or forgery experiment is needed.
[Pinned hash-chain source](https://raw.githubusercontent.com/scipr-lab/libiop/a2ed2ec2f3e85f29b6035951553b02cb737c817a/libiop/bcs/hashing/blake2b.tcc).

The proposed draft already specifies full framed absorption and full E(X) binding;
the defect is in the **upstream candidate**, not established production PQ-DID
code. A serializer around an unchanged upstream prover cannot repair its
challenges. Correcting the input length alone would still leave statement binding,
framing, challenge distributions and the remaining bridge obligations unresolved.

## Round correspondence

Notation: `a` lincheck repetitions, `P=a'` LDT combinations, `I=a_F` FRI interactive
repetitions, `q=q_F` seed queries, `r` folds, all localisation dimensions one.
`L_j` is the j-th domain, `|L_j|=2^(d-j)`; `D` below is a polynomial **coefficient
count**, distinct from the hash digest length above. `D_f=D/2^r` must be an
integer. `t=max(M,N)` for padded constraint and assignment-domain sizes.
Every count is symbolic and source-derived, not a numerical profile selection.

The following is the **actual pinned registration order**, with its required
theorem correspondence and differences. Hash absorption is intended by the call
graph but ineffective for contents until the defect is corrected.

| Phase and required order | Prover-visible messages, fresh randomness and commitments | Verifier challenge/query/check; theorem correspondence |
| --- | --- | --- |
| Input, before any round | Trusted R1CS matrices/shape and primary assignment from canonical E(X); private witness only to prover | Draft binds PID,RID and full E(X). Upstream starts from a fixed state. BCS §6 includes the statement in seed/challenge derivation; absent upstream |
| R0: base and masks | Real oracle order: `fw, fAz, fBz, fCz`, then `r_i` for i=0..a−1, then `z_p` for p=0..P−1. Four base masks of b coefficients; independent zero-sum sumcheck masks; P independent LDT masks. C0=4+a+P columns on L0; one upstream salted coset tree. **No mu messages upstream** | Commit all these before challenges. Registration orders all a alphas, all a triples of matrix coefficients, then a two-field sumcheck challenges: 6a fields. Figure 5 instead has mask sums mu_i and 4a challenges with unit mask coefficient. This difference needs correction or a lemma |
| R1: sumcheck quotients | a real `h_i` columns on L0; upstream tree is unsalted because all h flags are false. `g_i`, `fz`, rowcheck and linear combinations are virtual, not extra independent messages | Absorb quotient roots before P vectors of `2(3a+5)+2=6a+12` LDT coefficients. FRI's I initial fold challenges follow, in this same verifier-message phase. All base/quotient/mask roots must precede these challenges. Aurora LDT reduction is the target, not literal equality |
| Fold j=1..r−1 | For each interaction u then combination p, real folded codeword `f[j,u,p]` on L_j; I*P columns, one upstream unsalted coset tree. They are deterministic folds of prior codewords, with no fresh prover masks | Commit the whole layer before its I fold challenges. Each challenge is reused across the P combinations for that interaction. Check subsequent coset interpolation links. This is the FRI proximity-test subprotocol, not an independent witness encoding |
| Terminal round after fold r−1 | Direct coefficient arrays in u,p order, exactly D_f coefficients each, zero-padded to registered length; `M_dir=I*P*D_f` fields upstream. No terminal tree or private polynomial remainder is sent | Absorb **every coefficient** before final random queries. Verifier evaluates final polynomial at the last localised point and checks equality to the preceding interpolation. Degree/length are public descriptor data |
| Upstream-only PoW boundary | Derive root-type challenge; solve/check answer; include answer in transcript | No answer absorption found in prover/verifier path. Default work credit therefore cannot be justified from this path, even classically. Draft omits this entire step; setting an integer to zero is not a no-PoW implementation |
| Final queries/openings | q random positions on L0; entire two-element coset at every layer; shared positions across u,p. Open union of requested positions across all columns in each tree; include leaf salts where enabled and pruned sibling hashes | Reconstruct virtual values from real dependencies at the **same field point**; verify Merkle paths, all FRI consistency equations and terminal evaluations. Both transcript validity and algebraic predicate are required. No acceptance flag substitutes for either |

This schedule has `r+2` prover rounds, `r+1` upstream trees, and
`4+2a+P+IP(r−1)` real oracle columns. The draft has one tree per column, not one
per round/domain. A literal Figure-5-aligned revision also sends `a` mask sums;
its direct-message count is consequently `a+IPD_f`. Exact round placement of
LDT masks must be frozen for that revision, not inherited from a source comment.

The reducer's ordered inputs are triples `(r_i,h_i,g_i)` for each i, followed by
`fw,fAz,fBz,fCz,rowcheck`: `3a+5` handles. `g_i` recursively requires its mask,
h_i and four base values. Rowcheck requires Az,Bz,Cz. fz uses fw plus public
input interpolation. Monomial degree shifts add no new point positions; they
multiply an existing value by a public point power. Virtual handles are therefore
counted through real dependencies, not as transmitted extra oracle values.

Two algebraic differences are material. The source samples `r_i` uniformly from
the zero-sum subspace by zeroing the additive-domain coefficient at `t−1`, and
multiplies mask and combined lincheck by two new random coefficients. The paper's
unrestricted mask and transmitted sum are different random variables. Further,
the reducer randomly scales its maximal-degree mask rather than giving it fixed
coefficient one. If a masking coefficient is zero, a uniform-pad argument cannot
be used unchanged. A possible bad-challenge event needs an explicit distribution
and joint proof; this report does not convert it to a claimed privacy loss.

FRI degree metadata also needs reconciliation: registration at layer j uses
`D >> sum(eta_0..eta_j)` whereas the produced j-th folded polynomial has the
natural bound `D >> sum(eta_0..eta_(j−1))`; the terminal bound uses all folds.
For binary localisation these differ by a factor of two for intermediate handles.
This is a source-level metadata discrepancy, not an executed completeness failure:
the final checks do not automatically enforce each intermediate handle's declared
degree. Freeze intended degrees and verify registration/production semantics before
using those metadata in a theorem, field mask or wire descriptor.

## Query and masking derivation

The exact source procedure is `FRI_protocol::register_queries` and
`bcs_prover::get_transcript`, with coset maps in `fri_aux.tcc`. For each of q seed
handles, it selects one L0 position, expands the whole coset and propagates its
localiser to subsequent domains. The same positions are reused across I and P.
It registers **2qIPr** scalar query handles for binary localisation, including
repeats at the first layer. This is neither the number of independent random
positions nor the number of transmitted field elements.

Let `S_j` be the union of full cosets at layer j, `U_j=|S_j|`, and `B_j=U_j/2`.
There are at most q distinct cosets, so

`U_j <= min(2q, |L_j|)` and `B_j <= min(q, |L_j|/2)`.

An initial virtual-LDT query expands to every real input column it needs.
The commitment code additionally opens every column at every position in that
round/domain's union. Hence the distinct exposed **field values** are

`E_open = (4+2a+P) U_0 + IP sum_(j=1..r−1) U_j`.

The r=1 sum is empty. The formula already includes all a sumcheck masks and
quotients, all P independent LDT masks and all I*P folded columns. Repeated
queries to the same `(oracle,index)` reveal no new field value, but still consume
wire/work if encoded repeatedly. Merkle compression reduces path bytes; it does
not reduce the exposed scalar count. A grouped upstream leaf contains
`2*C_round` field values, not one. Its input prehash does not hide values that
are subsequently opened.

The source also reveals `I*P*D_f` terminal coefficients. In the paper-aligned
option add the a mask sums. Define a conservative **view inventory**, not an
established simulator bound:

`B_view = (4+2a+P) min(2q,|L0|) + IP sum_(j=1..r−1) min(2q,|Lj|) + M_dir`.

Salts, authentication hashes, roots, public dimensions and challenges are additional
verifier-visible objects. They belong to the commitment/compiler analysis; they
are not silently converted into extra field queries. Opening values, terminal
coefficients and sums must each appear exactly once in the privacy inventory.

`queries_to_input_oracles()` returns **2q**, and Aurora's parameter iteration sets
`b=2q+1`. That is a bound on initial positions, **not** the total above. Individual
four-base masks have enough degrees of freedom for at most b distinct points:
evaluation outside the systematic domain is an invertible nonzero vanishing-factor
times a degree-<b polynomial evaluation; the Vandermonde matrix at distinct points
has full row rank. This explains the local position bound. It does **not** establish
joint simulation when sumcheck masks, h, LDT masks, repeated folded columns and
terminal polynomials are disclosed together.

Theorem 9.2's safe stated route is `b>=q_pi` with q_pi counted across the IOP's
actual prover-message queries, not a library function's name. Its hypotheses
include `2t+2b<=rho|L|`, disjoint systematic/evaluation domains and the specified
random distributions. Theorem 8.5/Protocol 8.6 simulates the LDT transcript using
an independent uniform pad; it does not license arbitrary extra correlated
messages. [Aurora, §§7–9](https://eprint.iacr.org/2018/828.pdf).

Thus there are two precise unfulfilled alternatives: supply a simulator for this
**exact** source variant that bounds each base oracle's distinct positions,
including all masks and terminal messages; or restore the theorem's distribution
and choose b from a proved complete-query closure. `b>=B_view` is a conservative
candidate accounting condition for the latter, **not a sufficient theorem for the
modified source**. Direct-message simulation may permit a smaller bound, but it
requires that argument; adding terminal coefficients to a tally is not itself a
privacy proof. This report deliberately does not manufacture a numerical b.

For any future finite descriptor, recompute b, tested and constraint degrees,
rounded FRI degree D, domain dimension d, all a,P,I,q,r,D_f, and the query closure
together. The source's tested bound is `max(2t+b−1, M+2b−1)`; its constraint bound
is `max(2t+b−1, 2M+2b−1)`. Rounding to a multiple of 2^r, strict proximity
inequalities and the draft `2t+2b<=2^d/8` must all hold. An iteration that cannot
produce a finite supported descriptor is a refusal, not an online unbounded loop.

For repeated presentations under Sections III/V–VIII, use fresh, independent base,
sumcheck and LDT randomness **and leaf salts** for each presentation, including
repeated statements. Never cache masked oracles, salts or challenge seeds across
sessions. Reuse of a b-masked polynomial lets different query sets accumulate
past b. Existing credential witnesses may persist privately; proof randomness may
not. Policies, disclosed values and revocation history remain permitted leakage
under the existing game, not new claims of absolute unlinkability. All sessions
share a modelled hash interface with domain separation; account for aggregate
Q_red, sessions and adaptive simulator/extractor access. Fresh randomness alone
does not prove concurrent/adaptive composition or settle adaptive Delta_tail.

## Applicable security transformations

| Property / primary result | Exact premise or bound used | Finding for this object |
| --- | --- | --- |
| Completeness and interactive soundness | Aurora Theorem 9.2, Figures 4–5; binary-field R1CS, valid domains/degrees/repetitions | Conditional mathematical basis. Source's altered masks and degree metadata preclude declaring literal correspondence |
| Interactive knowledge | Same theorem gives IOP knowledge, with decoding argument | Not automatically restricted state-restoration or round-by-round knowledge for this variant |
| IOP privacy | Aurora Theorems 7.4,8.5,9.2; bounded queries and fresh correctly distributed masks | Joint source-view simulation and q_pi/b mapping unestablished |
| Classical BCS soundness / knowledge | BCS Theorem 7.1 requires public coins and respective restricted state-restoration errors s_sr/kappa_sr; adds `3(Q_H^2+1)2^(-ell)` | Wrong absorption violates its construction. Packed symbols, ports and expansion still need correspondence after repair |
| Classical BCS ZK | Same theorem: HV statistical ZK z gives `z+p*2^(-ell/4+2)` in its ROM construction | p is its encoded IOP proof length, not wire bytes. No substitution of our leaf format or salt length without a bridge |
| Quantum IOP compilation | CMS Theorem 3 (explicitly informal), §2.9: public-coin round-by-round soundness epsilon gives `O(Q_H^2*epsilon+Q_H^3/2^ell)` | IOP-specific route; ordinary soundness is insufficient. No constants or concrete bit-security inferred from O notation |
| Quantum knowledge and privacy | CMS separately requires round-by-round knowledge and HVZK | Need exact variant's extractor and simulator; no PCP-specific shortcut, no implication from soundness alone |
| Adaptive PQ-DID security | Actual-history extraction, admissible leakage, colluding verifiers and shared oracle across sessions | Application composition and reduction budgets remain open, regardless of any future single-proof bridge |
| Concrete hashing | Draft unkeyed BLAKE2b-512 is a concrete primitive, not a random function | Ideal-RO/QROM statements remain conditional; previous SHAKE sponge analysis cannot establish this different hash instantiation |

Primary versions: [Aurora, 8 May 2019](https://eprint.iacr.org/2018/828.pdf),
[BCS, 10 February 2016, §6/Theorem 7.1](https://eprint.iacr.org/2016/116.pdf),
and [CMS, TCC 2019 proceedings, Theorem 3/§2.9](https://www.iacr.org/archive/tcc2019/11891143/11891143.pdf).
The previously identified 14 January 2020 CMS full version remains unavailable
through the authorised browsing path; its denied PDF was not bypassed. No unseen
formal lemma, constant, extraction running time or adaptive guarantee is asserted.

The algebraic IOP target, compiled proof, concrete hash and application game are
four separate steps. Missing correspondence is not a cryptanalytic attack.
The demonstrated byte-length defect is stronger than an inconclusive reduction,
but it still is not evidence of an executed forgery. No overall security number,
private-proof feasibility or production readiness follows from this review.

## Deviation and obligation register

| ID within AURORA-BRIDGE-001 | Required correction or missing argument; status |
| --- | --- |
| TB-01 absorption | Hash the **entire** canonical framed state/message input, not only state-length bytes; preserve roots/messages before dependent challenges. Mandatory code-path correction, inactive |
| TB-02 statement/shape | Seed and derive challenges with trusted PID,RID and full E(X), including all public context. A post-hoc Xtag or metadata label is insufficient. Mandatory wrapper change |
| TB-03 PoW | Remove solve/verify/root-squeeze and nonce entirely for the no-PoW variant; set query-security credit to zero. Default work is `dim_h+3+log2(work_per_hash)`. A zero work number can underflow `pow_bitlen=work−log2(cost)`; it is not a supported disabling switch. Never apply a classical work factor to quantum security |
| TB-04 algebraic distributions | Restore unrestricted sumcheck masks plus mu_i and unit pad coefficients, or prove the exact zero-sum/random-coefficient simulator and knowledge correspondence, including exceptional challenges. No lemma established here |
| TB-05 joint masking | Account for every column, coset, repetition, virtual dependency, terminal coefficient and direct sum. Pin a finite dimension/masking solution and verifier closure. Source's 2q+1 is not accepted as the theorem budget |
| TB-06 commitments | Upstream packs columns and cosets, salts only flagged trees, and uses `H_D(H_D(raw_fields)||salt)` with salt length ceil(2s/8). Draft salts every independent field leaf with 128 bytes. Need packed-alphabet privacy/extraction lemma or explicitly revert proposed commitments to literal theorem encoding |
| TB-07 hash ports/bytes | Upstream hashes raw `sizeof(FieldT)` memory and native-size_t counters, with keyed BLAKE2b at differing output lengths. Draft uses canonical fields, labelled unkeyed 64-byte blocks. Supply injective framing, disjoint oracle-port mapping and expansion proof; native ABI bytes are not an interoperability format |
| TB-08 FRI/field | Reconcile intermediate degree registrations with produced folds, field polynomial/encoding and quotient-domain order; pin submodule identities before any future build |
| TB-09 transformations | Establish source-variant restricted state-restoration and round-by-round soundness/knowledge; simulation including packed leaves/direct messages; concrete hash and adaptive composition remain separate obligations |
| TB-10 wire | Implement only after exact corrected oracle/message manifest and privacy view are frozen; bounded parsing must reconstruct that same transcript, not manufacture new public data |

A narrowly changed **proposed** no-PoW configuration must recompute query
repetitions using the full target, not `security+1−pow_bits`. In the source's
proven-mode formula, with `rho=1/8`, effective proximity is
`min(delta,(1−3rho−2/sqrt(|L|))/4)` for binary localisation; it must be positive.
Then q depends on `ceil(−(security+1)/log2(1−effective_proximity))`.
This records parameter dependence, not a justified finite QROM security choice.
More queries can increase masking, domains and proof work; no numerical overhead
or saving is estimated. Root length also cannot be selected by casually changing
the source's single security argument: its digest length, salt length and IOP
repetitions are coupled. The draft's 64-byte hash and 128-byte salt require explicit
separate selectors and their own proof mapping.

## Wire correspondence — contract only

The existing draft header/framing remains a **proposed format**, not a decoder.
Retain `PQDAUR01`, version 1, authentication kind, zero flags, 64-byte PID/RID/Xtag,
u32 exact body length: **208 bytes**. Trusted profile/relation lookup and canonical
E(X) reconstruction precede challenge derivation. No caller-provided matrices,
role/context override or acceptance field is permitted.

| Transmitted object | Verifier reconstruction and acceptance criterion |
| --- | --- |
| Ordered round ID, root count, direct-field count | Must match trusted corrected manifest exactly; reject omitted/extra/reordered rounds. Lengths are not prover-selected parameters |
| One root per real oracle in draft | Reconstruct exact tree length, ID and salt policy. Do not reinterpret a grouped upstream root as a scalar-tree root |
| Direct sums and terminal coefficients | Include every declared mu_i if using paper-aligned masks; include I*P*D_f terminal coefficients in fixed order, including required zero padding. All are absorbed before subsequent challenges/queries |
| Required scalar field openings | Expand virtual dependencies into ordered `(oracle,index)` slots. Derive seed/coset positions from transcript, not transmitted index lists. Private unqueried entries are never serialised |
| Fresh salt and path for each opened leaf | 24-byte canonical polynomial-basis field, 128-byte salt, 64-byte siblings, exact height and fixed left/right order; verify against that oracle's root |
| Repeated logical opening | If a scheduled slot repeats, require identical value/salt/path. A serializer must not resample salts or disclose additional positions merely to simplify batching |
| End of message | Exact exhaustion; fail closed for unknown profile, length overflow, truncation, extra fields, resource exhaustion or any mismatch |

Required byte accounting stays
`208+12R+64C+24M_dir+4+sum_slots(152+64h_j)`.
For the source-like scalar-tree schedule above, `R=r+2` and
`C=4+2a+P+IP(r−1)`; paper-aligned mask movement may alter per-round C/M but not
the requirement to count all roots/messages. `Q` counts ordered wire slots; it
need not equal distinct E_open. Explicitly choose and freeze duplicate handling
before computing bytes. Reconstructing a pruned upstream multiproof is an
additional conversion with its own checks, not currently supported by this draft.

The wire parser must check total B_pi and trusted maxima for R,C,M,Q,heights,
all length sums/products and u32/u64 ranges **before allocation**, using streaming
bounded input. All 24-byte strings encode a field element only once the exact
polynomial-basis convention is certified; integer/Boolean relation inputs have
their own constraints. The proposed 10 MiB proof target does not increase this
package's 1 MiB evidence-file or 256 MiB audit limits.

Do not transmit full oracle tables, witness assignment, mask coefficients,
unopened salts, private RNG state, diagnostic buffers or internal tree caches.
The deliberately declared short terminal polynomial is the sole relevant
coefficient-array exception and is included in the privacy analysis. Public
metadata that is deterministic from trusted shape can be reconstructed; mutable
library diagnostic values, such as `total_depth_without_pruning`, are not evidence
of validity and are excluded. A normal backend remains fail-closed.

**Acceptance criteria for future serializer work:** exact canonical round trip
of the reviewed verifier view; every message fixed before its challenge; no extra
disclosure; deterministic dependency/opening order; rejection of every omitted,
extra or conflicting representation; bounded lengths before allocation; no
acceptance bypass or synthetic proof conversion. No serializer or tests were
implemented in this source-only package.

## Decision, preserved relation and next action

**Decision 2** applies because TB-01/TB-02/TB-03 require actual construction-path
changes, not just a more favourable security assumption. TB-04–TB-10 additionally
name missing arguments and finite selectors. **AURORA-BRIDGE-001 remains open.**
No private prototype is admitted, and no dependency source has been patched.

The supported findings are an immutable-source transcript map, a source-demonstrated
absorption defect, exact symbolic query/disclosure accounting and explicit theorem
hypotheses. They do not establish complete Aurora–BCS knowledge or privacy for the
draft. Corrected byte binding alone would not establish algebraic simulation,
QROM security or concrete-hash composition.

The authentication relation remains the existing certified-message/ML-DSA check,
holder opening, selected-attribute equality and non-revocation path for the same
hidden identifier, with existing public checks and service freshness/expiry.
No SHA3/SHAKE computation, signature format, role context, sampler cap, encoded
credential, parameter, production circuit or BC-1 rule changes. Aurora and the
experimental RISC Zero profile remain distinct from the manuscript's proof
construction. No Boolean-count or Aurora estimate revises RISC Zero evidence.

Recommend only **S3-AURORA-TRANSCRIPT-CORRECTION-CONTRACT-1**: a source-only,
inactive revision and pseudo-diff that restores complete framed absorption,
trusted statement binding and a genuinely absent PoW path, selects paper-aligned
mask distributions rather than silently inheriting upstream deviations, and fixes
the complete message/query manifest with an explicit joint simulator obligation.
Propose at most 20 charged analysis seconds with a ten-second evidence reserve,
zero tests/builds/circuits and unchanged audit limits. This allowance is **inactive**;
no next package has started. Stop short of prototype admission if either the byte
transcript or simulator correspondence remains unresolved. This is a concrete
correction contract, not another survey or permission to patch/build a prover.

Stages 2–3 remain open. Adaptive Delta_tail, component advantages at enlarged
reduction budgets, bounded production signing/custody/entropy/erasure/side channels,
durable holder storage, complete private-proof knowledge/privacy and protocol
composition remain unresolved. Isolation stays safely stopped and unactivated;
CPU proving remains paused; proof ledger remains **two attempts used, one unused**.

Machine-readable findings are in [bridge.json](data/s3_aurora_transcript_bridge_1/bridge.json),
with [primary-source versions](data/s3_aurora_transcript_bridge_1/literature.json)
and the [inactive recommendation](data/s3_aurora_transcript_bridge_1/proposal.json).
The measured documentation and preservation closure follows below.


## Measured documentation and preservation closure

The bridge review is complete with **Decision 2: construction correction required**.
AURORA-BRIDGE-001 remains open; no private prototype or profile is admitted.
Helper lint/format and documentation/static consistency checks pass. No test,
circuit generation, arithmetic probe, build, estimator or cryptographic execution ran.
The single [preservation audit](data/s3_aurora_transcript_bridge_1/result.json)
completed content/inventory comparison, report readback and outer guard, exit 0.
Coverage: 10,788 disjoint content paths;
10,821 identity-inclusive paths.
Original baselines and historical document prefixes are preserved.

| Measurement | Result |
| --- | --- |
| Audit wall time | 2.542261570 s |
| Audit cgroup-v2 memory.peak | 23,666,688 bytes |
| Audit sampled process-tree RSS | 40,402,944 bytes |
| Maximum guarded-job cgroup peak | 23,666,688 bytes |
| Maximum separately sampled tree RSS | 40,402,944 bytes |
| Guarded commands | 7, 3.295097549 s |
| New analysis charge, including five bookkeeping seconds | 8.295097549 s |
| Cumulative analysis charge | 80.005991822/300 s |
| Analysis remaining | **219.994008178 s** |
| Implementation unchanged | **41.823218338 s**, **386/386 tests** |
| Temporary disk observed peak | 0 bytes; zero retained |
| Evidence bytes at audit completion | 690,135 |

No validation failures, retries or resource breaches. The retained preliminary
sandbox DNS diagnostic is a source-access failure, not a failed execution test.
Primary-source reads consumed 3.589289306 s inside the five-second
operator charge; downloaded source text was never executed.
The unchanged 256 MiB cgroup guard
covers the worker and descendants, including charged file-cache/kernel memory;
swap is zero. Sampled RSS is a separate metric. Final bounded bookkeeping uses
256 MiB address space, five-second CPU/alarm, two CPUs and 1 MiB/file inside the
five-second charge; it does not repeat content comparisons.
The [closure](data/s3_aurora_transcript_bridge_1/validation-closure.json)
and [additive seal](data/s3_aurora_transcript_bridge_1/manifest.json)
record the exact balances. Isolation remains safely stopped/unactivated with
250.22 s and 22 original cases pending. Stages 2–3 remain open; proof ledger
**two attempts used, one unused**, CPU proving paused.
