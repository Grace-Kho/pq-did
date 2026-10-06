# PQ-DID: a native-compatible Binius64 masking embedding

**Independent construction addendum — 30 September 2026**

**Result:** the supplied encoder sources support an explicit embedding that fixes the particular zero-index counterexample and preserves logical opening relations. It needs a permutation, padding and fresh randomness, rather than a dense change of polynomial basis. A restricted joint-view simulation argument is also given below.

**Decision:** this is a concrete candidate for an isolated component-correspondence experiment. It is **not** an adopted profile, a corrected native prover, or a proof of private PQ-DID authentication. `JOINT-OPENING-LEMMA-1` and `AURORA-BRIDGE-001` are not closed by this document. In particular, the current per-oracle claim interface cannot simply be retained and called a joint opening.

This addendum follows `PQ_DID_Binius64_Independent_Review.md` and the supplied `stage3_binius_joint_opening_construction.md`. It preserves their negative findings about the unmodified implementation. Only manuscript Sections II–VIII and SPEC-001–004 remain authoritative. A construction change would require its own versioned specification and security argument.

## 1. What was checked

The ten supplied source files, totalling **174,970 bytes**, match all of the following:

- the lengths and SHA-256 hashes in the supplied `source-acquisition.json`;
- their calculated Git blob identifiers;
- the corresponding entries in the previously retained recursive Git tree.

The retained identities are:

| Item | Identity |
| --- | --- |
| Commit | `441fbf51ff0bcb0bcd28f3f1b73f4954029e8577` |
| Root tree | `544452a781fee0f9b262d4ecfdcc47326fb6974f` |
| Original handover SHA-256 | `17a0ac8fd32038e6530254e4cd27610c8a76e76aba53f446986e435845262f8e` |
| Earlier independent review SHA-256 | `75e3d51861e2eead35bceec593909f1fcc23a604ee343e4c68859d7e3cecc97d` |

This establishes correspondence between the supplied bytes and the retained source snapshot. It does not establish an authenticated upstream release, successful compilation, or behaviour of a built binary.

No upstream code, native test, build, prover or zkVM was executed for this addendum. Mathematical deductions below are distinguished from source observations. No WSL project file, active profile, dataset, resource limit or execution ledger was changed.

### Source anchors

Paths below are relative to the pinned Binius64 repository.

| Source / function | Relevant observation |
| --- | --- |
| `crates/math/src/reed_solomon.rs::ReedSolomonCode::encode_batch` | Bit-reverses the input, repeats it for the skipped zero-padding layers, then performs the additive NTT. |
| `crates/math/src/ntt/subspace_polys.rs` module contract | Gives the exact generator-row identity, reversed factor order and lane correspondence used below. Its test bodies are available but were not run. |
| `crates/math/src/ntt/domain_context.rs` | Defines the normalised subspace polynomials and Gao–Mateer domain construction. |
| `crates/math/src/ntt/reference.rs`, `neighbors_last.rs`, `bit_reverse.rs` | Support the transform/permutation convention and the original zero-index finding. |
| `crates/iop-prover/src/fri/encode.rs::encode_masked` | Encodes `message || companion_mask` as two independent interleaved lanes. This existing companion mask is distinct from the new embedding randomness proposed here. |
| `crates/iop-prover/src/basefold/channel.rs` | Uses per-oracle claims and mask claims. It reverses sumcheck challenges into low-to-high variable-index order before the subsequent opening calculation. |
| `crates/prover/src/protocols/intmul/prove.rs::phase5` | Calls the transparent logup reduction, which commits a pushforward oracle. |
| `crates/verifier/src/protocols/intmul/verify.rs::verify_phase_5` | Describes the pushforward openings against both `eq_z` and the public power-table MLE. |
| `crates/verifier/src/protocols/intmul/common.rs::eval_power_table_mle` | Supplies the succinct public table operand; `LIMB_BITS` is 16. |
| `crates/prover/src/protocols/intmul/witness.rs::IntMulWitness::new` | Padding a logical exponent by zero refers to table row zero, whose value is one. Logical lookup padding must not be confused with the new physical layout. |

The called logup helper bodies are not part of the supplied additional ten files. IntMul conclusions here cover the visible caller contracts and linear operands, not an end-to-end audit of that reduction.

## 2. The native polynomial convention

Work over the native scalar field \(F=\mathrm{GF}(2^{128})\). Let \(\widehat W_j\) be the normalised subspace polynomial of degree \(2^j\). Its roots are the first \(j\)-dimensional domain subspace. In particular, \(\widehat W_j(0)=0\).

Define the novel basis

\[
\widehat X_h(X)=\prod_{j:\,\operatorname{bit}_j(h)=1}\widehat W_j(X).
\]

Each \(\widehat X_h\) has degree exactly \(h\) and a nonzero leading coefficient. Consequently, \(\widehat X_0,\ldots,\widehat X_{m-1}\) form a basis of the polynomials of degree below \(m\).

Let \(\operatorname{rev}_d\) reverse exactly \(d\) bits. The supplied row identity states that a raw message \(a\) of length \(2^d\) encodes the polynomial

\[
G_a(X)=\sum_{j=0}^{2^d-1}a_j\widehat X_{\operatorname{rev}_d(j)}(X).
\]

The polynomial constants must be derived from the **codeword** domain and truncated to the required message dimension, as the source specifies. For the native Gao–Mateer contexts, the domain basis is compatible across the relevant dimension prefixes.

At zero, every nonconstant basis term vanishes, so \(E(a)[0]=a_0\). This recovers the prior report's counterexample. Random trailing coordinates cannot alter that coefficient.

## 3. A concrete replacement embedding

Let the logical message have length \(k=2^d\). Choose \(m=2^\ell\geq k\). Let \(q\) be a justified upper bound on the number of **distinct original-codeword positions exposed for this oracle**, including any extra positions opened together in a leaf or coset. Require \(q\leq m\).

This inequality concerns one algebraic query view. It is not a complete protocol masking budget or a security parameter selection. The chosen codeword domain must also fit the field and implementation's supported dimensions.

Pad \(a\) with zeros to length \(m\), obtaining \(\bar a\). Sample a fresh independent uniform vector \(\rho\in F^m\), then form the physical message \(P\in F^{2m}\):

\[
\boxed{P_{2j}=\rho_j,\qquad P_{2j+1}=\bar a_j\quad(0\leq j<m).}
\]

Thus even coordinates are random and odd coordinates carry logical data. This is not merely prepending or appending a block of randomness. The placement is selected for the native bit-reversal convention.

Use independent embedding randomness for different oracles and different commitments. The same \(\rho\) must not be reused merely because the logical credential is unchanged.

### Decoder and exact operand transport

Define \(D:F^{2m}\to F^k\) by \((DP)_j=P_{2j+1}\) for \(j<k\). Writing the embedding as \(P=Ja+S\rho\), one has

\[
DJ=I_k,\qquad DS=0.
\]

For every logical opening operand \(t\in F^k\), set \(U=D^\mathsf{T}t\). Explicitly,

\[
U_{2j}=0,\qquad
U_{2j+1}=\begin{cases}t_j&j<k,\\0&j\geq k.\end{cases}
\]

Then, for **every** physical vector \(P\), including a maliciously chosen one,

\[
\boxed{\langle P,U\rangle=\langle DP,t\rangle.}
\]

This is an exact identity, not a statistical statement. It transports a linear opening relation and supplies a decoder for extracted physical messages. It does not itself supply an extractor or guarantee that two protocol steps use the same committed object.

Existing credential, bit, range and relation checks must refer to the decoded logical object \(DP\), not to an unrelated copy of the witness. The new even coordinates are field-valued randomness; they are not new credential attributes or logical bit variables. Applying the old witness layout directly to the physical vector would be a different relation.

Honest odd padding is zero. The decoder ignores odd positions beyond \(k\). If the protocol requires a canonical physical image, enforce those zero coordinates explicitly; do not claim that the opening identity alone checks them. Alternatively, a language defined solely through \(D\) may allow those unused coordinates. That choice must be explicit in the profile.

### Succinct operand evaluation

Let \(\widetilde t\) be the logical multilinear extension, with variables indexed low bit first. The transformed operand is

\[
\widetilde U(y_0,\ldots,y_\ell)
=y_0\,\widetilde t(y_1,\ldots,y_d)
\prod_{j=d+1}^{\ell}(1-y_j).
\]

The empty product is one. When \(m=k\), the transformation is just a new selector variable:

\[
\widetilde U(y_0,\ldots,y_d)=y_0\widetilde t(y_1,\ldots,y_d).
\]

The source reverses binding-order challenges before using variable-index order. Apply this formula in the resulting **variable-index order**. Do not identify \(y_0\) with the first challenge sampled without checking that conversion. The zero-padding selector here is also distinct from the native FRI lift/repeat operations.

## 4. Why the original-codeword queries are hidden

For \(0\leq j<m\),

\[
\operatorname{rev}_{\ell+1}(2j)=\operatorname{rev}_\ell(j),\qquad
\operatorname{rev}_{\ell+1}(2j+1)=m+\operatorname{rev}_\ell(j).
\]

Because \(\widehat X_{m+h}=\widehat W_\ell\widehat X_h\) for \(h<m\), the physical message encodes

\[
\boxed{F_P(X)=R_\rho(X)+\widehat W_\ell(X)G_{\bar a}(X),}
\]

where

\[
R_\rho(X)=\sum_{j<m}\rho_j\widehat X_{\operatorname{rev}_\ell(j)}(X),\quad
G_{\bar a}(X)=\sum_{j<m}\bar a_j\widehat X_{\operatorname{rev}_\ell(j)}(X).
\]

The polynomial \(R_\rho\) is uniform over **all polynomials of degree below \(m\)**. In particular,

\[
F_P(0)=\rho_0.
\]

The zero-index code symbol is therefore fresh randomness under this candidate. For example, with \(k=m=2\), the raw physical vector is \((\rho_0,a_0,\rho_1,a_1)\) and its polynomial is

\[
\rho_0+\rho_1\widehat W_0+\widehat W_1(a_0+a_1\widehat W_0).
\]

This replaces the earlier abstract monomial suggestion \(R+X^mG\) with a construction matching the actual native novel basis. No dense monomial-to-native conversion is required.

### Rank lemma

For any distinct field points \(x_1,\ldots,x_s\), with \(s\leq m\), the map

\[
R\longmapsto(R(x_1),\ldots,R(x_s))
\]

from degree-below-\(m\) polynomials onto \(F^s\) is surjective: interpolate any desired \(s\) values by a polynomial of degree below \(s\). Every fibre has the same size.

Consequently, \((F_P(x_1),\ldots,F_P(x_s))\) is jointly uniform and independent of \(a\). This holds for every such set, including sets containing zero. It is a symbolic all-set result, not evidence from sampled rank tests.

The same argument supports queries selected adaptively from earlier evaluations and independent public randomness: each new distinct query remains uniform until \(m\) positions have been exposed. Repeated positions return their earlier value. It does **not** automatically cover query selection influenced by commitment roots, other witness-dependent messages or previous hash-oracle queries.

## 5. A restricted joint-view simulation argument

The following extends the query-rank observation, but its hypotheses matter. It is a finite-dimensional algebraic lemma, not a zero-knowledge theorem for the pinned protocol.

Fix logical messages \(a_i\), public operands \(t_i\), and public \(B\), satisfying

\[
\sum_i\langle a_i,t_i\rangle=B.
\]

Embed each message independently as \(P_i\), and set \(U_i=D_i^\mathsf{T}t_i\). Sample independent uniform companion vectors \(\Omega_i\in F^{2m_i}\). Fix a nonzero \(\gamma\) independent of these vectors and embedding coins. Define

\[
V_i=(1-\gamma)P_i+\gamma\Omega_i,\qquad
\Sigma=\sum_i\langle\Omega_i,U_i\rangle.
\]

For each \(P_i\), the map from \(\Omega_i\) to \(V_i\) is a bijection. Hence the \(V_i\) are jointly uniform and independent of all \(P_i\). Also,

\[
\boxed{\Sigma=
\frac{\sum_i\langle V_i,U_i\rangle-(1-\gamma)B}{\gamma}.}
\]

Therefore, an **aggregate** mask claim adds no information about \(P_i\) once \(V_i\), \(B\), \(\gamma\), and the public operands are fixed.

A simulator for this limited view can:

1. Sample all \(V_i\) uniformly and compute \(\Sigma\) by the displayed identity.
2. Answer new original-codeword queries with independent uniform field values, caching repeats, subject to at most \(m_i\) distinct positions for oracle \(i\).
3. For an original query answer \(A=E_i(P_i)[x]\), return the paired companion answer
   \[
   E_i(\Omega_i)[x]=\big(E_i(V_i)[x]-(1-\gamma)A\big)/\gamma.
   \]
4. Derive any additional observations that are functions only of the \(V_i\) and independent public randomness.

This has the correct distribution for the joint view consisting of the whole \(V_i\), the aggregate claim, and the queried original/companion symbols. Query positions may depend on that limited view: \(P_i\) remain independent of the sampled \(V_i\), and the rank lemma handles adaptive original queries.

Equivalently, for two logical tuples with the same public aggregate target, a fixed query set admits changes to the embedding randomness that keep the original query symbols fixed. Changing the companion vectors by \(-((1-\gamma)/\gamma)\Delta P_i\) then keeps \(V_i\), the aggregate claim and paired query symbols fixed. The native low-degree mask space supplies the previously missing surjectivity for this coupling.

### What this lemma deliberately excludes

- Merkle roots, authentication paths, prior commitment/hash queries and the ability to commit before future query points are known.
- A simulator following the real message order, including publication of a mask claim before sampling \(\gamma\). A distributional argument with fixed \(\gamma\) is not such an online simulator.
- Operands, logical messages or challenges selected from a prefix correlated with the fresh masks. Their dependency graph must be established for the actual protocol.
- The earlier outer proof transcript, its one-time pads, IntMul/logup messages and exceptional challenges.
- Extraction, malicious-prover soundness, composition, Fiat–Shamir/QROM security, concrete hash instantiation and finite parameter accounting.

Only the **sum** of mask claims is covered. Individual \(\langle\Omega_i,U_i\rangle\) may reveal individual logical opening values when combined with the folded vectors. The current native per-oracle protocol cannot be justified by substituting this aggregate lemma.

For \(\gamma=0\), the displayed simulator is undefined and the blend does not mask the original message. For \(\gamma=1\), its privacy calculation remains valid, but the blend alone ceases to check the original message. The construction must specify and analyse exceptional challenges; this addendum does not change their sampling rule or assert a negligible error bound.

## 6. Connection to the terminal claim and IntMul

### Terminal claim

The earlier proposal replaces a revealed terminal value by a joint relation

\[
\langle\Pi,T\rangle-\langle z,e_s\rangle=0,
\]

where \(z_s\) holds that terminal value in the **same outer committed witness** used by the outer constraints. Under the new embedding, the relation becomes

\[
\langle P_\Pi,D_\Pi^\mathsf{T}T\rangle
-\langle P_z,D_z^\mathsf{T}e_s\rangle=0.
\]

The outer selector moves to physical coordinate \(2s+1\). The opening identity proves that this equation has the intended decoded meaning. It does not enforce that the two occurrences of the outer witness are the same commitment: the protocol must bind that identity, the terminal-value constraint and its place in the transcript.

A joint relation also must not silently replace several independent required equations by their unweighted sum: errors could cancel. Any batching of separate relations needs its own binding argument, challenge order and finite error accounting. Section 5 proves a privacy statement for a fixed aggregate relation, not the soundness of an arbitrary batching rule.

Over the binary field subtraction equals addition; the minus sign is retained to show the logical relation.

### IntMul pushforward

The visible Phase 5 callers use one public power table of \(2^{16}\) entries. The verifier contract identifies two linear operands for the private pushforward oracle:

| Logical operand | Transformed physical operand when \(m=k\) |
| --- | --- |
| Equality MLE \(\operatorname{eq}_z\) | \(y_0\operatorname{eq}_z(y_1,\ldots,y_d)\) |
| Public power-table MLE | \(y_0\widetilde T(y_1,\ldots,y_d)\) |
| An ordinary evaluation operand | \(y_0\widetilde t(y_1,\ldots,y_d)\) |
| Outer terminal selector \(e_s\) | Unit selector for physical coordinate \(2s+1\) |

If \(m>k\), include the high-variable zero-padding product from Section 3 in each row. Multiple operands for the same oracle must use the same physical commitment and decoder. The adapter must transform both IntMul operands; changing only the equality operand is insufficient.

The table values, limb indices and logical padding semantics stay unchanged. A transparent table does not make the pushforward public. The helper implementation must still be inspected for additional private oracles, claims and disclosures before asserting full IntMul coverage.

## 7. Calculated storage consequences

For one logical oracle of \(k\) field elements, this construction uses a physical message of \(2m\) elements. The factor is \(2m/k\), which is **two when \(m=k\)**. The separate native companion mask also has length \(2m\).

Let the reciprocal code rate be \(r\). Two encoded lanes then contain

\[
4mr\text{ field elements}=64mr\text{ bytes}
\]

for 16-byte field elements. The corresponding unchanged two-lane encoding of a logical length-\(k\) message would contain \(32kr\) bytes.

For the conditional IntMul example \(k=m=65{,}536\), the physical message is 2 MiB, the companion mask is 2 MiB, and their paired encoded payload is **\(4r\) MiB**. This is not peak memory: it excludes the embedding input, concatenation temporary, Merkle trees, folded buffers, allocator overhead, outer witness and all other oracles.

These are payload calculations, not measured allocations or a full-authentication resource admission. Recompute the query bound if the new dimensions change FRI parameters, leaf/coset widths or the number of queried positions. An assumed old value of \(q\) must not survive such a change without justification.

## 8. What remains before a private prototype

| Obligation | Status after this addendum |
| --- | --- |
| Explicit logical-to-native embedding | Specified, with a source-derived algebraic correspondence. |
| Decoder and linear-operand transport | Exact identities proved above. |
| Rank for original query sets, including zero | Proved for every set of at most \(m\) distinct field points. |
| Restricted joint linear view | Distributional simulator given under explicit independence and visibility hypotheses. |
| Native implementation correspondence | Unexecuted. Source inspection is not native validation. |
| Joint opening instead of per-oracle revealed claims | Still requires a protocol and implementation change. |
| Commitment privacy and online simulation | Unresolved. Rank of opened values does not prove Merkle-commitment hiding. |
| Binding of the terminal value to the outer witness | Required; local equation alone is insufficient. |
| IntMul/logup complete transcript coverage | Incomplete; helper bodies and all auxiliary oracles must be accounted for. |
| Extraction and quantum privacy/soundness | Unresolved. No overall classical or quantum security level follows. |
| Full authentication resources and performance | Unmeasured; no completion or latency commitment follows. |

The earlier NO-GO remains the status of the current private-authentication backend. This document narrows one of its missing construction arguments; it does not change that backend's admission status.

## 9. Concrete next work package

Proposed name: **S3-BINIUS-EMBEDDING-CORRESPONDENCE-1**. This is a synthetic component experiment, not G1–G3 private-proof activation.

Its deliverable should be one isolated layout/operand adapter, one independent polynomial reference, a bounded native encoder comparison if build prerequisites and resources are admitted, and one result report. Do not start another general candidate survey.

The work should cover:

1. **Explicit layout contract:** logical and physical dimensions, field, code domain/rate, randomness, decoder, padding policy, low-bit ordering and per-oracle identifiers. Count distinct original symbols actually disclosed by each query/leaf. Distinguish the new embedding randomness from the existing companion mask.
2. **Independent correspondence:** compare native encoding against independently evaluated \(R+\widehat W_\ell G\) at small fixed dimensions, including zero, nonzero positions, the two lane layout and more than one code rate. Reading the native test definitions does not count as running this comparison.
3. **Operand checks:** verify decoding and inner-product identities, full-vector versus succinct selector evaluation, the high-padding selector, the outer terminal selector, and both IntMul operands. Include wrong parity, variable order, dimensions and a mismatched commitment identifier as rejection controls where the adapter owns those checks.
4. **Small exact rank and joint-view examples:** corroborate the symbolic rank derivation on bounded examples and the aggregate-mask identity for fixed nondegenerate challenges. Retain a control showing why the corresponding claim for arbitrary individual mask claims is invalid. These checks validate the implementation of identities; they do not establish zero knowledge.
5. **A concrete full-protocol gap map:** enumerate precisely which outputs lie outside Section 5's simulated view and what additional commitment/simulator/extractor argument would cover each. Inspect the called logup helpers at the same pin if they are available. Do not invent their behaviour or silently expand acquisition scope.
6. **One resource and outcome record:** report measured component costs, exact scope, independent expected results and outstanding security obligations. Preserve earlier evidence and failures. Do not manufacture a complete-authentication benchmark from this component.

Success means the layout and operands correspond to the pinned native encoder within the stated cases. Failure means a reproducible convention, dimension, or implementation mismatch, or resource admission failure. Either outcome is concrete. A successful result still does not admit a private prover until the joint opening and commitment/composition arguments are established.

No execution allowance is granted by this document. Before execution, Codex should read the live ledger and make **one consolidated prospective request only for changes actually needed** in scope, analysis/implementation time, tests, builds, output and storage. Reuse current authorised resources where they apply; do not silently transfer an Aurora build authorisation to a new Binius task. Include routine in-scope corrections and completion headroom rather than serial one-case approvals. Do not spend a proof attempt, activate isolation, modify the active BC-1 profile, or alter production verification.

If a native build cannot be admitted, label any independent reference checks as such. Do not report them as native correspondence or repeatedly expand the experiment to obtain a passing result.

## 10. Historical resource qualification and project status

The supplied acquisition record reports lifetime RSS of **279,449,600 bytes**, alongside a 256 MiB `RLIMIT_AS` and no cgroup measurement. The prior report correctly leaves its measurement scope unresolved. Source hash agreement does not settle memory compliance; this addendum does not certify it or replace that historical record. A process-lifetime diagnostic and a scoped worker measurement must not be treated as interchangeable without evidence.

The reported WSL balances remain unchanged by this independent addendum: analysis 26.252 seconds; implementation approximately 810.618 seconds; KYC approximately 443.390 seconds including its protected reserve; invocation ledger 1,140/1,146; builds 10/13; proof attempts two used, one unused. The live project ledger is authoritative if it has changed since the supplied reports.

The validated KYC baseline and its measurements remain useful and separate from the missing anonymous authentication proof. Complete PQ-DID, KYC integration and comparative benchmarking remain the intended scope. This candidate supplies no basis to promise full completion by 31 October. Private verification remains fail-closed, with Binius64, proving and isolation paused.

### Suggested message to Codex

> Read `PQ_DID_Binius64_Native_Embedding_Analysis.md` as a proposed construction addendum. Check its native bit-order identities against the already pinned files and assess the precise hypotheses of its restricted joint-view lemma. Do not treat it as a security theorem for the complete protocol or as approval to resume private proving. Prepare the single component package S3-BINIUS-EMBEDDING-CORRESPONDENCE-1 described in Section 9, including a concrete implementation/check list and one consolidated amendment only where the live scope or ledger requires it. Keep the terminal joint-opening, commitment-simulation and extraction obligations separate and explicit. Preserve the current production profile, baseline datasets, historical failures and all existing pauses. Do not add another general candidate review or claim that passing component checks establishes private PQ-DID authentication.
