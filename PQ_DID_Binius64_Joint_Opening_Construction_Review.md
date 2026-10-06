# PQ-DID: independent joint-opening construction review

30 September 2026

## Decision and scope

**All 23 attachments were received. The 16 source files match the supplied pinned provenance. The completed Python-model component is useful, but the evidence does not yet justify a native private-authentication prototype.**

This review makes two mathematical advances beyond the earlier fixed-challenge embedding analysis:

1. An online simulator for the aggregate mask claim can follow the claim-before-blend order in a precisely restricted algebraic model.
2. A counterexample shows why extending that model to deterministic commitment roots requires an additional argument. When original queries exhaust the embedding randomness, roots can distinguish witnesses in the stronger view that contains the whole blended vector.

The counterexample is not an executed attack on the native transcript. It identifies a limit of the proposed simulation proof.

This is a read-only source and mathematical review. No upstream code, component tests, builds, proofs or zkVM executions were run. Metadata/hash checks were performed. No WSL resource ledger, production profile, benchmark dataset or manuscript was changed. Manuscript Sections II–VIII and agreed clarifications remain authoritative. All existing proving/isolation pauses and fail-closed private verification remain in force.

## 1. Receipt, provenance and evidence limits

| Attachment group | Received | Assessment |
| --- | ---: | --- |
| Pinned Rust sources | 16 | Lengths, SHA-256 hashes and Git blob hashes match the acquisition records and retained tree metadata. Total source size: 200,854 bytes. |
| Completed embedding report | 1 | Read with its appendices and historical stops distinguished from the completed continuation. |
| Acquisition, representation, case-summary and resource records | 5 | Applicable to the embedding package. |
| Uploaded validation-closure record | 1 | Belongs to an older Aurora package; excluded as evidence of the current package's final preservation. |
| **Total** | **23** | **One supporting attachment needs replacing. No source re-upload is needed.** |

Source pin:

~~~text
Commit: 441fbf51ff0bcb0bcd28f3f1b73f4954029e8577
Tree:   544452a781fee0f9b262d4ecfdcc47326fb6974f
~~~

The five field sources cover portable GHASH arithmetic, scalar and packed field definitions, the field module and the binary-field macro. Eleven sources cover the prover/verifier logup helpers and their IOP adapters.

The uploaded case summary reports EC-01–EC-25 passing on their first invocation. These are Python-model comparisons, not compiled native comparisons. The report's largest encoder fixture contains 16 physical coefficients and 128 encoded field words. No full-authentication performance conclusion follows.

The uploaded file named “validation-closure.json” identifies its package as **S3-AURORA-NATIVE-DEPENDENCY-LOCK-1**, with the older 402/426 invocation ledger. The current report and resource closure describe the embedding audit, but that older JSON cannot corroborate it. Supply the existing current record at:

~~~text
/home/grace/projects/pq-did/docs/data/s3_binius_embedding_correspondence_1/continuation-1/validation-closure.json
~~~

This is an attachment correction, not a reason to rerun the audit. The earlier acquisition-memory diagnostic also remains unresolved as recorded; later low-memory component observations do not resolve its measurement scope.

## 2. What the newly acquired sources establish

### Field and encoder premises

The scalar/macro/portable arithmetic sources support the recorded polynomial representation over

\[
F=\operatorname{GF}(2^{128}),\qquad
X^{128}+X^7+X^2+X+1.
\]

The portable reduction constant is 0x87, with low-bit polynomial coefficients. This is distinct from treating a GCM wire string as the same bit ordering. The macro maps the supplied constants to MULTIPLICATIVE_GENERATOR and TRACE_ONE_ELEMENT as recorded in representation admission.

This confirms the source-level premises used by the model. It does not independently validate compiled architecture-specific arithmetic, the complete native build or an overall security parameter.

### IntMul/logup oracle and claim coverage

The source path is:

| Step | Source/function | Consequence |
| --- | --- | --- |
| Construct private pushforwards | ip-prover/logup_star/witness.rs, combined_lookers | \(Y_t=\sum_i\eta^i(I_i)_*\operatorname{eq}_{r_i}\) depends on hidden index columns. |
| Commit pushforwards | iop-prover/logup_star.rs, prove_transparent | The looker-batching challenge is sampled, then the \(Y_t\) oracles are committed before the subsequent reduction challenges. |
| Receive the same oracles | iop/logup_star.rs, verify_transparent | One masked oracle handle per table is received in the corresponding order. |
| Bind both operands | Same verifier function | It queues \(\langle Y,\operatorname{eq}_z\rangle\) and \(\langle Y,T\rangle\) against the **same** oracle handle. |
| Handle opening claims | Existing wrapped prover/verifier channels | Both calls pass through the interface that sends/receives the individual plaintext claim and links it into the outer circuit. |

Here \(\eta\) denotes the logup looker-batching challenge. It is a different challenge from the later BaseFold blend, denoted \(\gamma\) below. The implementation uses a shared looker-batching challenge across tables; an introductory comment suggesting one per table is not the operative behaviour.

Consequently, hiding only the main packed-witness terminal value is insufficient. The two IntMul pushforward claims also require private claim slots and same-oracle binding. A public table does not make its pushforward or these claims public.

### A precise point-order qualification

The generic committed-table reduction and the transparent-table path must not be conflated. In verify_reduction_transparent, each table's pushforward evaluation point is taken from the **last table.n_vars coordinates of node_point**. The returned pushforward_eval_point is the authoritative point for its equality operand.

The generic reduction has its own later prefix conventions. Thus “table prefix / index suffix” is not a universal rule for both paths. Preserve the explicit output point for the transparent IntMul caller; do not reconstruct it from a generic prefix assumption. This is a correspondence clarification, not a demonstrated native implementation defect.

### Outer messages remain part of the view

The outer Spartan prover sends multiplication-check evaluations and a precommit-segment contribution, and queues openings for the precommit, private and mask oracles. These messages are not covered merely by proving the privacy of the new aggregate-opening layer. Their joint distribution with the inner ciphertexts, precommitted pads and commitment roots remains an explicit composition obligation.

## 3. A precise candidate for the joint linear relation

This section specifies proposed algebra, not an adopted profile or implemented native patch.

For each logical oracle \(a_i\in F^{k_i}\), let \(m_i\) be a power of two with \(m_i\ge k_i\). Use the earlier interleaving:

\[
P_i[2j]=\rho_{i,j},\qquad
P_i[2j+1]=\bar a_{i,j},
\]

where \(\rho_i\) is fresh uniform randomness and \(\bar a_i\) is zero-padded to \(m_i\). Let \(D_i\) select the first \(k_i\) odd coordinates. Then \(D_iP_i=a_i\). Any required padding constraints remain part of the relation.

Transport a logical operand \(t\) to \(D_i^{\mathsf T}t\). This preserves its opening:

\[
\langle P_i,D_i^{\mathsf T}t\rangle=\langle a_i,t\rangle.
\]

Let \(z\) be the **same outer private witness** committed for checking the wrapped verifier. For each inner opening call \(j\), allocate a fixed outer slot \(s_j\) constrained to equal that call's verifier-computed claim. The replacement opening equation is

\[
\boxed{
\langle P_i,D_i^{\mathsf T}t_j\rangle
+\langle P_z,D_z^{\mathsf T}e_{s_j}\rangle=0.
}
\]

Addition implements subtraction in characteristic two. The selector is at physical position \(2s_j+1\). It must come from the trusted compiled layout, not a free proof-supplied index.

Each IntMul pushforward needs both equations, using its equality and table operands and two corresponding claim slots. These must share the same \(P_i\), and the selectors must refer to the outer witness used by the outer proof.

Include all other required linear relations, with their justified public targets, in one ordered relation system:

\[
e_j=\sum_i\langle P_i,u_{j,i}\rangle-b_j,\qquad j=0,\ldots,r-1.
\]

Freeze the commitments, descriptor order, operands, targets and slot mapping before sampling a fresh batching challenge \(\lambda\). Consistent with the earlier contract, use the **same** coefficient \(\lambda^j\) on every term of relation \(j\):

\[
U_i=\sum_j\lambda^j u_{j,i},\qquad
B=\sum_j\lambda^j b_j.
\]

For a fixed nonzero residual vector, a uniform independent classical \(\lambda\) makes the aggregate residual vanish with probability at most

\[
\min\{1,(r-1)/|F|\}.
\]

This is only the polynomial-root counting fact. It presupposes that the residuals were fixed before the challenge. It is not a Fiat–Shamir, quantum extraction or complete proof-security bound.

### Aggregate companion claim and order

For each physical oracle, commit an independent uniform companion \(\Omega_i\) along with \(P_i\) at that oracle's prescribed commitment point. After relation batching, send **only**

\[
\Sigma=\sum_i\langle\Omega_i,U_i\rangle.
\]

Then sample a blend challenge and set

\[
V_i=(1-\gamma)P_i+\gamma\Omega_i,\qquad
S=(1-\gamma)B+\gamma\Sigma.
\]

The opening layer must establish \(\sum_i\langle V_i,U_i\rangle=S\) and authenticate the blends against those same earlier commitments. Sending individual companion claims is not justified by the aggregate privacy lemma.

The existing per-oracle BaseFold sumchecks cannot simply be called separately for the hidden terms. Combined FRI later in the current implementation does not itself supply the required joint hidden-target protocol.

A semantic joint sumcheck can use a common dimension by zero-extending both vectors of each pair. If \(Z_i\) is the high-coordinate zero selector, the terminal product is

\[
Z_i(r_{\mathrm{high}})^2\,
\widetilde V_i(r_{\mathrm{low}})
\widetilde U_i(r_{\mathrm{low}}).
\]

The square matters away from Boolean points. Repeating a smaller FRI codeword is a different map and cannot silently replace this lifting. This defines an algebraic option, not a memory-admitted native lowering.

For fixed \(P,\Omega,\Sigma\) before \(\gamma\), acceptance of the aggregate identity requires

\[
(1-\gamma)(A(P)-B)+\gamma(A(\Omega)-\Sigma)=0,
\quad A(X)=\sum_i\langle X_i,U_i\rangle.
\]

If either residual is nonzero, this is a nonzero polynomial of degree at most one in \(\gamma\). Its use in a soundness argument still requires binding to fixed committed objects and the rest of the opening proof.

At \(\gamma=0\), the blend exposes the original vector in the strong view. At \(\gamma=1\), it no longer checks the original relation. The future profile must specify rejection/resampling or explicit exceptional-event treatment. No challenge-sampling change is adopted here.

## 4. New lemma: online aggregate-claim simulation in the restricted model

The earlier analysis fixed \(\gamma\) and computed \(\Sigma\) afterwards. The following derivation handles sending \(\Sigma\) first.

### Hypotheses

Condition on a public prefix for which:

- The logical messages and public operands are fixed; \(A(P)=B\) for every permitted embedding randomness.
- The embedding randomness is independent across the relevant oracles and remains fresh under this conditioning.
- \(\Omega\) is uniform over the full product vector space and independent of \(P\).
- The prefix contains no additional information correlated with these coins, unless a separate argument has proved that the stated conditional distribution is preserved.

These hypotheses are **not yet established for the actual prefix containing Merkle roots and the outer proof**.

### Derivation

If \(A\ne0\), the linear image

\[
\Sigma=A(\Omega)
\]

is uniform over \(F\) and independent of \(P\). Given \(\Sigma=s\), \(\Omega\) is uniform on the affine hyperplane \(A(\Omega)=s\).

For any received \(\gamma\ne0\), the affine map

\[
\Omega\longmapsto V=(1-\gamma)P+\gamma\Omega
\]

is a bijection onto

\[
\boxed{A(V)=(1-\gamma)B+\gamma s.}
\]

This hyperplane does not depend on the particular logical witness or embedding coins. Thus \(V\), conditioned on \(s,\gamma\), is uniform on this hyperplane and independent of \(P\).

An online algebraic simulator can therefore:

1. Sample \(s\) uniformly and send it as \(\Sigma\).
2. Receive a nonzero \(\gamma\).
3. Sample \(V\) uniformly subject to the boxed equation.
4. Produce messages that are specified functions of \(V\), public operands and fresh public randomness.
5. Answer original-codeword queries by the embedding rank lemma, caching repeated positions, with at most \(m_i\) distinct positions per oracle.
6. For each paired companion answer, use
   \[
   E_i(\Omega_i)[x]=
   \frac{E_i(V_i)[x]-(1-\gamma)E_i(P_i)[x]}{\gamma}.
   \]

A hyperplane sample can be obtained by sampling all but one coordinate and solving for a coordinate with nonzero coefficient in \(A\). If \(A=0\), an honest statement requires \(B=0\); send \(\Sigma=0\) and take \(V\) uniform.

The challenge may depend on the exposed \(s\) and independent public randomness. It cannot depend on omitted mask-correlated information without revisiting the conditioning.

### What this settles

The aggregate claim's position before the blend challenge is not, by itself, an algebraic obstruction. This refines one limitation of Section 5 of the earlier embedding analysis.

It does **not** give an online simulator that first sends real commitment roots, programmes a hash oracle, supplies authentication paths or simulates the preceding correlated outer proof. Nor does it prove extraction. Those claims require additional results.

## 5. Why commitment privacy does not follow: a concrete boundary example

The native encoder identity is

\[
F_P(X)=R_\rho(X)+\widehat W_\ell(X)G_{\bar a}(X),
\qquad \deg R_\rho<m.
\]

For at most \(m\) distinct evaluation positions, the original values are uniform and independent of \(a\). This rank statement is correct.

However, suppose the strong view also contains:

- the whole blended vector \(V\);
- a deterministic commitment to the paired codewords \(E(P),E(\Omega)\);
- exactly \(m\) distinct original evaluations;
- a nonzero blend challenge;
- two known candidate logical witnesses with the same public aggregate target.

Such candidate tuples exist in nontrivial relation spaces; the statement is conditional on them. For each candidate \(a^{(b)}\), subtract its known high-degree contribution from the \(m\) evaluations. Polynomial interpolation uniquely determines \(R^{(b)}\), and hence \(P^{(b)}\). Then compute

\[
\Omega^{(b)}=
\frac{V-(1-\gamma)P^{(b)}}{\gamma}.
\]

The observer can now compute the entire paired codeword and its candidate commitment root. The actual root identifies the matching candidate, except when distinct encoded objects collide under the commitment.

The inspected Merkle-channel contract is deterministic for a supplied buffer and Merkle prover; it provides no independent fresh leaf-salt argument in this interface. The example concerns that type of commitment.

**Interpretation:** uniform opened symbols do not imply witness independence once a root and the stronger folded-vector view are included. At \(q=m\), all of the relevant embedding uncertainty can be consumed.

This does not show that the actual native transcript reveals all of \(V\), or constitute a native forgery or distinguishing experiment. It rules out extending the earlier strong-view lemma to roots at the equality boundary by assertion.

For this strong-view proof strategy, retaining random dimensions beyond those consumed by queries is necessary to avoid this particular reconstruction argument. A prospective choice such as \(m_i>q_i\) is still **not sufficient**:

- Count all exposed positions, including wider leaves, cosets and auxiliary openings.
- Account for additional linear information from the entire transcript.
- Prove conditional rank after adaptive observations.
- Analyse commitment/hash queries and simulator consistency.
- Determine finite classical/quantum bounds under the chosen commitment/hash model.

One extra field coefficient is not, by itself, a justified overall 128-bit security claim. No new mask dimension or privacy parameter is approved in this review.

## 6. The exact outstanding construction result

The immediate missing result is a **joint committed-view simulation and same-object extraction argument** for the selected protocol, with the following explicit inputs and outputs:

| Obligation | Required content |
| --- | --- |
| Logical relation | Every required credential, holder-binding, disclosure, non-revocation and context check remains enforced on the decoded, mutually bound objects. |
| Transcript dependencies | Ordered commitments, inner ciphertexts, logup challenges/oracles, outer proof messages, relation descriptors, batching and blend challenges. No independence assumption may be imported after correlated messages without proof. |
| Joint privacy | Simulator for roots, public claims, all sumcheck/folding messages, final codeword information, original/companion leaves, authentication paths and relevant oracle queries. |
| Same-object knowledge | Extraction gives the same inner oracles and outer witness that satisfy the hidden terminal equations, rather than unbound values chosen at different stages. |
| Finite accounting | Query/rank budgets, exceptional challenges, batching and polynomial-commitment errors, adaptive tails and all simulator/extractor resources. |
| Post-quantum composition | Applicable quantum/Fiat–Shamir argument and a clear distinction between ideal-oracle reasoning and concrete hashing. |
| Engineering admission | Native correspondence and simultaneous resource estimates for the complete relation, after the construction is justified. |

The existing source establishes neither this theorem nor a native implementation of the proposed joint protocol. A conditional assumption can be named for research discussion, but cannot be presented as implemented PQ-DAA privacy or knowledge security.

### Concrete question for a proof-system reviewer

> For the pinned binary-field encoder and interleaved messages above, construct an online simulator for the actual deterministic-Merkle/BaseFold transcript, with a quantified residual masking budget and all outer-wrapper/logup correlations included. Couple this to a same-object extractor for the ordered hidden joint relations. If that cannot be proved for this commitment/compiler, identify the required commitment or protocol change and its applicable theorem. Address the entropy-saturation example explicitly; a proof for opened field values alone is insufficient.

This is the next substantive construction question. More unchanged encoder-model tests would not settle it. Native experiments may later validate an approved construction, but do not replace this argument.

## 7. Recommended handover and current decision

1. Supply the correct existing embedding validation-closure record. Reuse the completed audit.
2. Retain EC-01–EC-25 as completed Python-model evidence. No rerun is suggested.
3. Add this review to the construction handover, clearly marking the online lemma and boundary example as mathematical derivations with stated hypotheses.
4. Obtain the construction result in Section 6 before authorising a private native prototype. Keep any prospective protocol/parameter change separate from the current production profile.
5. Preserve the working ML-DSA KYC baseline and its benchmark datasets independently of this research gate.

The current evidence supports continuing to treat Binius64 as a paused research candidate. It does not establish complete private authentication, W3C conformance, full-system post-quantum security or a commitment to complete the original scope by 31 October.

No new WSL execution package or resource amendment is authorised by this document. The reported proof ledger remains two attempts used, one unused.

## Source references

This review uses the supplied files and retained handover sources; no new upstream acquisition was performed.

- Current report: stage3_binius_embedding_correspondence.md, especially acquired-logup correspondence, completed continuation, individual outcomes and construction gate.
- Acquisition records: execution_source-acquisition(1), continuation-1_source-acquisition(1).json.
- Supporting records: representation-admission(1).json, case-summary(1).json, resource-closure.json.
- Newly supplied logup sources: crates/ip-prover/src/logup_star/{mod,prove,pushforward,witness}.rs; crates/ip/src/logup_star/{error,mod,output,pushforward,verify}.rs; crates/{iop-prover,iop}/src/logup_star.rs.
- Newly supplied field sources: crates/field/src/{lib,binary_field}.rs; fields/ghash.rs; packed_fields/ghash.rs; arch/portable/arithmetic/ghash.rs.
- Retained wrapper sources: spartan-prover/wrapper/zk_wrapped_prover_channel.rs and spartan-verifier/wrapper/zk_wrapped_channel.rs.
- Retained opening/commitment sources: iop-prover/basefold/channel.rs; iop/basefold/channel.rs; iop-prover/merkle_channel.rs.
- Retained outer prover: spartan-prover/src/lib.rs.
- Earlier independent reports: PQ_DID_Binius64_Independent_Review.md and PQ_DID_Binius64_Native_Embedding_Analysis.md.
- Earlier Codex joint-opening construction report, supplied as Pasted markdown(8).md.

The new mathematical claims in Sections 3–5 are derived here, with their limitations stated. They are not attributed to an existing security theorem.
