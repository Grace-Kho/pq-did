I approve **S3-AURORA-AUTH-CONSTRUCTION-CONTRACT-1** as a bounded research-direction package.

Develop a concrete proposed Aurora–BCS authentication-proof contract while preserving the existing complete authentication relation. This approval does not adopt the profile or authorise experiments.

**1. Scope and resources**

Only manuscript Sections II–VIII and agreed clarifications are authoritative. Record proposed construction changes separately from the active specification.

Reuse the compact-proof review and existing security assessments. Do not restart a broad candidate survey.

Use the existing analysis allowance, last reported as **236.675 seconds**, according to its ledger. Leave the **41.823-second implementation balance** untouched. The invocation ledger remains **386/386**.

No tests, builds, installations, circuit generation, proofs or zkVM executions are authorised. Perform only established documentation/static checks and the preservation audit within existing limits, including the **256 MiB audit ceiling**.

**2. Specify the exact construction**

Identify the Aurora variant, BCS transformation, implementation commit and applicable primary-source versions.

Specify the proposed field, evaluation domains, encoding, commitment/hash construction, transcript schedule, challenge derivation and zero-knowledge mode.

Give the rationale and constraints for each choice. Where complete-relation dimensions are unknown, express dependent parameters symbolically and identify the measurement needed to select them. Do not fill gaps with undocumented library defaults.

Separate protocol requirements from implementation conveniences.

**3. Preserve the full relation through lowering**

Map every authentication check into the proposed constraint system:

* Exact credential message and bounded ML-DSA verification.
* Holder-secret opening.
* Attribute encoding, disclosure and public policy.
* The same certified revocation identifier’s Merkle path.
* Public statement and verifier-context binding.

Define public inputs, private witness and auxiliary witness values.

Account for Booleanity, ranges, signed arithmetic, integer-versus-field semantics, parsing, sampler exhaustion and rejection. Auxiliary values supplied by a witness generator must be constrained; their correct generation is not a soundness argument.

Do not replace SHA3/SHAKE with a proof-friendly hash, alter the signature scheme or weaken the accepted relation.

Explain how existing experimental arithmetic can be reused, and what equivalence work remains. Do not equate Boolean gate counts with R1CS constraint counts.

**4. Define a bounded, privacy-preserving proof format**

Specify the verifier-facing proof object and canonical serialisation, including:

* Profile/version and relation identification.
* Binding to the complete public statement.
* Field-element encodings and transcript ordering.
* Commitments, permitted openings and authentication paths.
* Length/count bounds and rejection of malformed or ambiguous encodings.

Distinguish the transmitted proof from prover memory, full oracle tables, debug transcripts and witness data.

Identify the exact masking/randomisation and commitment mechanisms required for zero knowledge. Account for all revealed queries and openings against the applicable privacy bound.

Do not assume enabling a library flag or serialising a valid internal transcript automatically provides the required privacy.

**5. Map security claims to actual theorems**

Use the original Aurora, BCS and relevant quantum-security sources.

Check separately:

* Completeness and relation-lowering correctness.
* Soundness versus knowledge extraction.
* Classical versus quantum adversaries.
* Adaptive statements and the manuscript’s session/corruption model.
* Zero knowledge, repeated presentations and composition.
* Concrete hash instantiation and shared-oracle assumptions.

Do not substitute an interactive-protocol theorem for a non-interactive construction without the required transformation argument.

For each intended claim, list the exact theorem, hypotheses, parameter/resource losses and unresolved obligations. Preserve the existing outer-oracle and adaptive Delta_tail gaps where still applicable.

A precise missing lemma is an acceptable finding. Do not invent an assumption merely to mark a security obligation complete.

**6. Establish engineering feasibility criteria**

Account for complete-relation constraints, matrix sparsity, domain padding, zero-knowledge overhead, encoded oracle sizes and simultaneous memory use.

Consider prover time and verifier work separately from proof size. Do not transfer published Aurora benchmarks directly to this workload.

Define:

* What must be settled before a small isolated prototype.
* What must additionally be settled before profile adoption.
* The smallest next experiment capable of resolving a material uncertainty.

Keep proposed installations, parameters and experimental allowances inactive.

**7. Deliver a concrete decision and stop**

Create `docs/stage3_aurora_auth_construction_contract.md` containing the proposed construction, relation mapping, wire format, parameter dependencies, theorem-applicability matrix and implementation acceptance criteria.

Include a concise list of the changes that would eventually be required in Sections VII–VIII. Preserve the manuscript itself.

Update status, traceability and issues. Conclude either:

* The engineering contract supports a specifically bounded prototype, with security limitations explicitly retained; or
* A named construction/security blocker must be resolved first.

Do not automatically begin another review or experiment.

Preserve production code, active BC-1, dependencies, parameters and historical evidence. Raw-view integration and CPU proving remain paused; isolation stays safely stopped and unactivated.

Stages 2–3 remain open. The proof ledger remains **two attempts used, one unused**.
