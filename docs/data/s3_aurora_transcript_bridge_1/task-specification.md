Proceed with **S3-AURORA-TRANSCRIPT-BRIDGE-1**, addressing AURORA-BRIDGE-001 only.

Establish whether the pinned Aurora–BCS transcript, commitment construction and query/masking budget satisfy the hypotheses of the applicable security results. This is a source-only prerequisite; no private prototype or profile adoption is authorised.

**1. Fix the exact object being assessed**

Read the construction contract, pinned source references and existing issue definition.

Record the precise implementation commit, selected protocol variant, configuration and source locations. Distinguish features present in the library from features enabled in the proposed profile.

Compare the pinned construction against the theorem construction, including any:

* Proof-of-work/grinding step.
* Grouped or coset-based openings.
* Selective commitment salting.
* Transcript/hash-chain modifications.
* Custom serialisation.

Upstream documentation is a discovery aid, not evidence that the pinned version is identical.

Only manuscript Sections II–VIII and agreed clarifications remain authoritative for the authentication scheme.

**2. Produce a round-by-round correspondence**

For every round, map:

* Public statement and relation identification.
* Prover messages and committed oracles.
* Fresh masking randomness and commitment salts.
* Transcript absorption and challenge derivation.
* Query selection, openings and verifier checks.
* The corresponding objects in the cited theorem.

Identify ordering dependencies and which values must be fixed before each challenge.

Account for all verifier-visible information, including auxiliary messages, final polynomials, opening contents and commitment metadata. Do not omit information merely because it is outside the main proof-value array.

**3. Establish the query and masking budget**

Derive the relevant bounds from the actual selected query procedure.

Account for grouped openings, multiple oracle columns, FRI-related queries, repetitions and any additional disclosed values. Distinguish requested queries, distinct queried positions and revealed field elements.

Map those quantities to the exact privacy theorem’s budget. Explain how masking degree, domain size and fresh randomness satisfy its hypotheses.

Keep unknown relation dimensions symbolic. Do not substitute convenient defaults or claim numerical privacy without the required parameters.

Check repeated presentations under the manuscript’s restrictions, including randomness reuse and shared transcript/hash interfaces.

**4. Check the security transformations separately**

Use the actual primary theorem statements and hypotheses.

Distinguish:

* IOP completeness and soundness.
* Knowledge extraction.
* Zero knowledge.
* BCS compilation.
* Quantum and adaptive security.
* Concrete hash instantiation.

Do not transfer PCP-specific results to an IOP without justification, or treat a round-by-round soundness theorem as establishing every knowledge/privacy property.

For implementation deviations, provide either a justified correspondence or a precise missing lemma.

Do not credit a classical proof-of-work security factor directly against quantum adversaries. If a modification lacks the necessary justification, identify a minimally changed proposed configuration and its parameter consequences; leave that change inactive.

Preserve the existing concrete-hash, adaptive Delta_tail and protocol-composition gaps where still applicable. Closing this bridge under an idealised model does not close them automatically.

**5. Connect the theorem transcript to the proposed wire format**

Identify exactly which transcript fields may be transmitted and how the verifier reconstructs the theorem’s view.

Check canonical encoding, bounded lengths, statement binding, opening consistency and rejection of omitted, extra or ambiguous fields.

Keep full oracle tables, private randomness, witness values and diagnostic state outside the transmitted proof unless the applicable theorem explicitly permits their disclosure.

If serialisation requires new implementation work, specify its contract and acceptance criteria. Do not implement it in this package.

**6. Finish with one bounded decision**

Create `docs/stage3_aurora_transcript_bridge.md` with:

* The source-to-theorem correspondence table.
* Query/masking derivation.
* Deviation and obligation register.
* Wire-format correspondence.
* A decision on AURORA-BRIDGE-001.

Conclude one of:

1. Correspondence established under explicitly stated assumptions, permitting a proposed isolated prototype.
2. A specific construction/configuration modification is required before that correspondence can be established.
3. A named new argument is required and the bridge remains unresolved.

Do not manufacture an assumption or mark the issue closed because the library describes itself as zero knowledge or post-quantum.

Recommend one concrete next action without starting it.

**7. Preserve resources and project state**

Use the existing analysis allowance, last reported as **228.289 seconds**, according to its ledger. Leave the **41.823-second implementation balance** untouched. Invocations remain **386/386**.

Perform only established documentation/static checks and the required preservation audit within existing limits, including the **256 MiB audit ceiling**.

Preserve production code, active profile, dependencies, parameters, manuscript and historical evidence. Update status, traceability and issues.

No tests, builds, installations, circuits, proofs, zkVM executions or activation. Raw-view integration and CPU proving remain paused; isolation stays safely stopped and unactivated.

Stages 2–3 remain open. The proof ledger remains **two attempts used, one unused**.
