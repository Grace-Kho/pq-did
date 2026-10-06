Proceed with **S3-AURORA-TRANSCRIPT-CORRECTION-CONTRACT-1**.

Produce a patch-ready correction contract for the reported absorbed-digest omission and missing initial statement binding. Keep this package source-only.

**1. Confirm the precise affected path**

Reuse the transcript bridge findings and pinned source snapshot.

For each finding, record:

* Commit, file, function and selected configuration.
* Relevant prover and verifier callers.
* Data passed to absorption.
* Actual state-update and challenge-generation dependencies.
* Whether another active path supplies the allegedly missing binding.

Distinguish confirmed source behaviour, inferred security consequences and unexecuted attack hypotheses. An absent initialisation call in one function does not establish that the whole protocol lacks statement binding.

Do not repeat the broader literature review.

**2. Specify the corrected transcript exactly**

Provide replacement pseudocode and a concrete edit list for:

* Transcript initialisation.
* Commitment and prover-message absorption.
* Round transitions.
* Challenge generation and state progression.
* Verifier reconstruction.

Ensure newly absorbed data affects the subsequent transcript state and challenges through the specified construction.

Bind the appropriate protocol/profile identity, parameters, relation identity and canonical public statement at the point required by the selected security construction.

Use the existing public statement and context definitions. Do not include hidden credential or witness material in the public transcript to compensate for missing binding.

Specify exact encodings, lengths, ordering, domain labels, counters, empty-input handling and failure behaviour. Prevent ambiguous concatenations and inconsistent prover/verifier interpretation.

Preserve existing cryptographic primitives unless a separately identified construction change is necessary.

**3. Map the correction to the selected theorem**

Explain which transcript construction the corrected pseudocode implements and identify the supporting primary-source definition.

Separate:

* Restoring the intended implementation behaviour.
* Changing a protocol or transcript encoding.
* Establishing the remaining security arguments.

Identify any additional assumption or lemma introduced by the correction. Do not claim that absorbing more data automatically proves knowledge soundness or zero knowledge.

Keep query/masking, commitment transformation, adaptive extraction/privacy and concrete-hash obligations explicit. Do not close AURORA-BRIDGE-001 merely because the two source defects have proposed repairs.

**4. Prepare a minimal executable regression contract**

Specify a future isolated transcript harness using public synthetic inputs, without producing an Aurora proof.

Define independently reproducible expected traces and cases covering:

* Identical inputs producing identical transcripts.
* Changed statement, commitment or prover message.
* Changed round, message order or component boundary.
* Empty and malformed inputs.
* Multiple challenges and absorb-after-squeeze behaviour.
* Prover/verifier transcript agreement.
* Rejection of unsupported transcript versions.

Where the source findings permit it, identify a case that exhibits the old omission and the expected corrected behaviour.

Distinguish full transcript-state comparisons from challenges mapped into a smaller range. Do not require an impossible universal guarantee that every changed input produces a different finite challenge.

Passing these tests would establish specified transcript behaviour, not a security theorem or an executed forgery result.

**5. Make the implementation proposal concrete**

Identify the smallest isolated correction package, exact files/interfaces, invocation count, resource envelope and stopping conditions.

Preserve the pinned upstream snapshot. Describe the correction as a separately identified experimental variant with an explicit diff and provenance.

Keep normal proof verification fail-closed. Do not introduce compatibility fallback to the deficient transcript path.

Leave the proposed implementation and any additional allowance inactive. Do not require another general review before the narrowly scoped regression package if this contract is complete.

**6. Deliver and stop**

Create `docs/stage3_aurora_transcript_correction_contract.md` containing the confirmed data-flow findings, corrected pseudocode, edit list, theorem mapping, regression contract and next-package proposal.

Update status, traceability and issues. Separate proposed corrections from implemented and validated corrections.

Only manuscript Sections II–VIII and agreed clarifications are authoritative. Preserve production code, active profile, parameters, dependencies, manuscript and historical evidence.

Use the existing analysis allowance, last reported as **219.994 seconds**, according to its ledger. Leave the **41.823-second implementation balance** untouched; invocations remain **386/386**.

Perform only established documentation/static checks and the required preservation audit within existing limits, including the **256 MiB audit ceiling**.

No tests, builds, installations, circuits, proofs, zkVM executions or activation. No private prototype is admitted.

Stages 2–3 remain open. Raw-view integration and CPU proving remain paused; isolation stays safely stopped and unactivated. The proof ledger remains **two attempts used, one unused**.
