Proceed with **S2-HOLDER-WITNESS-REVOCATION-INTEGRATION-1** in `/home/grace/projects/pq-did`.

Connect issued credentials, authenticated manager updates, holder-local witness maintenance and the two durable reference verifiers. Use synthetic credentials, isolated stores and existing bounded cryptographic components.

**1. Budget amendment**

I authorise **27 additional focused test invocations**, increasing the cumulative ceiling from **172 to 199**. Count failures, repeats and parameterised cases individually. This is a maximum, not a required test count.

Preserve the remaining **183.341 seconds** of the cumulative implementation allowance, subject to the current ledger. Preserve all existing memory, process, storage and command limits, including the **256 MiB preservation-audit ceiling**.

Do not reset counters or borrow from analysis/isolation budgets. Reserve time for cleanup, documentation and the preservation audit. Stop if the remaining allowance cannot support meaningful completion.

**2. Reuse the established contracts**

Read the issuance integration, holder-local update module, durable manager publication, verifier integration, complete local authentication relation and current specification.

Only manuscript Sections II–VIII and agreed clarifications are authoritative.

Preserve:

* The same certified holder binding, attributes and revocation identifier throughout the flow.
* Existing canonical state/update encodings and signing contexts.
* The 16-record / 178,592-byte per-call update limit.
* Atomic witness/state results and existing failure semantics.
* Strict expiry, verifier-context binding and one-time consumption.

Identify how the holder obtains its initial authenticated witness and state. Reuse the specified procedure; do not fabricate a production interface where the specification leaves a gap.

**3. Implement the isolated holder lifecycle**

Connect:

* Successful credential issuance and holder acceptance.
* Initial witness/state validation.
* Authenticated public-update retrieval.
* Bounded local witness updates.
* Preparation of presentation inputs for each verifier.
* Revocation of another credential and revocation of the holder’s own credential.

Ensure witness updates do not change the certified credential. Commit the new witness and corresponding state together according to the existing holder contract.

Reject invalid update sequences or authentication failures without leaving a partially updated holder state. Preserve the existing explicit revoked outcome and its specified state effects.

For histories exceeding one call’s limit, use only the specified bounded continuation procedure. If none exists, report that limitation rather than inventing resynchronisation behaviour.

**4. Separate three kinds of evidence**

Label results explicitly as:

A. Real bounded signature/state authentication and Merkle/witness processing.

B. Complete local authentication-relation evaluation with the witness available to the test harness.

C. Verifier lifecycle execution using explicitly injected synthetic proof acceptance.

Use the local relation to test the certified identifier’s path, credential linkage and non-revocation after updates. Do not expose the private witness to a verifier adapter or present local evaluation as a privacy-preserving proof.

Normal proof verification remains fail-closed. Synthetic acceptance must not be used as evidence that a revoked credential is cryptographically rejected.

**5. Validate the lifecycle boundaries**

Prepare a compact matrix prioritising:

* Issuance followed by a valid initial witness and local authentication relation.
* Revocation of a different credential, successful witness update and continued local validity.
* Revocation of the holder’s credential and rejection by the local relation against the new authenticated state.
* Modified or incorrectly signed update records.
* Wrong instance, identifier, path or credential combinations.
* Missing, reordered, repeated or stale updates according to the existing contract.
* Update batch limits and atomic failure behaviour.
* Presentation-context preparation for both independent verifiers.
* Stale-state rejection under the actual verifier freshness policy.

State the observation points for concurrent revocation and presentation. Do not claim instantaneous rejection beyond the specified freshness guarantee.

Reuse completed replay, crash, signing and verifier tests unless this integration introduces a concrete new risk. Do not retry failures automatically.

**6. Deliver an integrated reference scenario**

Provide a reproducible local scenario showing issuance, an unrelated revocation and witness update, presentation preparation, holder revocation and subsequent local rejection.

Account for any scenario execution within the test and time allowances. Prefer reusing the integration test entry point over adding another execution.

Clearly mark all synthetic proof steps and distinguish the reference scenario from a complete privacy-preserving KYC demonstration.

**7. Record evidence and stop**

Create `docs/stage2_holder_witness_revocation_integration.md` with the data flow, state transitions, individual outcomes, evidence categories and remaining gaps.

Update status, traceability and issues. Include a short checklist showing which original KYC lifecycle operations are now connected and which still require real proof integration, services or interoperability work.

Complete required lint, formatting and preservation checks within the limits. Preserve manuscript, parameters, dependencies and historical evidence.

No host activation, installations, proofs or zkVM executions. Isolation remains safely stopped and unactivated. Stages 2–3 remain open; the proof ledger remains **two attempts used, one unused**.

Finish with resource consumption and one recommended next package. Keep production-security, adaptive Delta_tail and complete proof knowledge/privacy obligations explicit.
