Proceed with **S3-AUTH-PROOF-FEASIBILITY-PLAN-1** in `/home/grace/projects/pq-did`.

Prepare a bounded, decision-oriented plan for implementing the complete private authentication relation. Reuse existing measurements and security assessments.

**1. Preserve scope and allowances**

Only manuscript Sections II–VIII and agreed clarifications are authoritative.

This package permits source inspection, evidence analysis and documentation only. No installations, builds, executions of proof guests, circuit generation or proof attempts.

Read the resource ledgers first. Preserve their separation: the last reported implementation balance is **104.137 seconds**, with **one remaining test invocation**. Use the existing analysis allowance only according to its recorded scope. Do not reset, transfer or extend allowances.

Reuse completed checks. Preserve all resource ceilings, including the 256 MiB preservation-audit ceiling. If mandatory validation cannot fit, record the incomplete result and stop.

**2. Define the complete proof target**

Map the current authentication relation to:

* Credential signature and exact certified message.
* Holder-secret opening.
* Attribute encoding, disclosure and policy checks.
* The same certified revocation identifier’s non-revocation path.
* Public statement and verifier-context binding.

Separate proof obligations from external freshness, expiry, authenticated-state and one-time challenge checks.

Identify the precise public inputs and private witness. Do not weaken the relation, expose hidden credential material or move required private checks outside the proof to improve performance.

**3. Establish the actual implementation gap**

Create a coverage table for:

* The executable local authentication relation.
* Original BC-1 circuit components.
* RISC Zero enrolment and CredValid guests.
* The remaining components needed for complete authentication.

Reuse the existing gate, cycle, segment, receipt and timing evidence. Distinguish measurements, capped prefixes and projections.

In particular:

* The enrolment receipt is not a complete authentication proof.
* CredValid execution excludes any authentication components absent from that guest.
* The approximately 9.893-hour CredValid proving forecast is unmeasured and already includes its recorded uncertainty allowance.
* Original-profile component proof-size projections are not generated complete proofs.

Do not extrapolate complete authentication performance from enrolment alone.

**4. Make a concrete engineering decision**

Compare at most three evidence-supported routes, including the existing reference profiles where relevant.

For each route, state:

* Whether it can express the complete relation.
* Missing implementation work.
* Available evidence for knowledge, privacy and post-quantum security.
* Expected bottleneck and supporting measurements.
* Required profile/manuscript changes.
* Whether it plausibly addresses the recorded KYC targets.

Keep computational feasibility separate from security justification.

Do not propose another proof attempt unless a specific change or new measurement could materially alter the previous admission decision. Repeating the unchanged configuration is not new evidence.

If considering acceleration or optimisation, identify the exact affected workload, dependency/hardware prerequisites and evidence of applicability. Do not assume GPU availability implies supported acceleration or sufficient memory.

**5. Select one next action with a stopping rule**

Recommend one bounded implementation or measurement package that resolves the most important uncertainty.

Specify its:

* Concrete deliverable.
* Required inputs and dependencies.
* Resource envelope.
* Success/failure criteria.
* Decision enabled by each outcome.

Leave any new limits or installations proposed and inactive.

If no evaluated route plausibly meets both the functional and security requirements within the intended performance envelope, say so explicitly. Identify the construction-level change requiring a research decision. Do not substitute more lifecycle infrastructure for the missing proof.

Do not require a favourable feasibility conclusion to mark this planning package complete.

**6. Deliver and stop**

Create `docs/stage3_auth_proof_feasibility_plan.md` containing the relation coverage table, evidence comparison, selected next action and unresolved security obligations.

Update status, traceability and issues. Preserve production code, active parameters, dependencies, manuscript and historical evidence.

Keep W3C mapping and durable-holder-storage gaps visible without expanding this package into those tasks.

Isolation remains safely stopped and unactivated. Stages 2–3 remain open. No proofs or zkVM executions; the proof ledger remains **two attempts used, one unused**.

Finish with a clear decision and the exact next package proposed for authorisation.
