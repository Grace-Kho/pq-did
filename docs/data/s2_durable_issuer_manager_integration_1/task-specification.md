Proceed with **S2-DURABLE-ISSUER-MANAGER-INTEGRATION-1** in `/home/grace/projects/pq-did`.

Integrate the existing durable manager and issuer reference components using synthetic credentials, isolated stores and bounded signing. Validate issuance and recovery across their separate transaction boundaries.

**1. Budget amendment**

I authorise 24 additional focused test invocations, increasing the cumulative ceiling from **124 to 148**. With 121 consumed, **27 remain**, including failed cases and repeats. Count parameterised cases individually.

Preserve the remaining **251.286 seconds** of the cumulative implementation allowance, subject to the current ledger. Preserve existing memory, process, storage and command limits, including the **256 MiB preservation-audit ceiling**.

Do not reset counters or borrow from analysis/isolation budgets. Reserve time for cleanup and required evidence.

**2. Reuse the established issuance contracts**

Read the issuance/enrolment reference model, durable issuer and manager components, signing adapters, recovery admission and interrupted-issuance reconciliation design.

Only manuscript Sections II–VIII and agreed clarifications are authoritative.

Map the integrated transitions, identifying:

* Which service owns each durable fact.
* Each local transaction boundary.
* The checks required before advancing.
* Recovery behaviour after each interruption point.

Preserve permanent identifier reservation, issuer/enrolment checks, certification logging before release and atomic holder acceptance.

Use the existing reconciliation design. Do not imply a single atomic transaction across separate stores or introduce a new distributed protocol without identifying the necessary specification change.

**3. Implement the isolated integrated path**

Connect the existing components through their reference interfaces.

Require:

* Trusted role/key/instance selection and existing authorisation.
* Binding of reservation, enrolment statement, credential fields and recipient to the same issuance operation.
* Permanent reservation despite later abort or interruption.
* Durable certification/outcome recording before release.
* Fencing and expected-state checks at relevant commits.
* Recovery that reconciles durable evidence and fails closed when evidence is insufficient.
* Redelivery of committed bytes without resigning or allocating another identifier.
* Holder acceptance only after the established credential and context checks.

Check how intervening manager-state changes affect an in-flight issuance under the existing specification. Do not infer current non-revocation solely from an earlier reservation.

**4. Preserve the proof boundary**

Real enrolment-proof verification remains incomplete. Keep the normal proof adapter fail-closed.

For positive integration cases, use an explicitly injected test-only proof adapter with narrowly defined synthetic inputs. Ensure it cannot be selected accidentally through normal configuration.

Label results as lifecycle integration with synthetic proof acceptance. Do not report complete PQ-DAA, anonymous authentication or end-to-end cryptographic security.

**5. Validate cross-service failure and recovery**

Prepare a compact matrix within the available invocation allowance, covering:

* Successful issuance and holder acceptance.
* Interruption after reservation but before certification.
* Interruption after durable certification but before delivery.
* Recovery and exact recipient-bound redelivery.
* Duplicate requests and conflicting reuse of an operation identifier.
* Wrong recipient, instance or mismatched reservation/credential fields.
* Stale writers and inconsistent recovery evidence.
* Relevant intervening revocation/state changes.
* Rejected proof, signing failure and required commit failure.

Reuse completed primitive, signer and manager tests. Add only checks needed for the integration boundary.

Use controlled process crashes selectively where they resolve an untested persistence boundary. Distinguish them from injected exceptions. Preserve the limits of crash evidence: no power-loss or whole-store rollback guarantee.

Do not retry failures automatically.

**6. Deliver evidence and stop**

Create `docs/stage2_durable_issuer_manager_integration.md` with the transition/ownership matrix, transaction boundaries, proof-adapter limitations, individual test outcomes, recovery evidence and remaining obligations.

Update status, traceability and issues. Preserve manuscript, active parameters, dependencies and historical evidence. Complete required lint, formatting and preservation checks within the limits.

Do not activate services, modify host resources, install dependencies, generate proofs or execute zkVM guests. Isolation remains safely stopped and unactivated.

Stages 2–3 remain open. Production custody, entropy assurance, erasure, side channels, adaptive Delta_tail and complete proof knowledge/privacy remain unresolved. The proof ledger remains **two attempts used, one unused**.

Report cumulative resource consumption and recommend one next package, without starting it.
