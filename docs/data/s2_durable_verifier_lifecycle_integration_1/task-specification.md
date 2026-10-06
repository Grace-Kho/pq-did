Proceed with **S2-DURABLE-VERIFIER-LIFECYCLE-INTEGRATION-1** in `/home/grace/projects/pq-did`.

Integrate the existing verifier reference model with durable authority storage and authenticated revocation-state interfaces. Use two independent verifier instances, synthetic credentials and isolated stores.

**1. Budget amendment**

I authorise 24 additional focused test invocations, increasing the cumulative ceiling from **148 to 172**. With 145 consumed, **27 remain**, including failures and repeats. Count parameterised cases individually.

Preserve the remaining **214.398 seconds** of the cumulative implementation allowance, subject to the current ledger. Preserve all existing memory, process, storage and command limits, including the **256 MiB preservation-audit ceiling**.

Do not reset counters or borrow from analysis/isolation budgets. Reserve sufficient time for cleanup and required evidence.

**2. Establish the verification and acceptance contract**

Read the existing verifier state model, durable challenge-consumption implementation, recovery/fencing contracts, manager retrieval interfaces and current specification.

Only manuscript Sections II–VIII and agreed clarifications are authoritative.

Map the integration sequence for:

* Stored verifier challenge and presentation context.
* Audience, nonce, policy, instance and strict expiry checks.
* Authenticated revocation-state reads and the specified freshness rule.
* Proof verification.
* Durable one-time challenge consumption.
* Release of the acceptance result.

Identify the exact acceptance commit point and recovery behaviour. Preserve the existing treatment of failed presentations and challenge consumption; do not invent a new policy.

**3. Implement two independent reference verifiers**

Give each verifier its own audience identity, challenge namespace and durable store. Preserve trusted configuration and writer fencing.

Ensure that:

* Presentation inputs match the stored challenge context.
* Public disclosures and policy checks use existing canonical modules.
* State authentication and freshness checks use the established contracts.
* Normal proof verification remains fail-closed.
* Acceptance cannot be released before durable one-time consumption commits.
* Concurrent submissions cannot produce two distinct successful acceptances for one challenge.
* Restart preserves consumption records and prevents replay.
* Any permitted redelivery returns the existing committed outcome under the established authorisation rules, without creating another acceptance event.

Do not introduce a hidden-holder-DID lookup or a persistent holder authentication key into anonymous verification.

**4. Preserve the proof and freshness boundaries**

Positive tests may explicitly inject the existing narrowly scoped synthetic proof adapter. Ensure ordinary configuration cannot enable it accidentally.

A synthetic proof-acceptance result does not establish credential authenticity, holder knowledge or private non-revocation. Keep those limitations explicit.

If testing revoked credentials through a real local relation evaluator, identify that evaluator separately from remote proof verification.

Apply the specification’s freshness semantics to concurrent revocation and verification. State the relevant observation/commit points; do not claim globally atomic revocation and acceptance across separate services.

**5. Validate the integration risks**

Prepare a compact matrix within the invocation allowance. Prioritise:

* Successful acceptance at each verifier using its own challenge.
* Wrong audience and cross-verifier presentation reuse.
* Replayed and concurrent submissions to the same challenge.
* Strict expiry boundary and stored-context mismatch.
* Stale, unauthenticated or inconsistent revocation state.
* Proof rejection and verifier-storage failure.
* Interruption before the acceptance commit.
* Interruption after commit but before response.
* Recovery preserving consumption and any authorised outcome redelivery.
* Stale-writer fencing and inconsistent recovery evidence.

Use controlled process crashes only where they resolve a new persistence boundary. Distinguish crash evidence, injected failures, local relation checks and synthetic proof outcomes.

Reuse completed component tests. Do not retry failures automatically or rerun historical suites without a specific integration-related reason.

**6. Record evidence and stop**

Create `docs/stage2_durable_verifier_lifecycle_integration.md` documenting the two-verifier configuration, acceptance commit point, freshness semantics, individual outcomes, crash/recovery evidence and proof limitations.

Update status, traceability and issues. Complete required lint, formatting and preservation checks within the limits.

Preserve manuscript, active parameters, dependencies and historical evidence. No host activation, installations, proofs or zkVM executions. Isolation remains safely stopped and unactivated.

Stages 2–3 remain open. Production-security obligations, adaptive Delta_tail and complete proof knowledge/privacy remain unresolved. The proof ledger remains **two attempts used, one unused**.

Report cumulative resource consumption and recommend one next package without starting it. Identify how that package advances the remaining KYC lifecycle, rather than adding general infrastructure.
