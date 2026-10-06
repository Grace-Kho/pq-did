Proceed with **S2-KYC-INTEROPERABILITY-CONTRACT-1** in `/home/grace/projects/pq-did`.

Define implementation-ready application and data-container boundaries for the connected reference KYC lifecycle. Produce contracts and synthetic examples; do not deploy services or introduce a new proof profile.

**1. Preserve scope and budgets**

Only manuscript Sections II–VIII and agreed clarifications are authoritative for the scheme. Use primary W3C specifications for interoperability requirements, recording their exact versions and relevant sections.

Reuse the current KYC checklist and completed integration evidence.

Preserve the cumulative limits:

* **194/199 test invocations consumed: five remain.**
* **121.296 seconds** of implementation allowance remain, subject to the current ledger.
* Existing memory/process/storage limits, including the **256 MiB preservation-audit ceiling**.

No additional test allowance is authorised. Count validation cases transparently; do not conceal additional cases inside aggregate tests. Reuse completed lifecycle validation and stop with explicit gaps if the package cannot fit.

**2. Define the external-to-internal mapping**

Cover issuer, holder wallet, both verifiers, DID registry/resolver and revocation service.

For each exchanged object, record:

* Producer, consumer and purpose.
* Required fields, types, bounds and canonical internal representation.
* Authorisation and instance-binding requirements.
* Which fields are cryptographically authenticated or proved.
* Which fields are unauthenticated application metadata.
* Error, retry and redelivery semantics inherited from the existing implementation.

Include issuance, presentation request, presentation submission, verification result, DID resolution, authenticated revocation state and witness-update retrieval.

Reuse existing protocols and encodings. Do not replace binary signed messages with JSON signatures or introduce new signed fields silently.

**3. Establish an honest W3C compatibility profile**

Map the design to DID Core and VC Data Model 2.0, distinguishing:

* Applicable standard requirements.
* Project-specific extensions.
* Requirements not yet implemented or validated.

Specify the proposed representation of issuer identity, credential subject, disclosed claims, status references and presentation context.

Identify the securing-mechanism specification still needed for the project’s credential/presentation format. Do not invent a registered cryptosuite, DID method, key encoding or status mechanism.

Do not label a synthetic proof placeholder as a valid secured VC/VP.

If a required mapping would change the certified message, authentication relation or privacy model, record a specification issue and leave it proposed. Do not alter the active scheme to obtain apparent conformance.

**4. Preserve privacy at the application boundary**

Separate the holder’s private credential/witness container from the verifier-facing presentation.

Ensure presentation examples do not expose hidden attributes, holder secret, credential signature, revocation identifier, Merkle path or persistent holder identifier unless explicitly required by the existing disclosure contract.

Check for stable identifiers and metadata that could correlate presentations across the two verifiers. Record unavoidable/public leakage under the manuscript’s restrictions.

Preserve issuance-time DID authorisation separately from anonymous presentation. Do not introduce hidden-DID resolution or persistent holder-key authentication into the anonymous path.

Define expiry conversion carefully: preserve the internal unsigned POSIX-seconds representation and strict acceptance rule. Do not relabel verifier/session expiry as credential expiry unless the specification actually defines it that way.

**5. Produce concrete examples and a bounded validation plan**

Provide synthetic examples for the principal objects, clearly marking:

* Private holder-only content.
* Public authenticated content.
* Disclosed presentation content.
* Synthetic proof placeholders and their non-verifying status.

Define the proposed transport encoding of binary fields, parser limits, handling of duplicate/unknown fields and failure behaviour. Keep proposed conventions distinct from already agreed conventions.

Use the remaining validation allowance only for meaningful contract/example consistency checks. Do not claim full W3C conformance from schema validation or round-trip conversion alone.

**6. Deliver and stop**

Create `docs/stage2_kyc_interoperability_contract.md` and a small machine-readable example set in an appropriate project location.

Update status, traceability and issues. Include an implementation checklist with concrete acceptance criteria for the next adapter package.

Keep durable holder storage, real proof integration and unresolved security obligations visible. Do not expand this package into general infrastructure or another broad cryptographic review.

Preserve production code, active parameters, dependencies, manuscript and historical evidence. Complete required lint/format and preservation checks within the limits.

No installations, host activation, proofs or zkVM executions. Isolation remains safely stopped and unactivated. Stages 2–3 remain open; the proof ledger remains **two attempts used, one unused**.

Report the supported compatibility claims, proposed conventions, unresolved mappings, remaining resources and one recommended next implementation package.
