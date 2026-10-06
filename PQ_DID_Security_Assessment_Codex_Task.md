# PQ-DID concrete security assessment: task for Codex

## Execution schedule and stage gates — 21 September 2026

This concrete-security assessment is a required part of the implementation programme. Its first pass is due during the current Stage 2–3 work; it must not be postponed until all services and benchmarks are complete. The schedule below records when to perform the applicable work. It does not assert that any assessment or security validation has already been completed.

**Next package:** perform `S2-CONCRETE-SECURITY-ASSESSMENT-1` after the current version-2 isolation activation attempt has safely completed or reached a documented stopped state. Confirm that no privileged workload remains active or uncontained before beginning the separate analysis package. If the isolation pilot remains blocked, its incomplete validation does not prevent this source-and-calculation assessment once the host state is safely settled. Carry out the initial assessment before the next substantial lifecycle integration package. Preserve the existing activation authorisation; this task does not expand or consume it.

| Stage / trigger | Required security work | Evidence and decision |
| --- | --- | --- |
| **Current Stages 2–3: initial assessment** | Execute the applicable work in Sections 1–10 below: establish the actual profile, review standard-component evidence and implementation deviations, reproduce the manuscript's concrete bounds, and assess existing alternative-backend evidence separately. | Versioned security report, analysis-only profile and reproducible calculations; per-property supported claims and explicit gaps. |
| **Stage 2: bounded key generation/signing and release integration** | Revisit randomness, sampler/signing caps, exhaustion behaviour, pre-release checks, invocation totals and `Delta_tail` when the relevant implementations become available. | Update DEP-001/DEP-002 evidence; close an obligation only when its particular implementation and analytical requirements are satisfied. |
| **Stage 3: before adopting or freezing a concrete proof profile** | Assess the selected proof mode, parameters, circuit/program identity, recursion/compression path, knowledge/soundness and zero-knowledge arguments, and quantum assumptions. Refresh affected calculations for each proposed change. | A documented profile decision. An engineering experiment may retain unresolved security questions, but must not inherit the original construction's theorems or an unsupported PQ/security-level claim. |
| **Stages 4–5: complete PQ-DAA and KYC integration** | Check the actual prover/verifier path jointly binds certification, holder secret, disclosed attributes and the certified revocation identifier; inspect public outputs and lifecycle freshness, replay and revocation conditions. Record side-channel and deployment assumptions. | Traceability to the implemented complete relation and relevant adversarial tests. Test adapters and local evaluators remain explicitly distinguished from real private authentication; successful tests do not replace security arguments. |
| **Stages 6–8: baselines, external comparisons and benchmarking** | Record the exact security profile, supported claims and assumptions for every comparator. Revisit multi-key/target effects, nonce counts and cap/failure aggregation using declared deployment workloads. Refresh the assessment when parameters, dependencies or proof modes change. | Comparable parameter choices and honest qualifications for differences. Benchmark trial counts must not silently replace the lifetime workload used in security bounds. |
| **Stage 9: reproduction and manuscript claims** | Reconcile the final implementation, parameters, workload assumptions, evidence and current primary security sources with Sections II–VIII and the claims made in the completed manuscript. | Reproducible final security accounting. Any unsupported overall bit-security claim remains omitted or explicitly qualified. |

### Persistent tracking and scope

When taking up this task in the WSL repository, record this schedule and its next trigger in the existing `docs/status.md`, `docs/traceability.md` and `docs/spec_issues.md`. Link the entries to this task and to the eventual `docs/stage2_concrete_security_assessment.md`. At each trigger, refresh only the affected findings and record the assessed revision, parameters and evidence; reuse unchanged evidence. Do not create a new security-review package for every unrelated infrastructure edit.

Keep **assessment completed with unresolved terms** distinct from **security claim justified**. A documented gap may permit further reference implementation or an explicitly labelled experiment, while preventing a claim of production readiness or a particular overall quantum security level. Completing the initial report does not automatically close Stage 2, Stage 3, DEP-001, DEP-002 or backend privacy/knowledge obligations.

A fresh lattice-estimator run is conditional on relevance, a justified problem mapping and an available isolated execution allowance. For unchanged standard ML-DSA-65, begin with FIPS 204 and appropriate primary security evidence, checking that the implemented bounded variant is accounted for. The historical `n=32, m=64` prototype is not the active construction. No default 80-bit floor or overall 128-bit quantum claim is adopted by this schedule.

Retain all resource and permission boundaries in the original task below. This scheduling addition does not authorise estimator installation, proof attempts, guest executions, profile changes or host activation, and does not borrow the isolation pilot's allowance. No timed or background automation is established by this document; execution and follow-up are tracked through the local Codex project workflow.

---

Continue in `/home/grace/projects/pq-did`.

Complete **S2-CONCRETE-SECURITY-ASSESSMENT-1**: assess the concrete security of the current PQ-DID construction and its implementation parameters, and determine which security claims the available analysis supports.

This package adds analysis, reproducible calculations and documentation. It does not authorise a change of cryptographic profile, a new proof experiment or deployment activation. Use UK English.

1. **Establish the authoritative profile and preserve existing work**

Read `AGENTS.md`, the implementation specification, parameter manifest, traceability, issue register, current status, agreed SPEC-001–004 decisions, relevant security/proof reports and manuscript Sections II–VIII. Resolve the actual locations from the repository. Record the manuscript version or digest and source revision used.

Only Sections II–VIII and explicitly agreed clarifications govern the construction. Preserve the manuscript, production source, active parameters, canonical encodings, dependencies and historical evidence. Do not infer current parameters from an older prototype or from Sections IX onward.

Distinguish these three objects throughout the report:

- The manuscript's specified reference construction.
- The code and cryptographic adapters actually implemented.
- Experimental or proposed alternative proof profiles.

The previously reviewed manuscript specifies ML-DSA-65, SHA3-384 holder binding, a depth-20 Merkle revocation tree and the BC-1 Boolean MPC-in-the-head profile with 480 repetitions. Verify these against the authoritative local files rather than treating this description as permission to overwrite a newer agreed specification.

The values `n=32, m=64` belong to the earlier prototype. Exclude them from the active profile unless current authoritative evidence expressly uses them. Preserve that prototype as historical evidence. Do not assign it a security level from those dimensions alone.

Keep CPU proving paused and the ledger at **two attempts used, one unused**. Launch no proofs, zkVM/guest executions, circuit-synthesis campaigns or cryptanalytic attacks. Read existing experiment evidence without repeating it. Preserve pending isolation/deployment work and its separate budgets. Do not create accounts, activate services or alter store permissions.

2. **Define precisely what a security level means**

Separate the following in every calculation and conclusion:

- A protocol security parameter such as `lambda=128`.
- Key, secret, nonce, salt, digest and proof lengths.
- A NIST security category for a standardised component.
- An estimated classical or quantum attack cost at a stated success probability.
- A theorem's bound on advantage, extraction error or operational failure at a specified resource budget.

Do not assume that 80 bits is a universal acceptable minimum, that a 128-bit label establishes 128-bit quantum security, or that Category 3 means exactly 128 quantum bits. Do not obtain quantum estimates by automatically halving classical estimates.

Extract any previously agreed system security target. If none is sufficiently precise, assess the current profile and propose a clearly labelled target definition in the report. Do not silently adopt a new target or block the remaining analysis while waiting for one.

Specify the attack-cost units, success criterion, classical/quantum memory and depth assumptions where relevant, number of targets, and permitted oracle access. Record `T_A`, `Q`, `N`, signing-query budgets, system-key counts, nonce counts and workload limits. Keep quantum hash queries separate from classical protocol/signing queries.

Describe estimator results as costs of modelled known attacks under their assumptions. They are not unconditional lower bounds against every attack. A security reduction provides a different kind of conditional evidence. Do not combine unrelated exponents by simply taking their minimum and calling it the scheme's security level.

3. **Create a component and assumption inventory**

For each component, record its role, exact parameters, source location, intended property, underlying assumption, implementation status, evidence and unresolved obligations. Include:

- Issuer, controller, registry, revocation and request signatures, including their domain separation.
- Holder-secret generation and binding.
- Credential encoding and the exact certified message.
- Merkle leaves, nodes, roots, identifier capacity and witness updates.
- Enrolment and authentication relations, circuit identity and proof encoding.
- Repetitions, challenge distribution, commitments, salts, proof nonce and proof hashes.
- Request/read nonces, trusted time, current-state ordering and challenge consumption.
- Bounded sampling, key-generation, signing and verification behaviour.

Trace the implemented relation to one consistent credential witness: valid issuer certification, correct holder binding, certified attributes matching disclosed values, and the same certified identifier in the non-revocation check. Identify test-only adapters or missing backends explicitly.

Keep operational assumptions separate from cryptographic strength. Correct signatures do not establish freshness, and larger keys do not repair replay or rollback failures. Describe the existing lifecycle evidence without expanding this package into another deployment implementation.

4. **Assess ML-DSA and determine whether lattice-estimator runs are needed**

Confirm whether the implementation uses standard ML-DSA-65 parameters, including the polynomial ring, module dimensions, modulus, distributions and signature bounds. Use FIPS 204 and relevant primary design/security sources. Cite the standard's Category 3 classification without assigning it to the complete PQ-DID scheme.

Check whether the project's bounded samplers, signing limits or pre-release verification change the connection to standard ML-DSA. Distinguish heuristic tail estimates, proven conditional bounds, total invocation counts and the unresolved sampling-model discrepancy. Do not set an unresolved `Delta_tail` term to zero for the real adaptive execution.

For lattice estimates, first identify the precise security problem and attack objective. Assess the relevant key-recovery and forgery problems, not merely a convenient LWE instance. For any custom lattice component actually in scope, trace the LWE/SIS or module/ring problem and bounds from its security reduction.

Document the complete estimator input:

- The meaning of each dimension, including ring degree and module rank where relevant.
- Modulus, distributions, available samples, and any rounding or public leakage.
- For SIS, the solution norm and bound derived from the relevant attack/reduction.
- The mapping from the structured problem to the estimator instance and attacks that this mapping does not cover.

Do not assume that an estimator preset named Dilithium3 exactly matches final ML-DSA-65. Verify the mapping. Do not present a generic flattened estimate as a complete analysis of possible structural attacks.

Inspect the pinned version of `malb/lattice-estimator`. Where applicable, use its supported LWE and SIS routines. Record the exact commit, Sage version, inputs, algorithms, reduction/shape models and cost units. Compare supported attacks and report the cheapest estimate within each consistently defined model. Report classical and quantum results separately. A quantum lattice-reduction model does not automatically make every surrounding attack step quantum-correct.

Check the difference between `estimate.rough` and the full estimator: their cost models may differ. Do not mix their outputs as if only search thoroughness changed. Record unsupported, failed and resource-limited cases rather than excluding them silently.

Run only a small, justified set of instances if an appropriate existing isolated environment and resource allowance are available. No dependency installation, upgrade, unrestricted sweep or parameter search is authorised. If a required environment/model is absent, prepare exact rerunnable inputs and commands, label them **not executed**, and complete the assessment using verified published evidence where applicable. An unchanged standard component can be assessed from appropriate published evidence; a fresh estimator run is not automatically necessary.

5. **Assess the non-lattice components**

Check the actual entropy and generation of holder secrets, salts and nonces. Explain any idealised quantum search or collision estimates with their assumptions, success probabilities and resource model. Account for multiple targets and repeated operations. Do not translate a byte length directly into a scheme-level security claim.

For SHA3-384 binding and the Merkle tree, identify whether the reduction needs collision, preimage or another property. Tree depth 20 defines identifier capacity, not 20-bit cryptographic security. Check canonical encodings and domain separation needed by the reductions.

Review the outer proof hash carefully. The specified 1024-bit SHAKE256 output length does not establish 1024-bit cryptographic strength or independently justify all bounds derived for an ideal 1024-bit random oracle. Record the actual SHAKE256 capacity and distinguish:

- The theorem proved in the ideal QROM.
- The assumption used to instantiate that oracle with the concrete hash.
- Any available quantitative justification or remaining gap.

Do not assume the ideal theorem is false merely because the concrete hash differs from an ideal oracle. Identify the exact scope of the theorem and the additional justification needed for concrete claims. Keep internal SHA3/SHAKE computations and the modelled outer oracle distinct.

6. **Check the concrete proof analysis and reproduce its bounds**

Read the actual proof protocol and Section VIII reductions. Verify the cited primary theorems and their hypotheses before substituting numbers. Check the applicable proof kind, challenge distribution, complete-witness extraction, adaptive statements, preservation of the target event and issuance/revocation history, classical external oracles, and online simulation across subsequent revocations.

Assess the argument as written. Do not assume that a theorem citation alone establishes compatibility, that a transcript alone permits extraction, or that the baseline repetition error is the final quantum soundness bound. If a claim requires specialist justification beyond the available evidence, identify the specific missing step.

Implement a small analysis-only calculator using the existing environment. Derive the formulas from the authoritative text, retain their provenance and check their numerical evaluation independently. Use exact arithmetic or sufficient precision and conservative rounding for claimed upper bounds.

Reproduce the manuscript's illustrative rows, including `Q=2^64` and `Q=2^80` with the stated proof count and workload assumptions. The previously reviewed text reports extraction-error bounds below `2^-148` and `2^-116`, and privacy bounds below `2^-150` and `2^-134`, respectively. Treat those values as claims to check, not expected outputs to hard-code. Record discrepancies without changing the source manuscript.

Evaluate the component advantages at the **reduction's** running time and query budgets. Do not insert an advantage estimated at `T_A` into a reduction whose runtime or signing workload is substantially larger. Include aggregation over system keys, nonce collisions and relevant cap/failure terms without double-counting them.

Preserve the meaning of each theorem. In particular, an extraction lower bound is not automatically an upper bound on authentication failure. Derive any additional conversion explicitly and justify its conditions.

Report authentication/certification, binding, revocation soundness, presentation privacy and historical privacy separately. Keep unresolved terms symbolic and name what evidence would instantiate them. Clearly distinguish the attacker budget, error probability and attack-cost estimate: `Q=2^80` does not mean 80-bit security, and an error bound `2^-116` does not mean 116-bit attack cost.

7. **Assess any alternative proof backend separately**

Use the repository's actual pinned backend version, configuration and existing receipts/logs. The reported successful RISC Zero enrolment receipt is evidence of that experiment. It is not evidence that the complete authentication relation has been proved or that the manuscript's proof theorems apply to the backend.

Identify the exact proof mode and complete verification path, including any recursion or compression layer. Check its documented soundness, knowledge and zero-knowledge claims, assumptions, hash parameters and quantum analysis. If an elliptic-curve or pairing-based wrapper occurs in the selected path, identify its effect on a post-quantum claim. Do not assume such a wrapper is present merely because the backend offers one.

Check what the public statement/journal reveals and how verification binds the intended program, suite, issuer instance, policy, context and revocation state. Report source-level findings separately from a full backend security audit.

Classify the candidate as supported under stated assumptions, unresolved, or incompatible with a specified claim. A transparent/STARK label or a verified receipt alone does not establish the required quantum knowledge and privacy guarantees. Do not transfer the 480-repetition BC-1 bounds to another backend, select a new backend or launch another experiment in this package.

8. **Produce a reproducible assessment and a bounded next decision**

Create:

- `docs/stage2_concrete_security_assessment.md`: the main report.
- `analysis/concrete_security/security_profile.json`: an analysis-only parameter, assumption and provenance record, separate from the active suite configuration.
- `analysis/concrete_security/security_bounds.py`: the bounded numerical calculator.
- Supporting estimator inputs, raw outputs and execution metadata in the repository's established evidence location. Do not overwrite previous runs.

Adapt new analysis filenames only if repository conventions require it, and record the final paths. The report must contain:

- The authoritative version and implemented/profile differences.
- A parameter/property/evidence matrix.
- Applicable lattice estimates or a precise explanation of why a new run was unnecessary or not executed.
- Reproduced proof bounds and any arithmetic or modelling discrepancies.
- Remaining assumptions, reduction costs, backend gaps and conditional terms.
- A separate conclusion for each security property, distinguishing demonstrated implementation behaviour from theoretical or heuristic evidence.
- Accurate wording suitable for the manuscript and monthly meeting.
- One bounded next package addressing the most important unresolved issue.

Answer explicitly: **Does the available evidence justify any stated overall classical or quantum security level for the current PQ-DID profile?** If not, state exactly which missing terms or arguments prevent the claim. Do not infer an attack merely because a reduction gives a weak bound, and do not infer security merely because no attack was found.

Identify proposed fixes without applying protocol changes. Resolve routine analysis choices autonomously. A blocked estimator or unavailable source should leave a clearly labelled gap while all unaffected work continues. Do not weaken the target, parameters or evidence requirements to obtain a favourable conclusion.

9. **Resource limits, validation and completion**

Before launching analysis subprocesses, record the applicable existing numerical limits for memory, runtime, process count and output. Reuse existing guards with no limit escalation or automatic retry after exhaustion. Do not borrow or reset the proof-attempt or isolation-pilot budgets. If no suitable estimator execution allowance exists, provide the prepared, unexecuted inputs and finish the source/numerical assessment.

Validate profile extraction, calculation domains, probability clipping and numerical upper bounds. Use a small number of meaningful independent checks. Run relevant lint/format and documentation/data checks. Reuse existing functional evidence for unchanged production code rather than rerunning unrelated campaigns.

Update status, traceability and issues with precise new evidence. Keep Stages 2–3 open wherever obligations remain. Do not close production-signing, proof-feasibility, recovery/isolation or security-review obligations merely because this report is complete.

Run the corrected preservation auditor under its unchanged **256 MiB ceiling**, retaining the original baselines, failed-run evidence and explicit change authorisations. Preserve unrelated work and report the exact authorised changes.

Finish with the assessed profile, supported claims, unresolved claims, calculations/estimator runs actually completed, resource measurements and the next bounded recommendation. State that no proof or zkVM execution occurred and that the proving ledger is unchanged.

10. **Primary starting sources**

Check versions and relevant errata, and record exact sections, theorem identifiers or commits used. Follow the manuscript's cited proof literature to the primary papers rather than substituting summaries.

- [NIST FIPS 204: ML-DSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- [NIST FIPS 202: SHA-3 and SHAKE](https://csrc.nist.gov/pubs/fips/202/final)
- [NIST PQC security evaluation criteria](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-%28evaluation-criteria%29)
- [Lattice Estimator source](https://github.com/malb/lattice-estimator)
- [Lattice Estimator documentation](https://lattice-estimator.readthedocs.io/en/latest/)
- [Keccak specifications summary](https://keccak.team/keccak_specs_summary.html)
- [RISC Zero source, if that candidate remains relevant](https://github.com/risc0/risc0)

Completion means a reproducible assessment with honest boundaries and an actionable result. It does not require manufacturing a single bit-security number when the available evidence cannot support one.
