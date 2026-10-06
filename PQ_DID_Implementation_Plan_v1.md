**PQ-DID implementation and benchmarking plan — version 1**

Prepared for Kho Yun Xing (Grace), 14 September 2026. Working specification: *PQ_DID__TIFS revision V3.pdf*, particularly Sections III–VIII and the concrete algorithms on pp. 14–17. Language: UK English.

**Recommendation: begin implementation with an executable relation and circuit-feasibility study.** The issuer, wallet, verifiers, registry, resolver, revocation service and ML-DSA baseline are credible engineering targets on the supplied computer. Successful execution of the full V3 proof, at useful latency and communication cost, remains unvalidated. That is the main project risk and the first substantial decision point.

This document is a plan. No scheme code, circuit, library build or performance benchmark was executed for this assessment. Repository and documentation availability were checked; compatibility with the eventual pinned environment still needs testing. The earlier BDLOP/LNP prototype and its 4,677-byte token do not measure the current MPC-in-the-head construction.

The intended deliverable is a reproducible research implementation suitable for evaluating the manuscript's claims. The KYC example uses synthetic records and demonstrates credential workflows; it does not establish that a bank's legal or operational KYC obligations have been satisfied.

The work will be tracked through the following stages. A stage becomes complete only when its stated evidence exists; writing its code is insufficient by itself.

| Stage | Work and dependency | Evidence required to complete the stage | Current status |
|---|---|---|---|
| 0 | Assess V3, libraries, hardware and evaluation scope | This referenced implementation plan and initial risk assessment | Complete |
| 1 | Freeze the implementation contract and development environment | Versioned parameter manifest, encoding examples, algorithm-to-code/test mapping, W3C representation design and environment lock | Next |
| 2 | Build the executable cryptographic relations and native primitives; depends on 1 | Valid and invalid enrolment/authentication vectors, native-library cross-checks, exact bounded-operation behaviour | Planned |
| 3 | Generate BC-1 circuits and implement a minimal complete proof pilot; depends on 2 | Per-component gate counts, circuit-generation time, size projection, peak memory and a full-parameter proof/check run if resources permit | Planned; critical feasibility gate |
| 4 | Complete and validate the PQ-DAA module; depends on a successful 3 | Enrolment, certification, fresh presentations and stateless proof verification, with all private checks bound together | Planned |
| 5 | Integrate the W3C KYC lifecycle; final integration depends on 4 | Issuance, independent verifier A/B sessions, revocation, local witness updates, current-state checks and conformance evidence | Planned |
| 6 | Implement and integrate the persistent-key ML-DSA baseline; can begin after 1 | The same workload and services using issuer and holder signatures, with verified credential-to-key binding | Planned |
| 7 | Reproduce external comparators; build checks can begin after 1 | Pinned source, successful original tests, documented operation/parameter mappings and rerun measurements | Shortlist identified; execution planned |
| 8 | Complete adversarial tests and controlled performance experiments; depends on 4–7 as applicable | Correct rejection/acceptance outcomes, raw measurements, resource limits, statistical summaries and failure counts | Planned; relevant tests start in 2 |
| 9 | Package reproducibility artefacts and replace the evaluation section; depends on 8 | Reproduction instructions, code/dependencies, synthetic workloads, raw data, figures and manuscript consistency check | Planned |

Service skeletons, revocation data structures and the local baseline can progress while the proof is investigated. Full benchmark integration waits for the proof gate. No completion date for the whole project is defensible before Stage 3 establishes the circuit and proving workload.

**Stage 1 freezes exactly what will be implemented.** Use the current suite name `PQ-DID-MITH-1` and circuit profile `BC-1`. Record the V3 file/version or digest alongside the implementation version. Preserve the current reference profile:

| Item | V3 requirement |
|---|---|
| Issuer and service signatures | August 2024 FIPS 204 ML-DSA-65; role-specific external contexts and fresh hedging randomness |
| Hash-based holder binding and revocation | SHA3-384, including the specified domain tags and encodings |
| Outer proof hash | SHAKE256 with a 128-byte output, using V3's commitment/challenge encodings |
| Holder secret | 32 bytes; distinct from DID controller keys |
| Attribute encoding | Fixed 1,024-byte canonical encoding; 2–16 fields subject to V3's capacity constraints |
| Revocation tree | Depth 20; at most 2^20 allocated identifiers; identifiers are never reused |
| Authentication witness | 32-byte secret, 1,024-byte attributes, 4-byte identifier, 3,309-byte issuer signature and 960-byte path; 42,632 bits in total |
| Enrolment witness | 256 bits |
| Proof protocol | 480 three-view repetitions; raw tapes/opened views, specified salts, challenge derivation and exact parsing |
| Circuit generation | BC-1 operand/gate order, checked arithmetic, bounded loops, private-index handling and permitted public constant folding |
| Security claim | Preserve Section VIII's component, QROM, bounded-operation and service qualifications; the parameter name lambda=128 is not a complete 128-bit security calculation |

ML-DSA has current standard and implementation resources, but the manuscript-specific caps must be checked separately. NIST's FIPS 204 page also lists potential errata: record which specification text and corrections are followed and resolve any relevant differences explicitly. [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)

Define immutable canonical encodings for the schema, issuer/key instance, namespace, state, context, credential and proof. Reject duplicate or unknown critical fields, wrong lengths/tags/types, non-zero padding, trailing bytes and inconsistent repeated instance fields. Maintain the exact distinction between external protocol byte order and FIPS internal byte order. Include accepted and rejected examples that can be used by every language binding.

Freeze a synthetic KYC schema within the existing limits. Suitable claims include `kycPassed`, `assuranceLevel`, `countryOfResidence` and `validUntil`, alongside the required issuance-time DID/version and optional identity details that remain hidden. Verifier A can request KYC status and assurance level; verifier B can request KYC status and country. Their approved disclosure masks and policies are distinct. Treat `kycPassed` as an issuer-certified claim. For expiry, any relied-upon validity value must be certified and checked under the disclosed-field policy. V3 does not provide arbitrary predicates over hidden attributes: for example, an undisclosed birth date cannot silently become a hidden age-range proof.

Create a traceability record for each requirement with fields: manuscript location, algorithm, implementation module, test, measurement and status. Select operational timeouts and resource budgets before full experiments, then retain them in the run manifest. If a proof cannot finish within an application deadline, report the failure rather than silently extending the deadline in the measured run.

**Useful open-source components can reduce the work substantially, but none checked here supplies the complete V3 construction.** The initial stack should keep orchestration in Python and the large cryptographic/circuit workload in native code.

| Component | Candidate and what can be reused | Integration decision or limitation |
|---|---|---|
| Native ML-DSA | [liboqs](https://github.com/open-quantum-safe/liboqs), its [Python binding](https://github.com/open-quantum-safe/liboqs-python), and upstream [mldsa-native](https://github.com/pq-code-package/mldsa-native) | Preferred starting family for ordinary signing/verifying, test vectors and native code. Select one pinned backend for both local systems. Confirm external-context support in the selected binding. V3's sampling/signing caps may require an instrumented adapter or a narrowly modified source implementation. |
| Independent ML-DSA cross-check | [Python cryptography ML-DSA API](https://cryptography.io/en/47.0.0/hazmat/primitives/asymmetric/mldsa/) | Provides ML-DSA-65 and context-aware signing/verification. Useful as a separate interoperability check where the installed backend supports it. Seed-form private-key storage must not be confused with the expanded secret-key size in V3. |
| SHA3/SHAKE | [XKCP](https://github.com/XKCP/XKCP) and the selected native hash backend | Reuse ordinary hash implementations and reference vectors. The private-input SHA3/SHAKE computations also need actual Boolean-circuit implementations. Calling an external hash API is not a substitute for their constraints. |
| Related MPC-in-the-head code | [Generalized ZKB++](https://github.com/isec-tugraz/gzkbpp) | Offers an exchangeable inner-circuit design and shared/direct evaluation examples. Treat it as a reference for reusable mechanisms. Its default protocol, fields, compression and transcript must not be assumed to match V3. |
| Circuit compiler research | [HyCC](https://github.com/stskeeps/HyCC) | Useful for studying C-to-circuit compilation and exploratory cost comparisons. It targets optimised hybrid MPC circuits; its output is not automatically V3's deterministically specified BC-1 circuit. A faithful BC-1 emitter or justified profile revision is still required. |
| W3C object handling | [Digital Bazaar vc](https://github.com/digitalbazaar/vc) and the [VC Data Model 2.0 test suite](https://github.com/w3c/vc-data-model-2.0-test-suite) | Evaluate adapters and test tooling. The vc README describes older data-model support, so do not assume complete VC 2.0 conformance from dependency selection alone. A PQ-DAA securing mechanism and status mapping remain custom work. |
| Testbed services | [FastAPI](https://fastapi.tiangolo.com/), with separate process state and a transactional database | A reasonable Python API layer for the issuer, wallet interface, verifier services and registry/status endpoints. Run proving in native worker processes so long proofs do not block request handling. |
| Alternative proof research | [LaZer](https://github.com/lazer-crypto/lazer) | Provides a native lattice-proof library, Python interface and anonymous-credential demo. Useful for comparison and a possible redesigned concrete instantiation. Its demo is not the complete ML-DSA/SHA3/Merkle authentication relation. |

The standard signature libraries reduce implementation effort outside the proof. They do not automatically turn ML-DSA verification into a zero-knowledge proof about a hidden signature and hidden attributes. Equally, an existing Boolean proof library does not automatically provide the exact circuit, serialisation and QROM theorem instantiation used by the paper. Reuse is therefore component-level, with explicit validation of each boundary.

The earlier `pqcrypto` dependency should be checked by exact package/version/source before reuse. Its old behaviour cannot be inferred from today's similarly named packages. PQClean itself is now archived, which is an additional reason to evaluate maintained native sources for the new implementation. [PQClean retirement notice](https://github.com/PQClean/PQClean)

**Stage 2 builds an executable relation that becomes the correctness reference.** It should check, for the same witness, all of the following: a valid issuer signature over the certified holder binding, attributes and revocation identifier; correct recomputation of that binding from the holder secret; equality between the certified attributes and disclosed values; and a zero-leaf Merkle path for that same certified identifier under the public root. Include every private encoding/range check needed to make those equations meaningful.

Bind the complete public statement—including issuer/key/schema, namespace, revocation reference, audience, session, nonce, expiry, policy and disclosures—into the proof transcript exactly as V3 specifies. Signature/state authenticity, issuer trust, disclosed-value policy evaluation, request authentication and final freshness/replay checks remain in their specified public/lifecycle positions. The complete system verifies them in addition to the private relation.

Implement and test the enrolment relation too: possession of the holder secret must match the binding that the issuer certifies. Issuance must preserve holder approval, controller authorisation, fresh issuer nonce, current DID/state rechecks, permanent identifier allocation and the specified abort behaviour. Cross-check the native capped verifier against standard-library results on admissible cases. Use deliberately instrumented boundary cases for cap exhaustion; ordinary random tests will not reliably reach extremely rare sampler failures.

A reference evaluator is allowed to see its local test witness. The verifier service must not receive that witness, the complete credential, the holder binding, hidden attributes or the revocation path merely to run the evaluator. The real presentation verifier receives only the specified public inputs and proof.

**Stage 3 establishes whether the concrete proof is executable and useful.** Implement circuit gadgets progressively: checked arithmetic and selectors; canonical parsing; SHA3/SHAKE; the enrolment relation; ML-DSA verification; the revocation path; and finally the complete authentication relation. Compare circuit evaluation against the reference evaluator for valid and adversarial inputs. Check deterministic circuit generation from public inputs. Never accept a circuit chosen by the prover.

BC-1 is unusually restrictive: it specifies 64-bit checked arithmetic, wider intermediate products, fixed-capacity loops and only fully public constant folding. A compiler that changes to smaller arithmetic, reorders gates, eliminates repeated private computations or removes partially constant operations may preserve the mathematical relation but would implement a different circuit profile. Document such a change, its new gate counts and its impact on Sections VII–VIII before using it as the manuscript's implementation.

Measure circuit-generation time on both prover and verifier paths, total gates, AND gates, wire/liveness storage, compiled-circuit bytes and peak resident memory. Distinguish fresh statements from genuinely reusable cached components; a changed public root, schema or disclosure can change the generated circuit. Public matrix computations can be cached only where the exact specification and instance permit it, and cache construction/storage costs must be recorded.

For V3 authentication, the exact raw proof-length rule is:

\[
|\pi|=64+480\left(515+2\left\lceil\frac{42632+2g}{8}\right\rceil\right)
=5,363,104+960\left\lceil\frac g4\right\rceil\ \text{bytes},
\]

where `g` is the authentication circuit's AND-gate count. The following are calculated scenarios, not generated gate counts or timings. MB and GB use decimal units.

| Assumed AND gates | Raw proof size | Implication |
|---:|---:|---|
| 0 | 5.36 MB | Algebraic size floor; not a realisable complete authentication circuit |
| 1,000,000 | 245.36 MB | About 19.6 seconds of payload transfer alone at 100 Mbit/s, before overhead or computation |
| 10,000,000 | 2.41 GB | A single proof already creates substantial bandwidth, storage and memory pressure |

Initially profile component circuits and a small number of repetitions for diagnosis. Label those runs as development measurements. Passing the cryptographic feasibility gate requires at least one valid enrolment proof and one complete authentication proof using the final 480-repetition profile, together with rejecting modified/invalid instances, within documented resource limits. If synthesis itself cannot finish, record the last completed component and its measured or rigorously counted lower bound; do not present extrapolation as a completed circuit.

As an initial desktop resource policy, keep one prover worker and leave several GiB for the OS and services. An approximately 8 GiB peak budget for the cryptography process is a planning starting point, subject to actual free memory and the WSL/VM limit. Set a scratch-space budget before producing proofs. Counted size admission in V3 is not a practical memory guarantee.

There are two separate decisions after this gate: whether the specified proof can execute at all on available resources, and whether its measured time/bytes support the intended KYC use case. Execution alone does not establish practical interactive performance. Under frequent state changes, long proving time can also cause repeated rejection of otherwise valid holders because their challenge references an older root. This must be measured later rather than hidden by a weaker freshness rule.

If the gate fails, preserve the completed executable relation, lifecycle interfaces and service work. Investigate a new concrete proof/circuit profile, then revise VII and the affected VIII analysis. LaZer or a STARK implementation are candidates to investigate, not validated replacements. Check the complete relation, all hashes/commitments, quantum security argument, leakage and parameter accounting. Seeded tapes, different commitment/challenge encodings, fewer repetitions, a different credential signature or a smaller tree are changes that require explicit specification and security review.

Reducing peak memory through a faithful storage/scheduling implementation may be possible without changing the transcript, but must preserve exact distributions and verification behaviour. For example, retaining raw views temporarily on disk changes the resource profile; report that I/O. It does not remove proof communication costs. Do not replace the raw-view format with a seeded format and claim to have benchmarked V3 unchanged.

**Stage 4 completes PQ-DAA as a module with a small, reviewable interface.** Expose setup, enrolment, certification, presentation and stateless proof verification as specified by Sections IV–V. Preserve issuer/holder input separation and witness confidentiality. Use fresh proof randomness for every attempt and prevent reuse/reopening of committed views under another challenge. Register the suite and circuit identity with each run and test vector.

The acceptance evidence must include a mix-and-match test: a valid signature from one credential combined with another credential's holder secret, disclosures, revocation identifier or path must fail. Four unrelated checks on four unrelated records would not implement the jointly bound authentication relation. Passing the module tests is also distinct from the later lifecycle checks for current state and one-time challenges.

**Stage 5 builds the end-to-end KYC testbed around that module.** Start with processes or containers on one machine; separate roles do not require six physical computers.

| Role | Responsibility | Required separation and behaviour |
|---|---|---|
| Credential issuer | Synthetic evidence approval, enrolment checks, certification and authorised revocation requests | Issuer key and approval records; never needs the holder secret |
| Holder wallet | Secret/controller keys, credential storage, user-approved disclosure, proving and witness updates | Hidden material remains local; verifier receives only authorised public content and proof |
| Verifier A | Authenticated requests, policy A and acceptance decisions | Its own audience, request key, pending challenges and session state |
| Verifier B | Authenticated requests, policy B and acceptance decisions | Separate audience, request key and state; tests sharing of their observed transcripts |
| DID registry and resolver | Signed method records, current/historical reads, publication, rotation and deactivation | Atomic append-if-current and authenticated nonce-bound resolution responses |
| Revocation service | Permanent allocations, depth-20 state tree, authorised revocations and public updates | Atomic state transitions and authenticated ordered current-state responses |

Keep DID controller keys in validated method records as V3 specifies. The anonymous holder document remains minimal. Verifiers must not resolve a hidden holder DID to complete an anonymous presentation. If an explicitly approved policy discloses the DID/version, run the configured resolution checks and acknowledge that disclosure's linkability. DID deactivation and credential revocation are separate operations.

Run at least these successful lifecycle demonstrations: issuance and presentation to A; a fresh presentation of the same credential to B; another fresh presentation to A; revocation of a different credential followed by local witness update and successful presentation; and rejection after revocation of the presented credential. Also exercise interruption/recovery for issuer nonce retirement, pending DID publication and committed revocation retrieval.

A credential issued in an earlier epoch is not automatically stale or invalid. An unrevoked holder updates its witness, obtains a request referencing the current state and reuses its original credential. A stale presentation or witness must fail against a newer required state. A revoked holder must fail after attempting an update too. This distinction is essential to demonstrating the claimed lifecycle.

Verifiers make the final authenticated current-state read specified in V3, match its reference to the pending context and atomically consume the challenge. Replicas of the same verifier share that atomic state. Signed old roots are not evidence of freshness. In race tests, record the state-read order: acceptance before a subsequent revocation is permitted by V3's logical verification epoch; accepting an older root after the newer state has been ordered before the final read is not.

The W3C target should be DID Core 1.0 and VC Data Model 2.0, with a documented experimental PQ-DAA securing mechanism and status extension. Define the VC/derived presentation fields, media types, extension contexts, proof validation and a deterministic mapping to the signed/proved bytes. A JSON wrapper alone does not establish conformance. Ensure every application claim used for acceptance is cryptographically bound; test alterations to the external JSON as well as the internal encoding. Do not expose the original credential's stable signature, binding, identifier or status path in the derived presentation. [DID Core 1.0](https://www.w3.org/TR/2022/REC-did-core-20220719/), [VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)

Run applicable official data-model tests through an adapter and publish which requirements pass, fail or are outside the test coverage, supplemented by tests of the custom proof/status mechanism. The W3C Quantum-Resistant Cryptosuites document is a Working Draft; using it as a baseline reference does not standardise PQ-DAA or imply support in existing wallets. [VC 2.0 test suite](https://github.com/w3c/vc-data-model-2.0-test-suite), [Quantum-Resistant Cryptosuites draft](https://www.w3.org/TR/2026/WD-vc-di-quantum-resistant-1.0-20260616/)

Implement the manuscript's authenticated confidential issuance channel and authenticate service/request messages. Record the actual channel configuration and its trust assumptions. Credential-layer PQ security does not by itself establish PQ confidentiality or authentication of every network channel. A local deployment demonstrates the assumed registry/current-state services; it does not measure distributed consensus or prove real-world authority independence.

**Stage 6 builds the local ML-DSA baseline, which remains useful even when external PQ-SSI code exists.** It controls the common software and workload, making the incremental cost of the chosen anonymous flow easier to assess.

1. Generate a persistent holder authentication key, publish it through the baseline DID method and use ML-DSA-65 for both issuer and holder signatures.
2. Have the issuer sign the same approved attribute vector and revocation identifier, together with an unambiguous binding to the holder authentication key and the relevant DID/version. Signing only an unrelated credential is insufficient holder binding.
3. Present the complete signed credential and a fresh holder signature over the credential digest and full context, including audience, nonce, session, policy, expiry and required revocation-state reference.
4. Verify issuer certification, certified holder-key binding, holder signature, policy, current status and the same challenge-consumption rules. Use the common tree/state service with a publicly checked identifier/path, so status freshness remains comparable.

Here “ML-DSA-only” means a signature-based credential authentication baseline without PQ-DAA; hashes and status data structures are still needed. Ordinary signature-only presentation does not allow arbitrary removal of signed attributes. This baseline discloses the signed credential and is linkable through its persistent holder key and credential data. If a separate redactable/disclosure baseline is later added, describe it as a distinct construction.

| Control | How to keep the local comparison fair |
|---|---|
| Signature and hash parameters | Same ML-DSA-65 implementation/flags for shared operations, same hash family and explicit failure/cap policy |
| Application task | Same synthetic claims and acceptance policy; report the different amount of information disclosed |
| Services | Same registry, issuer trust, status freshness, database persistence, request authentication and network settings where semantically shared |
| Resource allocation | Same machine, CPU allocation, process limits, timing definitions and concurrency |
| Measurement boundary | Report primitive cost, circuit generation, proof/signature computation and full flow separately |
| Optimisation | Disclose library/native backend, cache state, batching, threading, precomputation and retained state |

This measures the aggregate overhead of the selected PQ-DAA design over the persistent-key design. It does not individually identify the cost of anonymity, selective disclosure, unlinkability and private revocation, and it does not establish a universal “cost of privacy”. Use subcircuit gate accounting and profiling to locate contributions. Optional reduced-relation experiments must be labelled as diagnostic variants with reduced guarantees. Sharing ML-DSA-65 parameters does not make the complete constructions' security levels or adversarial models identical.

**Stage 7 adds external comparisons at the operation level.** Prioritise one SSI implementation and one anonymous-credential implementation before broadening the set. Availability below means source/documentation was located, not that the build or all claimed features were independently validated.

| Priority and implementation | Overlapping operations to investigate | What must be kept distinct |
|---|---|---|
| Primary SSI: [IOTA Identity PQ support](https://docs.iota.org/developer/iota-identity/how-tos/post-quantum) | ML-DSA credential issuance, VP creation/verification, serialised credential/presentation sizes | Select ML-DSA-65 if the pinned release and key store support it. Separate local SDK cryptography from registry/ledger effects. Signature-based VP creation is not anonymous-proof generation. |
| Primary anonymous VC: LINKS Foundation [pqzk-blns](https://github.com/Cybersecurity-LINKS/pqzk-blns) | Issuance, showing/disclosure proof generation, verification and serialised sizes | BLNS-based C++ construction with different certification/proof assumptions. Audit the exact executable's status/update features before comparing revocation. The repository lists GMP/NTL and optional Falcon components. |
| Additional anonymous credentials: [Argo et al. implementation](https://github.com/Chair-for-Security-Engineering/lattice-anonymous-credentials) | Credential-layer operations exposed by its benchmark and parameter scripts | Native dependencies and parameter/security estimates differ. Its README supplies build and Docker workflows; rerun tests before adapting the benchmark. |
| Additional lattice proof demo: [LaZer anonymous credentials](https://github.com/lazer-crypto/lazer) | Available credential proof operations and sizes | Pin the paper-specific commit; a library demo does not necessarily implement the full DID/revocation lifecycle. |
| Additional STARK comparator: [zkDilithium](https://github.com/guruvamsi-policharla/zkdilithium) | Signature-knowledge proving/checking and proof bytes | Uses a Winterfell fork and a modified signature construction. The public prover example proves knowledge of a signature on a public message. It is not an identical hidden-attribute, FIPS-204 ML-DSA-65 task. |

For every external run record the source commit, build options, parameter set, assumed security, statement/witness, number and encoded size of attributes, disclosure pattern, issuer visibility, revocation support, threading and what is timed. Prefer rerunning on the same computer. If reproduction fails, retain the reason; a paper's published measurement can be shown only in a separately labelled literature table, without direct speedup claims across different hardware. Mark an unimplemented/unavailable operation as such rather than assigning zero cost.

The manuscript's Margaria comparison has a directly relevant source: the QUBIP project identifies the LINKS repository as its BLNS-based anonymous VC implementation and describes its connection to the SSI work. That makes it a stronger initial comparator than selecting an unrelated PQ signature benchmark. [QUBIP implementation overview](https://qubip.eu/quantum-secure-ssi/)

**Stage 8 verifies failure handling and produces the performance evidence.** Tests must run against the real proof verifier and lifecycle service; malicious fixtures may bypass the honest wallet's preliminary checks to exercise the verifier's rejection path.

| Test family | Required outcome |
|---|---|
| Valid credentials and approved disclosures | Both independent verifiers accept valid fresh presentations under their own policies |
| Replay | A second submission after acceptance fails; simultaneous duplicate submissions produce at most one success per verifier challenge |
| Audience/session/context substitution | Wrong audience, nonce, session, expiry, policy, issuer, namespace or state reference fails |
| Modified certificate or attributes | Modified signature, holder binding, certified attribute or external accepted claim fails |
| Credential/witness substitution | Signature, secret, attribute, identifier and path assembled from different credentials fail |
| Malformed proof or encoding | Truncation, extra bytes, padding errors, malformed hints, invalid field ranges and oversized inputs fail safely |
| Wrong or old Merkle data | Wrong path, wrong identifier, old root or stale witness fails when the required current reference differs |
| Update success for unrevoked holder | Valid ordered public updates yield a new local witness; the original credential succeeds with a fresh request |
| Revoked credential | Cannot prove current non-revocation; update fails for its revoked identifier |
| Update corruption or rollback | Altered signatures/paths, missing or reordered epochs, wrong namespace and rollback attempts fail |
| Current-state outage/races | Unavailable or inconsistent current state fails; concurrent revocation follows the specified final-read ordering |
| DID and issuance state | Conflicting publication, deactivation, controller/key mismatch, nonce reuse and interrupted issuance follow V3's state rules |
| Privacy regression | Presentation payloads contain no unapproved persistent holder key/DID, certificate signature, binding, identifier or path; compare A/B's joint view and later public revocation updates |

Privacy regression tests can find identifiers, accidental deterministic outputs or forbidden fields. Distinct-looking proofs or a classifier that fails to link samples do not establish cryptographic unlinkability. Retain Section VI's honest-authority, holder-corruption and authorised-leakage restrictions. Public claims may identify a holder by themselves; network addresses/timing are outside the stated credential-level model.

Collect the following measurements with exact definitions:

| Measurement | Reporting boundary |
|---|---|
| Setup and DID operations | Initialisation, key generation, publication/rotation and current/historical resolution; history length varied separately |
| Credential issuance | Holder enrolment proving, issuer proof/check/signing, status allocation and total issuance; exclude manual evidence review and report synthetic evidence processing separately |
| Presentation | Circuit generation, optional witness catch-up, local checks, proof generation and serialisation; disclose precomputation |
| Verification | Parsing, circuit generation, proof checking, public checks, final current-state read and atomic challenge consumption |
| End-to-end latency | Fresh authenticated challenge request through final decision; report with and without witness catch-up, and with network settings stated |
| Sizes and messages | Raw proof bytes, complete VC/VP/request/state/update bytes, number of messages and round trips; count wire encoding and envelope overhead separately |
| Communication | Bytes per successful flow and per attempted flow, including failed attempts, state queries, resolution, retries and update downloads |
| Storage and memory | Holder keys/credential/witness, issuer/registry/status records, tree/update history, circuit/cache/temp views, peak RSS and any swap/I/O |
| Throughput | Completed successful flows per second plus offered load, failures, queues and median/tail latency, under declared CPU/RAM allocation |
| Revocation scalability | One revocation, repeated revocations, update publication, holder catch-up, verifier current-state cost, state changes during proving and retry rate |

Use the depth-20 tree unchanged for the principal V3 experiments. Vary allocated holders and revoked fraction independently, starting with small populations and scaling towards 10^3, 10^4, 10^5 and, only if practical, 10^6 entries. V3's capacity is 1,048,576 total allocated identifiers, including retired allocations. Do not regenerate one million expensive enrolment proofs just to measure tree operations: separately label tree/state microbenchmarks and end-to-end credential populations.

At fixed depth, increasing occupied entries need not increase path length or authentication-proof cost. Measure manager storage, update volume and catch-up work instead. Vary missed update count (for example 1, 10, 100, 1,000) and revocation frequency. V3 publishes individual updates; a batch-processing experiment should count those updates and must not silently introduce an aggregate revocation protocol. Measure total update-distribution traffic as well as an individual holder's processing.

Vary supported field counts, masks and disclosed values within the fixed schema/1,024-byte limits. Hiding more fields need not reduce proof size because the witness remains fixed. Circuit counts can nevertheless vary with the allowed public constant folding, so report the actual statement/configuration with each count. Parameter sweeps outside depth 20, ML-DSA-65 or 480 repetitions are separate profiles requiring explicit accounting.

Begin timing with warm-up and a pilot, then choose sample counts from observed run cost and variability. For inexpensive operations, many independent trials are feasible; for very expensive proofs, use fewer complete trials and report the resulting uncertainty. Record sample count, mean/standard deviation, median and justified percentiles/confidence intervals. Do not imply a stable p99 from a small sample. Use independent synthetic credentials, sessions and fresh proof randomness, repeat experiments in blocks and interleave baseline/PQ-DID order to reduce thermal/time drift.

Pin microbenchmarks to the same performance-core allocation, record threading/CPU utilisation, and separate single-worker latency from multi-worker throughput. Keep release builds, compiler flags, native backend and cache conditions explicit. Compare common code under the same optimisations. Record OS/WSL/container settings and power/thermal conditions; the displayed base clock is not the sustained execution frequency.

One-host loopback is an initial deployment profile. Add controlled bandwidth and latency profiles where possible, identifying them as emulation. Same-host throughput shares CPU/RAM across issuer, prover, verifier and status service; it is not independent distributed-server capacity. If a remote machine is later available, label those results separately. Separate cryptographic payload sizes from JSON/base encoding, HTTP/TLS bytes and connection establishment.

Save raw measurements with run ID, implementation commit, dependency manifest, suite, workload, CPU allocation, circuit counts, bytes, timing breakdown, peak memory, success/failure reason and state version. Synthetic dataset seeds may be fixed for reproducibility; do not fix or reuse production-style proof/session randomness across fresh presentations. Keep large proof samples only where needed for reproducibility/debugging; record size and digest for other trials so storage does not multiply unnecessarily.

**The supplied desktop can support the initial implementation and baseline; the full proof remains conditional.** The assessment uses the stated processor and RAM. It is not a remote inspection of the user's computer, and disk capacity, OS configuration and exact GPU memory were not supplied.

| Hardware | Assessment and action |
|---|---|
| Intel Core i7-14650HX | Intel lists 16 cores: 8 performance and 8 efficient, with 24 threads. Suitable for development, native crypto, isolated services and controlled CPU benchmarks. Use a consistent core allocation because the cores are heterogeneous. |
| 16 GB RAM, 15.6 GB usable | Sufficient to start the service testbed, baseline, native primitive tests and limited proof/circuit pilots. Full circuit compilation, raw views and concurrent provers may exceed it. Measure before increasing concurrency. |
| RTX 5060 Ti | No GPU dependency is planned. It will help only if a selected backend has a compatible implementation that is actually used and benchmarked. Its presence does not automatically accelerate ML-DSA or the V3 proof, and GPU memory is not a replacement for process RAM. |
| Storage not specified | Confirm free SSD space before generating circuits/proofs. At the one-million-gate scenario, retaining 100 raw proofs alone is approximately 24.5 GB; at ten million gates, approximately 240.5 GB. These are calculated storage scenarios. |
| OS not specified in this request | If using Windows, WSL2 with a supported Ubuntu environment is a reasonable development path; native Linux is also suitable. Keep initial services lightweight and record actual guest memory limits. |

[Intel's processor specifications](https://www.intel.com/content/www/us/en/products/sku/235996/intel-core-i7-processor-14650hx-30m-cache-up-to-5-20-ghz/specifications.html) support the CPU description. Software resource estimates above are engineering judgements, not measurements on this machine.

There is no reason to buy a different GPU or replace the computer before the feasibility pilot. If profiling demonstrates a memory-only bottleneck and the machine supports expansion, 32 GB or 64 GB RAM may help; neither capacity is guaranteed to fit an unmeasured circuit, and added RAM does not solve excessive proof transmission time. A later server run should use a clearly recorded hardware profile and rerun the comparison baseline there.

The probability of success cannot responsibly be expressed as a numerical percentage at this stage. The available evidence supports the following more useful assessment:

| Intended outcome | Present judgement |
|---|---|
| Signature-based baseline and isolated lifecycle services | High engineering feasibility on the supplied machine |
| W3C-compatible research KYC workflow | Feasible, with a custom securing/status mechanism, deterministic claim mapping and explicit conformance tests |
| Correct full V3 authentication relation | Credible to implement, but requires substantial specialist circuit/protocol engineering |
| Full V3 proving/checking within 16 GB | Unknown until generated circuit and memory measurements exist |
| Compact, fast interactive V3 authentication | Significant risk because of the existing proof-length formula and strict current-state freshness |
| Strong evaluation for the manuscript | Achievable if the implementation and claims follow the evidence, including any required change of concrete instantiation; no implementation plan guarantees venue acceptance |

**Stage 9 aligns the evidence and manuscript.** Replace the earlier prototype results with measurements of the actual selected construction. Record any changes to BC-1, the proof protocol, caps, service assumptions or W3C mappings in the specification and affected proof analysis. Publish a reproducible research package with source, pinned dependencies/licences, vectors, synthetic workloads, configurations, raw data, plotting instructions and known limitations. Keep mandatory manuscript results compact and use supplementary material for detailed circuit/encoding and reproduction records.

The first implementation work package is therefore Stage 1 followed by Stage 2 and the Stage 3 feasibility study. Its concrete deliverables are a frozen specification manifest, a tested executable relation, circuit/component counts, projected and measured proof resources, and a decision about whether the exact V3 profile supports the intended testbed. Those results determine the realistic schedule for completing the remaining stages.
