# PQ-DID implementation and evidence consolidation

**Scope unchanged.** The goal remains the complete privacy-preserving PQ-DID
scheme, its KYC testbed and benchmarking. **31 October remains the target. Current
evidence does not support committing to full completion by that date.** The
original implementation programme is incomplete; Stages 2–3 remain open.

This supersedes the scope-reduction recommendation in the preceding decision
report; that recommendation was not approved. Historical text and seals are
preserved. The examined Aurora route is closed **under its assessed construction,
representation, masking and resource conditions**. That is neither an impossibility
result for PQ-DID nor permission to remove private authentication from delivery.
No replacement is selected or adopted here.

Only manuscript Sections II–VIII and SPEC-001–004 remain authoritative. This
consolidation indexes existing results; it does not rerun tests or benchmarks.
Production code, active BC-1, dependencies, parameters, manuscript, original vectors,
historical failures and comparison point v1 are unchanged. Completion of this
documentation/preservation package is not completion of the programme.

## Evidence categories and working functionality

| Category | Available functionality and evidence | Claim boundary |
| --- | --- | --- |
| Executable reference cryptography | Canonical encodings, schema/disclosure/policy, holder binding, Merkle paths; bounded ML-DSA-65 key generation/signing/verification and fixed-role signing adapters | Synthetic keys, reference implementation; not production custody, entropy assurance, erasure or side-channel resistance |
| Local joint relation | `relations.py` checks credential authenticity, the same holder secret/attributes, selective disclosure and the same certified identifier's non-revocation path, with public checks kept distinct | Evaluator receives the private witness locally. A true result is not a remote proof or extractor |
| Reference lifecycle with synthetic proof gates | Durable manager/issuer/verifier contracts; permanent allocation, log/commit-before-release, recipient-bound issuer redelivery, fenced recovery, two verifier stores, final expiry/consume, local holder witness updates | Actual bounded signatures and state transitions coexist with explicit synthetic proof acceptance in lifecycle fixtures; these are not private-proof successes |
| Disclosed comparison baseline | `pqdid-mldsa-reference-1` uses actual signatures and complete disclosed credential/path checks, persistent holder-key possession and durable consumption | Linkable; reveals full attributes, DID/version, holder key, issuer signature, rid and path. It uses no synthetic proof adapter and is not private PQ-DID or PQ-DAA |
| Native experimental components | Corrected native EXP2, masking/operator cases, bounded nontrivial R1CS loader/evaluation and independent component comparisons | Specific pinned binaries/patches/callers only; neither complete Aurora correctness nor complete authentication/proof security |
| Historical RISC Zero evidence | A real enrolment Succinct receipt with independent verification/tamper rejection; separate completed CredValid executions | Enrolment is not authentication. Execution journals are not receipts. CredValid proving and complete authentication remain unmeasured; the two-attempt ledger is unchanged |

Working reference modules include
[relations](../src/pqdid/relations.py), [bounded signing](../src/pqdid/bounded_mldsa_sign.py),
[signing adapters](../src/pqdid/signing_adapters.py),
[manager](../src/pqdid/bounded_manager.py), [issuer](../src/pqdid/durable_issuance.py),
[verifier](../src/pqdid/durable_verification.py), [DID state](../src/pqdid/did_state.py),
[holder lifecycle](../src/pqdid/holder_lifecycle.py), and
[containers](../src/pqdid/containers.py). Authority-store transactions do not imply
atomicity across issuer/manager stores. Independent retained heads and explicit
admission remain necessary; local fault injection is not power-loss durability or
whole-store rollback defence. The reference holder lifecycle is in memory; the
isolated disclosed baseline's wallet file does not complete production private-wallet
storage or multi-owner isolation.

The completed KYC/native milestone covers its 392 distinct cases/trials, including
48 baseline cases, 16 harness cases, 12 integrations, 24 final-binary native cases,
16 final-binary transcript cases and 276 trials. It consumed 419 invocations,
including failures and affected revalidation. Earlier-binary results and rejected
admissions remain separate; the final closure supersedes the report's earlier
pending checkpoints. See the [final milestone closure](oct31_kyc_native_milestone.md#final-milestone-closure--29-september-2026)
and [native outcomes](stage3_aurora_masking_native.md#final-binary-validation--29-september-2026).

The [holder integration report](stage2_holder_witness_revocation_integration.md)
explicitly separates actual bounded cryptography, complete local relation evaluation
and synthetic verifier acceptance. Its 22 passing cases and the durable verifier's
24 distinct cases are reused, not reclassified as proofs. The
[RISC Zero enrolment report](stage3_r0_enrol_po17.md) records the actual successful
receipt; [CredValid execution](stage3_r0_credvalid_exec24.md) and
[proof-admission decision](stage3_r0_credvalid_po17.md) record the separate limits.
Historical per-package statements of earlier unused proof slots are not current
balances: the authoritative ledger is **two used, one unused**.

## Original requirements mapped to evidence

The [machine-readable coverage index](data/implementation_consolidation_1/coverage.json)
contains every original R-001–R-052 exactly once, its original title, evidence
locations and remaining obligation. Index completeness is not implementation or
security completeness. The original detailed [traceability](traceability.md) remains
the historical record; this table is its current navigation and qualification layer.

| Requirements | Existing evidence | Remaining obligation |
| --- | --- | --- |
| R-001–004: trust, owners, services, state | [Owner boundary](stage2_authority_owner_boundary.md), [isolation record](stage2_authority_isolation_pilot.md) | Trusted deployment/custody/service assumptions; 22 actual-identity cases still pending |
| R-005–008: codec/schema/disclosure/context | [Codec](stage2_codec.md), [credentials](stage2_credentials.md), [relations](stage2_relations.md) | Complete proof binding to the same canonical inputs |
| R-009–010, R-032–033: crypto, caps, release | [Bounded core](stage2_bounded_mldsa_keygen_sign.md), [adapters](stage2_bounded_signer_release_contract.md) | Production security; adaptive cap-tail coupling and reduction-budget advantages |
| R-011: setup | [Parameters/credentials](stage2_credentials.md), [durable authority](stage2_durable_authority_pilot.md) | Production trust/secret provisioning and operational setup |
| R-012–015: DID lifecycle | [DID state](stage2_did_state.md), [recovery](stage2_recovery_admission.md) | Deployed registry, conformance and complete durable/rollback guarantees |
| R-016–017: requests/current state | [Signing adapters](stage2_bounded_signer_release_contract.md), [durable verifier](stage2_durable_verifier_lifecycle_integration.md) | Real service/clock assumptions and integration with admitted private proof |
| R-018–022: issuance | [Durable issuer/manager](stage2_durable_issuer_manager_integration.md) | Actual enrolment-proof integration; external evidence policy remains trusted |
| R-023–025: credential/joint predicate | [Reference relations](stage2_relations.md), [experimental lowering](oct31_auth_relation_integration_result.md) | Full lowering/evaluation and private-proof equivalence |
| R-026–027: Present/VerifyDAA | [Holder integration](stage2_holder_witness_revocation_integration.md), [inactive proof boundary](oct31_auth_relation_integration_result.md) | Complete prover/checker unavailable; ordinary path fails closed |
| R-028: atomic acceptance | [Verifier integration](stage2_durable_verifier_lifecycle_integration.md) | Synthetic proof gate remains a fixture; external business-action atomicity unresolved |
| R-029–031: tree/revocation/updates | [Durable manager](stage2_bounded_manager_durable_release.md), [holder integration](stage2_holder_witness_revocation_integration.md) | Production holder persistence and deployment isolation |
| R-034–037: compiler/admission | [Forward NTT](stage3_mldsa_full_forward_ntt_pilot.md), [relation result](oct31_auth_relation_integration_result.md) | Full circuit identity/equivalence/admission; experimental lowering is not canonical BC-1 |
| R-038–043: proof/tapes/transcript/check/erasure | [Feasibility](stage3_feasibility_review.md), [native components](stage3_aurora_masking_native.md) | Complete raw-view implementation remains paused; replacement needs explicit profile and proof argument |
| R-044–051: correctness/security/composition | [Security assessment](stage2_concrete_security_assessment.md), [outer composition](stage3_outer_oracle_composition.md) | Complete-witness knowledge, adaptive/historical privacy, finite bounds, service composition and adaptive Delta_tail |
| R-052: W3C mapping | [Interoperability contract](stage2_kyc_interoperability_contract.md), [container adapter](stage2_kyc_container_adapter.md) | Complete standards mapping, securing mechanism and conformance remain unfinished |

The experimental full-relation source contains the complete intended checks, but
full joint constraint generation/evaluation did not finish. Keep these 21 cases
explicitly **unrun**: M-01–M-03, J-01–J-16 and Q-02–Q-03. Partial counts, source
coverage, a completed NTT or a small native R1CS evaluation cannot substitute.

## Reproducibility and measurements

[Reproduction guide](data/implementation_consolidation_1/reproduction.md) consolidates
environment/source identities, exact retained command records, configs, failures,
binary versions and the conditions for any later fresh run. No rerun, rebuild,
receipt verification or statistics regeneration is needed for this consolidation.
Existing closed output paths and ledger admissions must not be replayed.

Comparison point **OCT31-KYC-NATIVE-MILESTONE-1/v1** remains sealed in
[comparison-point.json](data/oct31_auth_relation_integration_1/comparison-point.json).
The 276 observations comprise 12 cold-process, 24 warm-up and 240 warm trials,
with three independent process sessions per scenario. The
[retained report](kyc_milestone_benchmarks.md) gives these warm local descriptive
statistics; they are not population guarantees or private-proof measurements:

| Scenario | Warm n | Median ms | Nearest-rank p95 ms |
| --- | ---: | ---: | ---: |
| ISSUE | 60 | 189.175 | 268.009 |
| PRESENT-A | 60 | 465.898 | 565.499 |
| PRESENT-B | 60 | 468.337 | 572.229 |
| REVOKE-UPDATE | 60 | 534.213 | 620.661 |

Actual cryptography is measured in the **disclosed baseline**. Setup is outside
operation latency but inside resources; per-job cgroup peaks and process-lifetime
RSS are not per-trial memory. Cold-process does not mean cache-flushed. There is
no measured WAN distribution, throughput/saturation result or private/baseline
overhead ratio. Future comparable measurements must preserve workload, source,
parameters, instrumentation, fixture transformation and hardware conditions, or
start a separately labelled comparison. A changed test-inclusive tree digest has
a retained [measured-source reconstruction](data/oct31_kyc_native_milestone_1/benchmark-source-provenance.json);
do not rewrite old hashes to match today's tree.

**Unavailable, represented as null with reasons:** complete authentication proof
generation/verification latency, proof size, complete private presentation size,
prover/verifier peak memory, private end-to-end distributions, private throughput,
and private/PQ-DAA/baseline overhead. Neither the RISC Zero enrolment receipt nor
its CredValid journal supplies those values. [Benchmark targets](benchmark_targets.md)
are still labelled project proposals; they are not passed acceptance tests or
permission to change current execution ceilings.

## Unfinished interoperability and security

The nine supported container conversions return unverified typed data. The local
profile's strict UTF-8, duplicate/unknown-field rejection, unpadded base64url,
minimal decimal-string protocol integers, exact canonical-byte checks and trusted
receiver routing are implemented. The 24 parser cases and 15 draft examples remain
evidence of that boundary only. Synthetic previews cannot become ordinary proof
objects; ordinary presentation/enrolment proof parsing remains unsupported.

W3C work still requires issuer URL/vocabulary binding to certified claims, explicit
securing-mechanism/cryptosuite and graph coverage, DID method/verification-key
representation and resolution metadata, privacy-preserving shared status mapping,
and interoperability/conformance tests. Session expiry must not become credential
validity. No hidden identifier/path/credential-specific status URL may be exposed
to gain interoperability. The retained dated W3C review is reused; no new standards
survey or conformance claim is made. A project JSON wrapper is not a secured VC/VP.

Security obligations remain property-specific: commitment hiding/simulation for
the full disclosed view; quantum complete-witness extraction in the actual-history
game; adaptive and post-revocation historical privacy; concrete-hash/outer-oracle
composition with actual query/message bounds; finite parameters and component
advantages at reduction budgets; adaptive Delta_tail across all bounded calls;
trusted services, entropy, custody, erasure and side channels. Native algebra and
finite rejection tests do not establish these results or an overall bit-security
number. DEP-001/DEP-002 retain their implementation/security distinction: the
bounded reference signer is implemented, but its existence does not close all
production or adaptive-tail obligations.

## Replacement construction decision

The [concise handover](data/implementation_consolidation_1/handover.md) is the
acceptance contract for a replacement integrated construction. It includes the
exact same-witness relation, public preprocessing boundary, hidden-input checks,
complete resource accounting, security conditions, proof parser/lifecycle boundary
and meaningful validation. It neither selects a backend nor authorises execution.

**Decision required before further private-proof implementation:** explicitly
approve one named integrated construction and its exact changes from the active
profile, supported by (1) whole-relation semantic correspondence, (2) applicable
masking/commitment/knowledge/privacy arguments and labelled unresolved conditions,
(3) finite parameters and complete simultaneous-resource admission, and (4) a
bounded implementation/proof validation plan. Any classical/ideal-model exploratory
claim must be labelled separately and must not replace the intended post-quantum
goal. Resource amendments require a sufficient complete model, not a component
floor. No currently examined route satisfies these admission conditions; none is
silently substituted here. This construction decision does not ask to reduce the
project scope or move the target date.

The assessed Aurora closure is retained as a specific NO-GO, including the internal
ML-DSA hash obstruction and conditional resident-storage floor. Other constructions
are not ruled out. Current evidence supports substantial reference/component work;
it does not support a commitment to the full original programme by 31 October.
Private-proof implementation awaits the construction decision; independent future
work would still need its normal scoped authorisation.

## Accounting and preservation

Opening balances are 2,676.6609291199384 implementation seconds, 974/1,050 invocations,
10/13 builds and 77,593,603/2^32 work events. Cumulative evidence is 26,774,908 bytes;
shared evidence headroom 4,757,981 bytes remains inside the 32 MiB cumulative cap.
Artifacts remain 58,966,547 bytes. The 300-second and 2 MiB completion reserves
remain inside these balances. Analysis 80.91750274339225 seconds and isolation
250.22 seconds remain separate and unchanged. This package admits no functional
cases, builds or work events; necessary static/evidence/audit checks are separate.
Measured guarded work and established conservative operator charges are retained.

Preservation uses the inherited original baselines, seals and complete name inventory,
with the unchanged 256 MiB auditor. Only this new consolidation and explicit
append-only status/traceability/issues updates are authorised. Older statements
are retained with their dates and superseding records, not silently edited.
The final audit, inventory, report readback, cleanup and actual balances are recorded
in the package closure after completion. This is not complete private authentication.

Isolation stays stopped/unactivated; CPU proving and raw-view integration remain
paused. No installations, proofs or zkVM executions occur. The proof ledger remains
**two used, one unused**. The original programme and Stages 2–3 stay open.


Documentary validation passed: all 52 requirement IDs appear once, 362 retained
dataset/evidence identities and 21 source/binary identities match comparison point
v1, and 24 exact historical command records match their seals. Scoped lint and
format passed. No functional test, measurement, build, proof or zkVM execution was
repeated. The current invocation/build counters remain 974/1,050 and 10/13.


Preservation completed: one full audit exited 0 with 10,901
disjoint content comparisons and 10,936 historical
identity-inclusive paths, complete inventory and reporting. Guard time was
4.656938 seconds; worker 4.345925 seconds.
Cgroup-v2 memory.peak was 47,390,720 bytes under
256 MiB, including descendants and charged cache/kernel. Separate sampled summed
process RSS peaked at 64,061,440 bytes. No resource breach occurred.
Final report seals, inventory/readback, cleanup and balances are in the
[closure](data/implementation_consolidation_1/validation-closure.json).
Only this consolidation is complete; the original programme remains incomplete,
with unchanged scope and 31 October target, not a supported completion commitment.
