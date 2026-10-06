# Isolated ML-DSA reference baseline — OCT31-KYC-NATIVE-MILESTONE-1

Implemented and validated **pqdid-mldsa-reference-1**, an explicitly disclosed,
linkable comparison baseline. This is not private PQ-DID authentication, PQ-DAA,
a W3C securing mechanism or production deployment. Only manuscript Sections II–VIII
and agreed clarifications inform reuse of the scheme's internal contracts.

## Implemented boundary

The implementation is in [baseline](../experiments/kyc_milestone_1/baseline/).
It reuses the real bounded ML-DSA-65 core, typed parameters/schema/policy encoders,
manager signing adapters, durable manager and verifier SQLite transactions,
authenticated current-state response and Merkle witness updates. Production sources,
active BC-1, cryptographic parameters, dependencies and original vectors are unchanged.

The issuer binds the persistent holder public key into its signed credential.
The holder proves possession during enrolment and signs the **exact signed verifier
request**, complete credential and path. The verifier checks both signatures,
trusted instance/request key, approved policy, certified validity, authenticated
current revocation state and path before durable one-time challenge consumption.
A/B have independent keys, audiences, stores, generations and retained head tickets.
The normal PQ-DID proof path still fails closed; no synthetic proof adapter is used.

| Operation | Trusted role/key | Exact canonical message | Fixed context |
| --- | --- | --- | --- |
| Credential | Issuer; parameter-pinned public identity | parameters, holder key, approved attributes, rid | `PQ-DID-REF/credential/v1` |
| Enrolment possession | Holder; persistent checked key pair | parameters, session, issuer nonce, holder key, attributes, rid | `PQ-DID-REF/enrol/v1` |
| Request | A/B verifier; configured request key | encoded context, signed revocation state | `PQ-DID-REF/request/v1` |
| Presentation | Credential-bound holder key | **exact signed request**, credential, 960-byte path | `PQ-DID-REF/presentation/v1` |
| Manager state/current/update | Existing trusted manager adapter | Existing canonical state/current/update constructors | Existing unchanged `PQ-DID/*/v1` contexts |

Outer frames use LP(ASCII profile/tag), uint32be field count and LP fields. The fixed
`pqdid-mldsa-reference-1/` tags are isolated; production codec arities, role contexts,
proof-object types and proof configuration are not modified. Integer validators
reject booleans; rid remains restricted to the active 20-bit tree. Public keys are
1,952 bytes, signatures 3,309 bytes; inputs use canonical typed encodings.

## Publication, persistence and rejection

Issuance records INTENT, reserves the ID permanently in the existing manager,
records RESERVED, verifies holder enrolment, commits SIGNING, signs with the bounded
core, checks current manager state, then atomically records CERTIFIED and its exact
credential bytes. Retrieval requires the configured recipient. Redelivery retrieves
stored bytes without signing again. A failure after SIGNING can leave an explicitly
unpublished uncertain outcome; there is no automatic resigning or reservation reuse.

The issuer journal uses SQLite DELETE/EXTRA and a bounded head/generation chain.
Independent retained tickets gate reopen and fencing. Manager allocation and issuer
certification are **separate transactions**: final manager-state observation is
ordered before issuer COMMIT, not atomic across stores. Wallet files persist with
private modes and bounded canonical payloads; one trusted local owner is assumed.
Reopen tests retain expected heads outside databases; database contents never
self-authorise recovery. Simulated transaction faults are not process crashes,
power-loss durability or whole-store rollback defence.

Certified `validUntil >= session expiry` is separate from strict `now < expiry`,
including the final durable consumption recheck. The baseline adds its required
validity range/disclosure to the immutable example's base policy using `make_policy`.
Freshness is checked against the manager immediately before consumption under the
existing ordered-read contract; no cross-store atomic freshness claim is made.

## Individual validation

All 48 distinct B cases passed in 50 counted invocations. The first B02 failed because
the fixture's original policy had no validity clause; baseline policy construction
was corrected, leaving the fixture and expected validity rule unchanged. The first
B20 fault injection rejected enrolment too early; it was narrowed to the actual
issuer-key/credential-context post-sign verification. Its expected bounded error,
SIGNING state, permanent allocation and no-release assertions were retained.
Both failures, pre-correction B20 source and all guarded outcomes are retained in
[the evidence](data/oct31_kyc_native_milestone_1/).

| ID | Contract case | Recorded invocations | Result |
| --- | --- | --- | --- |
| B-01 | credential-canonical-roundtrip | M1-0017: pass | passed at recorded inputs |
| B-02 | presentation-canonical-roundtrip | M1-0018: failed, M1-0043: pass | passed at recorded inputs |
| B-03 | malformed-binary-width | M1-0044: pass | passed at recorded inputs |
| B-04 | trailing-data-rejected | M1-0045: pass | passed at recorded inputs |
| B-05 | wrong-tag-arity | M1-0046: pass | passed at recorded inputs |
| B-06 | boolean-not-integer | M1-0047: pass | passed at recorded inputs |
| B-07 | foreign-instance | M1-0048: pass | passed at recorded inputs |
| B-08 | foreign-issuer-key | M1-0049: pass | passed at recorded inputs |
| B-09 | holder-key-substitution | M1-0050: pass | passed at recorded inputs |
| B-10 | attribute-substitution | M1-0051: pass | passed at recorded inputs |
| B-11 | rid-out-of-range | M1-0052: pass | passed at recorded inputs |
| B-12 | private-key-excluded-from-export | M1-0053: pass | passed at recorded inputs |
| B-13 | role-override | M1-0054: pass | passed at recorded inputs |
| B-14 | context-override | M1-0055: pass | passed at recorded inputs |
| B-15 | public-secret-key-mismatch | M1-0056: pass | passed at recorded inputs |
| B-16 | keygen-entropy-failure | M1-0057: pass | passed at recorded inputs |
| B-17 | signing-entropy-failure | M1-0058: pass | passed at recorded inputs |
| B-18 | sign-attempt-exhaustion | M1-0059: pass | passed at recorded inputs |
| B-19 | sampler-exhaustion | M1-0060: pass | passed at recorded inputs |
| B-20 | post-sign-verification-failure | M1-0061: failed, M1-0062: pass | passed at recorded inputs |
| B-21 | allocation-retained-after-failure | M1-0063: pass | passed at recorded inputs |
| B-22 | wrong-enrolment-possession | M1-0064: pass | passed at recorded inputs |
| B-23 | unapproved-attributes | M1-0065: pass | passed at recorded inputs |
| B-24 | signing-claim-commit-failure | M1-0066: pass | passed at recorded inputs |
| B-25 | fenced-issuer-before-certification | M1-0067: pass | passed at recorded inputs |
| B-26 | certification-commit-failure | M1-0068: pass | passed at recorded inputs |
| B-27 | interrupted-delivery-exact-redelivery | M1-0069: pass | passed at recorded inputs |
| B-28 | wrong-delivery-recipient | M1-0070: pass | passed at recorded inputs |
| B-29 | fresh-verifier-A | M1-0071: pass | passed at recorded inputs |
| B-30 | fresh-verifier-B | M1-0072: pass | passed at recorded inputs |
| B-31 | wrong-nonce | M1-0073: pass | passed at recorded inputs |
| B-32 | cross-audience-request | M1-0074: pass | passed at recorded inputs |
| B-33 | context-substitution | M1-0075: pass | passed at recorded inputs |
| B-34 | policy-failure | M1-0076: pass | passed at recorded inputs |
| B-35 | initial-session-expiry | M1-0077: pass | passed at recorded inputs |
| B-36 | final-atomic-expiry | M1-0078: pass | passed at recorded inputs |
| B-37 | live-replay | M1-0079: pass | passed at recorded inputs |
| B-38 | restart-replay | M1-0080: pass | passed at recorded inputs |
| B-39 | persistent-holder-key-reopen | M1-0081: pass | passed at recorded inputs |
| B-40 | stale-verifier-writer | M1-0082: pass | passed at recorded inputs |
| B-41 | authenticated-current-state | M1-0083: pass | passed at recorded inputs |
| B-42 | wrong-manager-signature | M1-0084: pass | passed at recorded inputs |
| B-43 | stale-state-reference | M1-0085: pass | passed at recorded inputs |
| B-44 | mutated-merkle-path | M1-0086: pass | passed at recorded inputs |
| B-45 | own-revocation | M1-0087: pass | passed at recorded inputs |
| B-46 | other-revocation-witness-update | M1-0088: pass | passed at recorded inputs |
| B-47 | out-of-order-update-chain | M1-0089: pass | passed at recorded inputs |
| B-48 | history-gap-unavailable | M1-0090: pass | passed at recorded inputs |

## Limits and remaining obligations

The baseline reveals complete attributes, DID/version, persistent holder key,
issuer signature, rid and path. It offers no selective disclosure or unlinkability.
DID resolution is explicitly off: these are opaque certified attributes, not a claim
about a current external DID controller. Synthetic stores/keys and local trusted
configuration establish no service activation or OS identity-isolation result.

Production custody, entropy assurance, erasure, side channels, concurrent/durable
holder ownership, external recovery-head availability, adaptive Delta_tail and
complete proof knowledge/privacy remain open. Primitive/native interoperability
and historical suites were reused. No installations, proofs or zkVM executions ran.
Stages 2–3 remain open; proof attempts remain two used and one unused.

## Final preservation checkpoint

The complete audit passed with exit status 0: 8,759 original and 2,142 disjoint
supplemental content comparisons (10,901 total; 10,936 identity-inclusive historical
paths), protected immutable inputs and report prefixes, and a 10,625-entry inventory.
There were no unexpected or missing paths. All 841 local documentation links passed.
The worker completed report generation and readback; its outer guard also passed.
Guarded elapsed time was 6.058319 seconds (audit child 4.163477 seconds). Peak
cgroup-v2 memory was 51,773,440 bytes under the unchanged 268,435,456-byte cap,
including charged worker descendants, file cache and kernel memory; swap and memory
events were zero. Independently sampled summed tree RSS peaked at 62,828,544 bytes;
shared mappings can be counted more than once in that separate metric.

The first preparation failed at the auditor's 10,000-entry traversal admission.
Its helper, new-output inventory and failure remain in `corrections/` and `jobs/`.
The correction partitions the same inventory by its 16 disjoint original roots,
retains the 10,000-entry limit per partition and requires full expected-path union
with no overlap. Corrected preparation and final lint/format checks passed. No
historical baseline, expected entry, digest, permitted-content boundary or file
limit was changed. This is preservation completion; it does not clear the native
admission blocker or establish proof security. Final accounting and post-report
inventory/readback are recorded in the [closure](data/oct31_kyc_native_milestone_1/validation-closure.json).

## Confirmed final validation — 29 September 2026

Normal approval review admitted the directly confirmed native checks. All 24
strengthened-final-binary cases, 16 transcript comparisons and C-09 passed once,
with no new build or functional correction. Earlier-binary results and both prior
approval rejections remain historical evidence. The baseline's 48 cases, 16 harness
cases, other 11 integrations and all 276 measurement trials were reused unchanged;
all 12 integration cases are now covered. No benchmark statistics changed.
See [individual final native outcomes](stage3_aurora_masking_native.md#final-binary-validation--29-september-2026).

The cumulative ledger is 867/1,050: 419 milestone invocations, 181 remaining plus
two separate historical tooling slots. Builds remain 8/13. All originally planned
392 distinct cases/trials are covered; the extra 27 invocations retain scoped failed
checks and affected revalidation. Functional scope is complete; final preservation,
readback and resource closure follow in the continuation evidence. This milestone
does not close Stages 2–3 or AURORA-BRIDGE-001 and establishes no private-proof claim.

## Final milestone closure — 29 September 2026

**OCT31-KYC-NATIVE-MILESTONE-1 is complete at its approved reference/component
validation scope.** All originally planned 392 distinct cases/trials are covered,
including all 41 pending final-binary/transcript/C-09 checks. There were no native
failures or new builds in this continuation. Baseline and all 276 benchmark results
were reused unchanged; earlier-binary results, failures and rejected admissions
remain separately preserved.

The continuation's complete preservation audit exited 0: 8,759 original plus
2,142 disjoint supplemental comparisons, 10,936 identity-inclusive historical paths,
complete prior seals/report prefixes and a 10,732-entry inventory with no missing
or unexpected names. Audit worker reporting/readback and outer guard passed.
Elapsed guard time was 4.872552 s (worker 4.203994 s); cgroup memory peak was
46,354,432 B under the unchanged 256 MiB ceiling, with no memory-event breach or
swap. Separately sampled summed process-tree RSS was 63,078,400 B; shared mappings
can be counted repeatedly in that metric. All 1,520 local link checks passed.

The first preparation reported the already-sealed `benchmarks/README.md` outside
its traversal root. Content matched its historical seal. Its helper, snapshots and
failure are retained in `native-finalisation-1/failed-preparation-1`; the correction
traverses `benchmarks` in place of its existing testbed subdirectory and retains all
expected names and hashes. Corrected preparation and affected lint/format passed.
No baseline or expected digest was regenerated, no content permission broadened,
and no functional test was repeated for this tooling correction.

Final report seals, final inventory/readback, exact-unit shutdown and all time and
storage accounting are recorded in the [completed continuation closure](data/oct31_kyc_native_milestone_1/native-finalisation-1/validation-closure.json).
The invocation ledger is 867/1,050 (419 milestone invocations; 181 milestone slots
plus two separate historical tooling slots remain). Builds remain 8/13. Analysis
and isolation allowances are unchanged; completion reserves remain inside unused
implementation/evidence balances.

The next bounded native validation target is a nontrivial public R1CS fixture
through the corrected components before considering private integration; no such
work is started here. Complete Aurora correctness, authentication/private-proof
feasibility, query/masking and commitment-transformation arguments, extraction/privacy,
concrete-hash composition, adaptive Delta_tail and production security remain open.
Stages 2–3/AURORA-BRIDGE-001 remain open; isolation stopped/unactivated and CPU
proving paused. No proof or zkVM execution occurred; proof ledger two used/one unused.
