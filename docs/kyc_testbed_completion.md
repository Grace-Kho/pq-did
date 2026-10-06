# KYC testbed completion workstream

Status: implementation preparation; affected tests and new measurements have not
run. This is one workstream under the user's authorisation, not a new backend or
proof proposal. G0 NO-GO is accepted; pinned Binius64 remains paused. Reopening
requires the exact committed-key, support/rank and joint-view security
correspondence in [G0](oct31_binius64_g0.md). No G1–G3 or speculative repair.

Full privacy-preserving PQ-DID, KYC testbed and benchmarking scope is unchanged.
31 October remains the target without a supported full-completion commitment.
Only manuscript Sections II–VIII and agreed SPEC-001–004 are authoritative.
Stages 2–3 stay open. Private-proof generation/verification remains unavailable
and fail-closed; isolation/proving stay paused. Proof ledger: two used, one unused.

## Execution plan, recorded before affected tests

Use a single source owner and one serial guarded worker. No builds, installations
or host changes. Preserve v1 and its 276 observations in place. Existing baseline
modules are imported read-only; additions receive separate source and dataset
identities. Existing native, primitive and unaffected lifecycle tests are reused.

| Deliverable / files owned by this workstream | Contract and acceptance gate |
| --- | --- |
| Candidate `experiments/kyc_testbed_completion_1/wallet.py`; promotion to `src/pqdid/holder_wallet.py` only after focused validation | Fresh-only private SQLite wallet; whole canonical credential/witness/state committed in one bounded transaction. Independent expected head and writer generation; no recovery from self-consistency alone. Validate every recovered snapshot, exact instance and recipient identity, monotonic state, path/secret/signature consistency. Stale/fenced writer and stale/inconsistent recovery reject. Failed commit releases no replacement; committed interrupted reply is retrieved exactly without resigning. Local crash evidence is not power-loss durability, secure erasure, encryption-at-rest or whole-store rollback defence. |
| `experiments/kyc_testbed_completion_1/application.py` | Local application orchestration connects existing disclosed ML-DSA issuer, holder, two independently scoped verifiers, authenticated DID registry/resolver and manager revocation. No fake proof gate on this path. DID/version attributes must come from actual validated registry results before issuance. Persist state through explicit owner/head admission; never infer readiness from database presence. |
| `experiments/kyc_testbed_completion_1/mapping.py` plus pinned local mapping data | Implement only approved project-local projections of already validated canonical objects. Trusted issuer/schema/key mapping; exact certified field correspondence; bounded resolver result metadata. Unsupported secured VC/VP and private status mappings remain explicit. No network fetching or caller overrides. See proposed decisions below. |
| Focused case dispatcher / cases, individual results | 24 wallet/recovery cases, 14 connected-flow cases, 10 mapping/privacy/parser cases; every parameterised case and rerun individually charged. Test-only faults cannot enter ordinary interfaces. |
| Measurement runner and new dataset | 24 observations: 18 sequential presentation operations grouped into six three-operation throughput windows (A/B, three sessions); six witness-update scaling observations (history lengths 1/4/8, two independent sessions). Set-up signing/revocation work is outside measured latency but inside time/work/storage accounting. Each measured operation is one invocation. Message/storage sizes collected during those same operations, without uncounted scenario executions. |
| Documentation / evidence | Updated R-001–R-052 coverage; exact commands, input/source identities, conditions, individual outcomes and unavailable measurements. One consolidated preservation checkpoint after implementation and final report/readback, with failures retained. |

The maximum is **72 distinct checks/observations plus four explicitly logged
affected reruns = 76**, within the existing 974/1,050 ledger. No automatic retry.
Prior failed data are retained. A material failure affecting another case suspends
that case until the correction is understood; unchanged cases are not repeated.

Wallet cases cover initial acceptance/restart; exact retrieval; atomic update;
old ticket/wrong owner/instance; generation fencing; stale state, wrong root and
inconsistent credential/witness/identifier; malformed/truncated storage; before
commit and after-commit-before-response faults; bounded actual child interruption;
rollback and partial-state rejection; filesystem/sidecar bounds and unavailable
proof preparation. The final dispatcher must list the 24 literal IDs before it
runs. No collection of hidden subtests is charged as one case.

The 14 application cases cover independent A/B acceptance; replay/cross-audience
denial; issuer recipient/recovery; DID create/resolve/rotate/deactivate and wrong
controller evidence; revocation/witness catch-up; holder restart; expired request;
missing proof backend. Genuine local reference evaluation, synthetic-proof
historical evidence and disclosed-baseline acceptance remain separate categories.

The ten mapping cases cover the trusted issuer/key/schema table, exact canonical
round-trip/projection, metadata conflict, unexpected fields, unsupported keys,
resolver status/error separation, time range/session-vs-credential validity,
private-field leakage, and unsupported proof/securing inputs. These are not an
external W3C conformance suite.

## Resource admission and consolidated prospective request

Authoritative opening is **2,067.2276139201385 implementation seconds**, invocations
**974/1,050**, builds **10/13**; 77,593,603/2^32 work events. Cumulative evidence
is **30,058,985/33,554,432 bytes**, shared headroom **1,473,904 bytes**, artifacts
**58,966,547/134,217,728 bytes**. Historical usage is not reset. The unchanged
ordinary-job reserve is **2,097,152 bytes** inside both evidence ceilings, so no
test can currently be admitted. Source preparation is not a disguised execution.

**Proposed amendment, inactive:** reallocate **1,572,864 bytes** of already
available cumulative evidence headroom into the shared remaining-work allowance.
The opening shared headroom would become **3,046,768 bytes**, before charging this
workstream's actual preparation. The cumulative 32 MiB ceiling remains unchanged;
no existing evidence is deleted, moved or reclassified. This leaves 949,616 bytes
for ordinary work above the unchanged 2 MiB completion reserve, subject to actual
usage. Expected new code/fixtures/results are at most 600 KiB, plus completion
metadata within the reserve. Stop if that estimate ceases to fit.

No added time, invocations, builds or proof allowance is requested. Prospective
workstream ceiling **1,700 charged seconds including its 300-second completion
reserve**: preparation/source work 200, implementation 550, focused validation
300, measurements 200, quality/preservation/reporting 150, unspent completion
margin 300. These are admission estimates, not measured costs or spending targets;
they leave at least 367.227 seconds of the opening implementation balance. Actual
charges and any failed attempts are deducted. No analysis/isolation allowance is
borrowed. Every worker retains the existing memory, process, CPU, timeout and
disk limits; Python/tooling/audit 256 MiB, aggregate 2 GiB, serial worker, two CPUs,
zero swap, ordinary file 1 MiB, temporary data 8 MiB, diagnostic stop 60 KiB.

Use per-case work bounds before dispatch and include all setup in the aggregate
2^32 work counter. Benchmarks are serial local throughput observations, not
saturation/capacity claims. Three-operation windows and two scale repetitions do
not establish tail percentiles. Report raw bytes, operation counts, elapsed time,
database/sidecar sizes and guarded process memory with the exact metric.

## W3C decisions requiring confirmation

The existing KYC-INT-001–004 decisions remain open. Official dated sources are
[VC Data Model 2.0](https://www.w3.org/TR/2025/REC-vc-data-model-2.0-20250515/),
[DID Core 1.0](https://www.w3.org/TR/2022/REC-did-core-20220719/) and
[Data Integrity 1.0](https://www.w3.org/TR/2025/REC-vc-data-integrity-20250515/).
The official pages were checked for this workstream; no third-party suite is
invented and no remote contexts are fetched by adapters.

| Proposed local mapping, inactive until confirmed | Exact boundary |
| --- | --- |
| Trusted issuer mapping | Configure the synthetic issuer URL `https://issuer.kyc.example/` against the exact canonical refI, parameter/instance bytes, issuer public key and schema. It is reserved synthetic configuration, not domain ownership or an issuer URL newly covered by an unchanged signature. A supplied issuer label cannot override this table. |
| Vocabulary | Use `https://vocab.kyc.example/pqdid/v1#` as an explicitly project-local, pinned vocabulary. `kycPassed` derives only from the Boolean field; `assuranceLevel` and integer validity retain exact integer semantics; country remains `countryOctets` with a specified byte encoding, not an invented ISO-country interpretation. Fixed schema-index mappings are part of trusted configuration. |
| DID/key representation | Preserve the exact existing minimal DID document and authenticated registry/controller records. Add resolution metadata plus a **separate local key descriptor** containing the validated ML-DSA-65 public bytes, method version and record identity. Do not add an invented standard verification-method type, JWK/multicodec code, cryptosuite or verification relationship to the signed/canonical document. Standard consumable key representation remains unsupported pending a separately specified mechanism. |
| Canonical binding and securing | Projection is a local view of already verified canonical baseline/reference objects, with explicit provenance and conflict rejection. Do not call it a secured VC/VP, emit `DataIntegrityProof`, accept a wrapper's `verified` flag or treat issuer ML-DSA over Mcred as a signature over arbitrary JSON-LD. The baseline's original full-disclosure signature remains verifiable through its own existing API. |
| Time/status | Credential validity may be displayed only from the certified field, with checked date-time range; session expiry remains separate. Baseline status is explicitly disclosed. No credential-specific URL/rid is inserted into a private projection. A conforming private status mechanism remains unsupported. |

VC2 distinguishes issuer identification, claim meaning and securing mechanisms;
DID Core distinguishes resolution metadata from verification methods. These
proposed local bindings implement useful testbed projections without resolving
the still-missing standards-level securing and key/status mechanisms. Approval
would authorise only these explicit local conventions, not a claim of W3C
interoperability. Declining them leaves the mapping deliverable as a proposal;
wallet, baseline flows and measurements remain independent once resource
admission is resolved.

## Requirement coverage and completion criteria

R-029–031 gain durable holder witness/state handling only after the focused
recovery checks pass. R-012–022 and R-028 gain connected local baseline evidence,
without claiming deployment isolation, cross-store atomicity or actual enrolment
proof integration. R-052 gains only the supported, explicitly local mapping
layer. Complete private authentication, its proof sizes/latencies/memory/throughput,
PQ-DAA comparisons and privacy-overhead ratios remain **unavailable**, never zero
or inferred from the baseline. All 21 historical full-relation circuit checks
stay unrun. Security, production custody and complete knowledge/privacy remain
open. No programme or Stage 2–3 completion claim follows from this workstream.

## Prepared implementation boundary

An isolated, explicitly **unvalidated** wallet candidate is prepared. No active
production module changed. `Head` binds owner/instance, sequence, generation and
the complete canonical snapshot. `Plan` retains the expected post-commit ticket
before mutation, so a lost reply can be resolved by exact committed retrieval
without signing or adopting the database's own head. Preparing a plan is not a
successful update. Commit rechecks the original head and complete transition
under `BEGIN IMMEDIATE`; recovery increments the writer generation and requires
the independently supplied head plus authenticated expected current state.
Explicit valid history may catch up a stale snapshot; silent stale admission is
rejected. A failed fresh bootstrap without a retained independent head remains
quarantined, not automatically adopted.

SQLite policy reuses the existing DELETE journal, synchronous EXTRA and bounded
page/cache/SQL limits. An intact local store and trusted owner are assumptions.
The ticket must be retained independently; storing both ticket and wallet in one
rollback domain does not supply rollback defence. The candidate is a private
holder store, not a proof endpoint or a production custody system. The baseline
wallet and snapshot types are distinct and must not be conflated during the
application integration.

The [literal execution matrix](data/kyc_testbed_completion_1/execution-plan.json)
records 72 individually counted cases/observations, all **unrun**. There are no
new functionality or benchmark results. No requirement has been marked satisfied
on the strength of this draft. Implementation/testing continues only after the
nested evidence reservation is resolved; the local W3C conventions are separately
proposed in the same consolidated decision. Approval of the original workstream
is not being requested again.

## Preservation

Preparation receives the inherited complete audit, final inventory, report
readback and resource closure under unchanged limits. Static lint is not wallet
validation. The original G0 failures/seals and comparison point remain protected.
This preparation is not complete private authentication.


Preparation checkpoint: lint/format and read-only identity checks passed. The
complete preservation audit exited 0: 10,901 disjoint
historical comparisons, 10,936 identity-inclusive
paths, no content/inventory discrepancies. Audit guard time 4.648s;
cgroup-v2 worker peak 47,980,544 bytes (45.758 MiB), including descendants
and charged cache/kernel memory, under 256 MiB. No functional checks or new
measurements ran; the prepared wallet is unvalidated.

The remaining work is blocked on the exact nested evidence reallocation requested
above, not on a renewed approval for the original KYC scope. The mapping proposal
may be approved with it or deferred. Final resource balances and sealed inventory/
readback are recorded in `docs/data/kyc_testbed_completion_1/resource-closure.json`
and `validation-closure.json`. Those records close preparation/preservation only;
**the KYC completion workstream remains incomplete**.

## Approved continuation: implemented result

This section supersedes the preparation-only status and pending approvals above,
which remain intact as historical evidence. The user approved the **1,572,864-byte
transfer** and exact experimental local mappings. The cumulative ceiling remains
32 MiB. Opening reconciliation: 30,222,398 bytes retained; 3,332,034 bytes cumulative
headroom; 1,310,491 bytes previously shared; 2,021,543 bytes unallocated. The transfer
leaves shared headroom 2,883,355 bytes and unallocated headroom 448,679 bytes, with
**2,097,152 bytes still reserved for completion**. There is no double allocation.
The new [execution evidence](data/kyc_testbed_execution_1/amendment.json) continues
all prior time, invocation, build and storage charges.

**Implemented and validated:** durable reference holder storage; a connected local
genuine ML-DSA baseline; and the approved local projection layer. **Incomplete:**
requested larger durable revocation-scaling measurements, external W3C
interoperability, and genuine private authentication. This is not a programme or
Stage 2–3 completion claim. The full PQ-DID/KYC/benchmark scope and 31 October target
remain unchanged; the evidence does not support committing to full completion by
that date. Binius64 remains paused at G0 NO-GO; Aurora remains closed under its
assessed conditions. No replacement construction has been adopted.

### Holder storage and recovery

[`src/pqdid/holder_wallet.py`](../src/pqdid/holder_wallet.py) is an exact byte-for-byte
promotion of the isolated implementation after its 24 focused checks passed.
The promoted import path also passed an explicitly counted recovery revalidation.
There is no active signer/proof/service configuration change. This is a **reference
wallet**, not production custody.

`Wallet.create(pp, path, owner_id, accepted, holder_secret)` starts from the existing
`HolderAcceptance`, checks CredValid and the signed state/path, then stores the whole
canonical credential/witness/state in one private SQLite transaction. `Head`
commits the instance/owner identity, sequence, generation and complete payload.
`prepare_update(expected, target, records)` validates the bounded signed transition;
`commit(plan)` rechecks the expected head, writer generation and entire transition
under `BEGIN IMMEDIATE`. Nothing can retrieve an uncommitted replacement.

Recovery requires the owner to supply an **independently retained Head** and trusted,
freshly authenticated expected current state. `prepare_recovery` does not infer
freshness from a self-consistent database. Explicit verified history is required
to advance a stale wallet. Recovery increments the writer generation and fences
old plans. The owner retains the private Plan/expected after-head **before COMMIT**;
a lost reply is resolved by exact retrieval with that after-head, without signing.
A failed fresh bootstrap without an independent ticket is quarantined.

All 24 wallet outcomes passed: exact retrieval; atomic witness/state change against
an independent sparse-tree path; owner/instance/stale-ticket/old-writer rejection;
wrong state, root, credential fields, rid, secret and signature; malformed/truncated
or incomplete storage; rollback versus independent head; unsafe sidecars; and
unavailable proof verification without mutation. W-17/W-18 inject exceptions.
W-19/W-20 actually terminate a forked child with `os._exit(77)` before/after commit
and validate the reopened result. These do **not** establish power-loss durability,
secure erasure, hostile-owner isolation or rollback resistance when the external
head is rolled back with the store. Encryption-at-rest and secure ticket custody
remain deployment obligations. The historical baseline wallet has a different
credential type; it is not silently treated as this PQ-DID holder store.

### Connected application and approved local mappings

[`Application`](../experiments/kyc_testbed_execution_1/application.py) joins the
existing disclosed-baseline issuer, holder, two independent durable verifier stores,
manager and authenticated DID registry/resolver. It generates fresh synthetic keys
with the existing bounded core. Actual registry/controller ML-DSA records establish
the DID, version and holder/controller public-key binding before issuer admission;
those exact values become certified attributes. Role/key/context selection remains
trusted and existing signed encodings remain byte-identical. Rotation does not
silently rewrite an earlier issuer intent; deactivation prevents new issuance.
The coordinator is trusted and serial. The DID registry is the existing **in-memory
reference registry**; no new crash-durable registry or cross-store transaction is
claimed. F-06/F-12 reuse the baseline's independently retained authority tickets and
check exact issuer/holder reopen, not whole-store rollback protection of that wallet.

F-01–F-14 passed: genuine A/B acceptance; independent exactly-once consumption;
replay and cross-audience denial; original-recipient exact redelivery; reopen;
DID publication/resolution/rotation/deactivation and wrong-controller denial;
revocation/catch-up and revoked-holder rejection; expiry; fail-closed private proofs.
No controlled/synthetic proof adapter participates in baseline acceptance.

[`LocalMapping`](../experiments/kyc_testbed_execution_1/mapping.py) implements the
approved **`pqdid-local-kyc-projection/1`** profile. The trusted synthetic issuer is
`https://issuer.kyc.example/`, pinned to the complete canonical pp, refI, issuer key
and schema. The exact local vocabulary is
`https://vocab.kyc.example/pqdid/v1#`: schema indices 3/4/5/6 map to `kycPassed`,
`assuranceLevel`, `countryOctets`, `validUntil`; designated DID/version fields retain
canonical byte values. Booleans remain booleans, integers are exact decimal strings,
octets are canonical unpadded base64url. Validity seconds receive checked UTC
rendering only through year 9999. Session expiry remains separately named and bound.

DID output preserves the minimal document and supplies **separate local metadata**:
raw ML-DSA-65 public bytes, version and record digest. It invents no JWK/multicodec,
standard verification-method type or cryptosuite. Authenticated absence differs
from resolver unavailability. The existing bounded JSON parser provides size,
depth, collection, duplicate-key, exact-type and numeric-token rejection. Validation
reconstructs the entire expected view from trusted canonical objects and compares
it exactly; extra metadata, key overrides, acceptance flags and proof placeholders
are rejected. It fetches nothing. All M-01–M-10 passed.

An anonymous projection accepts only the existing public AuthenticationStatement
and its already disclosed fields. It does not add a holder public key, secret,
credential, rid or new stable identifier. DID/version can appear only if already
explicitly disclosed by that statement. The local issuer/vocabulary table is
application configuration; the existing credential signature is **not** a signature
over arbitrary JSON-LD. These are local unsecured projections, not secured VCs/VPs
or external interoperability. The official dated W3C sources above are reused.
Standard securing/key representation, real issuer governance and private status
mapping remain open.

### Additional benchmark evidence and concrete stop

The new dataset is [measurements.json](data/kyc_testbed_execution_1/measurements.json),
with 19 successful observations and individually retained raw case records. All
**276 v1 measurements** and comparison-point identities are unchanged.

- Eighteen genuine presentation operations: three independent fresh-key sessions,
  A/B, three sequential operations each. The six active-operation rates are
  **1.771, 1.754, 1.815, 1.979, 1.728, 1.826 operations/s**. Rate means three divided
  by summed request + presentation + verification/atomic-consumption time. Setup,
  inter-case ledger/reporting gaps and storage scans are excluded; this is not
  continuous wall-window throughput or a saturation/capacity estimate.
- Canonical requests are **7,554 bytes** and disclosed presentations **22,948 bytes**.
  Credential, signature, state, path, reply and individual store sizes are also
  recorded. File sizes are observed snapshots, not fsync/power-loss measurements.
- One-record authenticated history fetch, verification and holder update took
  **108.884 ms**, over an **11,162-byte update record**. Setup is separately recorded.
  One such observation cannot establish a scaling curve or tail percentile.

R-1-4 **failed in setup**, not catch-up: the baseline issuer journal hashes a complete
encoded session inventory under the existing **65,536-byte** local-record cap.
Certification of the next credential exceeded that cap. Read-only inspection of the
retained store finds **three CERTIFIED sessions and one SIGNING session**, sequence
16/generation 1; no replacement SQL writes or credential release occurred for the
failed certification. The permanent manager reservation remains. This is an
application storage bound, not a cgroup memory/disk breach or a cryptographic
rejection. The failed timing is not included as a successful measurement.

The exact new disposable failed stores (553,757 bytes) were archived losslessly to
61,304 bytes, with every pathname, byte length, mode and SHA-256 read back before
cleanup. The archive remains private evidence with synthetic keys; it was not
reclassified as an artifact. No historical store or failure was deleted or moved.
See [failure analysis](data/kyc_testbed_execution_1/failure-analysis.json) and
[archive inventory](data/kyc_testbed_execution_1/failed-R-1-4-inventory.json).

R-1-8 was not admitted: eight retained manager update records alone require
89,328 bytes, exceeding the same checkpoint cap before any other fields. R-2-1,
R-2-4 and R-2-8 remain unrun after the scaling stop. No limit was increased, no
failed trial retried and no in-memory substitute presented as durable scaling.
Larger-history completion requires a **separately versioned incremental authenticated
issuer/manager storage design**, with complete heads, independent recovery,
permanent reservations, exact outcomes and fencing preserved. Merely raising a
session-count limit or optimising a hash will not remove this encoding obstruction.
No such architectural change or new resource allocation is made here.

Private proof latency, verification latency, proof size, prover/verifier memory,
private throughput, PQ-DAA performance and privacy-overhead ratios remain
**unavailable**. None is inferred from this baseline.

### Reproduction, coverage and accounting

The active source identity, exact guarded commands, CPU/WSL/Python/SQLite conditions,
synthetic clock model, per-operation durations, outcome and resource records are
in `docs/data/kyc_testbed_execution_1/`. Fresh entropy is intentional: reproduction
means matching source/conditions/behaviour, not identical random keys/signatures.
The original literal 72-entry matrix is retained. Actual usage is **71 invocations**:
68 passed, three failed; 68 distinct planned cases attempted and four unrun. This
includes one W-01 fixture-argument correction, one F-01 resolver-argument correction,
and one affected W-02 import-path revalidation. Failures and static diagnostics are
retained; the successful reruns do not overwrite them. The ledger is **1,045/1,050**;
builds stay **10/13**, proof attempts **two used, one unused**. No circuit events
were emitted/evaluated; the inherited 77,593,603/2^32 gate/row-work count is unchanged.
Host setup, signing, checking, reporting and cleanup are charged to time/resources.

Example recorded commands (historical jobs must not be automatically rerun):

```sh
.venv/bin/python -I -B experiments/kyc_testbed_execution_1/run.py job wallet-cases-corrected python 150 -- /home/grace/projects/pq-did/.venv/bin/python -I -B /home/grace/projects/pq-did/experiments/kyc_testbed_execution_1/dispatch.py W
.venv/bin/python -I -B experiments/kyc_testbed_execution_1/run.py job connected-flows-corrected python 150 -- /home/grace/projects/pq-did/.venv/bin/python -I -B /home/grace/projects/pq-did/experiments/kyc_testbed_execution_1/dispatch.py F
.venv/bin/python -I -B experiments/kyc_testbed_execution_1/run.py job throughput-session-1 python 90 -- /home/grace/projects/pq-did/.venv/bin/python -I -B /home/grace/projects/pq-did/experiments/kyc_testbed_execution_1/dispatch.py T 1
```

A future reproduction needs explicit invocation/time admission and a fresh evidence
ledger linked to this immutable checkpoint. Existing commands reject successful
case reuse and existing output paths. No unguarded rerun or counter reset is implied.

[Requirement-level coverage](data/kyc_testbed_execution_1/coverage.json) indexes all
R-001–R-052 and preserves four evidence categories: working disclosed baseline;
validated local PQ-DID reference functionality; historical synthetic-proof scenarios;
and unavailable genuine private authentication. Durable holder work adds evidence
to R-029–031 and persistent-state obligations; connected flows support R-012–022 and
R-028 within their stated limits. R-052 gains the approved local bindings only.
The 21 complete-relation checks remain unrun. Adaptive Delta_tail, component
advantages at reduction budgets, QROM knowledge/extraction, privacy/commitment/hash
composition, finite parameters, production entropy/custody/erasure/side channels
and deployment isolation remain open.

The remaining construction decision is unchanged: reopening Binius64 requires G0's
specific committed-key/support-rank/joint-view correspondence, or an explicitly
approved replacement integrated construction meeting the retained handover. No new
backend survey or private implementation is started. Product decisions remain the
larger-history storage design and standards-level securing/key/private-status
mechanisms. Current local mapping approvals do not settle those decisions.

### Continuation Preservation

Final scoped lint/format, complete historical preservation, final inventory, report
readback and guard shutdown are recorded below when completed. The unchanged audit
worker ceiling is 256 MiB, including descendants/cache/kernel charges. This work is
not complete private authentication. Stages 2–3 remain open; isolation remains
stopped/unactivated and CPU proving paused.


Continuation preservation audit **passed**, exit 0: 10,901
disjoint historical content comparisons, 10,936
identity-inclusive paths, no changed/missing protected content, no inventory
discrepancy. Full audit guard time 4.750s; worker cgroup-v2
`memory.peak` **48,279,552 bytes (46.043 MiB)** including descendants
and charged cache/kernel, below 256 MiB; no resource-guard breach. Final readback,
shutdown, exact inventory and balances are sealed in
`docs/data/kyc_testbed_execution_1/validation-closure.json` and
`resource-closure.json`. Original failures remain failures; this successful audit
does not supply missing functional/scaling/private-proof results.


### KYC-ISSUER-INCREMENTAL-STORAGE-1

The isolated v2 issuer stores bounded per-session records and atomic digest-event/head
updates, with explicit origin-bound migration and independent freshness tickets.
35 storage/recovery cases, eight genuine bounded-ML-DSA application cases and three
new baseline scaling observations passed (46 invocations; 1,091/1,146 cumulative).
The retained v1 four-record failure is reproduced on a sealed copy, then resolved in
v2; actual four-record catch-up now passes. R-2-1 and R-2-4 are newly measured.
R-1-8/R-2-8 remain unrun: the unchanged manager aggregate checkpoint needs at least
89,296 update-payload bytes before other fields, exceeding 65,536; its observed
four-record database is already 475,136/524,288 bytes. The manager needs a separately
scoped incremental history/checkpoint/outcome design before larger-scale admission.
No manager architecture or limit was changed implicitly. See
[issuer storage report](kyc_issuer_incremental_storage.md) and its new evidence series.
Original 276 and subsequent 19 observations, v1, protected sources and failures stay
unchanged. Private authentication/security/standards obligations and Stages 2–3 remain
open; this is not completion of the KYC workstream or original programme. Binius64
remains paused, private verification fail-closed, proof ledger two used/one unused.


Preservation checkpoint: the single full audit **passed**, exit 0, with
10,901 disjoint historical comparisons and
10,936 identity-inclusive paths; no changed/missing
protected content or inventory discrepancy. Guard time 4.840s; worker
`memory.peak` 48,730,112 bytes (46.473 MiB), including descendants
and charged cache/kernel, below 256 MiB with no resource breach. Final inventory,
report readback, terminated workload and actual balances are recorded in
`docs/data/kyc_issuer_incremental_storage_1/validation-closure.json` and
`resource-closure.json`. Historical failures remain failures; two eight-record
measurements remain unrun, and no missing private-authentication result is supplied.


### KYC-MANAGER-INCREMENTAL-STORAGE-1

The isolated manager-v2 storage, bounded public-state paging and atomic holder
catch-up now pass 47 distinct checks (49 invocations including two retained, corrected
failures). R-1-8/R-2-8 completed: eight updates, two 55,041-byte responses, one final
wallet update; manager DB 450,560/524,288 bytes. Largest validated history is eight.
One/four-record affected measurements are also retained as a new series. Original
276, subsequent 19 and issuer-v2 three observations remain immutable. No larger-scale
capacity, private authentication or privacy-overhead claim follows. See
[manager storage report](kyc_manager_incremental_storage.md) and its individual outcomes.
Cumulative invocations 1,140/1,146; builds 10/13; proof ledger two used/one unused.
KYC-TESTBED-SCALE-001's tested four/eight-record obstruction is resolved for v2;
production custody/rollback/power-loss, larger capacity, standards-level interoperability
and full proof/security obligations remain open. Stages 2–3 remain open; private
verification fail-closed, Binius64 paused, proving/isolation paused. The full scope
and 31 October target remain unchanged without a supported completion commitment.


Preservation checkpoint: the single full audit **passed**, exit 0, with
10,901 disjoint historical comparisons and
10,936 identity-inclusive paths; no changed/missing
protected content or inventory discrepancy. Guard time 4.878s; worker
`memory.peak` 49,483,776 bytes (47.191 MiB), including descendants
and charged cache/kernel, below 256 MiB with no resource breach. Final inventory,
report readback, terminated workload and actual balances are recorded in
`docs/data/kyc_manager_incremental_storage_1/validation-closure.json` and
`resource-closure.json`. Historical failures remain failures; two eight-record
measurements remain unrun, and no missing private-authentication result is supplied.


## KYC-TESTBED-DELIVERY-1 — current delivery evidence

[Delivery report](kyc_testbed_delivery.md) and
[interoperability limits](kyc_testbed_interoperability_limits.md) provide the current
reproduction entry points and requirement boundary. All 18 fixed invocations passed
once: 10 genuine baseline demonstrations, 4 export checks and 4 smoke observations.
No functional rerun occurred; one failed static pass and its correction are retained.
V2 recovery uses the versioned issuer interface, not historical Scenario.reopen.
Seven-update catch-up used two bounded pages; own revocation reached epoch eight.
The baseline wallet and private reference wallet remain different objects; the DID
registry remains an in-memory reference service.

Verified/exported 302 retained successful observations in separate 276/19/3/4
datasets, with seven historical failed invocations separately indexed; four new
runner-smoke observations remain separate. No distribution/capacity/private-proof
measurement is inferred. The earlier statements that benchmarks do not exist or
eight-record scaling remains unrun are superseded by the retained benchmark and
manager-v2 results; their historical text/evidence is preserved.

Ledger before finalisation: 1,183/1,190, four delivery correction slots and three
embedding-only slots unused, builds 10/13, proof ledger two used/one unused. The
20-second preparation charge and 80-second internal transfer are recorded once;
220-second package and 2 MiB evidence caps retain KYC's 300-second/shared 2 MiB
reserves. Exact checkpoint and balances are in data/kyc_testbed_delivery_1 closures.
KYC-INT-001–004 remain standards obligations; approved local projections are not
secured VCs/VPs or an invented cryptosuite. CV-ONLINE-SAME-OBJECT-1 remains unresolved
and its attempt closed. Full scope, 31 October target and Stages 2–3 remain unchanged;
no supported full private-authentication completion commitment follows. Private
verification is fail-closed; Binius64 proving/isolation paused. No next package.

### KYC delivery preservation correction and final checkpoint

All 18 fixed delivery cases passed once. The first preservation comparison rejected
the newly appended benchmark README because its exact documentation permission was
missing at the inherited primary layer. The retained 211-byte prefix seal matched;
the routine correction registered only that filename while retaining prefix checks,
immutable inputs and the failed attempt. Corrected static/preparation/full audit
passed: 10,901 historical content comparisons and 10,936 identity-inclusive paths.
See docs/data/kyc_testbed_delivery_1/validation-closure.json for final inventory,
readback and termination, and resource-closure.json for exact final balances.
No functional revalidation was needed for this tooling-only correction. Baseline
items alone are eligible for closure; KYC-INT-001–004 and CV-ONLINE-SAME-OBJECT-1,
private authentication/security and Stages 2–3 remain open. All pauses are unchanged.
