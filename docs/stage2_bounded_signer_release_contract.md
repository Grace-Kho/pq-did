# S2-BOUNDED-SIGNER-RELEASE-CONTRACT-1

25 September 2026. Isolated reference adapters and release-contract checks only.
**All 18 focused tests pass.** No live signing, host activation or proof work was
performed. Existing source, fail-closed production defaults and the completed
bounded ML-DSA core are unchanged. The measured preservation closure below is
required in addition to the functional result.

## Authority, baseline and carried allowance

Only manuscript Sections **II–VIII**, agreed SPEC-001–004 clarifications and the
[current specification](implementation_spec.md) apply. The manuscript identity is
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
[Preflight](data/s2_bounded_signer_release_contract_1/preflight-evidence.json)
verified all 66 entries of the completed bounded-core seal
`888305ac284a0872ea3f6fc7993e5d5626529a631e7b79c1309b689f4821505f`, plus all 53
assessed source inputs. The [previous report](stage2_bounded_mldsa_keygen_sign.md),
its exact native interoperability evidence and DEP-001/DEP-002 findings are reused.
No native ABI harness, historical test suite or numerical security calculation was
repeated. No original baseline was regenerated.

The existing implementation allowance began this package at **11.616396492929198 s
charged / 288.3836035070708 s remaining**, and **79/100 test invocations used**.
This package adds 18 invocations, leaving **3**, not a fresh allowance of 100.
Its [configuration](data/s2_bounded_signer_release_contract_1/config.json) and
[run ledger](data/s2_bounded_signer_release_contract_1/run-ledger.json) carry forward
that charge and the previous 409,577 evidence bytes. Analysis has
270.1814811680233 s remaining; isolation has 250.22 s including its ten-second
reserve. Neither separate allowance is consumed. Existing safe-stopped/unactivated
isolation evidence is reused: 100 historical invocations, 22 identity cases pending,
retained failures/approvals/host resources unchanged. The proof ledger remains
**two attempts used, one unused**; CPU proving stays paused.

## Trusted selection and operation mapping

[The new module](../src/pqdid/signing_adapters.py) is opt-in and has no import into
the old service defaults. Owner construction provides a frozen `TrustedSigningKey`:
complete public parameters, 32-byte service identity, authority role, 1–64-byte
local key reference, expected public key and expanded private key. Reference and
service identity are local authority handles, not new signed fields. Expanded-key
import uses the unchanged bounded core to recompute and compare the public identity.
The selected parameters, role and public key must match the configured adapter.
The key reference comes only from owner configuration; no request selects it.

The owner also supplies a trusted `SigningAuthorisation` dependency. Its default
denies. It receives the exact pinned key, fixed operation and typed inputs, and must
return literal `True` both before signing and immediately before returning the
signature. The synthetic lifecycle tests use explicit local grants tied to those
keys. This callback is an authority integration seam, not a claim of remote user
authentication. Durable issuance instead binds it to the existing store policy,
writer permit, service/role/instance and independently held generation/head ticket.

Every row uses the configured key reference for its indicated role. Instances are
checked against the full pinned `PublicParameters`; DID configuration additionally
pins the registry, and verifier configuration pins the audience and request key.
Every context below is the exact existing ASCII `PQ-DID/<operation>/v1` context.

| Operation / authorised role | Expected public identity | Existing exact message constructor | Fixed context | Lifecycle release condition |
| --- | --- | --- | --- | --- |
| Credential / issuer | `pp.issuer_public_key` | `build_mcred(pp, pp.metadata, binding, rid)` | `PQ-DID/credential/v1` | Approved enrolment/binding, permanent manager reservation and certification log before credential delivery |
| Revocation request / issuer | `pp.issuer_public_key` | `build_revocation_request_message(pp, request)` | `PQ-DID/revreq/v1` | Authorised typed identifier/current reference/nonce; manager verifies before mutation |
| State / manager | `pp.revocation_public_key` | `build_state_message(pp, state)` | `PQ-DID/state/v1` | Both new-state and update signatures validated before atomic publication |
| Update / manager | `pp.revocation_public_key` | `build_update_message(pp, update)` | `PQ-DID/update/v1` | Same atomic state/history/revoked-set/consumed-nonce snapshot commit |
| Current / manager | `pp.revocation_public_key` | `build_current_message(pp, nonce, state)` | `PQ-DID/current/v1` | Final locked comparison with the current snapshot |
| DID record / controller | Genesis key, or active predecessor controller key | `encode_body(body)` | `PQ-DID/did-record/v1` | Exact pending signed record; confirmation only after registry append; rotation successor signed by previous key |
| Registry read / registry | `DIDConfiguration.registry_public_key` | Existing `encode_record("did-read", (registry_id, did, selector, nonce, status, encode_record("did-chain", records)))` | `PQ-DID/did-read/v1` | Ordered trusted registry snapshot; append already verifies records; no latest-at-delivery claim |
| Enrolment control / controller | Active controller at certified DID/version | `encode_enrol_statement(pp, statement)` | `PQ-DID/control/v1` | Exact statement, matching active trusted DID/version; issuer retains current-controller recheck |
| Verifier request / verifier | Configured audience request key | `encode_context(pp, context)` | `PQ-DID/request/v1` | Reserve nonce before signing; failure retains reservation and returns no request |

The public adapter methods accept typed protocol inputs, not caller-supplied
contexts, roles, key handles or arbitrary messages. Invalid instance, foreign
audience/controller, malformed canonical field and override attempts fail. The
controller checks predecessor/index, DID derivation, rotation and deactivation
before signing. A rotated old key cannot sign the next record; a deactivated
record cannot gain a successor. Existing lifecycle final checks remain in place.

Unchanged lifecycle engines expect a `Signer.sign(message, context)` dependency.
A **private compatibility bridge** admits only the fixed grammar for its configured
role, reconstructs typed values under the pinned parameters and requires exact
whole-input re-encoding before invoking the typed method. It rejects foreign
contexts, trailers, suite/metadata substitution and noncanonical fields; bounded
registry history and the existing read-byte limit apply. Internal zero signature
slots reconstruct unsigned message fields only, and are never returned. The bridge
is an owner dependency, not an unrestricted raw-message endpoint. Python private
attributes are not an isolation boundary against arbitrary code in the same process.

All signing uses `bounded_sign_mldsa65`, fixed role contexts, fresh OS entropy and
the completed verification-before-return path. Caps remain **1026 / 512 / 256 bytes**
for the three samplers and **1024 candidate attempts**. There is no native fallback,
cap escalation or automatic retry. Sampler/attempt exhaustion propagates as
`SigningStatus.EXHAUSTED`; entropy/post-verification and admission failures return
failure with no signature. Unexpected runtime/resource errors propagate without
release. The request bridge preserves the existing exception-based request contract.
Key import, signing attempts and internal pre-return verification still count in
security/workload accounting even when no signature is released.

## Release ordering and recovery

The existing `ReferenceIssuer` permanently allocates an identifier before preparing
the challenge, checks the original approved binding/controller/proof statement,
signs once and commits certification before returning `IssuedCredential`. A failed
sign or log leaves no certification/result, retains the allocated identifier and
used nonce, and aborts the session. Repetition is a replay failure, not resigning.
An unauthorised begin request is rejected before allocation.

The existing `ReferenceRevocationManager` constructs and verifies both state and
update signatures privately. Its final atomic snapshot comparison publishes state,
history, revoked set and consumed nonce together. A second-signature failure returns
neither state nor update. A competing allocation before final commit causes conflict;
only that separately authorised allocation survives. These are **in-memory** atomic
contracts, not evidence of a durable manager transaction across a crash.

`BoundedDurableIssuer` composes the existing `DurableIssuer` and SQLite store. It
exposes intent/attach/pending/reconcile/snapshot/stored retrieval, plus typed
`certify(claim_operation, certificate_operation, issue_operation, submission)`.
Callers cannot inject a finished credential, recipient, signer or key/context.
The existing single-use signing claim commits before signing. The original session
and recipient come from the stored entry; a private reconstructed reference issuer
performs the existing enrolment checks with the bounded adapter. The successful
candidate is encoded through existing `IssuedRecord`/`WitnessRecord` constructors
and passed to the existing certification-log transaction. The operation result is
redacted (`response == b""`); private credential bytes become deliverable only
through the committed outcome and recipient-bound publication path.

The durable authorisation check requires the existing `sign-issue` policy and exact
generation/head admission before and after signing. A replacement writer fences
the old generation even if signing has just completed. A failed signing/logging
claim stays `SIGNING` until explicit reconciliation; it cannot be retried to obtain
another credential. Explicit retirement preserves the allocation. Commit failure
cannot create a recoverable certification row or deliverable private response.

Successful stored redelivery does **not** call the signer. Temporary SQLite reopen
with the independently retained ticket reproduces the exact committed bytes for
the original recipient. A wrong recipient receives no socket bytes. An injected
failure before enqueue receives no bytes; later correct retrieval works and a
further retrieval is labelled `REDELIVERY`. The test does not claim bytes were
already enqueued before that simulated interruption. Existing publish-time fencing
and recipient checks are retained, not replaced by a self-consistent-store test.

These tests use actual temporary SQLite transactions, socket pairs and application
fault points, with synthetic approvals, keys and authority principals. The proof
adapter recognises an exact locally evaluated enrolment statement/token: **reference
evidence, not a cryptographic proof**. No crash/power-loss durability, operating-system
identity isolation, production key custody or full lifecycle integration is claimed.

## Focused validation

[Tests](../tests/unit/test_signing_adapters.py) generate six keys from public
synthetic seeds using the completed reference core, modify only temporary fixture
objects/stores and retain no expanded secret keys in evidence. Normal signatures
use the bounded hedged wrapper. Fault injection exists only in the tests through
temporary monkeypatches; the ordinary adapter interfaces accept no fault callbacks.

| Focused case(s) | Returned outcome and service-state assertion |
| --- | --- |
| Trusted selection and override rejection | Wrong instance/role-context/trailer and role/key/context override attempts fail; no manager mutation or issuer certification |
| Default denial and identity mismatch | Default gate denies; wrong expected public identity, secret/public mismatch or role fails import/admission; no allocation/certification |
| All nine authorised operations | Credential logged, revocation committed with state/history/nonce, current read and verifier request valid; operation set covers all nine roles |
| Unauthorised begin / invalid enrolment | Unauthorised begin allocates nothing; bad proof fails before credential signing while permanent allocation and used nonce remain |
| Four signing faults: entropy, sampler, attempts, post-verification | All return no credential; exhaustion distinguished; aborted session, no log, one permanent allocation; replay does not sign again |
| Issuance log failure | A real signed private candidate cannot escape failed commit; resource failure, no certification, allocation retained |
| Second revocation signature failure | Real state signature remains private when update signing fails; identical manager snapshot and no returned state/update |
| Revocation final commit conflict | No update/state publication or consumed nonce; only concurrent permanent allocation survives |
| DID rotation/deactivation/stale key | Confirmed rotation changes trusted key; old key fails; deactivation blocks successor without registry mutation |
| Authority withdrawn during signing | Post-sign authority check discards signature; no credential/log, allocation retained |
| Durable commit, recipient and interrupted redelivery | Redacted successful commit; wrong recipient and interrupted enqueue release no bytes; reopen/redelivery returns exact committed bytes with zero new signatures |
| Durable log failure and retirement | SQLite rows-before-commit fault leaves `SIGNING`, no certification/delivery; repeated claim denied; explicit retirement, allocation retained |
| Durable writer fencing and stale head | Replacement generation wins during signing; no log/result, old writer/head denied, no resigning |
| Verifier request failure | Request absent, nonce remains pending/reserved, no consumed challenge |
| Ordinary API/default checks | No public raw signing, arbitrary certificate commit or fault hook; original unsupported issuer/manager defaults unchanged |

These are **18** pytest invocations (the four signing faults are four cases), all
passing in **10.51 s pytest time**, **10.749834676 s guarded wall time**. JUnit and
complete command/resource records are in
[focused.xml](data/s2_bounded_signer_release_contract_1/focused.xml) and
[focused.json](data/s2_bounded_signer_release_contract_1/focused.json).
The focused worker cgroup `memory.peak` was **49,573,888 bytes**; separately sampled
tree RSS was 71,483,392 bytes. Temporary storage observed peak was 217,696 bytes,
with none retained. No functional failure, extra invocation or automatic retry.

## Resource and preservation procedure

The [guard](data/s2_bounded_signer_release_contract_1/run_checks.py) continues the
existing accounting and ceilings: one sequential worker, two CPUs, 256 MiB aggregate
cgroup-v2 memory with swap zero, 60 s command / 55 s child, 300 s cumulative
implementation allowance, 8 MiB temporary storage, 10 MiB cumulative package output,
1 MiB per file, 60 KiB command diagnostic stop, existing 9 GiB experiment-storage
stop and 2 GiB memory headroom reserve. Charged cache/kernel memory and descendants
are included. The separate RSS observation is not the kernel cgroup metric. Five
additional seconds cover bounded operator/closure bookkeeping under the existing
accounting rule; they do not reset the 300-second allowance.

Commands use the package runner with, in order, `preflight`, `source-format`,
`focused`, `final-source-format`, `quality`, `correction-format`, `quality-final`,
`format`, `prepare`, `full-audit`:

```sh
.venv/bin/python -I -B docs/data/s2_bounded_signer_release_contract_1/run_checks.py NAME
```

The exact expanded systemd commands are in the run ledger. These are private-network
user validation workers, not pilot/authority deployment activation. `close.py`
performs bounded write-once reporting after the single full audit. No historical
tests, native harness, estimator, circuit, proof, zkVM or host-pilot command is run.

The initial lint check found I001 import ordering and an unused local variable in
the new bridge. Both were corrected without changing semantics; the failed record
and its time remain charged. A [source-reviewed correction](data/s2_bounded_signer_release_contract_1/correction-quality.json)
admits the separately named final lint check. No functional test is repeated and no
resource limit changes. The original `STOP.json` evidence is retained.
The final-lint admission first stopped before launching a worker because an inherited
`correction*.json` scan also matched the new formatter job's measurement file.
[That diagnostic](data/s2_bounded_signer_release_contract_1/admission-diagnostic.json)
is retained. Admission now reads only the exact reviewed `correction-quality.json`
record. This narrows the record selection; no failed workload is skipped, no test
ran during the admission failure, and its bookkeeping is within the fixed charge.

The only new implementation files are `src/pqdid/signing_adapters.py` and
`tests/unit/test_signing_adapters.py`. New package evidence/helpers and this report
are added. Status, traceability and issues receive append-only updates whose original
prefixes were sealed before editing. The original corrected auditor's content,
inventory, path/symlink semantics and SHA-256 algorithm are reused unchanged under
the same 256 MiB ceiling. Disjoint original/supplemental coverage, complete reporting
and the outer guard must all pass; no limit failure counts as a complete audit.

## Disposition and next bounded implementation

Satisfied at the **reference** boundary: trusted fixed key/role/instance selection,
typed canonical signing for all nine contexts, pre-return verification reuse,
failure without partial lifecycle release, permanent reservation, atomic in-memory
revocation, durable issuer commit/fencing and recipient-bound stored redelivery
without resigning. DEP-002's reference adapter subtask advances; its production
disposition remains open. No specification or profile change is made.

Still open: durable manager state/update/current publication with bounded signing;
complete all-role durable integration and actual-identity isolation; approved
production key provisioning/custody and entropy; reliable erasure, side-channel and
fault resistance; DEP-001/SEC-003 adaptive `Delta_tail` and component advantages at
reduction budgets; full BC-1 conformance and complete proof knowledge/privacy,
including SEC-001–005 and OC-REL/EXT/PRIV/BUDGET. Synthetic key consistency does not
prove provenance or production authority. The manuscript construction, implemented
reference components and experimental RISC Zero evidence remain separate.

One recommended next implementation package: **S2-BOUNDED-MANAGER-DURABLE-RELEASE-1**,
an isolated synthetic extension of the existing durable manager contract to commit
bounded state/update signatures, revocation history and consumed nonce atomically,
with stored-outcome recovery and fencing. Use the unchanged schema/encodings and
bounded core; no activation or proof work. Plan its focused checks against the
remaining three implementation invocations rather than silently resetting them;
any additional allowance needs explicit authorisation. This package is not started.
Stages **2–3 remain open**.


## Measured validation closure

The single [complete preservation audit](data/s2_bounded_signer_release_contract_1/result.json)
passed content/inventory comparison, report readback and its outer resource guard,
exit **0**. Coverage: 8,759 original and
942 supplementary paths,
**9,701 disjoint content paths**,
9,717 identity-inclusive paths.
No unexpected changes, additions or removals occurred. Three historical reports
have verified append-only prefixes; all pre-existing source/vectors/parameters,
manuscript, dependencies and original evidence are preserved. The only new source
is the separate adapter module and its focused test file. Lint and formatting pass.

| Measurement | Result |
| --- | --- |
| Audit wall time | 2.286035420 s |
| Audit cgroup memory.peak | 23,945,216 bytes |
| Audit sampled process-tree RSS | 41,975,808 bytes |
| Maximum guarded-job cgroup memory.peak | 49,573,888 bytes, below 268,435,456 |
| Maximum observed guarded-job tree RSS | 71,483,392 bytes; separate metric |
| Guarded commands | 10, 13.922685896 s total; one corrected lint failure retained |
| Cumulative implementation charge | **30.539082389/300 s** |
| Remaining implementation allowance | **269.460917611 s**, **3/100 test invocations** |
| Test invocations | 79 previously charged + 18 new focused = 97; no repeats in this package |
| Functional failures/resource breaches | 0/0 in this package; all historical evidence retained |
| Temporary storage | 217,696 observed peak bytes; zero retained |
| Package bytes at outer audit completion | 334,482 |

The audit's unchanged **256 MiB** metric is cgroup-v2 memory.peak for the complete
worker/descendant tree, including charged file-cache/kernel memory; swap is zero.
The cumulative time includes 11.616396493 s previously charged and five new
bookkeeping seconds; analysis and isolation time were not borrowed.
The external RSS sample can count shared pages more than once. No execution/proving
cost inference is made. The final bookkeeping has a separate 256 MiB address-space,
CPU/alarm-five-second, two-CPU and 1 MiB-file bound, within the five-second charge.
It checks new outputs, exact names, links and report prefixes, then writes the
[closure](data/s2_bounded_signer_release_contract_1/validation-closure.json) and
[new additive seal](data/s2_bounded_signer_release_contract_1/manifest.json) once; it does
not repeat the protected content scan or regenerate a historical baseline.

Analysis **270.181481168 s** and isolation **250.22 s** remain untouched. Stages
2–3 remain open; DEP-001/002 production obligations, adaptive Delta_tail, side
channels/erasure and complete private-proof knowledge/privacy remain unresolved.
Isolation stays safely stopped/unactivated. No proof/zkVM/activation occurred;
proof ledger two used/one unused. Next recommendation remains the bounded
**S2-BOUNDED-MANAGER-DURABLE-RELEASE-1**; it is not started.
