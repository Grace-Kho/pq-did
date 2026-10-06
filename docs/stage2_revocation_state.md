# S2-REVOKE-STATE-1 — bounded manager-side revocation reference

19 September 2026. **Implemented and validated at the reference-state-machine
boundary:** authorised revocations atomically publish a consistent tree/state/log
snapshot; failures publish nothing. Signed ordered current-state replies and
bounded public update pages compose with the existing holder and verifier models.
**73 focused and 25 scoped regression cases pass**, with no skips or test resource
stop. **The final preservation audit reached the 256 MiB cgroup ceiling.** Its
content checks completed, but the guard returned failure and closed validation.
No retry or limit increase followed; clean final-audit resource acceptance remains
unresolved. The authoritative package outcome is in [result.json](data/s2_revoke_state_1/result.json).

No proofs, zkVM executions, installs or changes to the active suite/parameters were
made. CPU proving remains paused; **two proof attempts used, one unused**.
Bounded production signing, persistent storage and distributed services are not
implemented by this package.

## Authority, inputs and authorisation assumptions

Read [AGENTS.md](../AGENTS.md), [implementation specification](implementation_spec.md),
[verifier-state contract](stage2_verifier_state.md),
[holder-update contract](stage2_witness_updates.md), status, traceability and the
issue register. Only manuscript **Sections II–VIII** supply requirements, particularly
IV-A/B/C, V-B/D, VII-A.1/.5/.7/.8 and VIII-E's service boundary. Checked the selected
PDF before implementation; SHA-256 remains
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
SPEC-001–004 are preserved. No genuine ambiguity or new cryptographic convention
was needed.

[revocation_state.py](../src/pqdid/revocation_state.py) defines
`ReferenceRevocationManager`. Its constructor imports a **trusted local manager
checkpoint**: pinned public parameters, authenticated current state, permanent
allocation counter, revoked set and complete consumed-revocation-nonce set.
It checks representation/capacity, registration of revoked identifiers, the state
signature with the existing bounded verifier, and the independently recomputed
tree root before making an instance available. Invalid input or authentication
raises a fixed `EncodingError`/`ManagerError`; resource failures activate no
partially initialised service.

R-018's sequential, non-recycling allocation is represented by the prefix
`[0, allocated_count)`, with counter in `0..2^20`. This is an imported counter,
not an allocation API or new protocol. No issuance-success flag is required:
R-030 permits revoking an allocated identifier even after aborted issuance.
Unallocated and already-revoked identifiers reject. The only permitted transition
is an allocated leaf **0 → 1**, advancing the uint64 epoch by exactly one without
wraparound. There is no reuse, unrevoke, DID-deactivation or credential-edit operation.

The constructor's pp and allocation/nonce data must come from the manager's trusted
configuration/storage. A valid state signature authenticates the signed root/epoch;
it does not authenticate an arbitrary imported allocation counter or establish the
completeness of its nonce set. This reference import does not prove the checkpoint's
entire history from genesis, implement Setup or provide crash restoration. Existing
synthetic old-state fixtures are checkpoints, not reconstructed lifecycle executions.
Missing historical update data is reported as unavailable, as detailed below.

For `revoke(request)`, the local `RevocationRequest` carries rid, the expected
starting state reference, and the specified `req=(nR,β)`. This typed carrier
introduces **no new wire encoding**. The manager uses its pinned issuer key to
authenticate the request and its pinned manager key to check generated artefacts;
request bytes cannot select the keys or namespace. `instance(expected)` supplies
the verifier's existing interface only for exactly matching configured parameters.
It is not issuer discovery, key registration or DID trust validation.

## Exact signed data and public records

| Signature | Key and external ML-DSA context | Exact authenticated body |
|---|---|---|
| Revocation request β | Issuer; `PQ-DID/revreq/v1` | `MR=enc_revreq(suite,E(µ),[rid]4,E(refe),nR)` |
| State τe+1 | Manager; `PQ-DID/state/v1` | `enc_state(suite,E(µ),[e+1]8,Ae+1)` |
| Update υ | Manager; `PQ-DID/update/v1` | `Mu=enc_update(suite,E(µ),E(refe),E(refe+1),[r*]4,s*0||...||s*19)` |
| Current-state reply | Manager; `PQ-DID/current/v1` | `enc_current(suite,E(µ),nS,E(rse))` |

Here `µ=(refI,ns)`, `refe=(ns,e,Ae)`, and `rse=(ns,e,Ae,τe)`.
The nonce is 32 immutable bytes; rid is an integer in `0..2^20−1`, encoded in
four big-endian bytes. Boolean identifiers/epochs and malformed types/widths reject.
MR's signed suite, metadata, identifier, current reference and nonce jointly
authenticate this issuer request. A nonce is consumed only by successful commit.

The public record remains exactly:

```text
ue+1 = enc_rupdate(E(rse), E(rse+1), [r*]4, s*0||...||s*19, υ)
```

SPEC-001's path is one raw **960-byte** payload, LP-wrapped once; transport is
five-field `rupdate`, whereas Mu is the distinct six-field `update` message.
Each encoded state is 3,427 bytes and each update 11,162 bytes. State signatures
authenticate both states separately; Mu authenticates their logical references,
not a replacement signature over the transport. No request nonce, issuer request,
holder secret, attributes or holder-specific private path is added to the public log.

## Preparation, validation and atomic commit

A snapshot is immutable and contains the current state/root, base state, permanent
allocation counter, revoked set, consumed nonce set, ordered encoded history and
sparse tree. The tree uses read-only maps of indexed nodes and existing SHA3-384
leaf/node functions. It materialises only affected nodes, not a million-leaf tree.
Administrative `snapshot()` is manager-local inspection, not a public RPC.

Each transition proceeds as follows:

1. Check request types/widths/domains, capture the committed snapshot, and require
   the exact current reference, allocated identifier, unused nonce and zero leaf.
   Check epoch and storage allowance before cryptographic work.
2. Authenticate MR under the expected issuer key using the existing bounded
   ML-DSA-65 verifier. A different nonce, identifier, metadata, role or key invalidates
   the signature; an obsolete reference is an explicit conflict.
3. Derive the public old path from the snapshot and construct a separate sparse tree
   with that leaf set to one. Check both
   `PathRoot(r*,0,w*)=old.root` and `PathRoot(r*,1,w*)=new.root`.
4. Construct the next state's exact message, request its signature and bounded-
   verify the returned signature. Then construct Mu, request its signature and
   bounded-verify it. Encode with the actual holder-update encoder and decode with
   the actual `decode_update`, requiring the decoded fields to equal the prepared
   record. No production verifier is mocked in the successful path.
5. Prepare the complete candidate snapshot and return object **before** commit.
   Acquire the local lock and require the committed snapshot to still be the same
   object captured at step 1. A concurrent winner causes conflict; there is no
   automatic rebuild, signing retry or publication against an obsolete root.
6. Replace the one committed snapshot pointer. **That assignment is the effective
   transition point**, simultaneously publishing tree/root, epoch, nonce consumption
   and the ordered state/update record.

Signing, parsing and cryptographic validation happen outside the lock. A
non-blocking local admission semaphore permits at most two active operations, and
non-blocking lock acquisition returns `BUSY` rather than waiting or spinning.
This bounds outstanding preparations while permitting the required race tests.
The test runner still uses one worker and at most two CPU cores.

Pre-commit failures leave the previous snapshot **identical**, including nonce
availability and history. Competing preparations may produce unused valid signatures,
but only the winning snapshot is published by the model. Invalid requests, duplicate
revocation and repeated nonces never advance the epoch. A repeated old request may
first report `CONFLICT`; a fresh request for the already-revoked identifier reports
`ALREADY_REVOKED`; a reused nonce at the current reference reports `REPLAY`.
None is treated as an idempotent successful new transition.

Delivery is outside the commit. If a caller loses the result after commit, the
record remains retrievable by public epoch range; resubmitting the old request
does not undo or duplicate the transition. The model does not run a delivery
callback inside the transaction.

This is an **in-process atomicity guarantee**. It supplies no durable log, fsync,
distributed compare-and-swap, replica agreement, process-crash recovery or remote
delivery protocol. A process kill may prevent any return; it is not evidence that
a previously committed state was rolled back.

## Signing dependencies and explicit failure outcomes

`ManagerSigner.sign(message,context) → SigningResult` is typed and defaults to
`UnsupportedManagerSigner`, which fails closed. Supported result statuses are
SIGNED, UNSUPPORTED, EXHAUSTED and FAILED. Successful signatures must be exactly
3,309 immutable bytes and pass the existing bounded verifier under the pinned key
and exact context. Exceptions, malformed adapter results, invalid signatures and
exhaustion produce no committed state or record.

A revocation requests **at most two signatures**, in state-then-update order;
a current read requests **at most one**. Failure of the first stage prevents the
second invocation. The number of adapter calls is bounded, but this does **not**
establish bounded signing internals. A production adapter must still implement
the manuscript's bounded key generation/signing and runtime guarantees. No native
fallback, signing retry, remote service or production signer is supplied.

The existing bounded verifier's internal diagnostic result distinguishes INVALID
from EXHAUSTED without changing that verifier. RejNTTPoly remains capped at
**1,026 bytes** and SampleInBall at **256 bytes**. The Boolean StateAuth/holder
verification APIs and production crypto parameters remain unchanged.

Public operations return fixed typed statuses and no exception text containing
request data:

| Outcome | State/output semantics |
|---|---|
| COMMITTED | One new state and exact public record, already atomically published |
| CURRENT / PAGE | Signed ordered current reply / bounded historical update page |
| INVALID_INPUT / UNAUTHORISED / UNALLOCATED | Representation, issuer-signature or registration failure |
| ALREADY_REVOKED / REPLAY / CONFLICT / BUSY | Duplicate, consumed nonce, obsolete reference or local contention; no new publication |
| RESOURCE_EXHAUSTED | Admission/storage/epoch limit, bounded sampler exhaustion or catchable allocation failure |
| SIGNING_UNSUPPORTED / SIGNING_FAILED / INVALID_ARTEFACT | Missing signer, adapter error or invalid completed artefact |
| UNAVAILABLE | Requested history outside the imported/committed range, or a detected gap/inconsistency |
| FAILURE | Unexpected processing exception; no prepared snapshot committed |

Failed revocations carry neither a replacement state nor a public record. Constructor
errors are exceptions before activation; subsequent operations return typed results.
The legacy verifier provider method `current(expected,nonce)` maps failed replies
to no response and propagates resource exhaustion through its existing MemoryError
boundary. `read_current` retains the precise typed result for direct callers.

## Bounded state and update access

`read_current(nS)` captures the state, signs the exact existing current response,
bounded-verifies it, and then rechecks the snapshot under the lock. If a transition
won during signing, it returns conflict without a stale successful reply. On
success, this final check is the read's linearisation point. A transition committed
after that read does not invalidate the historical acceptance epoch. The existing
verifier independently authenticates the outer reply and StateAuth at challenge
creation and its final ordered read.

A state certificate has **no expiry field** in the specified encoding; this package
does not invent one or claim an old certificate has become cryptographically invalid.
The application context's `texp` remains separate and uses strict
`now < texp`, including final atomic consumption. A valid signed state/path is
not automatically the currently authoritative state. Optional DID resolution is
unsupported and returns no result; configured DID requirements continue to fail closed.

`updates(namespace,after_epoch,target_epoch,limits=...)` uses only public namespace
and version bounds. It takes one immutable snapshot, checks the requested range,
and checks the retained sequence for gaps, wrong epochs/references, malformed records
and endpoint disagreement. It returns no hidden-holder query or tailored path.

A successful `UpdatePage` contains the starting state, returned endpoint, exact
ordered records and the caller's requested target epoch. `next_epoch` is the
returned endpoint; `complete` states whether it reached that target. Continue with
`after_epoch=next_epoch` and the **same explicit target**. No omitted records,
implicit latest-state substitution or automatic fetching is allowed.

| Local storage/work/admission bound | Value |
|---|---|
| Identifier domain / imported permanent counter | uint20 / 0..2^20 inclusive; no allocated-set materialisation |
| Retained new public history | At most 32 records = **357,184 encoded bytes** |
| Total revoked identifiers | At most 64, including the imported checkpoint |
| Total consumed revocation nonces | At most 64 × 32 = **2,048 payload bytes**, including imported nonces |
| Active operations | At most two; immediate BUSY on further admission or lock contention |
| Page output | At most **16 records / 178,592 encoded update bytes**, using the unchanged holder UpdateLimits |
| Per-page structural scan | At most 32 already committed records; no signature requests or verification loop |
| Complete transition | At most three bounded signature verifications, two signer invocations and 63 explicit Merkle hashes |
| Bootstrap | One bounded state verification; 21 default hashes plus 21 per imported revoked identifier |

The three storage allowances are lowerable to zero; larger values, negatives and
Booleans reject. The sparse tree has at most 21×64 stored hash entries plus 21
defaults, with fixed depth and bounded map-copy work. Page byte limits count update
records; its two fixed-size state endpoints are separate metadata. Bootstrap sets
are count-checked before iteration/tree construction, and request/output widths
precede costly cryptography. Caller/adapter allocations made before the call still
need their own bounds; these interfaces cannot reclaim arbitrary memory retained
by a caller or bound an unimplemented signer.

When any storage allowance is full, new revocations fail before signing; existing
state/current reads and complete retained history remain available. There is **no
eviction, compaction, nonce recycling or retention horizon**. This intentionally
finite reference model stops instead of silently changing the protocol's history
obligation. Holding many historical administrative snapshots externally is also a
caller storage responsibility, not a bounded manager history facility.

The imported state defines an explicit history base. A request before that base,
or beyond the current epoch, returns UNAVAILABLE without a partial page.
The model does not claim to serve records never imported, or permit a deployment
to discard them. Production checkpoint/recovery integration must retain and serve
all required historical records. Every record newly committed by this instance
is retained until the instance ends; no public history-mutation or restore API exists.

For a nonempty range, page capacity is the minimum of remaining epochs, record
allowance and floor(byte allowance / 11,162). An allowance too small for one record
returns RESOURCE_EXHAUSTED. An empty in-range request returns an empty complete page,
including with zero allowances; it is historical-state access, not freshness evidence.

## Tests and composition evidence

The new [test helper](../tests/unit/revocation_state_cases.py) uses the unchanged
[independent sparse-tree builder](../tests/unit/binding_merkle_reference.py).
Expected roots/paths and MR/Mu bytes are independently constructed; they are not
derived from the production transition's output. Original synthetic relation
messages, holder secrets and attributes are reused unchanged. Test-only ephemeral
issuer/manager keys sign requests/states, and credential signatures are re-created
over the original messages for that synthetic issuer. Those signatures are new
test material; no original fixture or historical credential is overwritten.

[73 focused cases](../tests/unit/test_revocation_state.py) validate:

- Exact MR, state, Mu, rupdate framing and emitted old/new roots/path; identifier
  boundaries; revocation of an allocated identifier without successful issuance.
- Malformed requests, wrong issuer/key/role/metadata, altered signed request
  fields, unallocated IDs, duplicate revocation, nonce replay and obsolete roots/epochs.
- Invalid or oversized bootstrap input, storage limits, epoch exhaustion, strict
  typed default signing failure, wrong signature widths and both signing phases'
  unsupported/exhausted/failed/invalid/exception outcomes.
- **Six real bounded-verifier exhaustion cases:** matrix and challenge streams at
  each of issuer request, generated state and generated update verification.
  Rejected bytes reach the actual caps with no fallback or repeated exhausted stream.
- Allocation/codec/decoder/candidate faults before commit; unchanged snapshots and
  no nonce consumption or inconsistent public record.
- Barrier-controlled competing requests for distinct and identical identifiers:
  one committed successor, no lost update or duplicate epoch; a separately signed
  request at the new reference can subsequently commit the distinct loser.
- Ordered current-read overlap, immediate contention outcomes, all 32 retained
  records retrieved in two complete 16-record pages and applied by the actual holder
  updater, smaller page allowances, unavailable/gapped/conflicting history, and
  loss of delivery after a successful commit.
- Frozen snapshots, no holder inputs to public retrieval, and no diagnostic leakage.

Four composition cases connect this manager to the existing verifier provider
interface and holder updater. A surviving holder updates to the independently
expected current path and passes the **complete local authentication relation** and
lifecycle checks; the revoked holder gets no replacement witness and fails the
current zero-leaf relation; an old-valid presentation fails the final current-state
comparison; a current valid local presentation at `now=texp=100` fails strict expiry.
All credential/secret/attribute/signature bytes stay unchanged through witness updating.

The controlled public proof adapter remains explicitly test-only; the private
same-witness relation is evaluated separately in the local harness. Tokens are not
receipts and these results establish no remote knowledge or zero knowledge.

**25 scoped regressions** cover exact holder-update messages, empty/consecutive
history, own revocation, expected issuer/authority, ordering and genuine exhaustion,
complete relation/credential reuse, uniform-subtree behaviour, public API separation,
deterministic state/expiry interleavings, atomic concurrent consumption, unsupported
proof defaults and state/parameter encodings. Unaffected broad native/environment,
reference/circuit and historical proof validation is reused.

## Commands, resource enforcement and preservation

[Configuration](data/s2_revoke_state_1/config.json),
[runner](data/s2_revoke_state_1/run_checks.py),
[run ledger](data/s2_revoke_state_1/run-ledger.json),
[focused XML](data/s2_revoke_state_1/focused.xml) and
[regression XML](data/s2_revoke_state_1/regression.xml) record exact commands,
effective controls, headroom and outcomes. The runner invokes only the named
pytest, Ruff and preservation-audit commands; no proving/zkVM/build/install command.

The inherited envelope is **256 MiB whole-worker cgroup memory, no swap,
one execution worker/two affined cores, 60 s per command and 300 s aggregate**.
The two-thread deterministic race tests stay inside that one worker/cgroup.
Retained limits: 10 GiB experiment disk / 9 GiB early stop, 64 MiB diagnostics /
60 MiB early stop, ≤100 collected cases and **10 MiB new package output**.
The inherited stricter individual-log stop is 60 KiB and individual-file limit
1 MiB. Services have private networking with no routes and read-only project access,
except the new evidence directory. A file lock enforces one check worker.

For the first four checks, WSL available-memory admission ranged from
4,853,825,536 to 4,875,632,640 bytes, above the 256 MiB allowance plus 2 GiB reserve.
Existing experiment storage was 7,618,673,412 bytes, below the unchanged early stop.

| Check | Result | Guarded seconds | Cgroup memory peak, bytes | Sampled aggregate RSS, bytes |
|---|---|---:|---:|---:|
| Focused | 73 passed, no skips | 3.175165 | 43,397,120 | 64,667,648 |
| Regression | 25 passed, no skips | 0.989488 | 43,737,088 | 64,942,080 |
| Lint, including audit/guard | Pass | 0.089988 | 10,993,664 | 13,897,728 |
| Formatting | Pass | 0.088612 | 11,517,952 | 31,821,824 |

All four passed on their first recorded run and totalled **4.343253 guarded seconds**.
No memory-max/OOM, swap, deadline or output stop occurred. Cgroup and aggregate
RSS are different accounting scopes; both are reported and remain below limits.
These are validation-command costs, not per-request throughput/percentiles or
proving costs. Routine source formatting/import preparation preceded the checks.

The final [audit content result](data/s2_revoke_state_1/validation.json) checks document
links, JSON, source syntax/lint/format, the earlier resource records, test counts
and preservation. It wrote its content result before the guard inspected that
audit's own resource events. Its `passed: true` therefore **does not mean that the
guarded audit passed**. The [guard result](data/s2_revoke_state_1/final-audit.json)
records exit 125 after **1.402034 guarded seconds**, a **268,435,456-byte cgroup
peak** and **387 memory.max events**, with zero OOM/OOM-kill/swap. Sampled aggregate
RSS was 39,108,608 bytes; the memory categories causing the discrepancy were not
captured, so attributing it to page cache would be an inference, not a measurement.

The guard's resource failure is authoritative. [STOP](data/s2_revoke_state_1/STOP.json)
and all diagnostics are retained. No audit, implementation test or failed resource
run was retried, and no limit changed. All five commands, including the failed
audit, used **5.745287 guarded seconds**. Only report/result/manifest finalisation
followed; this package stops with the final audit's resource acceptance unresolved.
The [manifest](data/s2_revoke_state_1/manifest.json) seals final source/report/evidence
hashes. Repeat runs require a fresh evidence namespace: run names and any STOP
cannot be overwritten or automatically retried.

The before-inventory protects **8,759 pre-existing files**. Only status,
traceability and the issue register are updated among them. Existing source,
vectors, dependencies, manuscript, reports, receipts, proof ledgers and the prior
witness-update package's failed audit, correction and STOP are preserved.
This package adds one module, its helper/tests and its own report/evidence.
The cumulative proof ledger remains
`fc64f7efbd2f20cd23fec24d828f36f1460afb0b73a76ea256d0716f309d75c5`:
**two used, one unused; zero new proofs or zkVM executions**.

## Remaining obligations and one next bounded package

R-030's manager transition, authorisation and local atomic publication are now
implemented as a bounded **reference model**, with the stated trusted bootstrap
and signer dependency. R-017 gains a manager-side ordered current-state response;
R-031 consumes its actual emitted records. This does not complete the production
services or the eight-algorithm lifecycle.

Recommend **S2-REVOKE-AUDIT-1** next: a separately authorised, read-only preservation
audit package under the **same 256 MiB ceiling**. Capture charged file/anonymous/
kernel-memory categories during a bounded scan, then address the evidenced audit
I/O or memory-accounting cause without changing the acceptance limit. Reuse the
98 passed tests and unchanged implementation; require a clean guarded preservation
audit before another implementation package. The observed low sampled RSS alone
does not justify raising the cgroup ceiling. Retain one worker/two cores, no swap,
60 s per command/300 s aggregate and existing disk/output limits, with no proofs,
zkVM executions or automatic retries. This next package has not begun.

Stages **2–3 remain open** for bounded keygen/signing and DEP-001/002, allocation/
issuance/certification-release integration, durable/distributed manager/wallet/
verifier/DID services, full authentication circuits, selective-disclosure/non-revocation
proof integration, complete BC-1, actual CredValid/authentication proofs, and
privacy/ZK/quantum-security/Section VIII review. No production-readiness or
security proof follows from these reference-model tests.


## S2-REVOKE-AUDIT-1 appended validation — 19 September 2026

The original report above, including the ceiling failure and next-package
recommendation as recorded then, is preserved verbatim. The separately authorised
[audit correction](stage2_revocation_audit.md) is now in progress under the same
256 MiB cgroup ceiling and inherited time/storage/concurrency limits. Its diagnostic
supports avoidable retained file-cache charge; the original peak's precise phase
and memory-category split remain unrecorded. A new streaming audit keeps all 8,759
original paths plus the historical final evidence manifest, and checks this original
25,818-byte report prefix. No manager code or functional inputs changed; the 73 + 25
passed tests are reused. The one complete guarded audit result will be appended
below. Historical validation/STOP/guard outputs are not overwritten. No proofs or
zkVM executions; CPU proving remains paused, two attempts used and one unused.

**Appended final result: PASS.** The [complete audit result](data/s2_revoke_audit_1/final_checks/result.json)
records guard exit 0, **1.053191021 s**, **21,823,488 bytes (20.8125 MiB)** cgroup
memory peak under the unchanged 256 MiB ceiling, and zero max/OOM/OOM-kill/swap events.
All 8,759 original entries and 30 supplementary historical entries were compared;
8,756 + 29 were unchanged, the original three permitted document changes and this
append-only report were allowed, and there were no missing or unauthorised changes.
This report's original 25,818-byte prefix passed its historical digest check.
The additional exact-name inventory passed 418 entries. Report generation/readback
completed before the clean guard result; sampled aggregate RSS was 39,415,808 bytes.
The new engine's **44 isolated fixture cases** and final lint/format pass. An initial
unused-variable lint failure and its STOP are retained in the new package; a trivial
source correction preceded fresh final-check evidence. There was only one complete
audit execution, no resource failure/retry/limit increase, and no manager test rerun.
The original ceiling failure above remains unchanged and historically authoritative.
This separate result resolves its follow-up audit obligation without marking Stages
2–3 complete. Recommend reusing this audit under the same envelope for the next
separately scoped reference-lifecycle package. All production integration, BC-1,
proof and privacy/security obligations remain open; CPU proving remains paused at
**two used / one unused**, with no new proofs or zkVM executions.
