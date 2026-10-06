# S2-DID-STATE-1 — bounded DID registry, resolver and lifecycle reference

19 September 2026. **74 focused and 14 scoped regression cases pass** under the
unchanged 256 MiB/no-swap guard. The new [reference module](../src/pqdid/did_state.py)
implements signed registration, controller updates/rotation, terminal deactivation,
current/historical resolution and in-process pending-publication recovery. It connects
the existing issuer and verifier contracts without changing their code or protocol.
Final lint/format and the single complete preservation audit **pass**; measured results are below.
Stages 2–3 remain open. No proof or zkVM execution was launched; CPU proving remains
paused at **two attempts used, one unused**.

## Authority and scope

The manuscript SHA-256 was checked before implementation:
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
Only **Sections II–VIII** are authoritative. IV-A/B and VII-A.1–4 specify method
configuration, publication/recovery, resolution and trust; VII-A.5/.7 define the
issuance and verification boundaries. The agreed [implementation specification](implementation_spec.md)
R-012–R-015 and R-052 records these requirements. All three operations queried by
this package—rotation, deactivation and historical resolution—are explicitly specified.
No new protocol decision or SPEC-001–004 revision is needed.

The separate roles are:

| Material | Authority and use |
|---|---|
| Controller `pkC/skC` | Authorises method records and the exact enrolment statement under the existing `control` context; current validated method state selects the key |
| Registry `pkG/skG`, identifier `γ` | Independent pinned authority for nonce-bound ordered reads; registry validates and atomically appends controller-signed records |
| Issuer `pkI`, revocation `pkR` | Immutable expected instance verification material; neither is obtained from nor replaced by a holder DID document |
| Private holder secret `xH` | Credential-binding/opening secret; absent from this module, registry records, resolution requests and anonymous verifier interfaces |
| Persistent holder authentication key in the separate comparison baseline | A different authentication construction; no such key is added to PQ-DID presentations or treated as the controller key |

`DIDConfiguration` pins the entire immutable `PublicParameters` and `(γ,pkG)`.
It is trusted setup/application configuration, not an assertion authenticated by a
DID lookup. Issuer/key/schema/namespace changes are different instances, not automatic
credential migration. Independent keys and uniform independent 32-byte `xH,ζ` sampling
remain setup/holder-generation requirements. `make_did` derives the exact identifier
from supplied controller public key and salt; it does **not** implement key generation
or claim to establish their independence. Bounded production key generation/signing
remain open; test signers are explicitly ordinary native synthetic helpers.

## Canonical records and authorisation

The DID is exactly 171 ASCII bytes:
`did:pqdid:` + lower-case hex of 32-byte `γ` + `:` + lower-case hex of
`SHA3-384(E_did-id(suite,γ,pkC,ζ))`. No case folding, Unicode transformation,
percent decoding, redirects or DID URL interpretation is introduced.

`DIDBody`/`DIDRecord` reuse the existing `did-body`/`did-record` framing, exact
seven fields, eight-byte index below 2^16, 48-byte predecessor digest, 1952-byte
controller key, one-byte activity flag, 32-byte salt and 3309-byte signature.
The version is `[k]8 || SHA3-384(E(Rk))`, exactly 56 bytes. It is **not** a
revocation epoch, root or `StateReference`. No signature format, suite parameter,
hash domain or encoding in an existing file changed.

Genesis requires authenticated absence in the controller helper, index zero, zero
predecessor digest, active status, exact DID recomputation and a signature by the
genesis key. The registry independently enforces absence at atomic commit and verifies
that signature. Successors require the active predecessor, next index, exact previous
digest, unchanged DID/salt/registry and a signature by the **previous** controller key.
A supplied new key or controller field alone never establishes authority. Active key
changes implement rotation; deactivation must retain the key and is terminal.
The operation metadata `(1,0)`, `(1,1)`, `(0,0)` remains local publication input:
the rotation flag is not invented as an extra signed record field.

All signatures use the existing bounded ML-DSA-65 verifier and external contexts
`PQ-DID/did-record/v1` and `PQ-DID/did-read/v1`. New/embedded keys reuse its FIPS
decoder and all 30 bounded matrix expansions, including the final endpoint key.
Sampler exhaustion is a resource outcome, with no native fallback. Internal bounded
diagnostic helpers are reused without changing their code or exposing a caller-selected
cryptographic verifier. Generated signatures are bounded-verified before use.
Missing signer dependencies return unsupported; malformed/truthy verdicts cannot succeed.

## Consistency and recovery

`ReferenceDIDRegistry` retains immutable per-DID tuples in a bounded map. Verification
uses a locked starting snapshot; commit compares the same predecessor again under the
lock, checks global capacity and swaps a fully prepared map. Concurrent authorised
successors cannot both replace the same predecessor. Input, signature, allocation and
resource failures before that assignment leave committed state unchanged. Exact duplicate
submissions receive conflict; controller recovery first checks authenticated occurrence.

Reads linearise at the locked snapshot before response signing. A concurrent write
can commit before delivery without invalidating that overlap ordering. A later read
sees the newer snapshot. This is an **in-process ordered service assumption**; a valid
signature alone cannot establish latest-state ordering of an arbitrary remote registry.
The resolver has no cache and does not treat old signed data as an authoritative
current response. Lost replies cannot undo committed records.

`ReferenceDIDController` serialises its operations and retains at most one pending
record plus the old and possibly active signer handles before submission. No operation
can supersede an unresolved pending attempt. Explicit `recover()` freshly reads current
history, then either confirms exact occurrence (even after later deactivation), retires
a losing conflicting attempt, or resends the **identical bytes once** while its predecessor
is current. There is no automatic retry loop. Delivery exceptions retain pending bytes
and possibly active keys. A transport acknowledgement without authenticated occurrence
never establishes success. A conflicting external update is not silently adopted as
the holder's retained key/version. Durable storage, crash recovery and shared replica
state remain deployment work; the reference does not claim persistence.

## Resolution and lifecycle adapters

`ReferenceDIDResolver.resolve(expected,did,selector)` checks the complete expected
instance before any lookup. Selector `00` is current; `01 || vD` requests history.
A fresh retained 32-byte nonce binds every request and response. The signed `did-read`
envelope binds registry, exact DID, selector, nonce, status and complete `did-chain`.
The resolver validates framing/counts, outer signature, every record/key/transition,
requested identity and historical endpoint. Authenticated absence has an empty chain;
an endpoint must have a non-empty chain. Unknown historical digests return absence.

Only an active endpoint returns `ResolvedDID` with exact bytes `{"id":"<did>"}`,
the authenticated version and `application/did+json`. Inactive endpoints retain validated
public method history for local recovery but return **no DID document**. Explicit status
values distinguish unknown, deactivated, malformed, unsupported, mismatched instance,
inconsistent response, unavailable dependency, unauthorised, exhausted, busy and conflict.
An oversized record/chain is exhaustion, not successful resolution or cryptographic rejection.

`IssuanceDIDAdapter.current` supplies the issuer's existing `ControllerResolution` from
the current active endpoint and validated controller key. The existing issuer still
checks evidence/approval and the exact controller-signed Xen, then freshly rechecks the
same current version/key before certification. Rotation/deactivation between approval
and completion rejects pending issuance. Authentication/channel confidentiality and
external evidence validation remain trusted authorisation adapter obligations.

`DIDLifecycleProvider.instance` pins all parameters independently and checks the
revocation authority provider's identical instance. Its `current` delegates the existing
authenticated revocation-state service. Neither method resolves a holder DID.
`resolve_did` implements only the verifier's existing historical lookup of explicitly
disclosed certified DID/version. The existing opt-in DID check requires both fields;
a policy hiding either cannot satisfy that optional check. Normal anonymous verification
does not enable it and makes **zero DID resolution calls**. No private witness or
holder identity is supplied to the public proof adapter.

Controller rotation and DID deactivation do not revoke credentials, alter roots/epochs,
consume verifier nonces or change certified attributes. Already-issued credentials retain
their original DID/version. An active historical endpoint remains resolvable after later
deactivation, without asserting current control. Credential revocation and strict SPEC-002
expiry remain separate existing checks. Tests issue through the real reference resolver,
rotate/deactivate, and authenticate at two independent verifier instances both with hidden
DID (no lookup) and with approved public DID/version (historical lookup only).

## W3C mapping and privacy limits

The target remains **DID Core 1.0, W3C Recommendation 19 July 2022**, as identified
by E-003; its [dated publication](https://www.w3.org/TR/2022/REC-did-core-20220719/)
was checked. The method-specific identifier maps to its DID syntax and document `id`;
the minimal JSON uses its `application/did+json` representation. Method versions and
validated controller records remain outside that document. No ML-DSA verification-method
type is presented as standardised. Generic resolution metadata/options, DID URL
dereferencing, method registration and formal conformance testing are not implemented;
these reference objects do not establish complete DID Core interoperability.

Public method records expose only specified DID/controller-key/salt/history fields.
Resolution queries expose DID, selector and fresh nonce; requesting history can reveal
a stable version. They contain no xH, credential, binding, certified attributes, credential
signature, revocation identifier or Merkle path. No registry value is added to the
anonymous presentation. Diagnostics use status-only errors and suppress dataclass payload
representations. Tests instrument transport calls and retain private fixtures locally.
This is a boundary test, not a security/privacy proof or a network-metadata anonymity claim.

## Local bounds and validation

Existing finite reference limits are reused: **32 total retained method records across
all DIDs**, at most two admitted operations per component, **64 retained resolver nonces**,
eight nonce draws by default (configurable only within 1–100), no eviction. Registry
histories therefore cannot exceed 32 entries; at most 32 DIDs can be retained. One body
has fixed field sizes; raw record admission is 8192 bytes. The raw signed-read message
ceiling is **263,296 bytes** (`32*(8192+4)+1024`); chain count is checked before the generic
decoder allocates its field tuple. Signature size is separately checked at 3309 bytes.
All these are lower local capacity/work admissions, not modified suite parameters.
Constructors reject increased limits. Trusted callback implementations must obey the
same resource envelope; Python cannot pre-empt a blocking in-process dependency itself.

The [focused suite](../tests/unit/test_did_state.py) has **74 cases**, with
[explicitly labelled native test helpers](../tests/unit/did_state_cases.py).
It covers exact bytes/signatures, genesis/update/rotation/deactivation/history,
identity and instance/key substitution, all response fields, complete-chain validation,
replayed nonce, duplicate/conflicting/concurrent writes, immutable snapshots, overlap
ordering, signing/transport/sampler failures, byte/count/history/nonce bounds, busy
admission, pending retries/conflicts/lost delivery and lifecycle/privacy composition.
**14 selected regressions** cover issuance, verifier defaults, reference enrolment and
manager concurrency; existing broader cryptographic/circuit/manager/auditor evidence is
reused because those files and inputs are unchanged. No proof token is labelled a receipt.

| Guarded command | Cases/result | Outer wall time | Sampled aggregate process-tree RSS |
|---|---|---:|---:|
| `.venv/bin/python docs/data/s2_did_state_1/run_checks.py focused` | 74 passed | 4.789624430 s | 69,066,752 bytes |
| `.venv/bin/python docs/data/s2_did_state_1/run_checks.py regression` | 14 passed | 1.030383074 s | 68,612,096 bytes |

The [configuration](data/s2_did_state_1/config.json) and [runner](data/s2_did_state_1/run_checks.py)
preserve 268,435,456-byte cgroup v2 memory.max, swap zero, one guarded worker, two
affined CPU cores, 60 s/command (55 s child stop), 300 s aggregate, 100 selected-case
ceiling, 10 GiB experimental disk/9 GiB early stop, 64 MiB diagnostic/60 MiB early stop,
10 MiB package output, 60 KiB per-log stop and 1 MiB per-file limit. Admission requires
256 MiB plus 2 GiB MemAvailable. The guarded tree has private networking with no routes;
project files are read-only except its evidence directory. No installs or subprocess
work outside the guard is used to bypass a limit. The outer monitor records bookkeeping.

Peak cgroup memory includes charged anonymous memory, file cache and kernel memory for
the worker and descendants; it is not address space or the sampled RSS sum. Both metric
scopes are retained separately. [Focused](data/s2_did_state_1/focused.json) and
[regression](data/s2_did_state_1/regression.json) guard/service records include commands,
headroom, memory.events, swap, process results and timing. Both completed with exit 0,
no skips/failures or resource event. These are reference test costs, not proof costs,
throughput or percentile estimates.

## Preservation audit and final result

The [explicit scope](data/s2_did_state_1/scope.json) pins the original 8,759-entry
pre-manager baseline and the historical manager (33), corrected-auditor (40) and
issuance (48) manifests. The new audit permits only the three existing documentation
files (status, traceability, issues); **no existing source file is permitted to change**.
The latest historical seal establishes already-authorised past changes. Original
baselines are never regenerated. Historical manager failure, later passing audits,
manuscript, dependencies, original vectors and proof ledger remain protected.

The unchanged [corrected auditor](../scripts/preservation_audit.py) hashes all protected
files in bounded SHA-256 chunks with its existing cache-advice policy. The new
[package audit](data/s2_did_state_1/audit.py) accounts for **8,869 distinct content paths**
(8,759 primary + 110 supplementary, zero overlap), plus **three** additional distinct
manifest identities: **8,872 historical paths**. It retains the original manager-report
prefix and latest full report digest, all inventory roots/metadata/symlink semantics,
and the literal 93 pre-existing inventory-only cache names. All new code/report/evidence
names are explicitly listed; there is no new directory exclusion.

Final command sequence after implementation: guarded `focused`, `regression`, `quality`,
`format`, then **one** `full-audit`, through the runner above. Authoritative completion
requires [result.json](data/s2_did_state_1/result.json), clean
[full-audit.json](data/s2_did_state_1/full-audit.json), completed
[validation.json](data/s2_did_state_1/validation.json) and
[phase record](data/s2_did_state_1/phases.json). A content comparison alone is insufficient.
The final measured result follows. The final package
[seal](data/s2_did_state_1/manifest.json) records only authorised new/changed artifacts;
it is not a replacement baseline or a second historical scan.

### Completed guarded audit

**PASS**, exit **0**, one complete attempt, no retries or raised limits. Exact command:
`.venv/bin/python docs/data/s2_did_state_1/run_checks.py full-audit`.
Content/inventory comparisons, report write/readback, worker completion and final outer
resource guard all passed. Peak cgroup charged memory was **22,933,504 bytes
(21.87109375 MiB)**; independently sampled aggregate worker-tree RSS peaked at
**40,480,768 bytes**. Outer wall time was **2.050973451 s**. Memory-max/OOM/OOM-kill
counters and swap peak were zero. The guard recorded **150,257 bytes** of package
output at completion and **zero temporary storage bytes**. These are process-tree
measurements of this audit, not proving-memory evidence.

All 8,759 original content entries were compared: 8,756 unchanged and precisely the
three permitted documentation files changed. All 110 supplementary content entries
were unchanged. The disjoint content union and pinned manifest identities account for
8,872 historical paths. The **494-entry inventory** passed with no missing or extra
name. The auditor also checked 262 local Markdown link paths at that point. No original
baseline, crypto/source dependency, old vector, manuscript or historical result changed.

Final guarded lint and formatting also exited 0. All five guarded commands totalled
**8.052034299 s**; the largest cgroup peak among them was **48,254,976 bytes** (focused
suite). The measured evidence files are preserved unchanged. After the guard, only
this result/obligation text, status/traceability/issues and the package seal are
finalised. Final documentation link/format and explicit artifact-list checks are small
bookkeeping, not another historical content scan or a second complete audit.

## Remaining obligations and next bounded package

R-013/R-015 now have a bounded local reference implementation; R-012 has derivation
from supplied material, while bounded independent key/secret generation is open.
R-014 has in-process pending recovery, while durable recovery and network/distributed
consistency remain open. Real bounded signing, signing-tail/DEP-001/002 validation,
authenticated confidential issuance services, DID interoperability and deployment trust
configuration still need implementation/review. Active-profile complete authentication
circuits/BC-1, selective-disclosure/non-revocation proof integration, actual credential/
authentication proofs and privacy/security review remain open. This package changes
neither suite nor experimental profile.

Recommend **S2-LIFECYCLE-REVIEW-1** next: a bounded integrated review/test package for
cross-service failure ordering, stale approvals, expiry, replay and restart/persistence
requirements across issuer, manager, DID controller/resolver and two verifier stores.
Use public controlled proof verdicts and existing native reference helpers; identify
the exact durable state and recovery obligations before choosing a persistence design.
No production service, proof or zkVM run is authorised or started by that recommendation.
