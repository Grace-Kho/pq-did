# S2-KYC-CONTAINER-ADAPTER-1

Implemented [bounded application-container decoding](../src/pqdid/containers.py)
for the project-local research KYC profile. **24 individually counted cases pass on
their first run**, with no signing, proof or lifecycle execution. Conversion returns
unverified typed data for the existing service checks; it never establishes
credential authenticity, freshness, proof validity, acceptance or release authority.

## Authority, preservation and budget

The [preceding contract](stage2_kyc_interoperability_contract.md), its unchanged
[15 examples](data/s2_kyc_interoperability_contract_1/examples), existing typed modules
and issue register define the boundary. Only manuscript Sections **II–VIII** and
agreed SPEC-001–004 govern scheme behaviour. The new version below is an application
transport choice authorised by this package, not a cryptographic profile change.

[Preflight](data/s2_kyc_container_adapter_1/preflight-evidence.json) verified the preceding
73-file seal SHA-256
`24794730fd7f759f3d3b5adc9af9d3e0bed7e0534f570105fbd05a8675975813`
and 53 assessed source inputs, including manuscript SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
All historical failures, reports, examples and source are preserved. The only new
ordinary source is `containers.py`; no existing canonical/lifecycle module changes.

The explicit amendment adds **24** invocations: **199 → 223**. Starting usage was
**198**, leaving **25**, including failures and repeats. This package plans and runs
24, leaving one. Starting implementation charge is **187.31629112013616/300 seconds**,
with **112.68370887986384 seconds** remaining. Measured guard commands plus five
bookkeeping seconds continue the ledger; ten seconds for evidence/cleanup and the
next 60-second command are reserved at admission. No counter reset or borrowing.
Analysis **270.1814811680233 s** and isolation **250.22 s** remain separate.

The sealed isolation closure is reused: safely stopped/unactivated, 22 original
actual-identity cases pending, previous permissions/resources and allowance unchanged.
CPU proving stays paused, proof ledger **two used, one unused**.

## Selected version and API

`ContainerAdapter(parameters, receiver)` is frozen trusted application configuration.
Receiver is one of holder, issuer, verifier, revocation or application. The requested
`kind` is supplied independently by the local route, and the document must match it.
The receiver's allow-list is checked before JSON decoding, preventing a verifier
route from admitting a private holder object. Constructor inputs must never be taken
from the incoming container. This is routing discipline, not OS isolation or a new
service-authorisation system.

`parse(data: bytes, *, kind, context=None, nonce=None, query=None, starting=None)`
returns `ConvertedInput(kind, value)` for supported objects. This wrapper has no
accepted/authenticated/proof-status property. Required context, nonce, query and
starting state come from the caller's independently retained request/read/holder
state. Caller-supplied JSON cannot select keys, signer role, proof backend or context.
The adapter contains no key material, service callbacks, fetches, clock reads,
mutable session state, signing, verification, retry or publication operations.

| Convention | Selected rule / rationale |
| --- | --- |
| Normal version | Exact `pqdid-application-container-1`, `synthetic:false`, `evidenceStatus:"unverified-input"`; makes the unverified boundary explicit |
| Synthetic version | Existing `pqdid-application-container-draft-1` and `synthetic:true` only through `inspect_example`; no ordinary allow-synthetic option |
| Envelope | Exactly profile/kind/synthetic/exposure/evidenceStatus/body; exact exposure per kind, no extra fields or metadata bag |
| Example labels | Existing bounded UTF-8 evidenceStatus text is documentary only, discarded from returned data; no interpretation of claims such as "authenticated" |
| Binary | Unpadded base64url; URL-safe alphabet, decoded widths/caps, encode-after-decode equality; rejects padding, alternate alphabet and non-zero unused bits |
| Protocol integers | Only minimal unsigned decimal **strings**, then explicit range-checked conversion to existing integer types. This is the chosen transport type, not permissive coercion. JSON numbers, floats, exponents, signs, leading zeros and booleans are not accepted as protocol integers |
| Boolean fields | Exact bool, never 0/1/string coercion; claim values follow the immutable schema |
| JSON | Strict UTF-8, no BOM/trailing input/NaN/Infinity/lone surrogate, duplicate keys or unknown fields; no field defaults |
| References | Remain data. No network, context/schema fetch, DID resolution, status lookup or redirect occurs |

The adapter is deliberately a decoder to typed inputs. Existing canonical encoders
remain the authority for signed/proved bytes; no general JSON signing, wallet
persistence, HTTP protocol or outbound service implementation is introduced.

Example use, after trusted routing and configuration:

```python
adapter = ContainerAdapter(trusted_parameters, "holder")
candidate = adapter.parse(
    received_bytes,
    kind="presentation-request",
    context=independently_expected_context,
)
# candidate.value is only an AuthenticationRequest candidate.
# Existing holder lifecycle still verifies its signature, time, policy and state.
```

`inspect_example` returns **ExamplePreview**, not ConvertedInput. An unsigned request
preview is a context/state tuple, not AuthenticationRequest; a presentation preview
is only an AuthenticationStatement, with no proof bytes or verdict. Missing DID
method evidence produces only document/version preview bytes; it never produces an
`authenticated=True` resolution. The illustrative verification failure produces no
service-result object. Changing example flags alone cannot admit a proof: the ordinary
proof branch is unconditionally unsupported, including non-null purported proofs.

## Supported conversions and binding checks

Every binary object is decoded by its existing typed validator and re-encoded to
require exact byte equality. Parameters are compared with independently pinned pp;
state namespaces, schema, issuer reference and repeated instance values cannot drift.
Wrapper metadata is discarded. Converted objects still require the original
cryptographic, authority, recipient, freshness and commit checks.

| Kind | Receiver / returned value | Additional binding and remaining checks |
| --- | --- | --- |
| instance | holder/issuer/verifier / PublicParameters | Exact configured pp, including keys/refI/schema; never installs trust from input |
| issuance-request | issuer / IssueRequest | Canonical attributes/holder approval agree; DID171 and version56 agree with designated attributes; existing DID syntax/index domain; session1–256, evidence≤65536. Evidence/control/approval authentication remains with issuer |
| enrolment-challenge | holder / EnrolmentChallenge | Configured pp, canonical1024-byte vector, rid<2²⁰, nonce32 and state3427. Pending nonce/allocation authority remains outside parser |
| issuance-delivery | holder / IssuedCredential with separate WitnessCheckpoint | Canonical credential and certified rid match checkpoint rid; path960, coherent state structure. Original-recipient retrieval and HolderAcceptance still required |
| private-holder | holder / PrivateHolderInput | Credential and5329-byte witness share attributes/rid/signature, plus state. No claim that the secret opens the credential or the path is current/valid; existing local acceptance/update checks must establish that |
| presentation-request | holder / AuthenticationRequest | Exact independently expected E(ctx), state reference and decimal session expiry. Signature3309 is merely structurally admitted; no signature verdict here |
| revocation-state | holder/issuer/verifier / RevocationState or CurrentStateReply | Both current fields absent means historical state candidate only. A current reply requires nonce32 matching independently supplied nonce and signature3309; no currentness inferred from a state signature |
| updates-request | revocation / UpdateQuery | Namespace matches pp, uint64 after≤target; no private rid/path/DID or caller-selected limits |
| updates-response | holder / UpdatePage | Exact trusted query and starting state, status PAGE, ≤16 consecutive records/178592 bytes, record11162 bytes; exact state continuity, nextEpoch and complete agree with endpoint/requested epoch. Existing signature/transition/NR evaluation still required |

Public update records contain the revoked identifier and transition path already
prescribed by the scheme. They do not add the requesting holder's private identifier
or path. The parser returns no replaced holder state and performs no page iteration.
No changes are made to issuer permanent reservation, certification logging, recipient
redelivery, manager commit-before-publication, fencing or verifier consumption.
A parse failure cannot consume a challenge or expose an uncommitted result: no service
is invoked. Previously completed lifecycle tests are reused without replay.

### Explicitly unsupported mappings

Ordinary presentation-submission and enrolment-submission fail with
`proof-transport-unsupported`; a real complete proof admission format is still unset.
Their synthetic statement previews use existing canonical statement encoders and
never create `Presentation`, EnrolmentSubmission, proof bytes or a verifier adapter.
Proof-null, placeholder tokens and claimed success cannot become valid proofs.

Ordinary did-resolution fails with `did-method-adapter-unsupported`; the necessary
trusted registry/read binding and interoperable method/key mapping are not selected
by this container package. Ordinary verification-result fails with
`outcome-admission-unsupported`, irrespective of an accepted flag. Parsing a client
response is not a safe way to authorise a downstream KYC action or recover a lost
acceptance reply. Existing acceptance tombstones/redelivery restrictions remain.

KYC-INT-001 issuer/claim vocabulary, KYC-INT-002 securing mechanism,
KYC-INT-003 DID method/key representation and KYC-INT-004 private status/time mapping
remain open. No W3C VC/VP, registered cryptosuite, issuer URL, credential-specific
status URL/index, new signed field or proof-profile semantics are invented.

## Resource bounds and allocation limits

Input must already be `bytes`. Before UTF-8 decoding or `json.loads`, reject documents
above **65,536 bytes**, except update pages/DID containers at **524,288 bytes**.
These are stricter than the retained1MiB absolute file ceiling. Kind comes from the
trusted route, so incoming metadata cannot obtain the larger allowance. Larger
mathematically valid core inputs, including a full64KiB evidence payload after base64
expansion, may be rejected; no truncation, fallback or limit escalation occurs.
The existing65,536-byte authority IPC reader is untouched.

A linear lexical scan, with a stack of at most eight frames, checks nesting≤8,
object members/array elements≤32 and total members/elements≤512 **before** underlying
JSON collection construction. Quoted/escaped delimiters are ignored; malformed
syntax still goes through strict grammar validation when it survives the scan.
The selected total counts array elements as well as object members, preventing the
collection budget from being bypassed with arrays. Keys are limited to64 UTF-8 bytes;
metadata text to256. Body lists/record counts and binary fields have tighter limits.

Limits that are **not** enforced before allocation:

- The caller has already allocated the bytes object. This API is not a bounded
  socket/file reader; a future transport must enforce its own byte cap during reads.
- UTF-8 text and JSON string/value allocations occur within the document cap.
  Duplicate-key/key-length checks run through object-pairs hooks after that bounded
  collection's keys/values exist. They cannot prevent the initial key/string allocation.
- Base64 text already exists when its encoded-length cap is checked. Decoded bytes,
  canonical re-encoding and internal decoder copies then allocate within admitted
  widths. Typed canonical validators can allocate bounded intermediate records.
- Small result objects, Python/runtime imports and caller-retained results are outside
  any claim of a parser-local hard RSS ceiling. This stateless API does not cap the
  number of results an application retains across calls. Resource exhaustion raises;
  there is no success fallback. A service must retain the existing process guards.

These bounds give finite per-call admission and controlled parsing work, not a claim
that every Python runtime/process stays below256MiB solely because this module exists.
The actual validation and full audit use the unchanged256MiB cgroup guard. Three
focused tests replace `json.loads` with a failure sentinel and demonstrate pre-parser
rejection for oversized bytes, depth9 and a33-element array. Other maxima are enforced
by source inspection; no fuzz campaign or maximum-history benchmark is claimed.

## Authenticated meaning, privacy and expiry

The successful conversion tests preserve exact E(ctx), E(X), private credential/
witness bytes and the independently framed fixture Mcred; they invoke no new signature
or proof. A deliberately width-correct **state** signature is used as a request
signature-shaped input in one test: its structural conversion succeeds and makes no
request-authentication claim. The existing holder must still reject an invalid
request signature under `PQ-DID/request/v1`. Context strings and all signed byte
constructors remain in their original modules, unchanged.

Public statement inspection requires independently expected context and exact typed
schema projections. Displayed index/name/type/value entries must match D,mD. A wrong
Boolean claim or conflicting expiry is rejected; arbitrary JSON metadata cannot add
claims. Private-holder fields on a verifier-facing body are rejected as unknown before
canonical conversion. The public fixture exposes only fields3,4,6, while secret,
full attributes, original signature and path are absent from its canonical X.
No persistent holder identity, hidden-DID lookup or holder-key authentication is added.
Issuer/schema/state/disclosed-value and network correlation remain outside any new
privacy claim; existing manuscript leakage restrictions and proof-security gaps remain.

Session expiry remains exact uint64 POSIX seconds in the canonical context, with its
redundant decimal value checked for equality. The adapter has no clock or date-time
conversion. Existing SPEC-002 strict **now < texp**, including the final atomic
recheck, remains with the lifecycle. Schema validUntil is a separate disclosed claim;
it is never inferred from session expiry or used to invent a W3C validity field.

## Individual validation results

The [focused test file](../tests/unit/test_containers.py) runs five positive cases and
19 individually parameterised rejection cases. [JUnit](data/s2_kyc_container_adapter_1/focused.xml)
and the [guarded log](data/s2_kyc_container_adapter_1/focused.log) record **24/24 PASS**,
0.17s pytest time; guarded command time is recorded separately. No repeats/failures.
Each rejection checks a fixed error and unchanged adapter/fixture input state.

| # | Distinct case | Result |
| --- | --- | --- |
| 1 | Holder private credential/witness/Mcred exact canonical hand-off | PASS |
| 2 | Issuance approved attributes/DID/version/evidence conversion | PASS |
| 3 | Exact request message/context, without claiming signature verification | PASS |
| 4 | History page bound to independent start/query; empty page byte equality | PASS |
| 5 | Public synthetic statement preview; private bytes absent, no proof/verdict object | PASS |
| 6 | Invalid base64 alphabet | PASS, binary |
| 7 | Non-canonical base64 unused bits | PASS, binary-canonical |
| 8 | uint64 overflow | PASS, integer-range |
| 9 | Boolean used as protocol integer | PASS, integer |
| 10 | Nested duplicate key | PASS, duplicate-key |
| 11 | Unsupported profile version | PASS, version |
| 12 | Wrong object type for expected route | PASS, type |
| 13 | Injected role selection | PASS, fields |
| 14 | Private witness injected into verifier-facing body | PASS, fields |
| 15 | 65,537-byte input before JSON allocation | PASS, document-limit |
| 16 | Depth9 before JSON allocation | PASS, depth-limit |
| 17 | 33-element array before JSON allocation | PASS, collection-limit |
| 18 | Different instance/key/schema parameters | PASS, canonical-input |
| 19 | Conflicting session-expiry representation | PASS, context-binding |
| 20 | Conflicting disclosed claim | PASS, claim-binding |
| 21 | Null proof with ordinary profile/flags cannot bypass unsupported path | PASS, proof-transport-unsupported |
| 22 | Client-supplied acceptance/consumption result | PASS, outcome-admission-unsupported |
| 23 | Truncated JSON | PASS, json |
| 24 | Floating-point protocol number | PASS, json-number |

There are no hidden mutation loops or aggregate parameter cases. Unaffected primitive,
native interoperability, real bounded signing, holder UpdateWit and durable lifecycle
validation are reused. This matrix does not independently test every supported kind,
every resource maximum, all malformed Unicode forms, non-empty history conversion or
interrupted transport. Those are explicit follow-up coverage gaps, not inferred passes
from reused primitive tests. No W3C conformance suite was run.

Commands, each once in ledger order under the existing guard:

```sh
.venv/bin/python -I -B docs/data/s2_kyc_container_adapter_1/run_checks.py preflight
.venv/bin/python -I -B docs/data/s2_kyc_container_adapter_1/run_checks.py imports
.venv/bin/python -I -B docs/data/s2_kyc_container_adapter_1/run_checks.py source-format
.venv/bin/python -I -B docs/data/s2_kyc_container_adapter_1/run_checks.py quality
.venv/bin/python -I -B docs/data/s2_kyc_container_adapter_1/run_checks.py format
.venv/bin/python -I -B docs/data/s2_kyc_container_adapter_1/run_checks.py focused
.venv/bin/python -I -B docs/data/s2_kyc_container_adapter_1/run_checks.py prepare
.venv/bin/python -I -B docs/data/s2_kyc_container_adapter_1/run_checks.py full-audit
.venv/bin/python -I -B docs/data/s2_kyc_container_adapter_1/close.py
```

Unchanged ceilings: one worker, two CPUs, four controlled processes,60s command/55s
child,300s cumulative implementation,256MiB worker/descendant cgroup memory with
swap0 and external aggregate tree-RSS stop,8MiB temporary storage,10MiB cumulative
output,1MiB/file,60KiB diagnostic stop,9GiB experiment-storage stop,2GiB free-memory
reserve. The single full audit uses the original8759-file baseline and historical
additive seals, exact permitted additions and three append-only report prefixes.
A content pass without reporting and outer-guard completion is not an audit pass.

## Remaining obligations and next package

The KYC testbed now has a bounded local conversion boundary for its existing typed
inputs, without granting service authority or bypassing proof verification. Container
transport does not resolve durable holder storage, authenticated deployed channels,
actual-ID isolation or downstream business-action/reply recovery. Production key
custody/entropy/erasure/side channels, trusted time/nonces, independent recovery
freshness, adaptive Delta_tail, component advantages and complete proof
knowledge/privacy remain open. Stages2–3 remain open.

Recommend **S3-AUTH-PROOF-FEASIBILITY-PLAN-1** as one bounded source/evidence planning
package tied to the KYC testbed's principal proof blocker: map the exact complete
authentication statement/relation and private witness to existing manuscript-circuit
and experimental-backend evidence; identify missing components, byte/cycle/memory
quantities and concrete stop criteria for a later pilot. Reuse the
[security assessment](stage2_concrete_security_assessment.md) and
[outer-oracle composition result](stage3_outer_oracle_composition.md); keep profile
soundness/knowledge/privacy separate from engineering feasibility. Deliver one scoped
proposal with an explicit budget and go/no-go prerequisites. No circuit generation,
proof attempt, backend adoption or execution is implied by this recommendation;
it is **not started**. One remaining test invocation is insufficient for a further
broad implementation matrix and must not be treated as a reset allowance.


## Measured validation closure

All **24 individually counted cases pass**, first run, with no retries or failures.
Cumulative invocation ledger: **222/223**, one remains. Lint and formatting pass.
The single [complete audit](data/s2_kyc_container_adapter_1/result.json) passes content,
inventory, report readback and its outer guard, exit 0. Coverage:
10,100 disjoint content paths and
10,122 identity-inclusive paths. No unexpected
changes, additions or removals; three existing reports preserve their entire prefixes.
The new module and its test file are isolated additions; prior code is unchanged.

| Measurement | Result |
| --- | --- |
| Audit wall time | 2.425557629 s |
| Audit cgroup-v2 memory.peak | 23,527,424 bytes |
| Audit sampled process-tree RSS | 41,496,576 bytes |
| Maximum guarded-job cgroup peak | 38,338,560 bytes |
| Maximum sampled tree RSS | 58,609,664 bytes, separate metric |
| Guarded commands | 8, 3.546745997 s |
| New package charge including five bookkeeping seconds | 8.546745997 s |
| Cumulative implementation charge | 195.863037117/300 s |
| Remaining implementation allowance | **104.136962883 s; one test invocation** |
| Temporary storage | 0 observed peak bytes; zero retained |
| Evidence bytes at outer audit completion | 322,908 |

The unchanged 256 MiB cgroup ceiling includes the worker/descendants and charged
file-cache/kernel memory; swap is zero. External tree RSS is separately bounded and
can count shared pages repeatedly. No resource breach occurred. Analysis
270.181481168 s and isolation 250.22 s remain unchanged. Final bookkeeping uses the
established 256 MiB address-space/five-second CPU+alarm/two-CPU/1MiB-file limits,
inside its five-second charge; it does not repeat the protected content scan.
[Closure](data/s2_kyc_container_adapter_1/validation-closure.json) and
[additive seal](data/s2_kyc_container_adapter_1/manifest.json) record exact balances.
No historical baseline was regenerated. Stages 2–3 remain open; isolation safely
stopped/unactivated, 22 identity cases pending; proof ledger two used/one unused.
Next: S3-AUTH-PROOF-FEASIBILITY-PLAN-1, a bounded source/evidence plan only, not started.
