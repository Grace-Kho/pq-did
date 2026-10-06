# S2-KYC-INTEROPERABILITY-CONTRACT-1

This package defines a **proposed application container contract** for the connected
reference KYC lifecycle. It preserves every canonical signed/proved byte and adds
15 synthetic JSON examples. It implements no production parser, transport, service,
W3C securing mechanism or proof backend. A container round trip is not evidence of
W3C conformance or a secured credential/presentation.

## Authority and starting balance

Only manuscript Sections **II–VIII**, agreed SPEC-001–004 and the
[current specification](implementation_spec.md), particularly E-001–003, govern the
scheme. The checked manuscript SHA-256 is
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
Reused source excerpts: VII-A.4–.8 and VIII-E in the preserved
[II–VIII extraction](data/s2_concrete_security_assessment_1/sections-II-VIII.txt).
No requirement is taken from excluded manuscript sections.

[Preflight](data/s2_kyc_interoperability_contract_1/preflight-evidence.json) verifies
all 75 inputs of the preceding holder integration seal
`64c34241115cfe98838e3ddafb2113fbf28d9cdadfb123b9b9288ba90f615e44`, plus the
53 assessed inputs. Starting implementation ledger: **194/199** test invocations,
**178.7042184660677/300 s** charged, **121.29578153393231 s** remaining. No amendment.
Four new consistency cases are planned, leaving one. Measured commands plus five
bookkeeping seconds continue the existing accounting; ten seconds remain reserved
for cleanup/evidence at admission. Analysis **270.1814811680233 s** and isolation
**250.22 s**, including its reserve, are separate and untouched.

The first preflight failed on a newly introduced helper assertion typo (`0.181…`
instead of the historical analysis balance `270.181…`), after baseline comparisons.
The [correction record](data/s2_kyc_interoperability_contract_1/preflight-correction.json)
preserves failed source/logs/STOP and permits one named corrected preflight. This
infrastructure failure consumed time but executed no functional test. The corrected
check passes. No historical test is restarted.

The [holder integration report](stage2_holder_witness_revocation_integration.md)
and issuer/manager/verifier reports linked there remain the functional evidence:
A actual bounded cryptography; B complete local relation evaluation with a private
witness; C synthetic verifier acceptance. Their failures and limitations are retained.
Sealed host evidence confirms isolation safely stopped/unactivated, with 22 original
identity cases still pending. Proof ledger **two used, one unused**; CPU proving paused.

## Implemented objects, authority and release boundaries

`B64` below means the proposed lossless JSON encoding described later, not a change
to scheme framing. `U64` is an unsigned decimal string converted exactly to the
existing eight-byte unsigned big-endian integer. Binary widths are **decoded** widths.
All input parameters are compared with independently configured `pp`, schema,
issuer/key version, namespace and role trust. The example instance file is never a
trust anchor supplied by a presenter. Local operation IDs, service capabilities,
writer permits and retained head tickets are authority/storage inputs; they are not
new public protocol fields or signatures.

| Object / producer → consumer | Required input/body and canonical mapping | Authentication, authority, release and failure |
| --- | --- | --- |
| Trusted instance / operator → all roles | `parameters:B64` = `encode_parameters(pp)`; suite, `refI`, namespace32, issuer and manager public keys1952 each, immutable schema. `refI=enc_iref(issuer,key-id,schema)`, issuer/key-id each1–256 bytes | Existing registered/trusted configuration selects keys/roles. Structurally valid presenter parameters confer no trust. Wrong instance/key/schema rejected before acceptance |
| Issuance intent / holder → issuer | `session:B64`1–256, `did:B64`171, `version:B64`56, `attributes:B64`1024, `evidence:B64`≤65536, `holderApproval:B64`1024. Exact `IssueRequest`, approved `Esch(m)` including DID/version | Confidential authenticated channel; issuer evidence policy and current resolved controller, exact holder approval. Evidence/session/approval are application arguments, not credential-signed fields. No release on authorisation/mismatch/state/proof/signing/commit failure |
| Enrolment challenge / issuer → holder | `parameters`, `approvedAttributes`1024, `identifier`decimal0..2²⁰−1 (four bytes internally), `nonce`32, `state`3427. Exact `EnrolmentChallenge`; holder constructs `B=(Y,Esch(m))`, `Xen` through existing encoders | Permanent manager allocation precedes challenge; unused issuer nonce is registered. Challenge delivery uses the private channel. Abort retains reservation and retires nonce; no implicit reallocation on retry |
| Enrolment submission / holder → issuer | `statement:B64=E(Xen)`, `proof:B64`, `controllerSignature:B64`3309. `Xen` includes pp,µ,approved vector,rid,B,nonce,state | Controller signs exact `E(Xen)` under `PQ-DID/control/v1`; complete enrolment proof must validate. DID and state freshly rechecked before certification. Null placeholders in examples must fail admission |
| Credential delivery / issuer → original recipient → holder | `credential:B64=encode_credential(pp,vc)` and separate `identifier`, `path:B64`960, `state:B64`3427. Private credential = cert(B,σ),m,rid,emptyρ,µ | Exact `Mcred=enc_cred(suite,E(µ),E(B),[rid]4)`, context `PQ-DID/credential/v1`. Issuer logs certification and committed recipient outcome before delivery. Holder validates approved vector/opening/signature/path/state before acceptance |
| Private wallet hand-off / holder acceptance → local holder | `credential`, `authenticationWitness:B64`5329, `state`3427. Witness is secret32 + m1024 + rid4 + σ3309 + path960 | Holder-only memory/container. Same credential/rid and coherent path/state; no remote endpoint for this object. Existing atomic snapshot replacement is in memory, not durable wallet storage or reliable erasure |
| Presentation request / verifier A or B → holder | `context:B64=E(ctx)`, `state:B64=E(rstate)`, `requestSignature:B64`3309; optional display is made required in this draft as `sessionExpiresAtSeconds:U64`, exactly equal to ctx.texp | Each verifier independently pins audience/key/store. Context fields: suite,audience1–256,session1–256,nonce32,policy,refI,stateRef,expiry8. Sign exact E(ctx) under `PQ-DID/request/v1`; signature remains outside ctx and vp. Holder approves exact policy/audience/session and validates request/state; labels cannot grant approval |
| Presentation submission / holder → selected verifier | `statement:B64=E(X)`, `proof:B64`, `disclosedClaims:array` matching canonical D,mD. X=(pp,µ,ctx,state,D,mD); internal `Presentation(D,mD,π)` | Reconstruct expected X using trusted pp and stored complete request; require supplied X equality. Then public/policy checks, actual admitted proof, final authenticated current read and atomic expiry/consume. No original credential or witness enters this interface |
| Verification result / verifier → relying application | `decision` exact Decision value; `accepted:bool`, `challengeConsumed:bool`, `businessAction` advisory enum. Example shows unsupported/false/false/not-authorised | Result is a channel-local service outcome, not signed scheme data, a transferable receipt or authorisation from client JSON. ACCEPTED is released after durable consumption. Lost response is not another acceptance: existing store withholds acceptance redelivery; replay can return UNKNOWN. Downstream business-action atomicity/recovery is unimplemented |
| DID mutation/read / controller, registry → resolver → issuer or explicitly authorised disclosed-DID verifier | Existing `DIDBody/Record`, `did-body`, `did-record` and `did-read/did-chain`; registry-id32, did171, index8 (implemented index<2¹⁶), predecessor48, controller-key1952, active0/1, salt32, signature3309. Read selector `00` current or `01||vD`, fresh nonce32; reply message ≤263296, ≤32 records, each≤8192 | Controller/registry contexts `PQ-DID/did-record/v1`, `PQ-DID/did-read/v1`; validate complete chain, pinned registry, nonce, selector and endpoint. Version56=index8+digest48. No redirects. DID/controller publication is separate from issuer credential signing and anonymous authentication |
| DID resolution result / validated resolver → caller | Draft `did`, `selector:B64`, exact document bytes as `document:B64`, `version:B64`56, `contentType`, `registryReply:B64`, `registrySignature:B64`3309. Method reply remains separate from exact `{"id":"did"}` UTF-8 document | Active result only after validated method evidence; historical resolution does not establish present control. UNKNOWN/DEACTIVATED/BUSY/UNAVAILABLE/INCONSISTENT/MISMATCH/EXHAUSTED remain distinct. Example lacks method evidence and is explicitly non-verifying; it must not resolve successfully |
| Current revocation state / manager → issuer, holder, verifiers | `state:B64`3427; for currentness `currentNonce:B64`32 and `currentSignature:B64`3309. State E(rstate) contains ns32,epoch8,root48,σ3309 | State message `enc_state(suite,E(µ),epoch,root)`, context `PQ-DID/state/v1`. Ordered current reply signs `enc_current(suite,E(µ),nonce,E(state))` under `PQ-DID/current/v1`. A state signature alone is not freshness. Example carries a preserved signed state only |
| Revocation instruction / authorised issuer → manager | Existing `RevocationRequest(rid,stateRef,nonce,signature)`; rid4 restricted to20bits, reference ns32/epoch8/root48, nonce32, signature3309; `build_revocation_request_message` | `PQ-DID/revreq/v1`; manager authorises allocation, expected state, nonce and fenced writer. Signed new state/update/history/checkpoint/head/outcome commit consistently before public release; no caller-selected key/context |
| Witness-update request / holder → manager public history | `namespace:B64`32, `afterEpoch:U64`, `targetEpoch:U64` with target≥after. Existing `updates(namespace,after_epoch,target_epoch,limits)` | Local limits are trusted configuration, not caller overrides. No private holder rid/path/DID, credential, secret or recipient token is needed. History unavailable/conflict/resource errors cannot be interpreted as non-revocation |
| Witness-update page / manager → any holder | `status` exact ManagerStatus, `startingState`,`endpointState`, `records:array[B64]`≤16, `requestedEpoch`,`nextEpoch:U64`, `complete:bool`. Each rupdate11162; total records≤178592. `nextEpoch=endpoint.epoch`; complete iff requested epoch reached | Carried states and each update authenticate contents. Update signature covers distinct six-field `update` message; transport remains five-field `rupdate` with raw960-byte sibling path. Public records disclose the **revoked** identifier and its old transition path; never insert the requesting holder's private witness |

The field names/types and mandatory sets of the 15 example envelopes are recorded in
[contract.json](data/s2_kyc_interoperability_contract_1/contract.json). These are proposed
application conventions; the typed APIs and canonical binary records above already
exist. No ordinary interface accepts a caller role/key/context override. Proof size
admission is unresolved for a real complete proof: the existing reference10MiB opaque
proof ceiling is not a demonstrated feasible wire size, and is not raised here.

### Exact errors and redelivery

Issuer retries use the same authorised operation and stored state. The durable flow
has separate issuer and manager commits: intent → permanent reservation → attachment
→ pending challenge → signing claim → certification log/outcome → original-recipient
retrieval. There is **no cross-store atomic transaction**. A signed but uncommitted
credential is inaccessible. A reply lost after certification is retrieved byte-for-byte
for its original recipient without resigning/reallocation; wrong recipient fails.
Interrupted holder receipt does not roll back a certification or reservation.

Manager public retrieval is not recipient-bound. A committed public mutation is
retrievable exactly after admitted recovery, while a stored CURRENT result is withheld
if its state has been superseded. Recovery uses independently retained heads, explicit
admission and writer fencing; self-consistent database contents are insufficient.
The examples confer none of that authority and expose no durable-store tokens.

A holder validates an entire page before replacing its witness/state. UPDATED commits
a coherent pair; REVOKED, INVALID_INPUT, INVALID_HISTORY, RESOURCE_EXHAUSTED and
PROCESSING_FAILED return no replacement. An earlier successfully committed page stays
retained if a later page fails. Continuation is explicit from nextEpoch, never an
automatic retry loop; incomplete catch-up must not be labelled complete. The sample
empty same-epoch page is intentionally not an advancing update or an NR proof.

Verifier proof/expiry/trust/state/policy failures do not consume that call's pending
challenge. The final ordered manager read defines currentness: a later revocation
can occur before local consumption without retroactively invalidating the read.
Freshness is not global transactional atomicity. Backend absence fails closed.
Transport timeout is an **unknown delivery outcome**, never evidence of acceptance or
permission to manufacture another verification. JSON result flags are not trusted
client input; successful KYC business effects need a later explicit commit/recovery
contract. No HTTP error/status or remote-authentication standard is invented here.

## Dated W3C requirements and proposed mapping

Versions checked on26 September2026: DID Core1.0, Recommendation19 July2022;
VC Data Model2.0, Recommendation15 May2025; Data Integrity1.0,
Recommendation15 May2025. The dated publications, not mutable drafts, are the targets.
The following concise standards matrix separates applicable requirements from our
project decisions; these requirements are **not claimed satisfied by this package**.

| Standard requirement and exact section | Existing/proposed mapping and remaining work |
| --- | --- |
| DID Core§§3.1,5.1.1,6.2: document id identifies the DID; JSON is a representation | Preserve exact manuscript minimal document. Project `did:pqdid:…` syntax and method records are experimental; no registered-method or DID conformance claim |
| DID Core§7.1: resolution returns document plus resolution/document metadata; errors have no document | Proposed resolver adapter separates contentType/error from version/method evidence. Keep non-active/failure outcomes explicit; do not map query failure to authenticated absence |
| DID Core§§5.2–5.3,8: verification relationships and method requirements are distinct | Current controller evidence lives outside the document. No invented ML-DSA verification-method/key encoding; method specification and consumer validation remain open |
| VC2§§4.3–4.5: base context and credential/presentation types identify the model | Future contexts/types must be specified and pinned. Current examples deliberately use project envelopes, no VC media type, @context, registered cryptosuite or valid-VP label |
| VC2§4.7: issuer is a URL or object with URL id | Propose independently trusted mapping from exact refI issuer/key/schema to an issuer URL. Arbitrary issuer bytes are not automatically a URL; do not use holder DID as issuer |
| VC2§4.8: credentialSubject describes subjects; subject id is optional | Holder-local view may represent full schema; anonymous derived view contains only selected claims and omits subject/holder/credential IDs. Issuance DID stays private unless authorised disclosure includes both DID/version |
| VC2§4.9: credential validity uses dateTimeStamp values | Keep session expiry separate; proposed credential display may derive only the certified/disclosed validUntil claim, with an explicit mapping decision and range check |
| VC2§4.10: status objects require id/type | Propose shared namespace/state reference, never a credential-specific URL/index exposing rid. No status type/IRI/mechanism is assigned; mapping remains unimplemented |
| VC2§§4.12–4.13,5.13: securing mechanisms define verification; embedded mechanisms secure all non-proof graphs | Project needs a complete securing-mechanism specification binding the returned claim graph to canonical X/Mcred. Wrapping a null token, RISC Zero journal or original σ does not supply one |

Sources: [DID Core1.0](https://www.w3.org/TR/2022/REC-did-core-20220719/),
[VC Data Model2.0](https://www.w3.org/TR/2025/REC-vc-data-model-2.0-20250515/).
Data Integrity1.0§§2.1,3.1–3.2 specifies a proof model and cryptosuite interface, not an
ML-DSA/PQ-DID suite. Adopting that framework would require an actual suite definition,
verification-method binding, transformation/hashing/proof algorithms and secured data
coverage. This package does not select that route or invent its identifiers.
[Data Integrity1.0](https://www.w3.org/TR/2025/REC-vc-data-integrity-20250515/).

In our proposed view, schema indices remain authoritative: name/type/value triples
are redundant renderings of exactly decoded mD. `kycPassed` is Boolean;
`assuranceLevel` and `validUntil` are unsigned decimal values; country remains opaque
bytes until a vocabulary defines its semantics. A predicate on a hidden field is not
supported by the current disclosed-only policy evaluator. Do not add claims merely
because a verifier can read them from a wrapper. Do not silently make a new issuer
URL, type, vocabulary, status locator or display timestamp credential-signed.

The missing securing specification must explain how independently pinned constant
vocabulary/issuer mappings and every asserted claim become the verified output,
without unauthenticated graphs or information outside the certified/proved relation.
If that cannot be established without changing Mcred, X, public information or the
privacy game, a separate specification/profile decision is required. The manuscript
MITH construction and experimental RISC Zero profile remain distinct. Neither this
contract nor completed component receipts settle full authentication knowledge/privacy.

## Privacy and time at the application boundary

The two examples use independently named verifier audiences, distinct sessions and
nonces. Neither presentation exports the holder secret, full attributes, B, original
credential signature, rid, Merkle path, credential identifier, subject DID/version,
wallet identifier, device fingerprint or recipient/operation token. The test checks
the **decoded canonical statement**, not merely visible JSON keys. No original VC is
nested inside the anonymous presentation; no persistent holder-key authentication or
hidden-DID lookup is added. Examples use D=(3,4,6): kycPassed, assuranceLevel,validUntil;
country and DID/version remain undisclosed. They illustrate one existing policy,
not every policy or the country-specific second scenario described in E-002.

There is still public common information: issuer/key/schema/namespace, signed state
and epoch/root, disclosure mask, policy, disclosed values and timing/context data.
Stable disclosed validUntil or unusual claim combinations can aid correlation. Unique
verifier policies/nonces can also tag requests; holder approval remains necessary.
Draft wrappers carry no arbitrary metadata bag, shared presentation ID or wallet
version. Their fixed synthetic labels are documentation labels, not authenticated
claims or real endpoint signalling. Production logs must avoid private containers,
full statements and cross-verifier identifiers unless separately authorised.

The manuscript's common-authorised-leakage, authority-collusion, compromise and
network-correlation restrictions still apply (VI and VIII-E). Byte omission alone
demonstrates no unlinkability or proof privacy. Public update records themselves reveal
revoked identifiers; a holder's **request** has no candidate identifier. Historical
resolver use happens only when both DID/version are explicitly disclosed and required.

SPEC-002 stays unsigned64 POSIX seconds, eight big-endian bytes, strict **now < texp**
including final atomic recheck. Draft JSON uses a minimal decimal string, retaining
all64 bits; floating-point JSON numbers are forbidden for protocol integers.
`sessionExpiresAtSeconds` must equal ctx.texp and is **not credential expiry**.
A trusted integer-second clock is supplied by the application, never client metadata.
No timezone or leap-second reinterpretation, rounding, overflow or saturation is allowed.
The example is1900000000 seconds; equality is expired. A later optional UTC display
conversion must round-trip exactly to seconds and reject unsupported date ranges;
uint64 covers dates outside ordinary date libraries. No date-time conversion runs
here. A VC validUntil view, if adopted, derives from the certified schema field only,
not ctx.texp; an applicable policy must disclose/check that field, e.g. validUntil≥texp.

## Proposed parser and container contract

All conventions in this section are **proposed**, awaiting the next isolated adapter;
existing binary encoders and the65,536-byte local authority IPC reader are unchanged.
Each example has the exact common fields profile/kind/synthetic/exposure/evidenceStatus/body.
The first five are fixed documentation/type labels. `synthetic:true` forbids operational
admission, rather than allowing a bypass. Changing that flag cannot make a proof valid.
The next adapter must keep fixture loading separate from its ordinary API.

- UTF-8 JSON, no BOM, exactly one object; no duplicate keys at any depth, trailing
  input, malformed/truncated input, NaN/Infinity, unknown fields, implicit defaults or
  coercions. Reject rather than skip/truncate/normalise. Fixed mandatory fields per
  kind are in contract.json. Omitted and null differ; null signatures/proofs/method
  replies are examples-only, never accepted for an authenticated operation.
- B64 uses unpadded URL-safe alphabet, with canonical encode-after-decode equality;
  forbid whitespace, standard `+`/`/`, padding and non-zero unused bits. Check encoded
  length against the decoded cap before allocation, then exact type/width and the
  existing canonical decoder. Empty bytes are allowed only where the existing field
  permits them (e.g. credentialρ), not for signatures or nonces.
- Ordinary documents≤65,536 UTF-8 bytes; public history and DID-chain containers≤524,288;
  absolute file ceiling≤1MiB. Depth≤8,≤512 total members,≤32 per object/array, key≤64
  UTF-8 bytes. Body constraints are tighter: schema≤16, policy≤32 clauses, update
  records≤16 and178592 decoded bytes, claims exactly D. Sum all fields as well as
  checking each field. No decompression, external references, downloads or redirects.
- These proposed transport admissions can reject a mathematically valid larger input,
  including a full64KiB evidence field after base64 expansion. Report explicit
  admission exhaustion before state mutation; do not truncate or enlarge core limits.
  Public update paging uses its existing explicit continuation. It is not authority
  IPC fragmentation or an excuse to pass a524KiB document to a64KiB reader.
- An actual proof transport cap/segmentation policy is **unset**: no complete proof
  size is established. The next container adapter must fail closed for live proofs
  rather than claim its64KiB document limit supports the full construction. Any later
  proof-format admission change needs its own evidence and approval.
- Re-encode all parsed canonical objects and require equality; verify every displayed
  claim and context field against those objects. Do not sign JSON, alter padding,
  reinterpret schema byte fields as Unicode, silently choose a new issuer key, or
  let presentation-supplied state replace the pending request's state.
- Errors return a bounded fixed code, never raw private bytes or parser tracebacks.
  Unsupported, malformed, unauthorised, resource-exhausted and unknown-delivery
  outcomes remain distinct. No automatic retries or business authorisation on errors.

## Examples and bounded validation

[Example directory](data/s2_kyc_interoperability_contract_1/examples) contains15 JSON
files: instance; private-holder; issuance-request; enrolment-challenge/submission;
issuance-delivery; request-a/b; presentation-a/b; verification-result; did-resolution;
revocation-state; updates-request/response. The
[provenance](data/s2_kyc_interoperability_contract_1/example-provenance.json) identifies
unchanged relations vectors alpha-42 / alpha-42-old-002c. The write-once generator only
uses existing canonical encoders and preserved fixture signatures; it creates no key,
signature, proof, authority store or service invocation. The historical state signature
is real fixture content; the newly distinguished request contexts are **unsigned**.
No file is a valid secured W3C VC/VP or a newly issued credential.

| New counted case | Exact purpose / limit of evidence |
| --- | --- |
| Private holder canonical hand-off | Decode/re-encode credential/witness, compare private fields and state with the existing fixture; no rerun of CredValid |
| Public projection/privacy, audience A | Exact expected canonical X, context/state agreement, three selected claim renderings, forbidden private data absent; null proof/request signature stays non-verifying |
| Public projection/privacy, audience B | Same independently counted case for distinct audience/session/nonce; not an aggregate hidden second test |
| Session expiry equality | Exact decimal/binary context binding and rejection at now=texp; no claim of a complete dateTimeStamp converter |

These four cases do not include parser fuzzing/negative campaigns, live signature
verification, registry-chain validation, non-empty update execution, JSON-LD expansion,
W3C test suites or any lifecycle replay. Those previously validated core behaviours
are reused; the new parser/mapping negatives remain future acceptance criteria.
Syntactic JSON/AST/link/inventory checks are preservation infrastructure, separately
timed, not unreported functional scenarios. One invocation is deliberately left unused.

Guarded command sequence (already run only when recorded in the ledger; no reruns):

```sh
.venv/bin/python -I -B docs/data/s2_kyc_interoperability_contract_1/run_checks.py preflight
.venv/bin/python -I -B docs/data/s2_kyc_interoperability_contract_1/run_checks.py preflight-corrected
.venv/bin/python -I -B docs/data/s2_kyc_interoperability_contract_1/run_checks.py examples
.venv/bin/python -I -B docs/data/s2_kyc_interoperability_contract_1/run_checks.py imports
.venv/bin/python -I -B docs/data/s2_kyc_interoperability_contract_1/run_checks.py source-format
.venv/bin/python -I -B docs/data/s2_kyc_interoperability_contract_1/run_checks.py quality
.venv/bin/python -I -B docs/data/s2_kyc_interoperability_contract_1/run_checks.py format
.venv/bin/python -I -B docs/data/s2_kyc_interoperability_contract_1/run_checks.py focused
.venv/bin/python -I -B docs/data/s2_kyc_interoperability_contract_1/run_checks.py prepare
.venv/bin/python -I -B docs/data/s2_kyc_interoperability_contract_1/run_checks.py full-audit
.venv/bin/python -I -B docs/data/s2_kyc_interoperability_contract_1/close.py
```

Resource ceilings remain one worker/two CPUs/four controlled processes,60s command/
55s child,256MiB aggregate worker cgroup memory with swap0 and external RSS stop,
8MiB temporary data,10MiB cumulative package output,1MiB/file,60KiB diagnostic stop,
existing9GiB experiment-storage stop and2GiB free-memory reserve. The full auditor
uses the corrected bounded engine and original8759-file baseline, extended only by
historical additive seals. Three status reports are append-only. Final comparison,
report generation and outer guard all must pass; no automatic audit retry is allowed.

## Updated KYC checklist and implementation decision

Completed previous integration items remain completed **at reference level only**:
DID/evidence/controller → durable issuance → holder acceptance → authenticated updates
→ local witness maintenance → approved two-audience preparation → synthetic verifier
consumption, with own-revocation rejection evaluated locally. This package adds the
explicit mapping and container examples; it closes no production/privacy obligation.

Recommend **S2-KYC-CONTAINER-ADAPTER-1**: implement an isolated parser/mapper for these
proposed project containers, preserving fail-closed proof boundaries. Do not claim
W3C conformance or choose a securing profile in that package. Its concrete criteria:

- [ ] Strict bounded parser accepts canonical examples only through a fixture API;
  ordinary operations reject synthetic/null/unsupported proofs and signatures.
- [ ] Individually count duplicate/unknown/truncated/noncanonical-B64/oversized/depth
  rejection tests, demonstrating no lifecycle or private-state change on failure.
- [ ] Typed mapping requires independently pinned pp/issuer/audience/request key;
  altered redundant claims/context/state fail before proof work or consumption.
- [ ] Export only D,mD and public X; both audiences omit private bytes and shared
  holder IDs; hidden DID never reaches the resolver. No arbitrary metadata passthrough.
- [ ] Preserve recipient-bound committed issuer redelivery, public manager retrieval,
  final-read/strict-expiry consumption and lost-response uncertainty. Reuse lifecycle
  evidence; do not add an unsound KYC-action success/redelivery endpoint.
- [ ] Resolve KYC-INT-001–004 separately before W3C/profile adoption: issuer/vocabulary
  binding, securing mechanism, DID method/key representation and private status mapping.

The negative matrix needs a **new explicit test allowance**; one remaining invocation
cannot validate that implementation meaningfully. No next package is started.
Durable holder storage, deployed authenticated channels, actual-ID isolation,
production evidence/trust/time/nonces, independent recovery freshness and downstream
KYC action/reply recovery remain open. So do production custody, entropy assurance,
reliable erasure, side channels, adaptive Delta_tail, component advantages at reduction
budgets, outer-oracle composition and complete proof knowledge/privacy. Stages2–3
remain open; no activation, installation, profile change, proof or zkVM execution.


## Measured validation closure

Four individually counted example checks pass, first run; **198/199 invocations**,
one remaining. Lint/format pass. The preflight typo failure, exact failed source and
single reviewed correction remain recorded; no lifecycle test or native ABI replay.
The single
[complete audit](data/s2_kyc_interoperability_contract_1/result.json)
passes content/inventory, report readback and outer guard, exit0. It covers
10,030 disjoint content paths and
10,051 identity-inclusive paths,
with no unexpected addition, removal or content change. The three existing reports
retain their complete historical prefixes. All production sources are preserved.

| Measurement | Result |
| --- | --- |
| Audit wall | 2.316034001 s |
| Audit cgroup-v2 memory.peak | 23,195,648 bytes |
| Audit sampled process-tree RSS | 41,230,336 bytes |
| Maximum guarded-job cgroup peak | 44,818,432 bytes |
| Maximum sampled tree RSS | 57,548,800 bytes, separate metric |
| Guarded commands including failed preflight | 10, 3.612072654 s |
| New package time including five bookkeeping seconds | 8.612072654 s |
| Cumulative implementation charge | 187.316291120/300 s |
| Remaining implementation allowance | **112.683708880 s; one test invocation** |
| Temporary data | 0 observed peak bytes; zero retained |
| Package bytes at outer audit completion | 509,039 |

The unchanged256MiB cgroup ceiling covers the worker and descendants, including
charged file-cache/kernel memory; swap0. The external RSS sample is separately
bounded and may count shared pages repeatedly. No resource breach occurred.
Analysis270.181481168s and isolation250.22s remain unchanged. Closure bookkeeping
uses the established256MiB address-space/five-second CPU+alarm/two-CPU/1MiB-file
limits within its five-second charge; it does not repeat the content audit.
[Closure](data/s2_kyc_interoperability_contract_1/validation-closure.json) and
[additive seal](data/s2_kyc_interoperability_contract_1/manifest.json)
retain the precise ledger. Original baselines were not regenerated.
Stages2–3 remain open; isolation safely stopped/unactivated,22 identity cases pending;
proof ledger two used/one unused. Next:S2-KYC-CONTAINER-ADAPTER-1, not started,
requires a separately authorised focused test allowance for its negative matrix.
