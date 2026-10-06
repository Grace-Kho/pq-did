# S2-UPDATE-WIT-1 — bounded holder-local witness updates

19 September 2026. **Complete at the reference-procedure boundary:** authenticated
ordered public updates produce a new local witness/state pair, or an explicit
failure with no replacement. **70 focused and 25 scoped regression cases pass.**
No proof, zkVM execution, dependency change or production service was launched.
CPU proving remains paused; the cumulative ledger is **two used, one unused**.

## Authority and exact public contract

Read [repository instructions](../AGENTS.md), [implementation specification](implementation_spec.md),
[Merkle contracts](stage2_binding_merkle.md), [relation contracts](stage2_relations.md),
[verifier lifecycle](stage2_verifier_state.md), status and traceability. Only
manuscript **Sections II–VIII** were used, specifically IV-A/B/C, V-B/D, VII-A.1/.5/.8
and the separate freshness boundary in VII-A.7/VIII-E. The selected PDF identity is
unchanged: SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
SPEC-001–004, the active suite and cryptographic parameters are preserved.
No genuine specification ambiguity or new SPEC decision was needed.

For the expected issuer instance, `µ=(refI,ns)`, the manager-signed state is
`rse=(ns,e,Ae,τe)` and its logical reference is `refe=(ns,e,Ae)`. Existing
canonical encoders and context strings are reused:

```text
State message = enc_state(suite,E(µ),[e]8,Ae)
State context = PQ-DID/state/v1
Mu = enc_update(suite,E(µ),E(refe),E(refe+1),[r*]4,s*0||...||s*19)
Update context = PQ-DID/update/v1
ue+1 = enc_rupdate(E(rse),E(rse+1),[r*]4,s*0||...||s*19,υ)
```

The five-field `rupdate` transport is distinct from the six-field `update`
signing message. SPEC-001's path is **one raw 960-byte payload**, LP-wrapped once,
twenty 48-byte siblings in leaf-to-root order. Each encoded state is 3,427 bytes;
each encoded update is exactly **11,162 bytes**, including tag/count/length framing.
No issuer request, holder secret, private credential or holder path is added.

R-030 authorises the manager to change only an allocated, unrevoked identifier from
zero to one after checking the issuer's `revreq` signature, unused nonce, expected
current reference and registration. The request message remains
`enc_revreq(suite,E(µ),[rid]4,E(refe),nR)`. The holder receives the resulting signed
public update, not that private service transaction. This implementation verifies
the public transition and authority; it cannot infer allocation, nonce consumption
or issuer authorisation from a tree path. Those manager-side obligations remain open.
A public zero leaf may still be unallocated.

## API, authentication and algorithm

The new [witness_updates.py](../src/pqdid/witness_updates.py) provides:

| API/type | Contract |
|---|---|
| `PublicUpdate`, `encode_update`, `decode_update`, `build_update_message` | Typed states, public revoked identifier/path and manager signature; exact existing transport and signed bytes |
| `WitnessCheckpoint(identifier,path,state)` | Immutable holder-local checkpoint, with private fields suppressed in repr |
| `update_witness(expected_parameters,starting,target,records,limits=...)` | Immutable finite tuple of public encoded records; returns a new checkpoint only on complete success |
| `update_authentication_witness(...)` | Takes an existing local authentication witness, derives r from its certified-identifier field, changes only the path and returns the matching target state |
| `UpdateLimits`, `UpdateStatus`, `UpdateReason` | Lowerable admission limits and fixed typed outcomes; no secret-bearing exception text or logging |

Expected parameters must come from the holder's trusted issuer-instance
configuration. Update contents never select a key, issuer or namespace. State
domains are checked against those parameters; both state and update signatures use
the expected revocation public key. The signed suite and E(µ) bind issuer/key/schema
reference and namespace, and the two signed references bind epoch and root. Trusted
registration of that key for the instance remains an external obligation.

Every carried state is authenticated, including the caller's starting and target
states and both states in every record. The implementation invokes the existing
bounded ML-DSA-65 core once per signature. It uses its internal
`_verify_diagnostic` result so sampler exhaustion remains distinguishable from an
invalid signature; the existing Boolean API merges those results. This is an
explicit internal-module dependency, not a new verifier or changed cryptographic
API. RejNTTPoly's **1,026-byte** and SampleInBall's **256-byte** limits are unchanged.
There is no uncapped verifier, alternate key, service call or retry.

Processing follows R-029–R-031:

1. Admit record count/bytes before parsing or cryptography. Validate parameters,
   identifier, raw starting path, state types/widths and uint64 epochs.
2. Decode each fixed-size record and require a complete sequence: each old reference
   equals the previous reference; each new epoch equals old epoch plus one; the final
   reference equals the caller's target; target epoch minus starting epoch equals
   record count. Namespace mismatches reject and epochs cannot wrap.
3. Authenticate both endpoint states and require
   `PathRoot(r,0,w)=starting.root`. Authenticate every record's two states and Mu.
   Require `PathRoot(r*,0,w*)=old.root` and `PathRoot(r*,1,w*)=new.root`.
   Cache the latter calculation's ancestors `a0=L1,...,a20=new.root`.
4. After the **entire public batch** passes, process the private path in order.
   If `r=r*`, return authenticated revocation with no replacement witness.
   Otherwise, for j=0,...,19, replace sibling j by aj exactly when
   `((r >> j) xor 1) == (r* >> j)`. Preserve every other sibling.
5. Require the resulting zero-leaf path to match each new root. Only after all
   steps succeed return the final path paired with the exact validated target state.

Hashes remain the existing depth-20 SHA3-384 domain-separated leaf/node operations;
numeric bit j controls child order, and node level is j+1. No tree resize, changed
leaf encoding, identifier reuse or unrevoke operation exists. Repeating a revocation
or trying a one-to-zero transition fails the required old zero-leaf/new one-leaf checks.

State chaining uses **logical reference equality (namespace, epoch, root)**, as used
by the specified signing messages. Different valid randomised signatures over the
same logical state do not create different epochs. Every supplied signature is
nevertheless checked. This routine representation choice introduces no new wire field.

The wrapper assumes the credential was already validated locally. Structural
validation and reading its identifier are not a new issuer-certificate check.
Credentials, certified attributes, holder secret and credential signature remain
unchanged. The complete authentication relation still checks the same certified
identifier, signature and binding at presentation time. Equal paths in uniform
subtrees are legitimate; a path alone does not certify an identifier or allocation.

## Limits and commit/resume behaviour

| Admission/work bound | Value |
|---|---|
| Records per call | At most 16; exact finite immutable tuple, no streaming iterator |
| Encoded update bytes per call | At most 178,592; caller may lower either limit to zero |
| Each record/path/index | Exactly 11,162 / 960 bytes; integer 0 through 2^20−1, excluding Boolean |
| Endpoint/checkpoint representations | Two fixed-width states, one 960-byte path and uint20 identifier; separately supplied trusted pp |
| Signature checks for N records | At most 3N+2; **50** at the maximum batch |
| Explicit Merkle hash calls for N records | At most 21+63N; **1,029** at maximum, excluding ML-DSA internals |
| Cached public ancestors | At most 16 × 21 × 48 = 16,128 payload bytes, plus bounded Python overhead |

Total/nested byte widths and identifier bounds precede costly authentication;
the byte allowance counts the public update tuple, not trusted pp or already held
credential objects. Fixed-width endpoints/path add bounded inputs. Caller-side
retrieval/allocation must apply the same admission policy before constructing the
tuple; the API cannot undo memory already allocated by its caller. The routine
does not materialise a million-leaf tree. Maximum work and byte limits are local
reference admission choices, not new suite parameters.

**A call returns one fully validated batch result.** Inputs are immutable; no
caller checkpoint is modified or partially committed. Public validation of a later
bad record prevents an earlier revocation from being returned as the result of that
requested batch. This is atomic local result semantics, not a persistent transaction.

| Status | Meaning and output |
|---|---|
| `UPDATED` | All required checks succeeded at the supplied target; one new checkpoint, or wrapper witness plus state |
| `REVOKED` | Entire public chain valid and certified holder identifier revoked within it; no replacement path/state |
| `INVALID_INPUT` | Malformed domains/encoding, invalid starting witness or invalid signature; no replacement |
| `INVALID_HISTORY` | Missing/replayed/reordered/conflicting sequence, endpoints, invalid tree transition or resulting path; no replacement |
| `RESOURCE_EXHAUSTED` | Admission limit, actual bounded sampler exhaustion or catchable allocation failure; no replacement |
| `PROCESSING_FAILED` | Unexpected processing exception; no replacement and only a fixed reason code |

The original witness/root/version remain paired after any failure. They may still
be mathematically valid **at the old root**; they are not permission to authenticate
under a newer context. An OS kill may prevent any typed return, but this pure
function still cannot mutate the caller's checkpoint. Durable crash recovery and
atomic wallet storage are outside this reference implementation.

A caller can explicitly divide a longer history into bounded consecutive calls,
each with its own authenticated target. After a successful call it may retain that
whole checkpoint, then continue with the next exact sequence. After a failure it
must retain the last previously successful checkpoint and obtain/validate the
missing or corrected public history. No automatic retry follows sampler exhaustion.

An empty tuple is accepted only at the same authenticated logical reference with
a valid starting witness; zero record/byte allowances permit that case. Resubmitting
already applied records is rejected. There is no duplicate-skipping or repair.
A result matching a target root makes **no currentness or freshness claim**:
the verifier still uses its stored context, final authenticated ordered current-state
read, strict SPEC-002 expiry and atomic challenge consumption.

## Privacy and deployment boundary

The caller supplies public log records for the expected instance and epoch range.
This package creates no retrieval API. Future retrieval must follow that public
log/state interface; it must not request a holder-specific path or send the
holder's private rid/path, attributes or secret to an update service. Published
r* and w* concern the publicly revoked identifier; they are different inputs from
the holder's private checkpoint. Private repr fields and diagnostics are suppressed.
Python timing, memory erasure, public-log traffic privacy and complete-view
unlinkability are not established by these tests.

Persistent wallet storage, production revocation publication/retrieval, trusted
issuer registration, key rotation and bounded key generation/signing remain open.
Controlled test signing uses ordinary native signing with ephemeral synthetic keys,
only in the test harness. It does not implement bounded signing or production services.

## Validation and recorded envelope

[Independent construction](../tests/unit/witness_update_cases.py) reuses the
unchanged [sparse-tree builder](../tests/unit/binding_merkle_reference.py), which
builds global indexed levels with independently framed SHA3 preimages. Expected
roots/paths do not use production PathRoot or the new update procedure. It constructs
Mu/rupdate independently, with ephemeral test-only manager signatures and the
original synthetic issuer/credential fixtures.

[70 focused cases](../tests/unit/test_witness_updates.py) cover exact independent
transport/signing bytes; authenticated empty history; **all 20 divergence levels**;
both identifier boundaries; own revocation at different batch positions; three
successive updates and explicit chunk resume; maximum 16-record batch; wrong
identifier/path; signed but false roots/siblings; state/update signature, role,
metadata and authority tampering; missing/replayed/reordered/forked history;
duplicate revocation/unrevoke; malformed indices/lengths/framing; epoch wrap;
byte/record admission and rejection of iterators before consumption.

Exhaustion tests inject rejected bytes into the **real bounded verifier**: one
matrix stream stops at 1,026 bytes and one update-challenge stream at 256 bytes,
with exactly one attempted exhausted stream and no fallback. Controlled memory
and runtime faults during public processing, a fault after one private step, a
corrupted intermediate ancestor, and invalid history following own revocation
verify no partial output and mandatory new-path checks.

Three composition cases use the existing explicitly test-only public proof adapter.
They first evaluate the complete local authentication relation separately over the
same witness: survivor 43 updates to the independently expected current path and
is accepted by the reference verifier; revoked 42 fails the local zero-leaf relation
and the adapter rejects; an old-valid presentation fails the final current-state
comparison with `Decision.STATE`. Wrapper credential/secret/attribute/signature
bytes are unchanged. **These tokens are not proofs or cryptographic receipts.**

**25 scoped regressions** reuse existing state encodings, uniform/non-uniform paths,
credential reuse, public/private API separation, strict expiry, state/expiry
interleavings, fail-closed proof defaults and atomic concurrent consumption.
Unchanged broad reference/circuit, native/environment and historical proof
validation is reused; it was not rerun.

The [configuration](data/s2_update_wit_1/config.json) and
[guard](data/s2_update_wit_1/run_checks.py) retain **256 MiB aggregate service cgroup
memory, no swap, one worker, two affined cores, 60 s per command and 300 s total**.
They retain the 10 GiB experiment disk ceiling / 9 GiB early stop, 64 MiB diagnostic
ceiling / 60 MiB early stop and smaller **10 MiB new-output** allowance.
The inherited runner also stops any individual log at 60 KiB and sets a 1 MiB
individual-file ceiling. At most 100 collected test cases were allowed; **95 ran**.

Before each command WSL available memory exceeded the 256 MiB allowance plus 2 GiB
reserve; the first four admitted readings ranged from 4,836,462,592 to 4,852,350,976
bytes. Existing experiment storage was 7,618,673,412 bytes. Each worker verified
its actual cgroup controls and private network with no routes. The project was
read-only inside each service, with only this new evidence directory writable.
No proof/zkVM/backend command appears in the explicit command list.

| Recorded check | Result | Guarded seconds | Cgroup memory peak, bytes | Sampled aggregate process RSS, bytes |
|---|---|---:|---:|---:|
| Focused | 70 passed, no skips | 2.298526 | 41,349,120 | 62,054,400 |
| Regression | 25 passed, no skips | 0.806343 | 41,873,408 | 63,422,464 |
| Lint | Pass | 0.089592 | 10,719,232 | 13,897,728 |
| Formatting | Pass | 0.088468 | 10,215,424 | 13,905,920 |

These four commands took **3.282929 guarded seconds** together. Cgroup and sampled
RSS have different accounting scopes; both remained under their enforced ceilings.
There were zero memory-max/OOM events and no swap, deadline or output stop.
These are validation-command measurements, not per-update throughput, percentile
latency or proving costs. All test/lint/format runs passed on their first recorded
run; ordinary formatting/import preparation preceded them.

Exact command arguments, service properties and results are in the
[run ledger](data/s2_update_wit_1/run-ledger.json), [focused XML](data/s2_update_wit_1/focused.xml),
[regression XML](data/s2_update_wit_1/regression.xml) and per-command JSON/logs.
The final [audit](data/s2_update_wit_1/validation.json) checks documentation links,
JSON, source syntax/lint/format, limits and preservation; the
[manifest](data/s2_update_wit_1/manifest.json) seals final hashes. Reproduction uses
a fresh package evidence directory; this guard refuses repeated run names or a
recorded STOP, except the single explicit audit-script correction described below.
It does not automatically retry failed tests.

The first final audit reached its combined lint check and failed because the new
audit script's scope-description line was 101 characters (limit 100). It ran for
0.396743 guarded seconds, without a resource event. The
[failed log](data/s2_update_wit_1/final-audit.log) and
[STOP](data/s2_update_wit_1/STOP.json) remain intact. A separate
[correction record](data/s2_update_wit_1/audit-correction-plan.json) explains the
one-line text fix and narrowly admitted audit-only continuation. Pre-correction
audit/guard sources are saved alongside the evidence. The corrected audit checks
the final source/guard lint and formatting as well as documentation/preservation;
its new run name cannot be repeated, and the aggregate resource allowance is
unchanged. No implementation test, proof, execution or failed resource run was
repeated.
The corrected audit passed in **0.417248 guarded seconds**. All six guarded
commands, including the preserved failed audit, took **4.096920 seconds** in total;
none reached a resource limit.

The before-inventory protects **8,723 pre-existing files**; only status, traceability
and the issue register are updated among them. Earlier source/tests, encodings,
vectors, pinned dependencies, manuscript, reports, receipts, STOP records and ledgers
remain unchanged. The new module, tests and this report/evidence are additions.
The cumulative ledger retains SHA-256
`fc64f7efbd2f20cd23fec24d828f36f1460afb0b73a76ea256d0716f309d75c5`:
**two attempts used, one unused; zero new proofs or zkVM executions**.

## Remaining work and one next bounded package

R-031's bounded holder-local **reference** procedure is implemented. R-030 remains
partial: public update encoding/authentication/transition checking exists, while
manager authorisation, allocation, nonce replay protection, bounded signing, atomic
publication and delivery recovery are not implemented here. Production wallet and
verifier services and the full privacy/security argument remain open.

Recommend **S2-REVOKE-STATE-1**, a separately authorised bounded manager-side
**reference state machine** for R-030: validate the existing issuer revreq, allocated
identifier/current reference/nonce, stage the exact zero-to-one transition, bounded-
validate returned state/update signatures, and atomically commit tree/epoch/nonce/
retrievable public records. Test aborted allocations, replay, concurrent requests,
pre-commit failure and post-commit delivery failure with controlled test signers.
Use this package's update decoder/procedure to cross-check the published record.
Retain the same one-worker, 256 MiB/no-swap, two-core, 60 s/300 s, ≤100-case/10 MiB
envelope, with no proof or zkVM call; stop at limits, incorrect acceptance or
unresolved transaction semantics. Real bounded signing and distributed persistence
must remain explicit obligations, not successful placeholders. This next package
has not begun.

Stages **2–3 remain open** for remaining issuance/release/revocation/services,
bounded keygen/signing, DEP-001/002, full authentication circuits, selective-disclosure/
non-revocation proof integration, BC-1, actual CredValid/authentication proofs and
privacy/ZK/quantum-security/Section VIII review. CPU proving stays paused.
