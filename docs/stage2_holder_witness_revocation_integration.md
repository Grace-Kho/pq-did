# S2-HOLDER-WITNESS-REVOCATION-INTEGRATION-1

Completed an isolated reference flow from real bounded synthetic credential issuance
through holder acceptance, authenticated public updates, atomic local witness
maintenance, presentation-input preparation for two durable verifiers, and local
rejection after the holder's own revocation. **22/22 cases pass on their first run**;
no additional scenario execution, retry or historical-suite replay occurred.
Cumulative invocations are **194/199**, with five remaining.

This is not a complete privacy-preserving KYC demonstration. Real bounded
cryptography, complete local relation evaluation and synthetic verifier acceptance
are explicitly separate evidence categories.

## Authority, baseline and budgets

The [task specification](data/s2_holder_witness_revocation_integration_1/task-specification.md)
adds 27 invocations to the exhausted 172 ceiling, making 199. Starting implementation
charge is **116.6594756442355/300 seconds**, with **183.3405243557645 seconds** left.
Measured commands plus five bookkeeping seconds continue that ledger. Analysis
**270.1814811680233 seconds** and isolation **250.22 seconds**, including its emergency
reserve, are not borrowed. Ten seconds for cleanup/evidence are reserved at admission.

[Preflight](data/s2_holder_witness_revocation_integration_1/preflight-evidence.json)
verified the preceding 96-file additive seal
`6e308920f5499a72eadc020f684abccebfae8e24e040376c6446a3ba819870c8` and the 53
assessed source inputs. The manuscript remains
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
Only Sections **II–VIII**, agreed SPEC-001–004 and the existing specification apply.
The relevant requirements are R-016–R-031: IV-A/B/C, V-B/C/D, VII-A.5–.8 and VIII-E.

Reused contracts:
[issuance integration](stage2_durable_issuer_manager_integration.md),
[holder-local UpdateWit](stage2_witness_updates.md),
[durable manager publication](stage2_bounded_manager_durable_release.md),
[durable verifier integration](stage2_durable_verifier_lifecycle_integration.md),
[complete local relation](../src/pqdid/relations.py) and
[current specification](implementation_spec.md).
No original module, vector, active parameter, dependency, manuscript or historical
result was changed. In particular the preceding assertion/lint failures remain sealed.

Sealed evidence confirms isolation safely stopped/unactivated, 100 historical
invocations, 22 actual-identity cases pending and unchanged retained resources.
CPU proving stays paused; proof ledger **two used, one unused**.

## Data flow and ownership

The new [holder integration](../src/pqdid/holder_lifecycle.py) is an **in-memory**
local adapter. Its public operations are `snapshot`, `apply`, `advance` and `prepare`.
It neither stores a wallet on disk nor implements proof generation or transport.

| Stage / owner | Input and checks | Result and effective point |
| --- | --- | --- |
| Issuance / existing issuer and manager | Existing authorised intent, permanent reservation, exact enrolment/controller checks, bounded credential signature, certification log and recipient binding | Separate durable authority transactions, then committed result retrieval |
| Initial witness delivery / existing issuer | Current registered-manager witness at the issuance reference accompanies the committed credential | Existing `IssuedRecord` returns credential plus separate rid/path/state to the original recipient; no new path service |
| Holder acceptance | Exact approved attributes/binding/rid/state, holder opening, credential signature, authenticated state and zero-leaf path | Existing `HolderAcceptance` atomically retains credential and initial checkpoint |
| Local hand-off | Accepted object and holder-secret configuration; expected pp, same certified/checkpoint rid, CredValid, empty same-state UpdateWit validation | One immutable `HolderSnapshot(credential,witness,state)`; no arbitrary initial path acceptance |
| Public update retrieval | Independently admitted durable manager; expected pp, namespace, holder's starting epoch and caller-selected target epoch | Existing bounded `HistoryResult/UpdatePage`; no private rid/path/attributes/secret in retrieval arguments |
| Local update | Existing canonical records, every state/update signature, endpoints, order, tree transition and certified identifier's path | Complete batch first; one pointer assignment of unchanged credential plus new witness/state only on UPDATED |
| Holder request approval/preparation | Trusted expected audience/session/key/policy/time; bounded request signature under fixed request context; exact local-state reference; canonical disclosure projection and public checks | `LocalPresentationInputs(X,witness)` stays local to a relation/prover; no proof or automatic disclosure approval |
| Verifier lifecycle / A and B | Public X and opaque test token only; existing stored context, state/policy, final authenticated read, expiry and one-time consume | Synthetic ACCEPTED only after durable consumption; unchanged proof boundary |
| Own revocation / manager and holder | Genuine authorised bounded revocation and authenticated chain | Manager advances; holder returns REVOKED with no replacement, retaining the old paired snapshot |

The initial witness is therefore obtained through the **existing issuance procedure**,
not reconstructed from a timestamp, invented resynchronisation endpoint or remotely
queried holder path. The constructor requires completed `HolderAcceptance`, validates
the hand-off again and rejects wrong secrets, identifiers, paths or credentials.
Test-only corruption of a temporary accepted object exercises this boundary; it is
not a supported setter or normal configuration option.

The same immutable credential object persists through all updates. Its original
binding, full canonical attributes, certified rid, signature, empty opening and
metadata never change. Only the authentication witness's path and matching state
can change. A lock serialises local operations; the complete replacement is
constructed before a single pointer assignment. This is atomic reference state,
**not crash-durable wallet storage** or reliable erasure of prior witnesses.

The test holder has credential rid **1**. A second actually issued credential, rid
**2**, uses a different synthetic holder secret and its own accepted issuance intent.
The original synthetic manager bootstrap had allocation prefix one; after both
issues it is three. Both credentials are genuinely signed and logged with the
bounded issuer adapter. Enrolment proof acceptance remains the existing explicit
test-only seam; local BindOpen was evaluated in that fixture, not proven remotely.

## Bounded updates and failure semantics

No state/update wire encoding, domain, cryptographic parameter or signing context
changes. `rupdate` still has five fields and one raw 960-byte path (SPEC-001), while
its signed `update` body has the existing six fields. State/current/request contexts
remain the existing role strings. Core sampler/attempt caps and release verification
are untouched.

The unchanged per-call limits are **16 records / 178,592 bytes**, with **11,162 bytes
per record**. `advance` makes exactly one public manager page request and at most one
local UpdateWit call. It returns both the original history result and the local update
result; failed retrieval has no local update. Stale manager admission exceptions
propagate with no holder replacement. There is no implicit loop, retry, skipped
record or automatic repair.

The established continuation procedure already exists: manager pages expose
`endpoint_state`, `next_epoch`, `requested_epoch` and `complete`. An explicit caller
may commit one fully validated page, then request the next consecutive page from
that retained endpoint. A successful incomplete page is **not** a completed catch-up.
The integration test lowers the admitted count to one and processes a two-record
history in two explicit calls. Existing successful maximum-16-record primitive
validation is reused; it was not rerun, and this package does not claim a new
17-record full-history benchmark. New count/byte overflow cases reject before
cryptographic work under the unchanged ceiling.

| Existing update result | Holder effect |
| --- | --- |
| UPDATED | Commit the complete new witness and its authenticated state together; same credential |
| REVOKED | No replacement witness/state; retain the last complete snapshot |
| INVALID_INPUT | No replacement, including malformed/wrong-instance/bad-signature inputs |
| INVALID_HISTORY | No replacement for missing/reordered/repeated/stale or inconsistent sequences |
| RESOURCE_EXHAUSTED | No replacement; admission/sampler/memory distinctions remain those of UpdateWit |
| PROCESSING_FAILED | No replacement; existing fixed runtime failure reason preserved |

Every record in the requested batch is validated **before** reporting own revocation
or a successful witness. A valid own-revocation record followed by a bad later
signature therefore returns INVALID_INPUT, not a partial REVOKED result. When a
previous explicit page already succeeded, a later failure/REVOKED preserves that
previous page, not the original pre-pagination checkpoint. There is no invented sticky
revocation flag, deletion or mutation of the certified credential.

An old stored witness may still satisfy the old-root relation. It is not eligibility
at a newer root. Preparation for a request at a different state reference fails;
when an old prepared presentation remains locally valid but revocation precedes the
verifier's final read, the existing verifier returns STATE and leaves the challenge
pending. The final ordered read defines freshness, as before: a subsequent update
can precede local consumption without retroactively invalidating that read. The
completed earlier before/after-read, strict expiry, replay, crash and fencing tests
are reused. No instantaneous/global manager-holder-verifier transaction is claimed.

## Evidence categories and the reproducible scenario

| Category | What actually ran | What it does not establish |
| --- | --- | --- |
| **A — bounded cryptography** | Existing bounded ML-DSA signing/verification for issuance, controller and service messages; both state/update signatures; public Merkle transitions; private local path updates | Production custody, entropy assurance, erasure, side channels or adaptive tail bounds |
| **B — complete local relation** | `relations.auth` with the real issued credential's holder secret, attributes, certified rid, signature and path available to the **local test coordinator** | Remote holder knowledge, privacy, zero knowledge or a cryptographic receipt |
| **C — synthetic verifier lifecycle** | Existing exact canonical public X/token adapter explicitly injected into two separate durable verifier stores/audiences, followed by normal public/freshness/consumption checks | Credential authenticity or private non-revocation, including rejection of a revoked credential |

The new ordinary module imports no synthetic proof adapter or test helper. Missing
normal proof verification remains fail-closed in the unchanged durable verifier and
issuer paths; their completed tests are reused. `LocalPresentationInputs` has private
repr and no presentation-wire serialisation. Only public X and an opaque token enter
`ControlledProofAdapter.verify`; the private witness is not an adapter argument.
The test coordinator's local relation evaluation and allow-set injection are visibly
separate from that public adapter call.

The single counted scenario `test_integrated_reference_scenario` performs:

1. Durable issuance/recipient delivery/holder acceptance for rid 1; validate the
   initial state and complete local auth at a signed verifier request (**A/B**).
2. Issue and accept rid 2 under a different synthetic holder secret, then genuinely
   revoke it. Retrieve one public page and atomically update rid 1 to epoch 1 (**A**).
3. Preserve the identical credential, prepare distinct signed audience-A/B requests,
   evaluate complete local auth separately for each, then inject exact public tokens
   and observe one durable acceptance at each verifier (**B/C**).
4. Genuinely revoke rid 1 and retrieve its epoch-2 public update (**A**). Observe
   REVOKED with no replacement; holder stays paired at epoch 1.
5. Obtain a new authenticated epoch-2 request. Verify StateAuth, observe the certified
   rid's zero-leaf path failure and complete local `auth == False` against that root
   (**A/B**). No synthetic verifier verdict is invoked for this rejection. Local
   preparation also refuses the mismatched retained epoch.

Final scenario evidence records two certifications, allocation prefix three,
manager epoch two, retained holder epoch one, unchanged credential and verifier
consumption counts `[1,1]`. It resides in
[per-case evidence](data/s2_holder_witness_revocation_integration_1/case-evidence-focused.json).
The test's two public page calls carry only namespace/start/target epochs.

Reproduction uses the existing test entry point, not another scenario driver:

```sh
.venv/bin/python -m pytest -q -x -p no:cacheprovider tests/integration/test_holder_lifecycle.py::test_integrated_reference_scenario
```

This is the underlying test selection, **not an instruction to bypass guards**.
It ran once within the guarded `focused` command below, with isolated temporary
storage and `PQDID_PILOT_RUN=focused`. Any future execution must be admitted and
recorded under the same ceilings and remaining invocation/time ledger; do not rerun
the one-shot package commands. No additional scenario execution occurred here.

## Individual outcomes

[Tests](../tests/integration/test_holder_lifecycle.py) and
[fixtures](../tests/integration/holder_lifecycle_cases.py) add 22 cases; every parameter
is counted separately. All use fresh isolated SQLite stores and temporary holder
objects. Existing helpers are reused without collecting their historical tests.

| # | Case | Result / state evidence |
| --- | --- | --- |
| 1 | Integrated scenario | PASS; A/B/C separated as above; own-root local rejection uses no synthetic verdict |
| 2 | Wrong initial secret | PASS; hand-off rejects, full local auth false, original holder unchanged |
| 3 | Wrong checkpoint/certified identifier combination | PASS; hand-off rejects, altered witness rid fails full local auth |
| 4 | Wrong initial path | PASS; hand-off and full local auth reject; original holder unchanged |
| 5 | Wrong credential signature | PASS; hand-off and full local auth reject; original holder unchanged |
| 6 | Unexpected presentation audience | PASS; local preparation refuses, snapshot unchanged |
| 7 | Bad request signature | PASS; preparation refuses, snapshot unchanged |
| 8 | Unapproved request policy | PASS; preparation refuses, snapshot unchanged |
| 9 | Fresh request but stale holder state | PASS; preparation refuses before proof inputs are returned |
| 10 | Bad update signature | PASS; INVALID_INPUT, no partial replacement |
| 11 | Modified public old path | PASS; authentication failure, no partial replacement |
| 12 | Invalid carried new-state signature | PASS; INVALID_INPUT, no partial replacement |
| 13 | Wrong target instance/namespace | PASS; INVALID_INPUT, no partial replacement |
| 14 | Missing update | PASS; INVALID_HISTORY, old snapshot retained |
| 15 | Reordered updates | PASS; INVALID_HISTORY, old snapshot retained |
| 16 | Repeated update | PASS; INVALID_HISTORY, old snapshot retained |
| 17 | Already applied/stale update | PASS; INVALID_HISTORY, last successful epoch-1 snapshot retained |
| 18 | 17-record input | PASS; RESOURCE_EXHAUSTED/ADMISSION, no replacement |
| 19 | 178,593-byte input | PASS; RESOURCE_EXHAUSTED/ADMISSION, no replacement |
| 20 | Explicit bounded continuation | PASS; first one-record page UPDATED/incomplete, second REVOKED, first checkpoint retained |
| 21 | Own revocation then invalid later record | PASS; full-batch INVALID_INPUT takes precedence, no partial REVOKED/result |
| 22 | Old-valid presentation, earlier manager revocation | PASS; local auth remains true at old root, verifier STATE; no challenge consumption |

JUnit: [focused](data/s2_holder_witness_revocation_integration_1/focused.xml) and
[updates](data/s2_holder_witness_revocation_integration_1/updates.xml).
Resulting authority heads, allocation/certification counts, epochs and holder
invariants are retained per invocation. Nine focused cases took **18.66 s pytest /
18.909420328 s guarded wall**; thirteen update cases took **34.44 s pytest /
34.672839171 s guarded wall**. These are validation workload costs, not protocol
throughput, proof time or security estimates. No failures, skips, retries or new
process-crash experiments occurred. Lint initially reported two overlong scenario
labels; the [retained correction](data/s2_holder_witness_revocation_integration_1/lint-correction.json)
wraps adjacent string literals without changing their values or test logic. The full
audit checks parsed-AST equality against the retained pre-correction test source.
No functional test was repeated for this formatting-only change. A
[second lint diagnostic](data/s2_holder_witness_revocation_integration_1/lint-correction2.json)
concerned one generated closure-prose line; that formatting failure and correction
are also retained and charged. No functional case is reclassified by either correction.

## Original KYC lifecycle checklist and next package

- [x] Synthetic DID/controller setup and issuer-authorised evidence/attribute binding
  connected to durable reservation, certification and original-recipient delivery.
- [x] Holder acceptance connects the certified binding/attributes/rid to its initial
  authenticated path/state.
- [x] Genuine bounded revocation, public namespace/epoch update retrieval, explicit
  continuation and atomic local witness/state replacement connect to issued credentials.
- [x] Holder audience/session/request-signature/approved-policy checks, canonical
  disclosure preparation and complete local auth connect to two independent durable
  verifier lifecycles with **synthetic proofs only**.
- [x] Other-credential survival, own-credential revoked outcome and new-root local
  rejection are distinguished from verifier freshness and synthetic acceptance.
- [ ] Real enrolment/authentication proof integration and complete knowledge/privacy
  security; concrete outer-oracle composition and component reduction budgets.
- [ ] Production evidence validation, key custody/entropy/erasure/side-channel assurance,
  adaptive Delta_tail, trusted clock/nonces and independent recovery freshness.
- [ ] Durable holder wallet and deployed authenticated services, actual-ID isolation,
  downstream KYC action/reply recovery and interoperable request/credential/presentation
  containers. Existing canonical bytes alone do not establish W3C DID/VC conformance.

Recommend **S2-KYC-INTEROPERABILITY-CONTRACT-1** as the next bounded package: map the
already connected KYC issuance, holder-approved request, public-update and presentation
flows to explicit application/container boundaries, retaining the canonical bytes,
proof-failure behaviour, audience binding and private-field exclusion. Identify exact
interoperability gaps before proposing any new wire format or live service. This
advances consumption of the KYC lifecycle rather than adding general infrastructure.
Plan within the remaining allowance or request an explicit amendment; it is not started.

## Preservation and resource envelope

The [configuration](data/s2_holder_witness_revocation_integration_1/config.json) and
[run ledger](data/s2_holder_witness_revocation_integration_1/run-ledger.json) record
continued accounting and expanded guarded commands:

```sh
.venv/bin/python -I -B docs/data/s2_holder_witness_revocation_integration_1/run_checks.py NAME
```

Sequential names are `preflight`, `imports`, `source-format`, `focused`, `updates`,
`final-source-format`, `quality`, `quality-final`, `correction-format`,
`quality-complete`, `format`, `prepare`, `full-audit`; `close.py` performs
bounded write-once bookkeeping. All functional tests are complete; later commands
perform no new scenarios or functional invocations.

Unchanged ceilings: one worker, two CPUs, four controlled processes; 256 MiB
cgroup-v2 memory for worker/descendants and charged cache/kernel, zero swap, separate
aggregate RSS stop; 60-second command / 55-second child; 8 MiB temporary data,
cumulative 10 MiB output, 1 MiB per file, 60 KiB command diagnostics, 9 GiB experiment
storage stop and 2 GiB headroom. Prior output charge **2,104,145 bytes** carries forward.
Transient private-network validation units do not activate live authority services.

Only the new holder module, two test/helper files, this report and package evidence
are added; status/traceability/issues are append-only. The corrected preservation
auditor keeps original protected scope, digest and inventory checks, including all
historical failures. The single full audit requires content/inventory completion,
report generation/readback and its outer guard under the unchanged 256 MiB ceiling.
Measured closure follows below; no historical baseline is regenerated.

Stages **2–3 remain open**. DEP-001/DEP-002, SEC-001–005, OC-REL/EXT/PRIV/BUDGET,
production security, adaptive Delta_tail and complete proof knowledge/privacy remain
unresolved. No activation, installation, estimator campaign, circuit, proof or zkVM
execution occurred. Isolation stays safely stopped/unactivated; proof ledger two
used/one unused.


## Measured validation closure

The single
[complete audit](data/s2_holder_witness_revocation_integration_1/result.json)
passed content/inventory comparison, report generation/readback and the unchanged
256 MiB cgroup guard, exit **0**. Coverage: 8,759 original,
1,199 supplementary paths,
**9,958 disjoint content paths** and
9,978 identity-inclusive paths. No unexpected
changes/additions/removals occurred. All three existing report prefixes, original
source, vectors, active parameters, manuscript, dependencies and historical evidence
are preserved. Lint and formatting pass.

| Measurement | Result |
| --- | --- |
| Audit wall time | 2.375583138 s |
| Audit cgroup memory.peak | 24,059,904 bytes |
| Audit sampled aggregate tree RSS | 41,951,232 bytes |
| Maximum guarded-job cgroup memory.peak | 112,439,296 bytes, below 268,435,456 |
| Maximum sampled aggregate tree RSS | 134,914,048 bytes; separate metric |
| Guarded commands | 13, 57.044742822 s total, including retained lint failure |
| New package charge | 62.044742822 s |
| Cumulative implementation charge | **178.704218466/300 s** |
| Remaining implementation time | **121.295781534 s** |
| Test invocations | **172 + 22 = 194/199; five remain** |
| Functional failures/repeats/resource breaches | 0 / 0 / 0 |
| Temporary storage | 736,387 observed peak bytes; zero retained |
| Package bytes at outer audit completion | 483,656 |

The unchanged cgroup-v2 memory.peak scope includes worker/descendants and charged
anonymous/file-cache/kernel memory; swap is zero. External tree RSS is separately
sampled and may count shared pages twice. Final write-once bookkeeping has a 256 MiB
address-space, CPU/alarm-five-second, two-CPU and 1 MiB file bound, within the charged
five seconds. It checks final names/links/prefixes and writes the
[closure](data/s2_holder_witness_revocation_integration_1/validation-closure.json) and
[additive seal](data/s2_holder_witness_revocation_integration_1/manifest.json).
It does not repeat the content scan or regenerate a historical baseline. Cumulative
output also retains the prior 2,104,145-byte charge.

Separate analysis **270.181481168 s** and isolation **250.22 s** remain unchanged.
Stages 2–3 stay open; no activation, installations, proofs or zkVM executions.
Isolation safely stopped/unactivated; proof ledger two used/one unused. Next bounded
recommendation: **S2-KYC-INTEROPERABILITY-CONTRACT-1**, not started. Production-security,
adaptive Delta_tail and complete proof knowledge/privacy obligations remain open.
