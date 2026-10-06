# OCT31-KYC-NATIVE-MILESTONE-1 — executable proposal awaiting approval

**Deliver one native masking implementation, one runnable ML-DSA-65 reference
baseline, and one shared measurement harness by 31 October 2026.** This replaces
the proposed stand-alone sumcheck pilot with a single coordinated milestone.
It does not commission another Aurora review. The work, new signing profile and
resource amendments below are proposed, not yet approved or executed.

The engineering exit is reproducible native component correspondence plus real
signature-based issuance/presentation/revocation measurements. Complete private
authentication remains conditional on explicitly identified cryptographic and
implementation obligations. A blocker in that route does not stop independent
baseline or benchmark work.

## Inputs, authority and current position

Only manuscript Sections II–VIII and SPEC-001–004 are authoritative. The manuscript
hash remains `d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The [masking correction contract](stage3_aurora_masking_correction_contract.md),
including its inactive sumcheck pilot, supplies the construction decision. Its
completed seal is `b841e6675bae216e9e0080b1861fd29e90b19df62335ad1338c72ed4759eb28b`.
No active BC-1 parameter or production implementation is replaced.

The authoritative opening ledger is that package's
[validation closure](data/s3_aurora_masking_correction_contract_1/validation-closure.json):
analysis 173.72262021855917/300 seconds used, 126.27737978144083 remaining;
implementation 562.1783621237846/674 used, 111.82163787621539 remaining;
native sub-budget 107.26425821718294 remaining; builds 5/5; invocations 448/450.
The two unused invocations belong to prior tooling, not a new native allocation.
Provisioning 41.843650440103374 and isolation 250.22 seconds remain separate.
Proof attempts remain two used/one unused, with proving paused.

Close the completed masking-contract reservation: release 873,382 unused bytes,
refund neither time nor retained bytes. Earlier query/masking and native
continuations are already closed. Their old stopped builds, failures, seals and
budget violations remain historical facts. Retained cumulative evidence starts at
16,499,024/18,874,368 bytes; preparation uses that existing headroom and analysis
allowance. It creates no smaller nested preparation quota. Its final charged
balance is recorded at the end of this proposal.

Existing results are separate evidence: public native EXP2 TR-01–16 and SEM-01–08;
ideal algebraic masking argument; bounded ML-DSA primitives; reference lifecycle
and durable storage; experimental Boolean/RISC Zero components. None is a complete
private-authentication measurement. [Benchmark targets](benchmark_targets.md)
remain provisional research targets, not approved SLAs or established security.

## Deliverables and completion criteria

| Workstream | Deliverable | Acceptance criterion |
| --- | --- | --- |
| N: native masking | Isolated explicit-branch implementation of SC-1–4, LD-1/2, FR-1 and IO-1; native caller trace, overlay manifest and independent expected values | All admitted native cases pass or an exact substantive blocker is reported; both required targets link; wrong inputs fail at the specified actual layer; production/pins unchanged; no cryptographic proof generated |
| B: ML-DSA reference baseline | Issuer-bound persistent holder key, real credential and possession signatures, A/B independent durable replay stores, authenticated revocation, restartable synthetic scenario CLI | Valid issuance and fresh A/B presentations succeed; wrong holder/challenge/context/instance, expiry, revoked membership and replay fail without acceptance; commit/release tests have no partial result; holder key survives reopen |
| H: shared measurements | One command producing schema-validated JSONL, CSV and Markdown with raw observations, environment/fixture identities and explicit capability states | Four scenario families run serially, actual messages and stage times exported; failure/censoring retained; unavailable private-proof metrics are null with a reason; no fake proof acceptance or full-scheme overhead ratio |
| C: coordinator | Single resource ledger, patch/input seals, test/build registry, consolidated reports, complete preservation and readback | Every attempt charged once to its proper category; all failures retained; final complete audit passes within 256 MiB; shared documentation reflects actual coverage |

The milestone can finish **engineering complete / private route blocked**, with
the baseline and harness delivered and a precise native or cryptographic blocker.
It cannot report native correspondence for unrun cases or close Stages 2–3.

## N — exact native patch and validation scope

Create `experiments/aurora_masking_milestone_1/{work,overlay,build,scratch}` from
the sealed corrected native source, preserving the original copy and all overlays.
The libiop commit remains `a2ed2ec2f3e85f29b6035951553b02cb737c817a`, tree
`2e2588ccb085242dd2237875c3b9adf1a0fc958c`. Reuse the acquired dependency prefix;
no installation, download, upgrade or selected revision change is needed.

Relative to the new `work/libiop/libiop/`, the allowlist is:

| Files / surface | Exact intended effect |
| --- | --- |
| `protocols/encoded/sumcheck/sumcheck.hpp/.tcc` | Explicit branch; unrestricted coefficient sampling, one beta message, beta=xi*u[t-1], [1,1] mask/lincheck coefficients, identical prover/verifier target sum; retain quotient and g bounds |
| `protocols/encoded/lincheck/basic_lincheck.hpp/.tcc` | Propagate branch and retain alpha/triple; remove only obsolete nested pair in this branch |
| `protocols/ldt/ldt_reducer.hpp/.tcc`, `ldt_reducer_aux.hpp/.tcc` | J tested handles plus last unit pad; exactly 2J coins; complete degree-equalised sum, identical vector/point map; no lost handles or malformed-input checks |
| `protocols/ldt/fri/fri_ldt.tcc` | Register each intermediate degree before advancing localisation; preserve fold equations, final Df, order and domains; reject inadmissible bounds |
| `protocols/aurora_iop.hpp/.tcc` and the corresponding existing parameter declarations only | Propagate opt-in; beta registration/submission before dependent challenges; early independent LDT pads unchanged |
| New overlay/harness files | `CMakeLists.txt`, `masking_native.cpp`, exact expected-input adapter and build-output registry; optional test-only coefficient injection inaccessible to ordinary branch interfaces |

No generic field, FFT, IOP-engine or random-linear-combination semantic replacement
is authorised by this proposed scope. Matching declarations may change with the
listed branch API; enumerate them in the patch manifest before the first build.
Keep legacy modes and public EXP2 construction/expectations unchanged. A needed
functional repair outside these surfaces is a substantive scope decision, not a
routine compiler fix.

The mathematical contract is unchanged: four independently masked base columns,
uniform sumcheck pads with disclosed correlated sums, fixed unit LDT pads,
complete quotient/fold/terminal view, disjoint systematic/evaluation domains,
shared-position query budget and the contract's degree/rate admission conditions.
Use the contract's small public synthetic admissible family; no private credential
or complete authentication circuit is introduced.

Actual calls must reach native sumcheck registration/submission/prover/verifier
state, basic lincheck registration and evaluation, reducer submission and
`combined_LDT_virtual_oracle` point/vector evaluation, FRI registration and fold
helpers, and Aurora/IOP message registration. Methods named `calculate_and_submit_proof`
may be exercised only to obtain public polynomial/codeword traces. No BCS/full
Aurora proof-generation entry point, cryptographic proof or accepted proof receipt
is in scope.

Independent expectations use exact coefficient arithmetic separate from native
FFT, division and schedule helpers. First certify the source field modulus
`x^192+x^7+x^2+x+1` (encoded `0x87`) using GF(2) Frobenius/gcd checks for degree
192 and prime divisors 2,3, and verify basis/byte interpretation. This is proposed
validation, not a certificate already obtained. A failure blocks N and preserves
the evidence; it does not authorise choosing another field.

Initial matrix: **24 new native cases plus 16 EXP2 regressions = 40 invocations**.

| IDs | Distinct cases |
| --- | --- |
| N-01 | Independent field/modulus/basis certificate |
| N-02–09 | Unrestricted mask mapping; non-unit xi sum; zero triple; nonzero quotient/remainder; prover/verifier point agreement; shifted vector/point agreement; altered beta violates g-degree condition; wrong beta-message length |
| N-10–15 | Zero reducer coins retain pad; mixed degrees; previously mis-indexed bump coefficient; shifted point/vector equality; wrong coin count; missing pad |
| N-16–19 | Two-fold bounds; longer-fold bounds; independent fold/terminal coefficients; nondivisible initial bound rejected |
| N-20–24 | Actual lincheck paths; actual Aurora early-mask/beta registration; dependent-challenge order; unsupported branch; invalid attached claim |
| TR-01–16 | Existing independent expected bytes/rejection, including labelled old omission control, on the rebuilt affected EXP2 target |

Each ID gets one concrete public fixture before admission. Additional variants or
parameterisations count separately from the contingency pool. Wrong beta is a
degree-condition observation, not automatic rejection by the standalone sumcheck
API and not a full cryptographic-proof test. Reuse unaffected SEM, primitive and
Python transcript evidence after verifying unchanged inputs; rebuilding an affected
binary requires its relevant comparisons again. Record dependency/source/build
fingerprints for every reuse decision.

Proposed build command, dispatched by the shared guard and counted as one attempt:

```sh
cmake -S experiments/aurora_masking_milestone_1/overlay \
  -B experiments/aurora_masking_milestone_1/build -G Ninja \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_BUILD_TYPE=Release \
  '-DCMAKE_CXX_FLAGS_RELEASE=-O0 -g0' '-DCMAKE_C_FLAGS_RELEASE=-O0 -g0' \
  -DPQ_SOURCE=/home/grace/projects/pq-did/experiments/aurora_masking_milestone_1/work \
  -DPQ_PREFIX=/home/grace/projects/pq-did/experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1/prefix
cmake --build experiments/aurora_masking_milestone_1/build \
  --target aurora_masking_native exp2_native --parallel 1
```

Retain the existing GNU++14 and disabled assembly/multicore settings. `TMPDIR`
points only to the new registered scratch directory for those commands. Configure,
compiler detection and any compile-only probe are part of a counted build attempt;
an incremental corrective build is another attempt. No permissive options, missing
operator mocks or easier expected results are allowed.

The last compiler body measured 6.052475 seconds and 450,625,536 bytes peak; its
outer-guard failure remains a failure. Later repaired-guard native cases took
0.308834 seconds. New template instantiations were not covered: plan 15–60 seconds
per build and 16–32 MiB new source/build storage, explicitly estimates.

**Private-route gate after N:** establish the TB-06/TB-09 simulator for the chosen
root/salt/opening encoding, binding before challenges and answering all permitted
adaptive openings consistently without the witness while realising the algebraic
lazy simulator. Hashing an entire hidden table is not licensed by that simulator.
Full private EXP2 binding, finite soundness/query parameters, concrete-hash and
quantum knowledge/privacy, and compilation of the complete joint authentication
relation also remain required. Native component success authorises none of these
claims or a private proof run.

## B — ML-DSA-only reference baseline contract

Use profile **`pqdid-mldsa-reference-1`**, isolated under
`experiments/kyc_milestone_1/baseline/`. It is a deliberately linkable reference
comparator, not the active PQ-DID profile and not anonymous authentication.
All keys are fresh synthetic research keys. Signatures are real ML-DSA-65, verified
through the completed bounded core; there is no synthetic acceptance adapter.

The new facade is necessary: `ReferenceIssuer`, `BoundedDurableIssuer` and
`DurableVerifier.verify` embody PQ-DID enrolment/authentication proof contracts.
Do not put a holder signature in `Presentation.proof`, install a controlled proof
adapter, or call an existing proof path and label its result a baseline signature
check. The ordinary PQ-DID proof path must remain fail-closed.

### Exact new records, contexts and disclosure

Define experimental framing `F(tag, fields)` as
`LP(ASCII(tag)) || uint32be(field_count) || LP(field_0) || ...`, using the existing
`encode_length_prefixed`/`encode_uint` primitives and a **separate exact tag/arity
table**. No change to production `_ARITIES`. All tags start with
`pqdid-mldsa-reference-1/`; tags and field order below are normative for approval.

| Tag suffix / fixed context where signed | Fields in order |
| --- | --- |
| `credential-body` / `PQ-DID-REF/credential/v1` | `encode_parameters(pp)`, holder public key1952, `encode_attributes(schema,m)`1024, rid as uint32be restricted to 20 bits |
| `credential` | Exact credential-body bytes, issuer signature3309 |
| `enrol-body` / `PQ-DID-REF/enrol/v1` | `encode_parameters(pp)`, session, issuer nonce32, intended holder public key1952, approved attributes1024, reserved rid uint32be |
| `request-body` / `PQ-DID-REF/request/v1` | `encode_context(pp,ctx)`, `encode_state(pp,state)` |
| `request` | Exact request-body bytes, verifier signature3309 |
| `presentation-body` / `PQ-DID-REF/presentation/v1` | Exact request bytes, exact credential bytes, path960 |
| `presentation` | Exact presentation-body bytes, holder signature3309 |

The enrolment signature proves possession of the intended persistent holder key
before issuance, with issuer-approved attributes and reserved identifier. It is
not a PQ-DID enrolment proof. The credential signature authenticates that exact key.
The presentation signature binds the exact verifier-signed request, including
challenge nonce, audience, session, policy, state reference, instance and expiry,
and binds the complete credential and path. No caller selects signing roles,
contexts or trusted keys through metadata. Trusted configuration pins pp, issuer,
manager, each verifier request key and audience; decoded pp must equal that anchor.

The embedded pp/context objects preserve the existing common suite's internal
encodings and lifecycle hashes. Their existing BC-1 suite field is **not** the
baseline profile selector: the outer fixed baseline tags, signing contexts, CLI
mode and independently configured verifier facade select this comparator. Never
register baseline verification as a provider for that active suite.

Require exact types, fixed arity, no trailing data, canonical integers/encodings,
ordinary object limit 65,536 bytes, schema at most16 fields, attributes1024, rid
20 bits and path exactly960. There is no JSON reinterpretation of signed bytes.
If JSON export is offered, use the completed local container conventions with
exact round trips, a new explicit baseline type and no claim to an existing proof
container. All redundant state/instance data must agree.

The baseline discloses the **complete attributes including DID/version, persistent
holder public key, issuer signature, rid and non-revocation path**, as well as the
request/current state. Thus issuer/verifiers can link presentations. Selecting
policy fields does not hide other fields in this baseline. This difference must
accompany all comparisons with future selective-disclosure/private-rid proofs.

Credential validity comes from the certified schema field `validUntil` and the
existing policy clause `validUntil >= ctx.expires_at`; session validity remains
strict `now < ctx.expires_at`, including the final atomic check. Do not add a
conflicting unsigned wrapper expiry or conflate the two meanings.

### APIs, state and release ordering

| New file | Public facade / reuse / boundary |
| --- | --- |
| `records.py` | Immutable BaselineCredential/Request/Presentation; `encode_*`/`decode_*(..., expected_config)` using the framing above; canonical attributes/context/state are reused |
| `signing.py` | Typed `sign_credential`, `sign_enrolment`, `sign_request`, `sign_presentation`; fixed trusted role/public-key/instance configuration. Call `reference_sign_mldsa65` with the fixed baseline context and fresh32-byte OS randomness; keep all caps and verification-before-return. Do not widen production nine-context admission |
| `storage.py` | Synthetic holder key/wallet persistence and baseline-specific issuer journal. Exclusive fresh creation, no symlinks, directories0700/files0600, bounded reads; public/secret correspondence checked on load. SQLite DELETE/EXTRA, bounded schema and explicit head/generation recovery evidence, modelled on existing authority contracts |
| `issuance.py` | `begin(approved_attributes, intended_holder_key, recipient)`; `complete(session,enrolment_signature)`; `retrieve(operation, trusted_recipient)`. Reuse permanent manager reservation. Commit signing claim before signing and certification/outcome before release; never resign for redelivery |
| `holder.py` | `create/open`, `accept_credential`, `synchronise`, `present(request)`; verify issuer/key/attributes and authenticated state; persistent holder key across reopen; use existing witness-update verification |
| `verifier.py` | `request(policy,session)`; `verify(request,presentation)`; own A/B stores. Reuse `DurableVerifier.register`, `_ChallengeStore.pending/consume`, `SQLiteStore` permits/head/fencing and strict final expiry, via an isolated wrapper; do not invoke proof-based `.verify` |
| `scenario.py` | Typed setup/run/restart/replay/revoke scenarios, no sockets or service activation required; clock, state-provider and issuer-policy configuration recorded |

The baseline issuer's record format is new. Existing `IssuedRecord`/`DurableIssuer`
recovery must not be claimed to support it unchanged. A dedicated local journal
uses the same commit/head/fencing pattern with its own schema and validation;
do not extend production checkpoints to admit arbitrary payloads. Manager and
issuer stores remain separate: permanent reservation first, durable signing claim,
then atomic issuer certification/outcome. No cross-store atomicity is claimed;
failure retains the reservation and an explicit pending/failed session. A signed
but uncommitted candidate remains inaccessible. Recovery reconciles stored state
against independently retained tickets; no automatic admission from self-consistency.

Issuer signing/commit failure releases no credential. Successful redelivery returns
the exact stored credential only to the bound trusted recipient, without resigning.
The local recipient authorisation is inherited from synthetic owner configuration,
not from a presenter-supplied string. Interrupted response and process restart are
distinguished from a simulated transaction fault; no power-loss, production key
custody, secure-erasure or whole-store rollback guarantee is inferred.

Verification performs actual issuer signature, holder possession signature,
canonical instance/context/policy/expiry checks and `state_auth` plus zero-leaf path
verification. Use `BoundedDurableManager`/`ManagerVerificationProvider` for ordered
authenticated current reads, signed updates and issuer-authorised revocation.
After cryptographic checks, repeat the required current-state comparison and
atomically consume the registered challenge with existing fencing/expiry checks.
There is no claim of atomicity across manager and verifier stores beyond the
existing ordered-read policy. A concurrent state change yields that policy's
explicit stale/unavailable outcome; it must not bypass consumption or be labelled
proof rejection. A successful acceptance can never be redelivered as a second one.

A and B use distinct service IDs, audiences, request keys, authority directories,
SQLite files and retained heads. Same holder key, issuer and common schema permit
controlled comparison. Restart retains challenge consumption; old writer generations
are fenced. Holder persistence is new reference work: the existing holder module
is in-memory, so its old tests do not establish it.

Initial baseline validation has **48 distinct invocations**, specified before
execution: 12 encoding/key-binding cases; 8 signing/entropy/exhaustion/verification
failures; 8 allocation/certification/commit/recipient/redelivery cases; 12 A/B
challenge/context/policy/expiry/replay/restart/fencing cases; 8 current-state/path/
own-revocation/other-revocation/update cases. The machine-readable execution plan
names every case. Rare failures use test-only injection inaccessible through the
ordinary interfaces. Real signature verification is always required for positives.

W3C requirements remain unresolved: issuer/vocabulary binding, DID method and
verification-method representation, normative securing mechanism and claim coverage,
credential validity/status mapping, and applicable conformance tests. A local
binary container is neither a W3C cryptosuite nor a standards-conformance result.
Production custody, entropy assurance, side-channel resistance and adaptive
Delta_tail remain open.

## H — executable shared measurement contract

New files under `benchmarks/kyc_milestone_1/`: `run_bench.py`, `scenarios.py`,
`backends.py`, `measure.py`, `export.py`, `schema.json` and `README.md`.
Update only the stale `benchmarks/README.md` to link the runnable baseline and
identify missing proof operations; preserve its historical contents in the new
change manifest. All production algorithms remain unmodified.

Implement this reproducible entry point as part of the milestone:

```sh
.venv/bin/python -I -B experiments/kyc_milestone_1/run.py benchmark \
  --plan docs/data/october_implementation_milestone_1/execution-plan.json \
  --run-id oct31-reference-01 \
  --output docs/data/oct31_kyc_native_milestone_1/benchmarks/oct31-reference-01
```

`run.py` dispatches the benchmark inside the common guard. Existing output IDs are
never overwritten; a repeat needs a new attempt ID and is charged. No baseline
execution is currently authorised. The frozen plan drives the following workload:

| Scenario | Timed operations and boundary | Setup excluded from operation latency, included in resource ledger |
| --- | --- | --- |
| ISSUE | Approved intent through manager reservation, holder-key possession, actual issuer sign/verify, journal commit and holder acceptance | Synthetic key generation, initial manager state, stores and policy fixtures; separately report setup/keygen times |
| PRESENT-A | Registered authenticated request through holder signing, encoding, actual verifier checks/current read and durable consume/reply | Credential load and human consent excluded; their policy is fixed and disclosed |
| PRESENT-B | Same operation at the independent B store | Same credential/key permitted; fresh challenge, independent consumption history |
| REVOKE-UPDATE | Issuer revocation request, durable manager state/update publication, holder update for another credential and local affected-credential rejection | Fresh isolated fixture state for each mutation; own-revocation rejection is reported separately from the successful update stage |

Use the existing synthetic KYC schema/1024-byte attributes, validUntil policy,
depth20/960-byte path and ML-DSA-65 parameters. Freeze the semantic fixture from
the existing interoperability examples, generate fresh real keys/signatures and
record its canonical hash. Do not reuse their synthetic proof placeholders. Use
a labelled 120-second synthetic session lifetime, existing ordered current-read
and authenticated update limits (16 records per page). Fix `require_did_state=false`
for this workload: DID/version remain certified opaque attributes, with no claim
of current controller resolution. Use the `alpha-42-old-002c` schema/policy shape
from `tests/fixtures/relations_vectors.json`, fresh synthetic keys, and approved
attributes with validUntil set to the recorded session base time plus86400 seconds.
Record this time-relative substitution and regenerated instance identity; never
modify the original fixture or import its proof placeholder. Use a recorded
synthetic epoch clock advanced by measured monotonic elapsed time, with separate
injected expiry cases in validation. Report this as a research workload, not a service SLA.

For each of the four scenarios: **three independent sessions**, each with **one
cold-process trial, two warm-up trials and twenty warm measured trials**. This is
`4*3*(1+2+20)=276` counted trials. Cold means a fresh process; do not drop system
caches. Warm means loaded code/public parameters, never cached signatures, accepted
decisions or proof results. Each trial is one predefined composite scenario with
named nested measurements; its sub-operation rows are not secretly new independent
test variants. Additional scenarios or retries consume separate invocations.

Record all warm-ups and cold trials; omit only the predeclared warm-ups from warm
statistics. Report per-session and pooled warm n=60 distributions, cold n=3
descriptively, min/median/nearest-rank p95/max and failure counts. These samples
describe this host; they do not establish population p95/SLA or throughput. Setup
costs, signing-cap exhaustion, expired/stale sessions and censored timeouts remain
visible. Do not replace a failed trial with a fast retry or change its denominator.

No shaped WAN or network service is activated. Measure local application time and
actual byte lengths. The existing 10 Mbit/s,50 ms model may be reported only as a
separately labelled arithmetic transport estimate. Do not label it measured network
latency or combine component p95 values into an end-to-end p95.

Every record includes version, run/attempt/session/scenario IDs, capability and
evidence category, outcome, start/end monotonic_ns, named stage durations, setup
duration, complete canonical/transport message sizes, artifact/fixture/build hashes,
signing attempts/exhaustion where available, RSS/cgroup metric and scope, counters
and environment. Record Python/compiler/liboqs/dependency identities, OS/WSL/kernel,
CPU/affinity/threads, effective guard limits and available memory. Read environment
metadata locally; never log private keys or real user records.

Backends expose `capabilities()`, `setup()`, `issue()`, `present()`, `verify()` and
`revoke_update()`; optional `prove_auth`/`verify_auth_proof` remain absent until a
real complete backend exists. Unavailable output is, for example:

```json
{"operation":"prove_auth","available":false,"seconds":null,"bytes":null,
 "reason":"complete private authentication backend not implemented"}
```

Do not treat this as a successful test or invoke a synthetic verifier. Separate
four evidence categories in exports: `mldsa_reference_measured`,
`reference_lifecycle`, `native_component`, `private_auth_unavailable`. Only a later
real backend can add `private_auth_measured`. No complete PQ-DID/PQ-DAA overhead
ratio may be computed from these component or missing-proof rows. Shared component
parameters and workloads aid eventual comparison; privacy leakage, algorithms,
storage boundaries and policies must also match or be explicitly distinguished.

The harness has 16 focused checks for export/schema/timing/classification/failure
accounting and 12 integration acceptance cases across the three workstreams.
Those IDs are frozen in the execution plan. Timing correctness uses small fixtures;
it does not rerun historical cryptographic suites.

## Consolidated proposed resource amendment

**Approval is required for this table; no value below is active during preparation.**
These replace completed-package microcaps, not their records or consumed resources.
The sole implementation time pool is the amended cumulative implementation ledger.
Planning allocations are estimates, never nested workstream admission caps.

| Resource | Current limit / recorded consumption | Proposed value and scope |
| --- | --- | --- |
| Implementation time | 674s ceiling;562.1783621237846 used;111.82163787621539 remain | **Add3600s: ceiling4274s;3711.82163787621539 remain at approval**. One milestone pool, including all agents' commands, corrections, checks, measurements and finalisation |
| Completion reserve | Old completed-package10/20/30s reserves | **300s within that single remaining pool** for preservation/reporting/cleanup; no new work admitted into the reserve |
| Native/provisioning subcaps | Completed native107.264258s and provisioning41.843650s remain, overlapping the overall pool; earlier nested build caps closed | Retire these completed-work admission caps for this milestone; **do not add their balances** to the new pool. No acquisition/install work authorised |
| Counted invocations | 448 used /450 ceiling; two earlier tooling slots unspent | **Add600: ceiling1050**. Exactly600 new milestone slots; retain the old two tooling slots separately. Initial plan392, remainder208 for scoped corrections/repeats and affected checks |
| Builds | 5/5 consumed | **Add8: ceiling13**. Configure/probes/rebuilds all counted. No full Aurora/BC-1/zkVM target |
| Concurrent work | One execution worker | At most **two guarded work jobs**, plus coordinator; up to three implementation agents with separate ownership. One native compiler job at a time. Benchmark/audit exclusive |
| Memory | Native1GiB; Python/tooling/audit256MiB | Per-phase ceilings unchanged. **2GiB common parent cgroup for all coordinator/jobs/descendants**, zero swap; coordinator256MiB; admit only if sum of child maxima plus coordinator fits. Two1GiB native jobs therefore cannot coexist |
| CPU/processes | Two CPUs/threads; TasksMax128; at most four controlled child jobs | **Two CPUs aggregate**, TasksMax128 in the common parent, at most two controlled work jobs and coordinator (compiler descendants included), `--parallel 1` native builds. No per-agent multiplication of the quota |
| Command time |60s outer/55s child | **300s outer/295s child** maximum; actual lower operation deadlines fixed before a benchmark session. Phase time remains charged to the single pool |
| Cumulative evidence |18,874,368B;16,499,024B before this preparation | **33,554,432B (32MiB)** ceiling, retaining all preparation and historical bytes. Entire remaining headroom is shared; **2MiB reserved within it for completion**. Retire old native/package output reservations, no refunded bytes |
| Evidence files/logs | Ordinary file1MiB; command diagnostics60KiB stop | Unchanged; stream JSONL/CSV into registered bounded chunks. Build metadata/logs/manifests stay evidence |
| Artifacts |134,217,728B aggregate;27,839,915B retained | **Unchanged128MiB aggregate**, includes downloads already retained, new copies, temporary compiler usage, binaries and explicitly registered synthetic stores. Keep32MiB per-file only for registered binary/build/Git/database artifacts; source/log/JSON retain1MiB |
| Temporary data |8MiB ordinary temporary cap; compiler scratch separately under artifacts | Unchanged ordinary8MiB; explicitly registered compiler/store temporaries also charged at peak to artifacts, never excluded by filename |
| Project stops |9GiB experiment storage stop within10GiB ceiling; diagnostic60MiB stop within64MiB;2GiB available-memory reserve | Unchanged; aggregate admission rechecked before heavy jobs. No existing evidence deletion to obtain space |
| Analysis/isolation/proofs | Analysis300s separate; isolation250.22s remaining, stopped; proofs2used/1unused | Unchanged. Preparation charges analysis only. Execution uses implementation only. No deployment, private proofs, proof attempt or zkVM run |

Projected implementation work is 400s source/fixture/metadata work, 500s native
builds/corrections, 900s baseline tests/corrections, 900s benchmark setup/trials,
600s shared tooling/regressions and 300s completion: **3600s**, leaving about112s
against the amended available pool. These are unmeasured planning allocations;
only retained native/audit timings are measurements. Rebalance them freely within
the single pool; do not borrow from analysis/isolation. If a workstream cannot fit,
report partial coverage and complete the independent admitted work.

Time accounting sums each job's measured elapsed execution once, even when jobs
overlap; parallelism is not free time. Do not also charge a supervisor's waiting
interval for the same job. Record supervisor-only execution separately. Continue
the established conservative local bookkeeping convention with one five-second
charge per agent's implementation work session, recorded before work; include
coordinator finalisation, or charge measured excess if five seconds is insufficient.
Human/agent deliberation time is outside these existing execution-second ledgers;
calendar dates below are not that accounting metric. Record CPU time separately.

Benchmark trials, individual parameterised tests, failed/partial runs and diagnostic
probes each consume a counted invocation. Static lint, formatting, input hashing,
inventory and audits are separately recorded checks charged in time/storage, not
cryptographic test invocations. Builds use the build counter and time, not a hidden
native-test count; any executed comparison during a build would also count as a
test and must be explicitly admitted. No uncounted CMake try-run of a test program.

The initial 392 invocations are40 native+48 baseline+16 harness+12 integration+
276 benchmark. The208 remainder is a shared correction/revalidation pool, not
permission for scope expansion or parameter weakening. No automatic blind retries;
diagnose, record a scoped correction, rerun affected checks with fresh attempt IDs.

New source/build copies are estimated16–32MiB; synthetic stores and fixtures
16–48MiB; retained27.84MB leaves approximately22MiB artifact margin at the upper
estimate. New evidence is estimated4–8MiB, including manifests, repeated failures
and measurement rows;32MiB cumulative leaves completion space after current use.
These are admission estimates. Actual output registries and prospective maxima
govern every launch. Synthetic databases are a new explicit artifact role under
this approval; arbitrary renamed evidence cannot gain the binary exception.

## Execution ownership, correction policy and checkpoints

The coordinator owns `experiments/kyc_milestone_1/run.py`, resource/configuration
files, shared job queue/ledger, `docs/data/oct31_kyc_native_milestone_1/`, all
status/traceability/issues and preservation. Agent N owns only the new Aurora
copy/overlay/harness. Agent B owns only baseline modules/tests. Agent H owns only
benchmark modules/tests. No concurrent editing of shared records. Required changes
across ownership boundaries go through the coordinator.

All execution jobs enter one bounded coordinator queue. Enforce the aggregate
resource hierarchy using **ephemeral user resource-control units only**, named
`pqdid-oct31-m1-*` under `pqdid-oct31-m1.slice`. Set parent limits before admitting
workload children; validate effective memory/swap/CPU/tasks properties and measure
the complete tree. No sudo, persistent unit/configuration installation, account,
membership or pilot activation is proposed. On shutdown stop only these owned
transient units and verify empty cgroups; keep failure evidence. This limited
user-manager effect is included in the consolidated approval request.

If the user-manager cannot enforce the common parent, continue with **one** guarded
job at a time under the existing stricter controls, recording that reduced
concurrency. Never run independent unmonitored helpers. A resource breach stops
the affected jobs and triggers bounded containment; admit further independent work
only after the cause and safe remaining envelope are established, without raising
limits. Benchmark sessions park other agents' commands/builds/tests, take the global
measurement lock, record ambient load, and abort/label contaminated trials rather
than claiming clean measurements.

| Checkpoint | Work and admission | Preservation / outcome |
| --- | --- | --- |
| C0 approval and baseline freeze | Record this plan's digest and authorised amendments; verify prior seals, current usage, local dependencies, ownership and tool availability; materialise exact file/output registry | One immutable opening inventory and explicit changed/new files; never regenerate an old baseline. Check stable report snapshots using repaired seal policy |
| C1 parallel implementation | N/B/H implement within their owned trees; coordinator freezes API/encoding above and records every patch/attempt | Cheap changed-input hash checks and focused lint throughout; preserve failed inputs/logs. No full audit after every formatting edit |
| C2 native/baseline functional acceptance | Build affected targets; run native matrix; validate baseline real signatures and durable state; continue B/H if N has a substantive construction blocker | One integrated review of independent expectations, source patch scope, no partial releases, counter integrity and source seals. Record exact unrun cases |
| C3 benchmark admission | Functional acceptance and harness schema/measurement checks pass; independent stores/fixtures ready; no concurrent project workloads | Run the frozen276-trial schedule only while predicted batch cost and300s completion reserve fit. Failed trial stays in denominator; no hidden retries |
| C4 finalisation | Freeze source/results; write workstream outcomes, measurements and one milestone summary | Existing corrected auditor, complete original+supplemental comparisons and inventory, strict immutable/full append seals,256MiB; final reporting/readback and headroom reconciled |

Routine compilation, declaration matching, formatting, tooling and implementation
corrections **inside the stated semantics and files** may proceed after approval
without a new permission round. Preserve pre-correction inputs, reason, expected
behaviour, new overlay hashes and affected rerun selection. Do not change pins,
EXP2 expectations, mathematical acceptance, signer caps, security parameters,
proof obligations or integrity policy to pass. Ordinary tooling corrections must
preserve scope/measurement semantics and be validated with synthetic fixtures.

A failed preservation audit is never completion. Within the shared budget, a
diagnosed inventory/format/tooling error may be corrected prospectively and the
full affected workflow rerun, retaining the failure. An unexplained protected
content mismatch stops execution for review; do not reseal it or broaden an
allowlist. Report repeated substantive failures rather than spend the pool blindly.

Allowed existing documentation changes are append-only status/traceability/issues
and the specifically registered `benchmarks/README.md` update. New reports are
`docs/stage3_aurora_masking_native.md`, `docs/stage2_mldsa_reference_baseline.md`,
`docs/kyc_milestone_benchmarks.md` and the milestone closure. Production `src/pqdid`,
active configuration, dependencies, manuscript and historical binaries remain
unchanged. Discovering a necessary production API change is a scope blocker to
report, not permission to patch it silently.

## Delivery schedule towards 31 October 2026

These are staged engineering targets from 28 September, contingent on timely
approval and the measured aggregate budget. They do not assign a deadline to a
missing cryptographic theorem.

| Window | Engineering output | Conditional research boundary |
| --- | --- | --- |
| 28 September–2 October | Approval, C0, isolated trees, exact APIs/fixture/output registration and common accounting | No private-proof admission |
| 3–11 October | Parallel native corrections, baseline real-signature issuance/presentation and harness interfaces | Report immediately if field/source conformance or the stated algebraic construction fails; B/H continue |
| 12–18 October | Native matrix, baseline persistence/replay/revocation, fault checks and corrections; C2 | TB-06/TB-09 remains a separately recorded theorem gate, not a reason to stall the baseline |
| 19–25 October | Serial baseline benchmark sessions, exports and reproducibility documentation; C3 | No complete-authentication latency, bytes or overhead claim from absent operations |
| 26–31 October | Final targeted regressions, audit/readback, evidence reconciliation and deliverable report; C4 | Full private authentication requires the commitment/transform argument and joint credential/holder/disclosure/non-revocation implementation; no unconditional October promise |

The complete intended authentication predicate is unchanged: credential authenticity,
holder-secret binding, selective disclosure and non-revocation must eventually be
verified jointly. The signature baseline measures a different, fully disclosed
predicate and does not replace that requirement. Bounded production security,
adaptive Delta_tail and proof knowledge/privacy remain unresolved.

## Consolidated approval requested

Approve **OCT31-KYC-NATIVE-MILESTONE-1** as specified here, including the new isolated
baseline format/contexts/storage, native SC/LD/FR/IO branch, benchmark harness,
ephemeral user resource controls, scoped correction/rerun policy and the resource
table: implementation **674→4274s**, invocations **450→1050**, builds **5→13**,
cumulative evidence **18→32MiB**, command ceiling **60/55→300/295s**, up to two
guarded jobs under **2GiB aggregate memory** with unchanged individual phase caps.
Keep128MiB artifacts and256MiB preservation audits; explicitly register synthetic
stores as bounded artifacts. Retire completed-package overlapping microcaps and
reservations without refunding consumption. Preserve separate analysis/isolation/
proof ledgers. No installations, host deployment, full proof or zkVM executions.

On approval, implement and execute this milestone directly. Do not prepare another
general review or require approval for each routine in-scope failure correction.
Only material scope, construction, dependency, integrity or resource changes need
a new decision. Nothing in this proposal activates these amendments in advance.

## Preparation checks and accounting

This preparatory task used source inspection and two read-only delegated mappings,
with separate file ownership and coordinator-only accounting. No functional tests,
builds, signatures, native comparisons, benchmarks or proofs were executed. The
established static checks and full preservation workflow are recorded alongside
the [execution plan](data/october_implementation_milestone_1/execution-plan.json).
The final preparation result and remaining analysis/evidence balances follow below.

### Completed preparation evidence

Static lint/format and proposal-count checks passed; no corrective pass was needed.
The single complete preservation audit exited0 and its outer guard/reporting passed:
**10,901 disjoint comparisons** (8,759 primary+2,142 supplemental), no missing or
changed protected content; identity coverage10,936 paths. Audit inventory
8286 names, no unexpected/missing entries. Final
inventory/readback and the complete seal are recorded in
[closure](data/october_implementation_milestone_1/validation-closure.json) and
[manifest](data/october_implementation_milestone_1/manifest.json).

Audit wall time **3.506725s**; cgroup-v2 `memory.peak`
**41,791,488 bytes (39.855MiB)** under256MiB, including worker descendants
and charged anonymous/file-cache/kernel memory. The external monitor is outside
that cgroup. Separately sampled tree RSS was59,375,616
bytes; temporary usage0, no resource event.

Preparation charged **19.222742s**: coordinator5s, two delegated source mappings
5s each, guarded commands4.222742s. Existing analysis balance
now **107.054637s**. Native107.26425821718294s and implementation111.82163787621539s
are unchanged; invocations448/450, builds5/5 and proofs2used/1unused unchanged.
No future amendment, benchmark, native build or functional case was executed.

Execution-plan SHA-256: `cbb310bee67ed9c237b0e1055b3e68d81652fffd96ccad611dc2f1c6a4fc0b27`. This preparation
ends with the single consolidated approval request above; the milestone is not
started and no further proposal is required to begin the agreed scope after approval.

Final preparation output 000000166074 bytes; cumulative 000016665098/18,874,368; available 000002209270. Final inventory 8291 names, complete with no discrepancies. No proposed ceiling applied.
