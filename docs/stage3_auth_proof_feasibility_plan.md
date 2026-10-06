# S3-AUTH-PROOF-FEASIBILITY-PLAN-1 — complete private authentication decision

26 September 2026. **No evaluated route presently has an evidenced path to both
the complete authentication/security contract and the proposed KYC performance
envelope. Keep CPU proving paused; do not spend the remaining proof attempt.**
This is a completed negative feasibility decision, conditional on the preserved
validation closure below, not a demonstrated attack or an impossibility theorem.

The next proposed package is **S3-PRIVATE-HINT-LOWERING-PILOT-1**: one isolated,
non-BC-1 Boolean lowering experiment, with a complete decoder comparison and a
strict stop. It needs explicit authorisation for the research construction and
eight additional test invocations. It does not adopt a replacement proof profile,
promise complete authentication, or authorise proving. The reason to measure this
specific component is the already attributed private-index bottleneck; repeating
the unchanged R0 proof configuration would not answer a new question.

## Authority, evidence and separate allowances

Only manuscript **Sections II–VIII**, SPEC-001–004 and the
[current specification](implementation_spec.md) are authoritative. The PDF remains
SHA-256 `d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The preserved [section extraction](data/s2_concrete_security_assessment_1/sections-II-VIII.txt)
supplies V-B, VII-A.6/.7 and VIII; excluded sections supply no timing or requirement.
Read with the [security assessment](stage2_concrete_security_assessment.md), its
[exact calculation evidence](data/s2_concrete_security_assessment_1/bounds.json),
[security profile](../analysis/concrete_security/security_profile.json),
[outer-oracle composition decision](stage3_outer_oracle_composition.md),
[R0 design review](stage3_r0_design_review.md), and
[container-adapter boundary](stage2_kyc_container_adapter.md).

The [preflight](data/s3_auth_proof_feasibility_plan_1/preflight-evidence.json)
verified the preceding 48-file seal
`5353a5efd51e1d505afb366eb4a938b2ab3869818c295cd2c5a9a70b0e25ad3e`
and 53 assessed source/input entries. Source revision here means a content inventory,
not a Git commit. The [evidence contract](data/s3_auth_proof_feasibility_plan_1/contract.json)
pins the reused reports/source/calculations. No numerical campaign, functional
regression, native interoperability harness or proof measurement was repeated.

| Ledger at entry | Preserved balance and use in this package |
| --- | --- |
| Implementation | 195.863037117/300 s consumed; **104.136962883 s remain**, 222/223 tests, **one remains**. Untouched |
| Source/calculation analysis | 29.818518832/300 s consumed; **270.181481168 s remain**. Source/evidence/documentation checks and preservation use this existing scope |
| Isolation | Safely stopped/unactivated, 100 historical invocations, **22 original identity cases pending**, 250.22 s including its ten-second reserve. Untouched |
| Proofs | **Two attempts used, one unused**, CPU proving paused. Untouched |

The sealed [host closure](data/s2_concrete_security_assessment_1/host-closure.json)
and [activation disposition](data/s2_authority_isolation_pilot_1/activation-v2-session/session.json)
are reused. Safe closure is not successful identity validation; pending cases,
failed preflights and outstanding isolation issues remain. No host activation or
new host-observation campaign occurred.

Analysis enforcement retains 256 MiB cgroup-v2 memory, zero swap, a separate
256 MiB sampled aggregate RSS stop, one worker, two CPUs, four controlled processes,
60 s command/55 s child and cumulative 300 s. Kernel `memory.peak` includes the
worker, descendants and charged file-cache/kernel memory; the monitor is external.
The monitor's RSS can count shared pages twice and miss transient peaks. Neither
metric is relabelled as the other. Retain 8 MiB temporary data, 10 MiB cumulative
package output, 1 MiB per file, 60 KiB command diagnostics, the existing diagnostic
and 9 GiB storage stops, 2 GiB headroom and ten-second cleanup/evidence reserve.
New commands plus five seconds of operator/bookkeeping are charged to analysis.
No budget is transferred, reset or enlarged by this plan.

## Exact public statement, witness and acceptance boundary

The canonical public statement is
`X = (pp, mu, ctx, rstate, D, mD)`, encoded only by
[`encode_auth_statement`](../src/pqdid/statements.py). Expected `pp` comes from
trusted instance configuration, never from a proof's self-declared key or suite.

| Public component | Required contents and binding |
| --- | --- |
| `pp` | Active suite, issuer/key/schema reference, namespace, expected issuer and manager ML-DSA-65 public keys (1,952 bytes each), exact schema |
| `mu` | That same issuer reference and namespace; no independent caller-selected instance |
| `ctx` | Suite, audience, session, fresh 32-byte nonce, supported policy, issuer reference, `(namespace, epoch, root)` state reference, unsigned64 POSIX session expiry |
| `rstate` | Namespace (32 bytes), epoch (uint64), root (48 bytes), manager signature (3,309 bytes); exact context reference equality |
| `D, mD` | Canonical two-byte disclosure mask for the registered schema and exactly its canonical disclosed vector; `D == ctx.policy.disclosed`, ordered and type checked |

Private witness `xi = (xH, Esch(m), rid, sigma, path)` is **5,329 bytes / 42,632
bits**: 32 + 1,024 + 4 + 3,309 + 960. `rid < 2^20`; the 960-byte raw path contains
20 ordered 48-byte siblings (SPEC-001). There is no additional prover-selected
decoded signature, holder digest, certified message, certificate binding or second
identifier. Auxiliary credential data are empty. Preserve the fixed schema,
padding/domain rejection and bounded operations in
[witnesses](../src/pqdid/witnesses.py), [schema](../src/pqdid/schema.py),
[credentials](../src/pqdid/credentials.py) and [relations](../src/pqdid/relations.py).

| Obligation | Exact target and location |
| --- | --- |
| Holder opening | Privately compute `Y = SHA3-384(Enc(holder; suite, E(mu), xH))`; build `B = Enc(binding; Y, Esch(m))`. Never expose Y/B as an extra presentation identifier |
| Certification | Build the sole `Mcred = Enc(cred; suite, E(mu), E(B), uint32(rid))`; bounded pure ML-DSA-65 verification of hidden sigma under expected pkI and **`PQ-DID/credential/v1`**, including FIPS message prefix `0 || len(context) || context || Mcred` |
| Non-revocation | `PathRoot(rid, 0, path) == rstate.root`, SHA3-384 domain-framed zero leaf and 20 level-tagged nodes; bit j of the **same certified rid** selects child order at bottom-up level j+1 |
| Disclosure | Validate the full private 1,024-byte vector and require `proj_D(m) == mD`, using the **same certified m**. No second public/private attribute vector |
| Statement binding | Fix all of E(X), operation and proof-profile identity in the transcript/journal and verify against independently expected values; only public context influences allowed specialisation |
| Public `PubOK` | Canonical types/domains, suite/instance/schema/context/state consistency and **bounded manager StateAuth** under `PQ-DID/state/v1` |
| Public `Ppub` | The supported conjunction on disclosed attributes/context, including unsigned range/equality rules. No private policy claim is silently moved outside |

V-B defines the complete conjunction. **VII-A.6 explicitly checks PubOK and Ppub
publicly**, while its circuit proves certification, opening, disclosure and path.
This is the existing construction, not a proposed weakening. The Python
`auth = pub_ok and auth_private and public_policy_ok` implements that composite
predicate. A future proof verifier must enforce both public terms in addition to
its private-relation proof. A public manager signature need not be reproved inside
the private circuit merely to duplicate an already required public check.

External wrapper obligations remain outside this stateless relation: authenticate
the verifier request, obtain holder approval, use registered trusted keys and the
stored complete audience/session/nonce/context; enforce trusted time, read an
authenticated current state in the specified order, and atomically recheck context
and strict **`now < texp`** before one-time challenge consumption. StateAuth proves
authenticity of a supplied root, not latest-state freshness. Updating a stale witness
does not authorise rewriting a challenge's state; request a fresh challenge if its
state changes. Optional DID/version checks use disclosed values only. Session expiry
is not certified credential `validUntil`; the latter requires the existing certified,
disclosed policy semantics. Preserve the durable verifier/holder lifecycle evidence;
none of these checks substitutes for private proof knowledge.

## Coverage of the implemented relation and proof fragments

| Layer | Implemented coverage | Missing for complete private authentication |
| --- | --- | --- |
| Executable local reference | `relations.auth` evaluates the entire conjunction using real bounded signature verification, holder opening, full attribute validation/projection and same-rid Merkle path. Holder/revocation integration tests already exercise valid, changed-root and mismatched-witness cases | This holder-local witness evaluator is **not** a remote proof verifier. No extraction, simulation, proof receipt or proof performance follows |
| BC-1 foundation/hash/enrolment | Deterministic emitter/control, SPEC-003/004 arithmetic, SHA3/SHAKE gadgets and complete provisional enrolment circuit with private 256-bit xH | Full compiler conformance, complete auth CGen, shared prover/checker and transcript machinery absent |
| BC-1 auth parsing/message preparation | Fixed 42,632-position parser, domain/padding and disclosure checks, holder/Mcred/key/message-representative components | Preparation does not verify sigma; changing signature bytes alone still passes that fragment |
| BC-1 signature components | Response decode/norm and scalar helpers; limited hint fragments; three preserved 32M-gate capped prefixes | Complete hint decode, complete bounded samplers/NTT/matrix verifier composition, final challenge comparison and full acceptance circuit unvalidated/unimplemented as a whole |
| BC-1 Merkle/auth integration | Native SHA3 path available; reusable hash gadgets | Complete private depth-20 path gadget, linkage to the same parsed rid and final auth conjunction not generated/validated |
| BC-1 proof protocol | Specification fixes three parties, 480 repetitions, raw tapes/views, salts/nonces and outer commitments/challenges | No complete sharing, 480-repetition prover, commitments, challenge mapping, opened-view checker or complete auth proof; ideal-oracle theorems are not an implementation |
| R0 enrolment guest | Expected pp/domain, public enrolment statement, holder opening and approved-attribute equality; private xH. One independently verified Succinct receipt exists | Journal exposes enrolment's public attributes/rid/binding; it is not an anonymous presentation. Guest only structurally parses supplied state; surrounding StateAuth/issuance checks remain required. No private issuer signature, disclosure or NR proof |
| Corrected R0 CredValid guest | Private encoded credential plus xH; canonical B/attributes/rid/metadata, holder opening, bounded ML-DSA verification and exact Mcred/context. Public wrapper binds pp/metadata and a diagnostic nonce | No auth ctx/audience/session/policy, D/mD, signed root or private path. No full `auth-statement` adapter or authentication image/journal/verification admission. Execution completed; **no CredValid receipt** |
| Future complete R0 auth, if ever approved | General VM semantics could express the existing bounded private conjunction, with PubOK/Ppub in the public verifier | Reconstruct credential from the **single raw auth witness**, add exact private path/disclosure, bind all E(X) in a distinct registered auth image/journal, validate malformed/mix-and-match/context cases, full proof and composed knowledge/privacy. None is implemented here |

Source boundary: the corrected [Rust relation](../experiments/r0_credvalid_cycle_1/relation/src/lib.rs)
dispatches only `enrol` and `cred-valid`. Its journal is
`Enc(r0-result; profile, operation, public)`; CredValid's public input contains pp,
metadata and the diagnostic nonce, not the authentication statement. Concatenating
its journal with an independently supplied disclosure/path would not establish the
missing same-witness relationship. Journal equality after execution is not a receipt.

## Reused measurements, caps and projections

| Evidence and classification | Preserved result | What cannot be inferred |
| --- | --- | --- |
| BC-1 enrolment circuit, measured construction | 194,691 total gates, **38,787 ANDs**, d=256 | **9,587,104 calculated proof bytes**, no generated proof; not auth size |
| BC-1 message preparation, complete measured fragment | **2,034,776 gates / 413,709 ANDs**, fingerprint `7778652f244202f6fda785104a5113964dc4172fccc6f39ec404a137d50a15b7`; nine functional cases, generation 3.686–3.768 s, evaluation 0.437–0.458 s | Native circuit generation/evaluation is not MPC proving. Do not multiply it by 480 to forecast proof time |
| BC-1 hint prefix, **capped** | 32,000,000 emitted gates / **13,532,448 ANDs**; 284/330 slots complete, 285th partial; padding/final validity unreached | Not full hints or full auth, no complete circuit fingerprint. Overlapping signature/preparation prefixes cannot be added |
| Conditional continuation projection | If that prefix embeds with the audited lowering/classification, `P_auth >= 3,253,150,624 bytes` | Conditional 3.030 GiB projection, **not a generated proof or unconditional whole-circuit lower bound** |
| R0 enrolment, measured successful proof attempt 2 | **196,311 user cycles**, 3 po2-17 segments; SDK paging 78,207, reserved 118,698, total padded 393,216. Full guarded pipeline **343.898929933 s**, cgroup peak **1,535,385,600 bytes**, tree RSS 1,571,074,048 bytes | Not auth/CredValid cost; one successful sample cannot establish p95. Attempt 1's 600 s timeout is retained, not a completed baseline |
| Enrolment receipt/verification, measured | Complete receipt **238,485 bytes**, seal 222,668 bytes; public journal 15,380 bytes; fresh independent verification **0.011627595 s**, eight prior tamper rejections | Receipt size is not seal size; fast verification says nothing about hidden auth implementation or complete PQ knowledge/privacy |
| R0 CredValid po2-17, complete measured **execution only** | **16,313,474 user cycles**, **182 segments** (181×2^17 + 1×2^15); padded 23,756,800. API **0.302627684 s**, guarded **0.392469114 s**, cgroup peak **48,640,000 bytes**, sampled tree RSS 71,516,160 bytes; accepted exact 5,147-byte journal | No proof time/memory/receipt/verification measurement. Padded minus user 7,443,326 includes several overheads; not a measured paging counter |
| CredValid CPU admission forecast, **unmeasured** | **35,615.571973026 s = 9.893214437 h**, already includes its **50% uncertainty allowance** | Neither a bound nor statistical confidence interval; no second allowance. Complete auth is absent, not extrapolated from enrolment |

The frozen CredValid guest is the one with six native tests and 35 reference
comparisons. Inventory revision
`fd5e917d158f2bf74e0825b0e5415f910e466d8cd8acd95ee5e4257da6144084`,
ELF SHA-256 `d5ef3682a8956ba03b710cdee14f02dbf967ec05e935c3d73fcc582aac19aaf2`,
image `a7b77747d5ebff0e520d17fc188afef06dfb91690062cb96f6b3cff78e93ae94`,
original synthetic `cred-alpha-42`, SDK 3.0.6, two CPU threads. The
[po2-17 manifest](../experiments/r0_credvalid_po17_1/evidence/manifest.json) retains
fixture and compiler identities: custom rustc 1.97.0-dev, opt3, thin LTO, one
codegen unit, overflow checks, panic abort, unchanged RISC-V target/flags. Nothing
was rebuilt. The 2^24 executor cap is SDK `Executor.cycles.user`, with 463,742
cycles (2.7641%) margin; it does not cap padded capacity. Additional auth work has
no measured cost or guaranteed fit under that cap.

The forecast reuses 182 bases × 41.574386 s, 182 lifts × 44.326462 s and
181 joins × 44.748385 s, execution proxy 0.302627684 s and assumed 10 s overhead,
then 50% **once** on the subtotal 23,743.714648684 s. The terminal po2-15 base/lift
uses an unmeasured po2-17 proxy. Enrolment's three bases/lifts and two joins supplied
the rates; no full-auth cycle ratio was used. Aggregate CredValid proving memory
is unknown: retained segments, intermediate receipts and overlapping recursion
buffers invalidate treating enrolment's peak as a bound.

These values are reused from [BC-1 feasibility](stage3_feasibility_review.md),
[hash/enrolment evidence](stage3_hash_enrolment.md),
[signature components](stage3_signature_inputs.md),
[enrolment po2-17](stage3_r0_enrol_po17.md),
[CredValid po2-17](stage3_r0_credvalid_po17.md),
[cost inputs](../experiments/r0_credvalid_po17_1/evidence/cost-model-inputs.json) and
[checked design-review calculations](data/r0_design_review_1/calculations.json).
No new calculation or cryptographic execution occurred in this review.

## Three routes and the adoption decision

The [KYC targets](benchmark_targets.md) remain **proposed**, not agreed SLAs:
complete raw proof ≤10 MiB, full presentation ≤12 MiB, generation p95 ≤30 s,
verification p95 ≤2 s, end-to-end p95 ≤45 s, prover RSS ≤4 GiB and verifier
RSS ≤1 GiB. Network scenario: 10 Mbit/s payload, 50 ms RTT. The stricter
1 MiB/10 s scenario is exploratory. The 600 s historical proof timeout and
2 GiB experiment limit are separate engineering ceilings, not application targets.
Actual transport/framing bytes count; a 10 MiB binary proof in base64 already
exceeds 12 MiB. Few samples establish no percentiles or throughput.

The security assessment has **no agreed precise overall bit target**. Its proposed
property/adversary/lifetime-workload contract remains provisional. ML-DSA-65
Category 3, lambda=128, ideal QROM error exponents and vendor STARK estimates
cannot be collapsed into an overall quantum bit number. Keep the illustrated
N/Q/reduction workloads and their unspecified terms; test counts are not lifetime
adversarial budgets.

| Route | Can express complete relation; missing implementation | Knowledge/privacy/PQ evidence | Cost and target decision; changes |
| --- | --- | --- | --- |
| **1. Frozen BC-1 / raw-view MITH** | Yes, bounded Boolean relation in principle; full auth compiler, signature/path composition, raw-sharing prover/checker and conformance absent | Manuscript VIII ideal-QROM extraction/simulation under its hypotheses; reproduced bounds. Concrete outer-oracle composition and actual implementation correspondence unresolved | Formula `P(g)=5,363,104+960*ceil(g/4)` permits only **21,344 ANDs** under 10 MiB; 1 MiB impossible even at g=0. Existing component evidence makes continuing this lowering unsuitable for target-led integration. Streaming affects RAM, not raw bytes. No parameter changes permitted; keep as reference |
| **2. Current R0 CPU Succinct/Poseidon2, with assessed relation-preserving optimisations** | General VM can express it; current guest is CredValid only. Full private auth, public admission and independent exact journal/image binding missing | One verified enrolment receipt under exact pinned parameters. No reviewed complete quantum extractor, complete-view/history simulator or adopted auth profile; no Groth16 in measured route | CredValid forecast 9.893 h versus 30 s draft generation; real enrolment alone 343.9 s. Existing hash/preprocessing screens do not justify another proof. Missing full cost/memory. Adoption changes VII proof encoding/admission and VIII-C/D arguments; optimisations also change guest/dependencies/image/control composition |
| **3. Separately reviewed Boolean lowering plus revised MPC-in-the-head representation** | Generic Boolean machinery can express the unchanged mathematical ML-DSA/SHA3/private-path predicate. Need complete optimised relation, equivalence, new transcript/decoder/parameters and full prover/checker | Prior source survey of generic ZKB++ and its paper identifies ROM versus different QROM transforms; no theorem for this proposed full relation/implementation. PRG seeds/hashes/transform need a fresh argument; current 480-round bounds do not transfer | No complete workload benchmark. The measured hint prefix makes a small lowering experiment useful, but no established KYC latency/bytes or security result. **Research route only**: change VII-A.6/.7 compiler/proof representation and affected VIII-A/C/D/E arguments; new profile identity, not a BC-1 optimisation |

Route 3 reuses the [pinned prior survey](stage3_profile_change_proposal.md), section
“Revised Boolean lowering / published improved MPC-in-the-head”, including generic
ZKB++ revision `3d7739fb2e17cea60d2187a169c5e652cba34448`. Its 438 repetitions,
16-byte seeds and SHA-256 settings are **not proposed PQ-DID parameters**. Published
LowMC results concern a much smaller different relation and different hardware.
No candidate source or dependency is installed/run, and no current upstream claim
is inferred from this historical survey. A new MPC representation is needed even
if hint lowering becomes cheap: the raw-view byte formula and other compulsory
hash/signature work remain. Do not silently seed tapes or change repetitions.

For route 2, the [completed optimisation review](stage3_r0_design_review.md)
already inspected exact FIPS SHA3/SHAKE via the pinned tiny-keccak accelerator
(`8fcc866dc94dcec3e79c3b2bc8fbc51b22f2d5e1`, SDK 3.0.6). It requires replacing
RustCrypto calls, explicit features/dependencies, a new isolated build/image and
verified Keccak base/special lift/union/resolve controls; unchecked host results
are inadmissible. The static ≤251-permutation scenario fits one default batch,
but its extra proofs and privacy composition are unmeasured. Public-key
preprocessing needs independently derived, exactly bound tables and cold-cache
accounting. Even the old optimistic six-private-NTT-only proxy retained a
3,671 s forecast. Neither that proxy nor the isolated **20.26%** polynomial saving
is a measured complete-CredValid speedup. No GPU route is recommended: no
workload-matched supported accelerator build, exact hardware/memory admission and
end-to-end proof/security evidence have been established. Mere hardware presence
would not supply them. No new accelerator or dependency permission is requested.

**Research decision:** retain the mathematical credential/holder/path predicate
as the comparison target, but consider a separately named replacement for **both
the BC-1 lowering and raw-view proof representation**. That is a construction-level
change requiring user review and new security work. This plan neither declares it
feasible nor changes the active suite. If no replacement can provide a joint private
proof with the required security and workload envelope, the construction/performance
requirements must be revisited explicitly; more lifecycle infrastructure cannot
resolve that conflict. No complete proof candidate is admitted today.

## One proposed next package and finite stopping rule

**S3-PRIVATE-HINT-LOWERING-PILOT-1 — proposed, inactive, for authorisation.**
The most useful bounded engineering uncertainty in route 3 is whether the dominant
private-index decoder can be expressed as a substantially smaller **complete**
Boolean predicate without changing FIPS acceptance. Existing attribution assigns
most of the capped prefix to scanned read/write selectors and signed64 data muxes.
A candidate can instead use explicit bounded byte/bit representations and
fixed-schedule membership logic, with proved range/domain invariants. This is a
different lowering; the prior audit found no BC-1 bug permitting its substitution.

This is a **component admission screen**, not a full-proof pilot. It deliberately
answers only that uncertainty. The security of a replacement transcript is a
separate blocking research obligation; no component gate count can settle it.

| Item | Proposed bounded contract |
| --- | --- |
| Deliverable | A separately named test-only decoder from the exact hidden 61-byte hint slice to six 256-element binary hint polynomials plus sticky validity; a source/range/equivalence argument, one complete gate inventory/fingerprint, eight individually reported comparisons and a stop/admit-component decision |
| Inputs | Existing synthetic signature/hint fixtures and `_decode_hints` in bounded_mldsa.py as the native acceptance/output oracle; FIPS/source schedule already reviewed, original immutable capped evidence, existing emitter/evaluator and .venv. No new keys or operational witness logs |
| Construction boundary | Existing production and BC-1 modules unchanged. A new research lowering may narrow representations only with explicit range/binary constraints; preserve endpoint/order/padding/rejection semantics, fixed structure and the original raw private bytes. No unconstrained decoded-hint witness or witness-dependent host skipping |
| Validation matrix, at most eight invocations | Original valid fixture; valid all-zero hints; decreasing endpoints; endpoint >55; duplicate coefficient within a row; descending coefficients within a row; nonzero unused padding; one valid boundary fixture with endpoint 55 and a coefficient repeated across different rows. Each is one case, not hidden parameterised batches. Use the same completed circuit across cases |
| Measurement | Count all core gates/ANDs, wire storage and trace memory separately from independent comparison overhead; compare valid outputs and rejection with the native decoder. Include all padding/final validity, count no incomplete prefix as success. Record complete-code identity and residual integration requirements |
| Proposed resources | No installs/build toolchain changes, proof guests, proofs or activation. Continue existing implementation time: **at most 30 charged seconds total**, including the five-second bookkeeping charge, lint/format, one preservation audit and cleanup; reserve ten of those seconds for required evidence/cleanup before admitting optional work. Retain 256 MiB cgroup/tree-RSS, zero swap, one worker/two CPUs, 60/55 s command/child maxima (shorten to remaining package allowance), 8 MiB temporary disk, 10 MiB cumulative output, 1 MiB/file, 60 KiB diagnostics and existing storage/headroom stops. At most one new circuit, **2,000,000 gates**, in-memory trace only; no large trace output. Stop if it cannot fit |
| Test amendment needed, **not granted here** | Propose **eight additional invocations**, cumulative ceiling 223→231, without resetting 222 consumed. Run at most the eight listed cases, including failures/repeats; do not treat the resulting spare allowance as authority for extra cases. Any failure ends the package; no automatic retry |
| Success | All eight cases agree on acceptance and valid decoded values, complete fixed circuit fits the limits, independent core accounting and preservation pass. Complete alternative AND count must be below the recorded **13,532,448-AND original prefix**; report that limited comparison, never a percentage for complete original hints/auth. Result admits this component for later joint-circuit/profile design only |
| Failure/incomplete | Wrong acceptance/output, unexplained binding/range change, gate/time/memory/output cap or incomplete audit stops with retained evidence. No extra gate/time allowance, no fallback to a successful partial prefix. Reject this candidate lowering pending an explicit new construction decision |
| Decision after either result | **No proof attempt and no profile adoption.** A passing result informs a replacement compiler's actual component cost; failed feasibility removes that proposed implementation path. Full private signature, SHA3 path, proof representation, security and end-to-end accounting must still pass before any whole-proof proposal |

The 30 s cap is an allocation **within** the remaining implementation balance,
not an extension or use of analysis/isolation time. The proposed eight-test
amendment and experimental lowering require approval; neither starts here. If the
live ledger cannot accommodate the complete package plus evidence at authorisation,
stop rather than borrowing another allowance. This deliberately small experiment
cannot rescue the current raw-view byte budget on its own and is not offered as a
route to a favourable overall feasibility result.

## Security checkpoints and remaining obligations

| Checkpoint | Evidence required before the corresponding claim/adoption |
| --- | --- |
| Complete relation | All hidden parts derive from one certified witness, canonical public context/key/profile admission, negative mix-and-match cases; no private data in journal, auxiliary tables or diagnostic output |
| Full lowering equivalence | Independent bounded FIPS/circuit correspondence, caps and error semantics; SPEC-003/004 do not establish full BC-1 conformance or validate a new compiler |
| Concrete security | Component advantages at actual reduction budgets, adaptive **Delta_tail**, adversary/lifetime target and event-preserving extraction; no overall bit number |
| Outer oracle | **OC-REL, OC-EXT, OC-PRIV, OC-BUDGET, A-K-MODEL** remain open. SHAKE capacity is not outer output length; do not attach an unproved instantiation error to extraction/privacy |
| Complete proof knowledge/privacy | Chosen transcript/transform/parameters, actual joint witness extractor, complete-view and subsequent-history simulator, leakage/failure/scheduling assumptions; neither ideal BC-1 claims nor enrolment receipts transfer automatically |
| Production release | DEP-001/DEP-002 production obligations, custody, entropy provenance, erasure and side channels; completed bounded synthetic signing/durable release evidence remains valid within its reference boundary |
| Application | KYC-INT-001–004 W3C vocabulary/issuer binding, securing mechanism, DID method/key and private-status mapping; **durable holder storage** and application action/reply recovery remain open. None is expanded into work here |

Stages 2–3 remain open. The present transport adapter remains structural and
fail-closed for proof admission; no synthetic acceptance becomes a real proof.

## Validation and preservation procedure

Run only the new evidence helpers through the existing guard, sequentially:

```sh
.venv/bin/python -I -B docs/data/s3_auth_proof_feasibility_plan_1/run_checks.py preflight
.venv/bin/python -I -B docs/data/s3_auth_proof_feasibility_plan_1/run_checks.py imports
.venv/bin/python -I -B docs/data/s3_auth_proof_feasibility_plan_1/run_checks.py source-format
.venv/bin/python -I -B docs/data/s3_auth_proof_feasibility_plan_1/run_checks.py quality
# The initial lint result failed; the inspected correction uses new names:
.venv/bin/python -I -B docs/data/s3_auth_proof_feasibility_plan_1/run_checks.py correction-format
.venv/bin/python -I -B docs/data/s3_auth_proof_feasibility_plan_1/run_checks.py quality-corrected
# Failure-disclosure prose also needed wrapping; both failures are retained:
.venv/bin/python -I -B docs/data/s3_auth_proof_feasibility_plan_1/run_checks.py final-correction-format
.venv/bin/python -I -B docs/data/s3_auth_proof_feasibility_plan_1/run_checks.py quality-final
.venv/bin/python -I -B docs/data/s3_auth_proof_feasibility_plan_1/run_checks.py format
.venv/bin/python -I -B docs/data/s3_auth_proof_feasibility_plan_1/run_checks.py prepare
.venv/bin/python -I -B docs/data/s3_auth_proof_feasibility_plan_1/run_checks.py full-audit
.venv/bin/python -I -B docs/data/s3_auth_proof_feasibility_plan_1/close.py
```

Commands above are evidence, not an instruction to repeat completed runs. The runner
rejects repeat names and unexpected failure continuation. Two E501 line-length
failures in the new closure helper are preserved with exact pre-correction sources
and log hashes in [the correction records](data/s3_auth_proof_feasibility_plan_1/lint-correction-v2.json).
The manually inspected text fix permits only the named corrected lint/format and
remaining evidence commands, with unchanged accounting and resource stops. This
exception cannot continue a resource, functional or full-audit failure. A
[prelaunch diagnostic](data/s3_auth_proof_feasibility_plan_1/prelaunch-diagnostic.json)
also retains the refused formatter command caused by the stale continuation-name
set; no service or test launched, and its bookkeeping is within the five-second
charge. The corrected chunked preservation engine is unchanged: original
8,759-entry baseline plus additive historical manifests,
disjoint content partitions, exact name inventory, input digests and full historical
prefixes of status/traceability/issues. Only this report/evidence and appended new
dispositions are authorised; no directory-wide exemption or regenerated baseline.
Documentation consistency, links, JSON and helper lint/format are checked; no
functional/calculation tests run. A successful content comparison alone is
insufficient: report readback and the outer guard must complete. One failed full
audit stops without retry. Final closure is bounded bookkeeping, not a second audit.


## Measured validation closure

Planning/evidence review is **complete with no profile admitted**. Helper lint and
format checks pass; one documentation/evidence consistency check is included in
the audit. No functional tests or new numerical calculations ran.
The single [complete preservation audit](data/s3_auth_proof_feasibility_plan_1/result.json)
passes content, exact inventory, report readback and outer guard, exit 0. Coverage:
10,145 disjoint content paths and
10,168 identity-inclusive paths. All three
existing reports retain their full prior prefixes. No source, parameter, dependency,
fixture, manuscript or historical evidence changed; no baseline was regenerated.

| Measurement | Result |
| --- | --- |
| Audit wall time | 2.283966482 s |
| Audit cgroup-v2 memory.peak | 24,895,488 bytes |
| Audit sampled process-tree RSS | 46,960,640 bytes |
| Maximum guarded-job cgroup peak | 24,895,488 bytes |
| Maximum sampled tree RSS | 46,960,640 bytes, separate metric |
| Guarded commands | 11, 3.365740499 s |
| New analysis charge including five bookkeeping seconds | 8.365740499 s |
| Cumulative analysis charge | 38.184259331/300 s |
| Remaining analysis allowance | **261.815740669 s** |
| Implementation unchanged | **104.136962883 s; 222/223 tests, one remaining** |
| Isolation unchanged | 250.22 s, 100 historical invocations, 22 original identity cases pending |
| Temporary storage | 0 observed peak bytes; zero retained |
| Evidence bytes at outer audit completion | 441,434 |

Two E501 lint failures are retained and charged; the final named lint check passes.
No functional-test or full-audit retry and no resource breach occurred.
The unchanged 256 MiB guard includes
worker/descendants and charged cache/kernel memory, swap zero; external tree RSS is
separately monitored. Final bookkeeping has the established 256 MiB address-space,
five-second CPU/alarm, two-CPU and 1 MiB/file limits within the five-second charge;
it does not repeat the protected content comparison.
[Closure](data/s3_auth_proof_feasibility_plan_1/validation-closure.json) and
[additive seal](data/s3_auth_proof_feasibility_plan_1/manifest.json) retain exact balances.
Proof ledger: two used/one unused; no builds, proof guests, proofs or activation.
Stages 2–3 remain open, isolation stopped/unactivated. The sole next proposal is
S3-PRIVATE-HINT-LOWERING-PILOT-1, **not started or authorised by this review**.
