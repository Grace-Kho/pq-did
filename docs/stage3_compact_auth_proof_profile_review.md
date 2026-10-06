# S3-COMPACT-AUTH-PROOF-PROFILE-REVIEW-1

26 September 2026. **Construction decision: pursue an Aurora–BCS proof-layer
research contract, subject to the user's direction; adopt no replacement profile
and admit no execution yet.** Preserve the existing credential construction and
complete authentication relation. The specific next package is
**S3-AURORA-AUTH-CONSTRUCTION-CONTRACT-1**, defined below. This is a finite decision,
not a recommendation to survey more systems or continue lifecycle infrastructure.

Pause further integration and optimisation of the measured arithmetic into the
unchanged raw-view encoding unless new feasibility evidence changes the decision.
Neither the seeded gzkbpp implementation nor the existing CPU RISC Zero mode
justifies the next experiment. Aurora supplies a relevant compact-proof and QROM
research basis, but lacks the project relation, a usable bounded ZK wire contract
in the inspected mode, and the required parameter/game correspondence.

## Authority, preserved baseline and resource opening

Only manuscript **Sections II–VIII**, SPEC-001–004 and the
[current specification](implementation_spec.md) are authoritative. The guarded
[preflight](data/s3_compact_auth_proof_profile_review_1/preflight-evidence.json)
verified manuscript SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`,
the previous 201-file seal
`ac17093a43c6e1c0d768601618cb1dac0830b23e1839de8acdec452ff7714dcd`,
and all 53 assessed source/input identities. No historical seal was regenerated.

Reuse the [full-forward pilot](stage3_mldsa_full_forward_ntt_pilot.md),
[authentication feasibility plan](stage3_auth_proof_feasibility_plan.md),
[earlier profile survey](stage3_profile_change_proposal.md),
[R0 design review](stage3_r0_design_review.md),
[concrete security assessment](stage2_concrete_security_assessment.md) and
[outer-oracle composition decision](stage3_outer_oracle_composition.md).
The older assessment's implementation-status snapshot is historical: subsequent
bounded signing/lifecycle packages remain recorded and are not undone here.

| Opening ledger | Treatment |
| --- | --- |
| Analysis | 54.57621684111655/300 seconds charged; **245.42378315888345 seconds remain** |
| Implementation | 332.1767816620413/374 seconds charged; **41.82321833795868 seconds remain**, untouched |
| Tests/probes | **386/386**, zero new invocations authorised or performed |
| Isolation | Sealed safe-stopped/unactivated closure reused; 100 historical invocations, 22 original identity cases pending, 250.22 seconds including reserve, unchanged |
| Proofs | **Two attempts used, one unused**; CPU proving paused |

Established analysis accounting charges guarded documentation commands plus five
seconds for operator/bookkeeping; it is not elapsed human reading time. Retain
256 MiB cgroup-v2 memory, zero swap, separate aggregate sampled-RSS stop, one worker,
two CPUs, four controlled processes, 60-second command/55-second child limits,
ten-second evidence reserve, 8 MiB temporary data, 10 MiB cumulative package output,
1 MiB/file, 60 KiB command diagnostics, existing diagnostic/storage stops and
2 GiB headroom. Opening cumulative evidence is 7,742,291 bytes. Source retrieval
used the read-only browser; nothing was installed or executed from those sources.

## What the NTT evidence does and does not establish

| Class | Existing evidence | Consequence |
| --- | --- | --- |
| Measured host-managed execution | 97 partitions, eight stages, 1,024 butterflies; full-output differential cases and intermediate checks passed. Generation 32.391877992 s; evaluation 39.296167895 s; separate observation 10.836545261 s | Component evaluation and schedule coverage, not a proof of privately linked partitions |
| Accounted logical composition | Complete producer aliases, private boundaries and guards account for 27,044,356 gates / 10,679,298 ANDs | One logical experimental forward transform; not canonical BC-1 and not a materialised monolithic authentication circuit |
| Conditional authentication projection | Retaining that graph and the frozen raw-view format gives **2,568,395,104 bytes**, using the previously evaluated `5,363,104 + 960*ceil(g/4)` formula | Incompatible with the proposed 10 MiB target under those assumptions; **not a universal lower bound for PQ-DAA** |
| Actual complete circuit/proof | Neither complete authentication compilation nor an authentication proof exists | No measured complete authentication size, generation latency, verifier latency or privacy result |

Do not add overlapping hint, message-preparation and NTT counts. The transform
does not include inverse NTT, all matrix products, complete signature decoding,
samplers, hashes, disclosure and path processing. The experimental hint lowering
also remains outside BC-1. Arithmetic equivalence does not adopt either lowering.

The [KYC targets](benchmark_targets.md) remain provisional: complete raw proof
10 MiB, encoded presentation 12 MiB, generation p95 30 s, verification p95 2 s,
end-to-end p95 45 s, prover/verifier process-tree RSS 4/1 GiB. The exploratory
1 MiB/10 s scenario is separate. These targets are neither activated resource
allowances nor supported percentile claims. The assessment has no agreed overall
bit-security floor. Its illustrative `Q=2^64/2^80`, `N=2^32` and other workload
rows are not lifetime deployment budgets or new candidates' reduction budgets.

## Same-witness contract for every candidate

Public `X=(pp,mu,ctx,rstate,D,mD)` must use
[`encode_auth_statement`](../src/pqdid/statements.py) and trusted expected `pp`.
One private witness has exactly 5,329 bytes:
`xH[32] || Esch(m)[1024] || rid[4] || sigma[3309] || path[960]`.
The target is [the complete reference relation](../src/pqdid/relations.py), with
the same rejection/cap semantics and public/private check placement.

| Link | Required enforcement in the proved relation |
| --- | --- |
| Secret opening to certification | Compute `Y=SHA3-384(Enc(holder;suite,E(mu),xH))`, then the existing canonical `B=(Y,Esch(m))`; never publish Y/B as an extra presentation identifier |
| Exact issuer signature | Build the sole existing `Mcred` from suite, metadata, B and rid; verify hidden ML-DSA-65 sigma using trusted pkI and `PQ-DID/credential/v1`, including the pure-FIPS context prefix and every invoked bounded operation |
| Attributes/disclosure | Validate the entire canonical 1,024-byte block, lengths/types/padding; use that same m for certification and `proj_D(m)=mD`. Bind D to the public policy |
| Identifier/revocation | Enforce `rid<2^20`; use that same certified rid, zero leaf, 20 ordered SHA3-384 siblings, level/domain tags and root from the public state |
| Public statement/context | Bind all E(X), proof kind and independently admitted profile identity; no caller-selected key/context override, second decoded witness or host-supplied acceptance flag |
| Invalidity | Preserve signature norm/hint checks, canonical encodings, checked integer semantics and sampler exhaustion; force overall acceptance, not just local arithmetic consistency |

VII-A.6's public `PubOK`/`Ppub` conjunction remains required, including bounded
manager StateAuth under `PQ-DID/state/v1`. A proof-system Merkle tree is unrelated
to the application's private SHA3 non-revocation predicate. External request
authentication, holder approval, authenticated latest-state reads, trusted time,
strict final `now < texp` and atomic one-time challenge consumption remain separate.
An authentic old root is not a fresh root; session expiry is not credential validity.
No candidate may disclose sigma, rid, private attributes or xH, or offload their
verification to a trusted unproved service to meet a size target.

## Exactly three candidates and their dispositions

| Candidate / identifiable implementation / mode | Relation and missing work | Disposition |
| --- | --- | --- |
| **gzkbpp ZKB++**, `3d7739fb2e17cea60d2187a169c5e652cba34448`; generic three-party seeded Fiat–Shamir driver, not Picnic's separate Unruh mode | Circuit adapter can express the conjunction; complete bounded ML-DSA/hash/path relation, strict portable transcript and new compiler/PRG argument absent | Reject as next experiment: seeds do not establish sufficiently small remaining communication or a matched quantum contract |
| **RISC Zero 3.0.6**, `1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`; local native **Succinct/Poseidon2**, lift/join recursion, no Groth16 | RISC-V can express fixed algorithms; corrected CredValid guest exists, but auth disclosure/path/context image and complete joint proof do not | Retain historical experiment only; no renewed CPU proof or full-auth port on the present evidence |
| **Aurora–BCS**, Ben-Sasson et al., ePrint 2018/828, **8 May 2019**; libiop proposed revision `a2ed2ec2f3e85f29b6035951553b02cb737c817a`, native R1CS with `make_zk=true`, binary field/BLAKE2b, no recursion or wrapper | General R1CS can express the relation; complete compiler, exact parameter profile, wire implementation and application security reduction absent | Sole proposed construction research direction; not execution-ready or approved as a profile |

The [source record](data/s3_compact_auth_proof_profile_review_1/sources.json)
distinguishes inspected text from reused evidence. gzkbpp/R0 pins and file hashes
come from the preserved survey. libiop's commit/history page identifies the proposed
revision, but readable files were browser `master` views; immutable raw/blob fetches
failed. Their byte identity to that revision/submodules was **not independently
verified**. No checkout/reproducible-build claim follows. Confirm this before any
future implementation or build; do not install a moving branch.

### gzkbpp: residual transcript cost is the relevant question

Reuse the [sealed survey and primary locators](data/stage3_profile_sources.json):
three parties, 438 repetitions, 16-byte seeds and SHA-256 are that demonstration's
choices, not a replacement for the active 480-round/raw-tape proof. The cited
[ZKB++/Picnic paper](https://eprint.iacr.org/2017/279.pdf) separates Fiat–Shamir ROM
and Unruh QROM constructions. Its small LowMC benchmark, 195,458 bytes with
31.31/16.30 ms generation/verification, does not measure this relation or generic
gzkbpp on it. No new source execution or fresh benchmark was performed here.

A valid future byte model must retain, per repetition, transmitted seeds, any
input-share correction, unreconstructible gate/view messages, unopened commitment,
output shares, challenge/nonce data and framing. Symbolically, count
`P_header + sum_i(P_seed_i + P_input_i + P_gate_i + P_commit_i + P_output_i)
+ P_challenge + P_framing`, with exact omitted/recomputed fields justified by the
chosen checker. PRG seeds can replace reconstructible tapes, not the independent
messages needed to check a nonlinear computation. Neither `P_gate` nor a complete
auth byte total is established here. Applying a factor-of-two to the raw-view
projection would not be a measurement of gzkbpp. A new proof relation/compiler,
bounded parser, domain/context rules, quantum-secure PRG assumptions and
transform-specific extraction/simulation are needed. Prerequisites are an isolated
C++/OpenSSL build and pins; none is installed. This changes VII's proof construction
and invalidates reuse of VIII-C/D's specific formulas. It does not change credentials
or eliminate adaptive Delta_tail.

### RISC Zero: compact enrolment evidence, inadequate authentication admission

Reuse the [R0 measurements](stage3_r0_design_review.md): the actual enrolment
Succinct receipt was 238,485 bytes, with 343.898929933 s guarded generation,
1,535,385,600-byte cgroup peak and 0.011627595 s independent receipt verification.
Enrolment reveals its own public fields and proves no private credential signature
or anonymous authentication. Corrected CredValid completed **execution only** at
16,313,474 user cycles in 182 segments. Its approximately 9.89-hour CPU proof
forecast is conditional, not measured proving time or a lower bound for other
implementations. There is no CredValid proof memory/receipt measurement. Boolean
gate savings do not revise this forecast. Accelerator/GPU possibilities in the
earlier review supply no comparable complete-authentication measurements.

The receipt must include seal, claim, control inclusion, parameters/profile,
journal and framing. A future auth image must bind all E(X), prove all private
checks and exclude witness-dependent public metadata; existing diagnostic journals
are not that interface. The pinned implementation uses reserved randomised trace
padding, including recursion data/accumulator noise; see the local
[recursion witness generator](../experiments/r0_enrol_po17_1/tooling/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/risc0-circuit-recursion-4.0.5/src/prove/witgen.rs).
This mechanism is not a privacy proof. The
[2023 protocol draft](https://dev.risczero.com/proof-system-in-detail.pdf)
describes the IOP family and predates the selected release and recursion profile.
It cannot certify the complete pinned pipeline.

The [version-3 security model](https://dev.risczero.com/api/security-model)
qualifies its ZK target, describes recursion's length-hiding purpose, and lists
ROM/Toy Problem assumptions with component estimates 96/99. Its BN254 wrapper
is not quantum-safe. These are not the project's overall security numbers.
Require a complete argument for masking, terminal control metadata, native receipt
encoding, quantum extraction and adaptive public-only simulation. Full verification
must use expected image/parameters, reject fake/composite/Groth16/unresolved claims
and check the exact journal. Rust/guest toolchain and pinned CPU prover already
exist; CUDA would require a separately justified hardware/dependency experiment.
VII would need a guest/admission/journal profile, VIII a new VM/recursion theorem
mapping. Component forgery, hash and Delta_tail obligations remain.

### Aurora: a different encoding, with identifiable integration blockers

The [Aurora paper](https://eprint.iacr.org/2018/828.pdf), Theorems 1.1/1.2 and 9.2,
provides an R1CS IOP/ROM zkSNARK: polylogarithmic proof communication, quasilinear
proving and linear verification. Its ZK mechanism combines random higher-degree
encodings on disjoint domains with algebraic masks for sumcheck and low-degree
testing; ordinary RS encoding alone is insufficient. Section 11 measures synthetic
R1CS with `2^10..2^20` constraints, roughly as many variables, binary field
`GF(2^192)` and the paper's 128 setting on a Xeon W-2155 3.30 GHz/64 GB machine:
40–130 kB, fractions of a second to minutes proving, milliseconds to seconds
verification. Host RAM is not measured peak RSS. These published values neither
size nor time the complete project relation or its required quantum parameters.

The [API](https://raw.githubusercontent.com/scipr-lab/libiop/master/libiop/snark/aurora_snark.hpp)
separates the constraint system, public input, auxiliary witness and proof
parameters. Proposed research mode is native ZK R1CS, binary extension field,
BLAKE2b BCS commitments/challenges; **not** a pairing wrapper, recursive mode,
non-ZK mode or adopted concrete parameter set. The paper's field/128 setting is
only the identified comparator. The
[implementation parameters](https://raw.githubusercontent.com/scipr-lab/libiop/master/libiop/protocols/aurora_iop.tcc)
pad constraint/variable domains, add ZK dimensions, and couple the query bound to
masking/FRI parameters. The printed achieved-security value is an IOP calculation,
not an evaluated CMS reduction at the project's lifetime budgets.

The [BCS tree code](https://raw.githubusercontent.com/scipr-lab/libiop/master/libiop/bcs/merkle_tree.tcc)
also samples private leaf randomness and uses ZK leaf hashing. Such salts must
remain correctly linked to every transmitted opening. The
[default BCS parameters](https://raw.githubusercontent.com/scipr-lab/libiop/master/libiop/bcs/common_bcs_parameters.tcc)
introduce proof-of-work/grinding linked to dimension/hash cost; the query-setting
routine credits it. Neither classical grinding credit nor a parameter named
`security_parameter` supplies the required quantum bound. Parameter selection must
account for this exact mode rather than quote a paper headline.

Two concrete wire/admission findings prevent a ready-to-run profile recommendation:

1. The [transcript structure](https://raw.githubusercontent.com/scipr-lab/libiop/master/libiop/bcs/bcs_common.hpp)
   retains query positions that its benchmark accounting deliberately omits.
2. The [serialisation source](https://raw.githubusercontent.com/scipr-lab/libiop/master/libiop/bcs/bcs_common.tcc)
   has an unimplemented binary-field/non-algebraic-hash branch. Its other Merkle
   serialisation helper is marked non-ZK only. The object byte estimate is not a
   complete portable wire encoding; this is source evidence, not an executed exploit
   or proof that Aurora's mathematics is unsound.

A complete wire model must count field messages, queried field values, roots,
pruned authentication nodes, opened ZK salts, grinding response, any non-recomputed
positions, canonical lengths, field/hash/profile identifiers and E(X) binding.
Every omission requires deterministic bounded reconstruction. A future parser
must reject oversized vectors, noncanonical fields, inconsistent dimensions,
wrong profile/context, truncation and trailing data before unbounded allocation.
No object-memory-size or benchmark-size function may stand in for wire bytes.

[Documented prerequisites](https://raw.githubusercontent.com/scipr-lab/libiop/master/INSTALL.md)
include C++/CMake, libff/libfqfft, libsodium, Boost and native GMP/support libraries;
test tooling additionally uses GTest. Binary-field optimisation needs an appropriate
CPU implementation. Exact submodules, compiler flags and portability must be pinned
before an isolated build. No existing project dependency is changed. The library
[warns that it is a research prototype](https://github.com/scipr-lab/libiop).

## Complete-cost model and relation lowering obligations

For Aurora, retain a fixed public-profile shape and a single bit-level source
witness. A simple **proposed, ungenerated** characteristic-two R1CS embedding has
`a*b=c` for AND, `(a+b)*1=c` for XOR, `(1+a)*1=c` for NOT, and
`b*(b+1)=0` for every free input bit. These equations plus topological wiring
propagate Booleanity; assert the final acceptance wire is one. Canonical E(X)
public bits must be tied to trusted expected bytes. Auxiliaries are constrained
wire values, not extra credentials. This is an elementary representability
argument, not full compiler conformance or a generated constraint count.

**Binary extension-field arithmetic is not arithmetic modulo 8,380,417.** Either
retain exact Boolean integer operations, or separately prove limb/range/carry,
division, representative and rejection constraints for a new lowering. The NTT
pilot's signed64 entry normalisation and canonical intermediates do not justify
dropping original signature norm/hint checks or adapting inverse NTT unchecked.
Keeping a variable/row for each gate gives a straightforward symbolic accounting;
eliminating linear wires may reduce rows but increase matrix density. Count
variables, rows **and non-zero matrix entries**, bit guards, final accept checks,
padding, masks and public input expansion. Never equate 10,679,298 ANDs with that
complete R1CS cost.

| Complete workload term | Required accounting; current evidence |
| --- | --- |
| Canonical witness/message | Fixed parsing, schema/padding, same-field construction and context prefix; existing Boolean fragments only |
| ML-DSA | Decode/norm/hints, all bounded sampler paths, matrix work, forward/inverse transforms, products, accumulation, reduction/decomposition/use-hint, SHAKE and final challenge equality; full lowerings/costs absent |
| Holder and application hashes | Exact SHA3/SHAKE blocks, padding, domains and private holder opening; existing hash gadgets do not establish complete candidate costs |
| Revocation/disclosure | Same rid, private direction selection, 20 SHA3 nodes, same attributes and public projection; include all canonical/range checks |
| Proof overhead | R1CS matrix/assignment storage, FFT/FRI codewords, ZK masks, commitment trees/salts, transcript hash/grinding, serialisation and self-check; unmeasured locally |
| Public verifier/wrapper | Decode/admit proof and X, trusted keys, StateAuth/Ppub, expected context and external atomic freshness/consumption; neither native proof verification nor a circuit count times these |

Define `N_auth` by the complete constrained representation, including non-zero
matrix entries, and `L_j` for padded oracle domains. The symbolic Aurora resource
model includes matrix/assignment storage plus the **maximum simultaneous** codeword,
FFT and Merkle buffers, not just proof bytes. Time includes witness generation,
IOP arithmetic, commitments/grinding, encoding/self-check and public checks.
The non-preprocessing verifier reads the relation; small communication does not
promise constant verifier work. There is no justified mapping from existing
Boolean-generation seconds or RISC-V cycles to these costs. Their local values,
complete proof bytes and KYC p95 results remain **unknown**. No new numeric campaign
or calculation script ran in this source-only package.

## Claim/evidence and theorem-applicability matrix

| Claim | Available basis | Exact limit / outstanding obligation |
| --- | --- | --- |
| BC-1 complete-view extraction/privacy | Manuscript VIII-C/D and prior ideal-oracle review | Premises belong to raw tapes/480 repetitions/fixed CGen; none transfers merely by changing the proof encoder |
| Seeded ZKB++ quantum knowledge/privacy | Cited Picnic/Unruh theory and generic implementation evidence differ in transform/parameters | Establish selected PRG, transcript and theorem premises; no inherited raw-tape simulator |
| R0 compact proof of recorded enrolment | Independently verified historical native Succinct receipt | Not full auth, not quantum history-preserving extraction/privacy; pinned IOP/recursion/metadata argument missing |
| Aurora IOP/ROM ZK and knowledge | Paper's stated construction and theorem interfaces | Match selected implementation, ZK mode, round-by-round property, relation and parameters; research code is not a proof of these correspondences |
| BCS quantum transfer | **Chiesa–Manohar–Spooner, TCC 2019, Theorem 3 (informal), §2.9:** public-coin IOP with round-by-round soundness; knowledge requires round-by-round knowledge, ZK requires honest-verifier ZK | Symbolic soundness `O(t^2*epsilon_IOP + t^3/2^h)` for quantum oracle queries t/output h. Not a numerical guarantee, not an automatic proof of the project's adaptive service game |
| Concrete BLAKE2b/Poseidon2/SHAKE instantiation | Concrete implementations plus explicitly modelled hash assumptions | Ideal QROM is not a theorem about fixed code. Enumerate hash interfaces, domains, lengths, salts, grinding and reduction costs; no unspecified error term silently added to extraction/privacy |
| KYC compact complete authentication | None of the three has a measured complete project proof | Published unrelated workloads and component results cannot certify bytes, p95 latency or peak memory |

The inspected [CMS proceedings paper](https://www.iacr.org/archive/tcc2019/11891143/11891143.pdf)
provides a relevant QROM route, not merely a hash-based-security label. Its full
ePrint revision could not be fetched; no claim to audit its missing detailed
constants or proof is made. Parameter/theorem matching remains an adoption gate.

For a replacement, prove a relation-preserving projection from every extracted
R1CS assignment or VM trace to the **same** canonical credential/opening/attributes/
rid/path. Then supply an extractor retaining the terminal predicate S, statement,
proof, residual state and actual authorisation/revocation history without rewinding
external services; quantify all reduction queries/time. Separately supply online
public-only simulation through the permitted future publications/continuation,
including proof length/metadata and hash state. A generic stand-alone theorem
cannot simply be added as a loss to the manuscript's different construction.

| Existing gap | gzkbpp | R0 | Aurora research direction |
| --- | --- | --- | --- |
| Outer-oracle composition | Changed transcript/PRG/transform; SHA-256 modelling and joint games require a new mapping | Changed Poseidon2/SHA-256/recursion oracle family; retained quantum knowledge/privacy obligation | BLAKE2b outer interface differs from fixed internal Keccak, avoiding that particular shared-permutation substitution **if explicitly specified**; concrete BLAKE2b modelling and adaptive composition remain unresolved |
| OC-REL/EXT/PRIV/BUDGET | Re-establish for seeded construction | Re-establish for guest/recursion claims | Re-establish for constrained relation/BCS transcript; no blanket closure of the historical BC-1 issues |
| Adaptive Delta_tail | Retained | Retained | Retained: unchanged FIPS caps/distributions; no proof-system choice makes failure probability zero |
| Component advantages | Retained at actual enlarged reduction budgets | Retained | Retained; no transplant of illustrative Q/N into a differently costed extractor |

No overall bit-security claim is assigned. Parameter names, digest lengths and
field size do not substitute for property-specific finite bounds. Production
custody, entropy assurance, erasure, side channels, durable holder storage and
deployment isolation obligations remain separate. Weak reductions and missing
arguments are not demonstrated attacks.

## Construction decision and one bounded next package

**Request a research-direction decision to replace the raw-view proof layer with
Aurora–BCS native ZK R1CS, retaining the exact existing credential relation.**
No candidate is yet adequately supported for a complete-authentication profile or
a costed proof pilot. This is a proof-system redesign, **not** a credential redesign:
no altered ML-DSA variant, holder hash, revocation tree, hidden fields or signing
context is proposed. Do not rename the credential suite inside signed messages.
A separately registered experimental proof-profile identity must bind the unchanged
E(X); its admission semantics require explicit specification.

| Required change before an experimental profile | Concrete scope |
| --- | --- |
| VII-A.1/.5/.6/.7 and circuit/proof profile | Specify the new proof-profile registration, R1CS compiler/field, single witness, canonical transcript and fail-closed verifier. Enrolment also needs its corresponding relation/admission contract; authentication alone cannot complete issuance proofs |
| VIII-A/C/D and derived privacy/knowledge uses | Replace proof-specific raw-view/repetition calculations with finite IOP/BCS parameter and composition premises; retain component reductions and Delta_tail |
| Implementation interfaces | New isolated relation adapter, bounded wire parser, immutable relation/profile identity, local prover/verifier and same public lifecycle checks. Current service default remains unsupported; no synthetic proof acceptance |
| Dependencies | Exact libiop/submodule/compiler inventory and bounded entropy/ABI review before any build; no moving-branch dependency or unattended install |

Propose **S3-AURORA-AUTH-CONSTRUCTION-CONTRACT-1** only after the user's decision:

1. Pin source/submodule identity and specify one native-ZK binary-field/BLAKE2b
   mode. Deliver a complete field/query/domain/masking/grinding/hash-output table
   or an explicit mathematical obstruction; no silent use of the paper's 128 label.
2. Write one bounded canonical transcript contract covering **all** fields above,
   deterministic query reconstruction where justified, domain separation and
   profile/E(X) binding. Resolve the observed binary/ZK serialisation gap at the
   contract level before promising an interoperable proof.
3. Give a same-witness R1CS mapping for the complete relation, with bit/range,
   fixed-shape, sampler-exhaustion and acceptance constraints. Separate proved
   representability from unmeasured implementation cost; prohibit unproved private
   signature verification and unauthenticated partition joins.
4. Map the selected IOP/BCS premises to the exact terminal extraction and adaptive
   simulation games. Produce explicit unresolved lemmas/parameter terms where
   necessary and a finite adopt/decline decision. If parameter, wire or relation
   requirements cannot be supported, stop with no implementation admission.

Proposed scope: **source/documentation only**, at most 30 charged analysis seconds
including static checks/audit, ten-second reserve, unchanged memory/process/storage
ceilings, zero tests/builds/circuits/proofs. This allowance is **inactive**, not a
transfer from the implementation or isolation balances. No empirical experiment is
proposed until that contract can price its smallest relevant deliverable honestly.
Success means a concrete implementable profile contract with every remaining
security condition explicit; it does not mean production adoption. Missing premises
must yield a negative decision, not another broad survey or a weaker relation.

This next package resolves the identified **interface/parameter/theorem admission
uncertainty**. Full proof feasibility and meeting the provisional targets would
still require separately authorised measurements. Stages 2–3 remain open.

## Validation and preservation record

Only the new report/evidence and append-only status, traceability and issue updates
are authorised here. Production code, active BC-1, parameters, dependencies,
manuscript and all historical evidence remain protected. The evidence
[contract](data/s3_compact_auth_proof_profile_review_1/contract.json),
[claim matrix](data/s3_compact_auth_proof_profile_review_1/claim-matrix.json) and
[inactive proposal](data/s3_compact_auth_proof_profile_review_1/proposal.json)
record the finite decision. Helper lint/format, Markdown/local-link/JSON/static
checks and one corrected preservation audit use the existing guard. No historical
functional validation is repeated; no new experimental invocation is disguised as
a documentation check. Measured closure follows after the full audit completes.


## Measured documentation and preservation closure

Compact-profile review complete: **construction-research-decision**. Recommend
an Aurora–BCS proof-layer research contract preserving the entire credential and
authentication relation; no profile adoption or experiment is admitted.
Helper lint/format and documentation/static consistency checks pass. No test,
circuit generation, arithmetic probe, build, estimator or cryptographic execution ran.
The single [preservation audit](data/s3_compact_auth_proof_profile_review_1/result.json)
completed content/inventory comparison, report readback and outer guard, exit 0.
Coverage: 10,680 disjoint content paths;
10,711 identity-inclusive paths.
Original baselines and historical document prefixes are preserved.

| Measurement | Result |
| --- | --- |
| Audit wall time | 2.597733224 s |
| Audit cgroup-v2 memory.peak | 23,707,648 bytes |
| Audit sampled process-tree RSS | 40,370,176 bytes |
| Maximum guarded-job cgroup peak | 23,900,160 bytes |
| Maximum separately sampled tree RSS | 40,370,176 bytes |
| Guarded commands | 11, 3.749033108 s |
| New analysis charge, including five bookkeeping seconds | 8.749033108 s |
| Cumulative analysis charge | 63.325249949/300 s |
| Analysis remaining | **236.674750051 s** |
| Implementation unchanged | **41.823218338 s**, **386/386 tests** |
| Temporary disk observed peak | 0 bytes; zero retained |
| Evidence bytes at audit completion | 438,382 |

Two retained E501 lint failures were manually corrected; lint repeated twice;
no experimental failure/retry or resource breach. The unchanged 256 MiB cgroup guard
covers the worker and descendants, including charged file-cache/kernel memory;
swap is zero. Sampled RSS is a separate metric. Final bounded bookkeeping uses
256 MiB address space, five-second CPU/alarm, two CPUs and 1 MiB/file inside the
five-second charge; it does not repeat content comparisons.
The [closure](data/s3_compact_auth_proof_profile_review_1/validation-closure.json)
and [additive seal](data/s3_compact_auth_proof_profile_review_1/manifest.json)
record the exact balances. Isolation remains safely stopped/unactivated with
250.22 s and 22 original cases pending. Stages 2–3 remain open; proof ledger
**two attempts used, one unused**, CPU proving paused.
