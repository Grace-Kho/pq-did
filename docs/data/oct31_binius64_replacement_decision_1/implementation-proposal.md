# One conditional integrated milestone — not admitted

Proposed name: **OCT31-BINIUS64-AUTH-INTEGRATION-1**. This is an implementation
runbook with admission gates, not permission to execute or a promise that they
pass. The current pin fails G0. Recommendation is **do not approve private proving
against that pin**. A decision to fund correction of the same named route would
approve the bounded work below and its explicit experimental profile delta; a
materially different construction, field, mask, hash or reduced predicate would
still require a new decision. No rolling sequence of generic reviews is proposed.

## G0 — fix the actual construction before private input

Owner A, isolated `experiments/binius64_auth_integration_1/vendor/binius64`, records
an overlay against `441fbf51ff0bcb0bcd28f3f1b73f4954029e8577`, preserving that checkout.
Required affected interfaces: `prover/src/prove.rs::{pack_witness,IOPProver::prove}`,
`verifier/src/verify.rs::{oracle_specs,verify}`, `prover/src/zk_config.rs`,
`verifier/src/zk_config.rs`, both `spartan-*/src/wrapper/*` and the BaseFold
channel/encoder/opening interfaces as required by a reviewed support mapping.

- Specify the inner oracle's q+2 randomisable support, in *field coordinates*,
  including the extra terminal-claim key. Prove every original relation operand
  vanishes there and every new claim operand includes only its intended key.
  Update packing, domain dimensions, ring-switch reductions, blinding and verifier
  checks together. Simply overwriting zero padding can change the predicate.
- Replace the clear private terminal target with the Blueprint's masked claim,
  bound by the outer constraints and PCS. Match OTP consumption to symbolic/replay
  order. Preserve the separate clear *public* wiring claim and its native check.
- Enumerate jointly disclosed inner/outer messages, interleaved openings, folded
  codewords, terminal coefficients and Merkle paths. Establish rank/query-union
  and commitment-hiding conditions, including dummy rows and all exceptional
  challenges. Resolve affine gamma interpolation versus additive Blueprint masking.
  A unit test or additional random wires alone is not this argument.
- Fresh CSPRNG-seeded masks are a proposed computational implementation assumption,
  not adoption of seeded tapes into BC-1. No fixed seed outside labelled tests.
- Add the precise OtterSec public-input substitution regression on both transparent
  and ZK APIs, not merely message-tampering roundtrips. Bind trusted circuit identity
  before all statement-dependent challenges. Fail G0 if only a non-ZK path works.

**G0 stopping decision:** without semantic and masking correspondence for the complete
revealed view, retain code/count results, record NO-GO and do not feed private witness
material to proofs. An implemented patch still does not establish QROM security.
An upstream corrected pinned version is an alternative input only after explicit
revision approval; no automatic upgrade is part of the proposal.

## G1 — reproducible dependency and build admission

Owner A resolves the recorded semver requirements into a project-local Cargo lock
with registry checksums, complete feature graph and build-script inventory; pins
Rust 1.98.1 and verifies its distribution checksum. No existing Python/liboqs or
global Cargo/Rust environment changes. Acquisition/toolchain installation is a
**future** approval effect. No sudo, system packages or services. Source checks must
include all retained blobs, not merely the commit label. Unavailable versions or
unreviewed executable build hooks stop provision/build rather than select fallbacks.

Only after approval and G0/G1 readiness, scoped commands would use:

```sh
env CARGO_HOME="$PWD/experiments/binius64_auth_integration_1/cargo-home" RUSTUP_HOME="$PWD/experiments/binius64_auth_integration_1/rustup-home" CARGO_TARGET_DIR="$PWD/experiments/binius64_auth_integration_1/target" CARGO_BUILD_JOBS=1 RAYON_NUM_THREADS=2 RUSTFLAGS='-C target-feature=+avx2,+pclmulqdq,+aes,+sha' cargo +1.98.1 build --locked --offline --release --manifest-path experiments/binius64_auth_integration_1/Cargo.toml --bin pqdid-b64-prover --bin pqdid-b64-verifier --bin pqdid-b64-check
```

These are **proposed targets**, not files claimed to exist now. Every configuration,
compiler probe and build is inside one of the three counted builds. Retain the
upstream release thin-LTO/debug settings in the estimate; no undeclared speed flags.
Ordinary test dispatch must use the package guard and an explicit case ID, never
`cargo test --workspace` with uncounted parameterised cases. Pin binary identities.

## G2 — complete relation lowering and count before allocation

Owner B owns `native/{statement,bytes,sponge,mldsa,arithmetic,relation}.rs` and
`count-plan.json`; Owner C owns `reference_cases.py`, `native/case_driver.rs`,
`lifecycle_adapter.py` and evidence. Coordinator alone owns ledger/guard/docs.
Parallel *source editing* is optional; execution remains one worker, two CPUs,
with one aggregate ledger and no concurrent builds/proofs. No public/private
classification may depend on a witness value.

The experimental descriptor contains source/overlay/lock/compiler identities,
all constraint rules and limits, domain/mask/hash/query parameters and exact public
framing. `RID/PID` identify these complete descriptors, not a circuit nickname.
Canonical internal `E(...)` byte encodings are reused; no signed message changes.
Word packing is little-endian eight-byte chunks of those already canonical bytes;
big-endian protocol integers remain big-endian *bytes* before packing. Constrain
unused high bytes to zero, lengths, counts, enums and all consistency links.

| Reference obligation | Planned implementation and independent comparison |
| --- | --- |
| Trusted statement / PubOK | Reuse `validate_auth_statement`, `pub_ok`, bounded `state_auth` and `public_policy_ok` on public X at both entry and independent verifier. Bind full expected pp/instance, issuer and manager keys, metadata, state root/epoch/signature, context/policy, disclosure mask/attributes and descriptor. Public rejection remains part of complete acceptance, not an untrusted caller flag. |
| Private witness | Exactly `xH[32] || m[1024] || rid[4] || sigma[3309] || path[960]` for the retained bounded profile; full validator, schema capacities and canonical padding. Host witness hints merely propose values; constraints must enforce every dependency and reject forged auxiliaries. |
| Holder binding / Mcred | SHA3-384 of the existing binding input; reconstruct the unique certificate and sole `build_mcred` byte-for-byte, including suite, metadata, binding and the same rid. Context `PQ-DID/credential/v1`; pure FIPS message framing, not a caller-supplied mu or context override. |
| Bounded ML-DSA-65 | Port exact signature decoding/hints, norm, ExpandA, tr/mu, SampleInBall, NTT/inverse, A*z−c*t1, UseHint/w1 and final challenge equality. Preserve q=8380417, k=6,l=5,n=256, tau=49, omega=55 and every original cap. Constrain canonical hint ordering/count/padding, z norm and rejection/exhaustion. Public A/t1/tr can be deterministically recomputed from the bound issuer key, never accepted as unauthenticated prover hints. |
| Integer arithmetic | Native IntMul constrains unsigned 64×64→128 hi/lo, unlike multiplication in characteristic-two GHASH. Signed64/65/128 conversion, exact carries/sign extension, comparisons, quotient/remainder ranges, positive divisor and checked overflow remain explicit. Enforce `a=q*d+r` using integer word constraints plus bounds, not the same expression in GF(2^128). Match original signed representatives where subsequent checks depend on them. |
| Hashes | Reuse fully constrained Keccak-f1600 (24 rounds, 25 lanes), SHA3-384 fixed core. Implement SHAKE128/256 absorb **and multi-block squeeze**, not Keccak-256 or SHA3 with a changed output size. SHA3-384 rate104/capacity768 bits, suffix06; SHAKE128 rate168/capacity256, SHAKE256 rate136/capacity512, suffix1f; final pad bit80. Test empty, exact-rate, last-byte and multi-squeeze boundaries. Preserve all project domain prefixes and native bit order. |
| Private samplers | Fixed 1,026-byte ExpandA cap and 256-byte SampleInBall cap (8 sign bytes+248 candidate bytes). Private rejection counters/index selection must be multiplexed/constrained with exhaustion false, no secret host branching that omits constraints. Public expansion can be host-preprocessed only with independent key/instance binding and the same cap. |
| Disclosure/policy | Project exactly the same certified m at D, equal mD, enforce disclosed schema and public policy. No separately supplied unsigned attributes. Private attributes, holder secret and rid never enter public containers. |
| Non-revocation | Depth20 SHA3-384 path, ordered children/level prefixes and zero leaf against authenticated state root; path bits are the **same certified rid**. No unrelated leaf/path or host acceptance. |
| Enrolment | Separate existing Xen/BindOpen relation and approved attributes; trusted expected context/controller/instance/state binding. Authentication does not replace enrolment. |
| Lifecycle | Existing issuer permanent reservation/commit-before-release and recipient-bound stored outcome; manager public retrieval; verifier trusted context/currentness, strict expiry and final atomic at-most-once consumption. Proof verification is only one predicate inside that transaction, never an acceptance flag supplied by transport metadata. |

Independent oracles: existing Python bounded relation and canonical encoders plus
host exact-integer arithmetic and FIPS SHA3/SHAKE through the existing environment.
Do not use the new Rust helper to produce its own expected bytes. Reuse existing
native interoperability results unless changed inputs justify a scoped repeat.
Host private computations are permitted only as *untrusted witness generation*
with complete constraints; full checks stay in the relation. No chip registration
or M4 outsourcing in the initial ordinary-word path; if an upstream gadget hint
runs, verify its expanded constraint body, not just its host return value.

Count zero/AND/IntMul/BinMul constraints, total shifted-index terms and actual
committed words, public segment, hidden segment, auxiliary/hint/padding words,
outer wrapper rows/columns/nonzeros and oracle supports. Run a non-allocating
counting sink first, then bounded small differential checks, then count the **whole**
relation. Count wire-elimination/index-map peaks and Rust container capacities,
not only compact serialised constraints. Independent count reconciliation is
required before allocating the complete instance. Preserve missing counts as null.

### Whole-workload model (no new circuit measured)

For the existing metadata shape, private-path hashing is 5 holder +12 mu +2
SampleInBall +7 final challenge +20×6 Merkle =146 Keccak permutations. Public
ExpandA adds 30 SHAKE128 streams of 1,026 bytes if not preprocessed. Actual lengths
must be derived from the descriptor; the mu shape must not be generalised to all
metadata. A partial-block private length is not a public constant. Existing source
has exactly 600 lane-level χ operations per permutation before optimisation:
87,600 here, plus all linear wiring, padding and conversion. This does not arise
by dividing the earlier 268,800 Boolean χ products by 64. That older quantity was
only the final seven-permutation **ML-DSA internal hash**, not the proof transcript.

Other dimensions that remain: six forward transforms and six inverse transforms,
7,680 A*z public-constant products, 1,536 c*t1 products, coefficient accumulation,
1,536 hint/decomposition/norm-related lanes as applicable, 1,280 z coefficients,
SampleInBall private selection, 61 hint bytes, 1,024 attribute bytes, policy/schema,
20 path levels, byte/range/validity links and the outer ZK verifier circuit.
No complete new word constraint count can be extracted from Boolean counts; no
Binius timing or proof-size measurement exists for this relation.

Let W be live 64-bit witness words, n_i padded GHASH elements for each of the four
oracles (inner, OTP precommit, outer private, Libra), E_i=n_i*2^r codeword positions
per row, h=32 SHA-256 digest bytes, and K actual constraint/index/layout bytes.
ZK commits **two** rows per oracle; both original and mask openings must be retained.
Use the following live-allocation inventory, with capacities/alignment measured
before approval of a full allocation:

```
M_peak = K_frontend + K_native + K_shift_keys + K_outer + 8*W
       + 16*sum(message_i + mask_i + transparent_i in field elements)
       + 32*sum(E_i)                  # two committed rows
       + 32*sum(2*E_i - 1)            # conservative binary trees, leaf count E_i
       + M_inner_operation_columns + M_sumcheck + M_ring_switch
       + M_combined_FRI_and_retained_folds + M_NTT_context_and_encode_temporaries
       + M_outer_replay_OTP_layout + M_buffer_pool_retained_highwater
       + M_proof_bytes + M_serialisation_copies + M_allocator_runtime
```

Count actual tree layout/FRI arities; do not double-count shared Arc layouts but do
include separately cloned constraint systems. The pool reuses buffers between inner
and outer phases, yet its retained high-water allocation still occupies memory.
Original commitments/codewords remain for query openings; not all phases can be
added as disjoint peaks. Streaming witness construction does not remove that fact.
The currently exposed verifier deserialises sizes/layouts; an application parser
must bound them before allocation and require exact transcript finalisation.

Illustration only: at rate1/2, retaining one message, mask, two-row codeword and a
full binary tree is approximately `224*n_i` bytes. For n_i=2^19 this is112MiB;
for2^22 it is896MiB. These are **partial storage calculations**, not complete
candidate estimates or measured allocations. The other three oracles, matrices,
working buffers, proof and verification are additional. Current 1GiB worker
admission therefore depends critically on the unknown complete dimensions.
Prover work must include every encoding/fold/hash/field operation, not emitted
constraints alone. Independent verification uses no witness but still stores public
matrices/keys, the wrapper and transcript; measure it in a separate process.
Disk includes pinned downloads/toolchain/deps, target intermediates, both binaries,
constraint/witness files if retained, proofs, logs and all historical artifacts.

## G3 — validation, proof boundary and benchmark

Proposed interfaces: `compile(expected_descriptor)->count/shape`,
`fill(X,w)->assignment`, `check_assignment(shape,assignment)->valid`,
`prove_experimental(expected_descriptor,X,w,rng)->bounded_bytes`,
`verify_experimental(expected_descriptor,X,proof)->bool`. The proof API does not
exist/admit proofs today. Never expose raw witness to the service verifier.
Trusted configuration selects descriptor/key/context; unsupported profile IDs and
synthetic placeholders fail before native deserialisation.

Proposed envelope framing uses a fixed local version/profile ID, explicit bounded
lengths and exact canonical X; no caller “accepted”, “verified” or backend override.
Bind descriptor hash, X, both roles and enrol/auth domain via the existing canonical
encoders before initial transcript challenges. Retain upstream internal SHA-256
only as an explicitly approved experimental profile difference from the manuscript's
outer SHAKE model. Set a provisional16MiB proof/parser cap; an excess is failure,
not permission to stream unbounded input. Parser memory remains inside the native
worker limit. Independent verifier is a separate binary/process with trusted X,
no prover state, no private witness and complete proof-byte consumption.

Proposed invocation allocation **128**, parameterised entries individually counted:
16 byte/hash/arithmetic boundaries;24 bounded-MLDSA/auxiliary rejection cases;
21 retained full-relation cases (still unrun now);12 joint credential/holder/rid/
path/disclosure adversarial assignments;12 transcript/masking/parser checks;
8 lifecycle/recovery/freshness/recipient cases;8 local-container/W3C boundary cases;
12 newly budgeted proof/independent-verification/measurement cases;15 reserved
routine corrections/repeats. Sum128. No blanket upstream test suite. Failures count;
no automatic retry after an integrity/resource failure.

The twelve prospective proof generations comprise two enrolment and ten complete
authentication proofs, on synthetic credentials with fresh private randomness, in
separate sessions/verifier contexts. Each is independently verified and its timings,
peak process-tree/cgroup memory, setup reuse, proof/presentation bytes and end-to-end
lifecycle state recorded. This small dataset permits individual costs and descriptive
summaries, not tail-percentile/throughput claims. Proof-generation attempts, including
failures and upstream roundtrip tests, count against **these twelve**, not the old
unused attempt. Any native test creating a proof must replace a planned proof slot,
not silently add a thirteenth. Rejection tests can reuse already created proof bytes
where their intended risk permits it. Maintain a separate new dataset; no changes
or gratuitous reruns of v1's276 disclosed/linkable observations.

Proof gate requires G0 privacy semantics, G1 reproducible inputs, G2 complete
resource admission, independent full-relation agreement, and a written **classical
ideal-model engineering-only** claim boundary. It does not require pretending QROM
knowledge/privacy has been proved. If that qualified experiment is not explicitly
approved, zero private proof attempts may run. Ordinary lifecycle private-profile
acceptance remains disabled even after experimental success; enabling it requires
its separate security/implementation admission, preserving the original PQ goal.

W3C/testbed deliverable: bounded local container↔canonical object mapping, negative
privacy/metadata-injection tests, genuine experimental proof integration in isolated
KYC scenarios, and an explicit unsupported-mappings table. Issuer/vocabulary binding,
DID method/key representation, securing mechanism and private status semantics
cannot be invented here. External W3C conformance and secure interoperable VC
claims require those product/specification decisions; local JSON success is not
completion of that part of the original programme. Durable holder storage and
production custody/entropy/erasure remain separate open implementation obligations.

## One prospective amendment, inactive

This is a **bounded attempt envelope**, not a sufficient-resource theorem. It must
be declined for the current uncorrected pin; it could accompany a decision to fund
G0 through G3 on the same named route. Complete counts must fit before large
allocation/proving. Observed WSL available3.868GiB supports neither borrowing the
physical16GB nor a request for8GiB proving. Stop if a credible complete fit fails.

| Resource | Single proposed allocation/amendment, preserving all prior usage |
| --- | --- |
| Time | At most7,200s for the entire milestone: reallocate2,000s of the eventual remaining implementation balance (only if that leaves the existing300s reserve), add5,200s to the cumulative4274s ceiling →9474s. Budget G0 relation/masking correction1200, acquisition/build900, lowering/count1800, validation1200, proof/measurement900, lifecycle/benchmark900, finalisation300. No success promised from these estimates. |
| Invocations |128 new allocated cases within a prospective cumulative ceiling1102 (1050+52); existing974 consumed preserved. The twelve proof cases and all reruns are included, not extra. |
| Builds | Reallocate the remaining3, keep ceiling13 and historical10. Every compiler/configuration attempt counts. |
| Memory | Proposed native/build1.5GiB, total worker+coordinator1.75GiB, tooling/audit256MiB, zero swap,2CPUs, one worker. Admit only with at least2GiB additional WSL headroom and bounded per-phase allocation model; this fits the *observed headroom envelope*, not yet the complete relation. No WSL/host reconfiguration. |
| Artifacts | Prospective3GiB additional isolated toolchain/dependency/build/proof/temporary artifact allowance, including downloads; cumulative cap old128MiB+3GiB. Only registered binary/archive artifacts up to256MiB/file; ordinary source/JSON/log remain1MiB; proof outputs have explicit16MiB role/cap. These are planning estimates, not measured build requirements. |
| Evidence | New12MiB shared package allowance; cumulative32→48MiB, reserve2MiB inside it. Historical metadata/logs remain evidence, not reclassified. Bound diagnostics at60KiB per job. |
| Work | Proposed cumulative work ceiling2^36 replacing2^32, retaining77,593,603 consumed; frontend, constraints, field/encoding/hash work across every trial charged. Pre-reserve each proof's complete conservative work bound; an unknown bound cannot be admitted. |
| Proofs | A new, separate maximum12 experimental attempts, conditional on all proof gates. Existing ledger2used/1unused is untouched and nontransferable. No recursion, zkVM or raw-view proving. |
| Timeouts / cleanup | Keep300s command/295s child and active storage stops; a predicted proof exceeding a child bound is not admitted. Preserve300s completion reserve. No service activation; remove only declared new temporary work after sealing, retain failures, sources, locks, overlays and final datasets. |

At present there are **no measured Binius build/proof times or whole-workload
sizes** to certify the envelope as sufficient. Unknown wrapper/constraint density,
GHASH work and witness-index growth can veto this proposal at G2. A failure to fit
must return a construction/resource NO-GO with exact dimensions, not another
component-optimisation promise or a silent memory increase.

## Security and completion criteria

The security target remains provisional as recorded in the assessment: lambda128
is a label, ML-DSA-65 is not a universal128-bit quantum guarantee, and lifetime
adversary resources/maximum advantage are not fully agreed. The current native96
query setting and GF(2^128)/SHA-256 defaults may only support a labelled engineering
profile; simply raising the query label cannot eliminate field/hash/reduction losses.

Required theorem work: map the corrected simultaneous inner/outer transcript to a
full HVZK simulator and commitment transform; derive finite algebraic/FRI/masking
losses; apply an actual adaptive/QROM Fiat–Shamir knowledge result with its exact
extractor/oracle premises, or supply the missing new argument. Retain adaptive
Delta_tail, component advantages at reduction budgets and concrete hash assumptions.
No source test closes these obligations. Blueprint §§6–7 is starting evidence,
not authority to replace manuscript security claims silently.

Completion within this proposed milestone means complete accepted/rejected predicate
correspondence, measured full count/live-resource model, any *actually admitted*
qualified private proof and separate verifier results, isolated lifecycle integration,
bounded transport checks and a separately labelled benchmark dataset. If G0 or G2
fails, only the corresponding engineering work is complete; private authentication
and the original programme remain incomplete. The 31 October target is retained,
with no evidence-based commitment to full delivery. Do not turn this conditional
runbook into a claim of current provisioning or proof readiness.
