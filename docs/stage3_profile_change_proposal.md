# Stage 3 concrete-profile change proposal

19 September 2026. **Proposal for review; no replacement profile is adopted.**
Recommend a bounded, local **RISC Zero v3.0.6 Succinct STARK experiment** to test
whether the existing hidden ML-DSA-65 credential predicate is practical without
BC-1's Boolean lowering. This is an engineering candidate, not a finding that its
privacy or quantum-security contract meets the manuscript. **None of the candidates
reviewed here presently establishes all required properties for this project.**
The principal RISC Zero gaps are its qualified zero-knowledge claim, lower published
soundness estimates and absence here of the specific Section VIII extraction and
simulation arguments. Passing the experiment would not close those gaps.

This package contains source inspection, arithmetic and documentation only. It does
not install dependencies, build candidates, generate proofs, repeat large gate
probes or activate a resource/profile change. The manuscript, production code,
active [suite manifest](../configs/suite.json), vectors and historical evidence are
preserved. SPEC-001–004 remain agreed. Only manuscript **Sections II–VIII** are
authoritative; the abstract, I and IX onwards supply no claims or timings here.
The PDF SHA-256 was rechecked as
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.

The [benchmark targets](benchmark_targets.md) are draft project proposals. The
[separate draft specification amendments](stage3_profile_spec_draft.md) make the
possible construction change reviewable without changing the active specification.
Primary-source pins, inspected-file hashes and a read-only host snapshot are in
[source-review data](data/stage3_profile_sources.json). Inspection is not an audit
of every source file or a claim that the builds are reproducible on this host.

## Decision baseline

Reuse the [feasibility review](stage3_feasibility_review.md) and its original JSON
records, without new large probes:

| Evidence | What it establishes; what remains open |
|---|---|
| Nine-case message-preparation pilot | All nine pass at 2,034,776 total gates, 413,709 ANDs and fingerprint `7778652f244202f6fda785104a5113964dc4172fccc6f39ec404a137d50a15b7`. This prepares the signed message; it does not verify the signature. |
| Hint-prefix audit | Reproduces 13,532,448 AND gates in the 32M-total-gate prefix. No demonstrated implementation error permits removing these under BC-1. Full hints and later verification stages were not reached. |
| Frozen authentication-size projection | 3,253,150,624 bytes if this prefix is included unchanged in complete CGen(auth). Exact inclusion in the complete compiler has not been proved: this is a conditional projection, not a measured complete proof or unconditional whole-circuit lower bound. |
| Overall implementation | Complete authentication compilation, privacy-preserving proofs and full BC-1 conformance remain unverified/unimplemented. Existing Stage 2 references do not constitute proofs. |
| Resources | The conditional 64M-gate/2 GiB proposal remains inactive. Ordinary/count/pilot controls are unchanged. |

Four distinct quantities drive the decision. **Circuit size** counts total/AND
gates under a particular lowering; a VM's cycles or an AIR's cells are different
units. **Proof encoding** determines transmitted bytes: the frozen authentication
format is P(g)=5,363,104+960*ceil(g/4). **Proving memory** includes traces, views,
commitments and simultaneous buffers; streaming can lower resident memory.
**Runtime** includes execution, hashing, commitments, repetitions, recursion and
I/O. Streaming does not change P(g), and a smaller proof does not imply a faster or
smaller-memory prover. A new lowering may reduce gates while requiring a new
compiler argument; a new proof system may reduce bytes while adding other work.

The [checked calculations](data/stage3_benchmark_target_calculations.json) confirm
the zero-AND floor of 5,363,104 bytes, the maximum of 21,344 ANDs under 10 MiB, and
the impossibility of 1 MiB with the frozen format. An informal factor-of-two
communication improvement does not resolve a conditional multi-gigabyte projection.

## Preserved relation and boundaries

The replacement must prove knowledge of one witness for one complete public
statement. Authentication uses the existing 5,329 bytes
`xH || Esch(m) || rid || sigma || siblings`, with lengths 32/1024/4/3309/960.
Reconstruct the holder hash, B and Mcred from that same witness; verify the issuer
signature privately, prove the zero leaf at that same certified rid under the
public root, and link disclosure to that same certified m. Enrolment uses the
existing 32-byte holder witness and full enrolment statement.

Keep ML-DSA-65, SHA3-384/SHAKE, depth 20, canonical byte encodings, external signature
contexts and the existing statement/credential semantics unless a later proposal
explicitly changes them. Bounded operations include RejNTTPoly≤1026 bytes,
RejBoundedPoly≤512 bytes where invoked, SampleInBall≤256 total bytes and signing
≤1024 attempts where invoked; no hidden retry after exhaustion. Verification-only
work does not close bounded keygen/signing/release obligations.

PubOK, StateAuth and disclosed policy checks stay with the public verifier.
Lifecycle services retain authenticated requests, holder approval, issuer trust,
expected context, trusted time, the final ordered current-state read and atomic
pending-context/expiry recheck and challenge consumption. Authenticity of a signed
old root does not make it current. SPEC-002 requires strict `now < texp` at the final
check. The proof binds **all of E(X)** even when some fields are only used publicly.
See [R-023–R-026](implementation_spec.md#complete-relation-and-check-placement).

A native verifier's unproved Boolean, disclosure of sigma or a trusted external
witness checker cannot replace private credential authenticity. A zkVM host may
provide bytes and hints only when their correctness is enforced by the proved
guest. A proof of a guest which merely accepts a host-supplied `true` is insufficient.

### Requirements-to-candidate map

“Implement” below means missing project integration, not demonstrated support by a
finished PQ-DID proof. A=optimised Boolean/MPC-in-the-head; B1=RISC Zero;
B2=Winterfell; B3=zkDilithium; C=LaZer credential redesign.

| Requirement and traceability | A | B1 / B2 | B3 / C |
|---|---|---|---|
| Issuer authenticity, R-023/024/032/044 | Implement full hidden bounded ML-DSA verifier in revised circuit; generic gzkbpp example does not supply it | B1: port verifier into proved guest. B2: implement exact AIR including FIPS hashes/decoding. Neither has this integration here | B3 verifies a changed Dilithium variant, publicly known message. C demo uses a different lattice credential/signing construction. Both change certification |
| Knowledge of certified holder opening, R-010/020/023 | Prove SHA3-384 opening linked to signature input | Implement same holder hash and B in guest/AIR, with quantum knowledge argument still required | Must add original binding or specify a replacement and prove its security |
| Same-attribute selective disclosure, R-006/007/024 | Canonical private 1024-byte block feeds both signature and projection | Same guest/AIR values must feed both; no host-provided independent commitments | C supports disclosure in its own scheme, not existing Esch/Mcred automatically; B3 demo alone insufficient |
| Same certified rid/non-revocation, R-024/029–031 | Private depth-20 SHA3 path, scanned index or reviewed alternative | B1 proved memory/index operations; B2 custom AIR constraints. Implement exact zero-leaf/domain/direction rules | Both need original SHA3 tree linkage or a separately reviewed revocation redesign |
| Parsing/bounds/rejection, R-004–009/032–037 | Revised lowering must preserve accepted language and checked arithmetic; changed BC-1 schedule is explicit | B1 checked integer implementation, caps and exact parsers; B2 range/byte/overflow constraints, including non-native arithmetic | Native demo arithmetic does not establish these semantics; new credential formats need new vectors |
| Complete X/context binding, R-016/024–028/037/040 | Include kind and complete canonical E(X) in revised transcript | Bind kind/profile/E(X) in guest journal or AIR public inputs; require expected programme/parameters | Add complete context to demo protocol; reject cross-profile/cross-instance substitutions |
| Enrolment and authentication, R-020/021/024 | Two relation implementations and distinct transcript kinds | Two reviewed images/AIRs; no “auth only” completion claim | New issuance/enrolment proof plus showing proof and lifecycle mapping |
| Confidentiality and qualified unlinkability, R-002/043/045–047/050/051 | Need QROM simulation for selected transcript and seeded tapes, and fresh randomness | B1 Succinct mode is the candidate, subject to documented qualifications. B2 lacks established required privacy in inspected implementation | B3 paper implementation lacks ZK. C needs complete leakage/length and QROM simulation review; lattice proof name alone is insufficient |

All routes require full-witness quantum extraction and simulation compatible with
fresh statements, the **actual** authorisation/revocation history and sequential
oracle model. None may add a public stable credential hash, holder binding, rid,
signature, private DID, witness-dependent profile ID or length. Qualified unlinkability
still permits public issuer/schema/policy/epoch/disclosures, honest authorities and
holders uncorrupted throughout; it does not extend to authority collusion or holder
compromise. Proof privacy does not conceal local proving time from an observing host;
any new remote timing/length leakage must be analysed or prevented.

## Candidates and primary evidence

These are a deliberately small set, not a comprehensive market survey. Source
versions were inspected on 19 September 2026. Licences below describe the main
repositories; a future build must inventory transitive licences and exact lockfiles.

| Candidate | Exact inspected revision | Maintenance observation |
|---|---|---|
| gzkbpp | `3d7739fb2e17cea60d2187a169c5e652cba34448` | Last commit 28 May 2019; MIT; research C++ implementation |
| RISC Zero | v3.0.6, `1cc70cf05033a79ebc90f07c679cb4bd1cd301b9` | Stable release 17 July 2026; repository activity August 2026; Apache-2.0/MIT |
| Winterfell | v0.13.1 source, `2f78ee9bf667a561bdfcdfa68668d0f9b18b8315` | Last commit 19 July 2025; MIT; README warns research/unaudited |
| zkDilithium | `a9dfe21bf967fbc4319ae18b74e6e9cdb0a7482a` | Last commit 18 December 2024; MIT; small research prototype |
| LaZer | `fc455c3b48bfe9e4b1e0607c74ae676c04020923` | Last commit 17 September 2026; MIT; current tree differs from paper reproduction pins |

The [provenance record](data/stage3_profile_sources.json) links repository metadata,
commit endpoints and every inspected source. Activity dates are observations, not
maintenance commitments or security endorsements.

### A — Revised Boolean lowering / published improved MPC-in-the-head

A reviewed new Boolean profile could replace scanned private hint writes with a
different constrained representation, use narrower range-proved arithmetic and
optimise common work. The accepted relation, hidden signature, SHA3/SHAKE, indexing
and Merkle verification remain expressible. These are proposals requiring proofs
of equivalence: the hint audit found no removable BC-1 implementation error.
Optimisation invalidates the current gate identity and BC-1 conformance claim; it
does not by itself change the frozen raw-view formula or its witness-size floor.

The [gzkbpp README](https://github.com/isec-tugraz/gzkbpp/blob/3d7739fb2e17cea60d2187a169c5e652cba34448/README.md)
offers generic ZKB++ machinery with a MiMC example and circuit adapter, using C++
and OpenSSL. It supplies none of this project's complete ML-DSA/hash/tree relation.
The inspected [driver](https://github.com/isec-tugraz/gzkbpp/blob/3d7739fb2e17cea60d2187a169c5e652cba34448/code/main.cpp)
sets three parties, 438 repetitions and 16-byte random-tape seed inputs;
[ZKBPP.cpp](https://github.com/isec-tugraz/gzkbpp/blob/3d7739fb2e17cea60d2187a169c5e652cba34448/code/ZKBPP.cpp)
hardcodes 32-byte SHA-256 hashes. Its
[proof structures](https://github.com/isec-tugraz/gzkbpp/blob/3d7739fb2e17cea60d2187a169c5e652cba34448/code/common.h)
are C++ memory structures, not our canonical portable transcript format. A robust
bounded decoder, full context binding and exact wire protocol would be new work.
No trusted setup or recursion is inherent to this route, but PRG/hash parameters
and transcript construction become security-critical dependencies.

The [ZKB++/Picnic paper, ePrint 2017/279](https://eprint.iacr.org/2017/279.pdf)
distinguishes a Fiat–Shamir ROM construction from an Unruh-transform QROM
construction. Its communication reductions use seeds and omitted/reconstructed
data. For a LowMC example, Table 1 reports a 195,458-byte Picnic proof/signature,
31.31 ms generation and 16.30 ms verification on an i7-4790/16 GB Ubuntu system.
That is a small block-cipher relation, not hidden ML-DSA-65 plus SHA3 and a tree.
The paper's concrete quantum cost assumptions need separate review; its QROM
result does not automatically certify this generic repository, our parameters or
Section VIII's extractor and simulator.

**Assessment:** fixed circuits can avoid witness-dependent shape/length leakage;
the selected commitment/PRG/transform still needs a quantum ZK and knowledge proof.
Do not inherit 128-bit security from 438 repetitions or 16-byte seeds, substitute
them into the current 480-round analysis, or assume ordinary Fiat–Shamir is covered
by the paper's different transform. Effort is high: complete optimised relation,
new compiler equivalence, transcript implementation and security derivation. Smallest
useful experiment would be a separately named, bounded hint-decoder alternative
with exhaustive boundary/mutation equivalence and independent AND accounting,
followed by protocol byte accounting. It would not establish full feasibility or
the 1 MiB target. Retain as a comparison route, not the recommended next package.

### B1 — RISC Zero v3.0.6, local Succinct STARK receipts

The pinned code provides a RISC-V execution proof and recursive STARK compression.
[`ProverOpts::succinct()`](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/zkvm/src/host/client/prove/opts.rs)
selects `ReceiptKind::Succinct` and `poseidon2`; **default options select Composite**.
Its [SuccinctReceipt](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/zkvm/src/receipt/succinct.rs)
contains a recursion STARK seal, claim, hash name, control ID, control inclusion
proof and verifier-parameter digest. This format is distinct from Groth16.
SHA3/SHAKE, ML-DSA decoding/arithmetic, hidden indexing and the depth-20 path can be
implemented inside a guest without changing credential bytes. No complete bounded
PQ-DID guest is supplied or built here; software hash/ML-DSA cost is unknown.

The [official security model, version 3.0](https://dev.risczero.com/api/security-model)
targets perfect ZK but says the mathematical argument is unwritten and engineering
changes remain. It warns about critical privacy use. Raw RISC-V receipts reveal
execution length; recursion is documented to remove that leakage. It lists ROM and
the Toy Problem conjecture, with 96-bit RISC-V and 99-bit recursion estimates.
It labels the STARK components quantum-safe, but the BN254 Groth16 wrapper is not.
The prover sees the witness, so proving must be local. These qualifications do not
establish this project's complete-view quantum simulation or target/history-preserving
extraction, and do not justify a 128-bit overall-security claim.

Select **only native Succinct receipts**, explicit `poseidon2`, fixed reviewed
verifier parameters/control root and a pinned image per kind. Disable development
mode at build and runtime; reject Fake, Composite, Groth16, guest failure and unresolved
assumptions. Invoke full
[`Receipt::verify_with_context`](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/zkvm/src/receipt.rs),
which checks the expected successful image/claim/journal, not just integrity of an
arbitrary claimed computation. Do not accept prover-selected parameters or image IDs.
All guest outputs, including metadata, must respect the public-leakage boundary.
The proposed wire format additionally prunes claims and omits segment-count statistics.
Length/timing tests can find leaks; they cannot prove ZK.

There is also a concrete metadata question beyond the documentation's recursion
claim. The pinned [compression routine](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/zkvm/src/host/server/prove/mod.rs)
lifts the first segment, joins additional segments and resolves assumptions when
present; the resulting control ID is public. **Inference from source:** merely
selecting Succinct does not by itself demonstrate witness-independent terminal
control metadata for our programme. Review control ID/path, seal length and pruned
claim format on matched-public-input witnesses. The draft requires a public,
witness-independent terminal metadata schedule; it has not been constructed or
validated. A leak must stop the privacy claim, not be hidden in benchmark statistics.

This mode requires no Groth16 ceremony, on-chain contract or remote proving service.
It still trusts the correctness of the pinned VM, recursion verifier and compiled
guest. Prover segmentation changes cost, not the requirement to prove every private
check. Security accounting must inventory the VM/recursion fields, FRI settings,
Poseidon2/SHA-256 commitments, claim/journal hashing and composition losses. The
source pin fixes these implementation choices; this review has **not validated
their complete quantum loss budget**. No parameter tuning or “more repetitions”
remedy is assumed available. The README's headline 98-bit claim is not substituted
for the component qualifications.

For reproducibility, the pinned [ZKP constants](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/zkp/src/lib.rs)
set 50 FRI queries, expansion factor 4, folding factor 16, terminal degree 256
and 1024 ZK cycles; supported segment exponents are 13–24. The query comment gives
a conjectured 97-bit target. These source/README/component estimates differ in
scope and do not add up to a reviewed 128-bit quantum guarantee. Keep the exact
constants fixed for the experiment; a new parameter set requires new analysis.
The inspected [BabyBear field](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/core/src/field/baby_bear.rs)
uses p=15*2^27+1 and a degree-four extension. These field sizes are inputs to the
soundness analysis, not stand-alone security levels.

The pinned [Cargo manifest](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/zkvm/Cargo.toml)
has local proving and optional CUDA support; its
[toolchain file](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/rust-toolchain.toml)
specifies Rust 1.97. A future build also needs its guest toolchain, native build
dependencies and a pinned dependency/artifact inventory; none is installed here.
Use CPU-only local proving for this WSL experiment; GPU acceleration is unverified.
The [official April 2023 datasheet](https://dev.risczero.com/datasheet.pdf), commit
`cd1a37e`, reports 256k loop cycles on an M1 CPU at 16.98 s, 1.87 GB and 247.7 kB.
This is old generic-loop evidence, not v3.0.6 Succinct proof performance, a recursion
budget or a prediction for ML-DSA. No matching complete-relation benchmark was found
in the inspected sources.

**Assessment:** substantial porting and security work, but the closest engineering
fit to preserving the credential and relation. The smallest informative package is
the bounded staged guest experiment below: enrolment first, then same-witness
credential preparation plus hidden ML-DSA verification. It measures costs before
full Merkle/authentication integration. The selected mode's security gaps remain
adoption blockers even if small proofs and correct execution are demonstrated.

### B2 — Winterfell 0.13.1, custom AIR

The [pinned README](https://github.com/facebook/winterfell/blob/2f78ee9bf667a561bdfcdfa68668d0f9b18b8315/README.md)
provides Rust STARK machinery, configurable fields/hashes, randomised AIR and
parallel proving. It explicitly warns that the implementation is not perfect ZK
and may leak secret inputs, and is unaudited research code. It reports 64 Lamport+
verifications at 123-bit settings: 0.2 s trace plus 1.2 s proving, 0.5 GB, 110 KB and
4.4 ms verification on an eight-core i9-9980KH/32 GB machine. That workload neither
verifies FIPS ML-DSA-65 nor establishes ZK for our private credential.

An AIR could constrain hidden ML-DSA, SHA3/SHAKE, private index selection and the
same-rid SHA3 path. All those constraints, canonical ranges, caps and joint binding
must be built. Proof-system Merkle trees do not supply the application's SHA3 tree
predicate. Plain integrity constraints do not repair secret leakage: masking,
boundary treatment, trace-length padding and a complete privacy proof are needed.
Trace length/options also require a public, witness-independent policy.

[`ProofOptions`](https://github.com/facebook/winterfell/blob/2f78ee9bf667a561bdfcdfa68668d0f9b18b8315/air/src/options.rs)
exposes queries, blowup, grinding, field extension and FRI choices. A displayed
conjectured security estimate is not a QROM extraction/simulation bound; quantum
hash/grinding costs and multi-proof composition need analysis. No project parameter
set is selected here. The native STARK format is transparent and needs no pairing
setup; adding recursion/compression would be another reviewed dependency, not an
automatic property. It needs a Rust toolchain and pinned crate set; parallelism
raises aggregate memory. **Effort very high** for exact AIR plus privacy/security
work. Smallest useful experiment is a private hash/opening AIR with proposed masking
and fixed trace length, reviewed against a simulator contract before secret use;
a fast unmasked proof would fail the privacy gate. Not preferred over the VM port.

### B3 — zkDilithium as a research comparator

The [repository](https://github.com/guruvamsi-policharla/zkdilithium/blob/a9dfe21bf967fbc4319ae18b74e6e9cdb0a7482a/README.md)
demonstrates knowledge of a signature on a **publicly known message**. Its
[Cargo manifest](https://github.com/guruvamsi-policharla/zkdilithium/blob/a9dfe21bf967fbc4319ae18b74e6e9cdb0a7482a/Cargo.toml)
uses `bwesterb/winterfell` branch `f23`, not the reviewed upstream Winterfell pin;
no Cargo.lock was present in the inspected tree. That dependency must be pinned
before any reproduction. The Python specification's stated ≤3.9 dependency limit
also differs from the project's existing Python 3.14 environment.

The [primary paper, ePrint 2023/414, §§3.4/4](https://eprint.iacr.org/2023/414.pdf)
changes Dilithium2: Poseidon replaces SHA3, public keys are uncompressed so hints
disappear, and challenge sampling changes. Its measured zk20 variant also changes
the modulus. It reports 85–175 KB, 0.3–5 s proving and 20–30 ms verification at
115 conjectured bits on a single-thread 2.4 GHz i9/16 GB MacBook Pro. Crucially,
§4 says the implementation lacks zero-knowledge; anticipated ZK overhead is not
measured. Its abstract proof requirements do not establish the project's complete
QROM history-preserving extraction or simulation for this code.

**Assessment:** incompatible with the preferred ML-DSA-65/SHA3 preservation and
currently fails the required implementation privacy gate. The STARK proof format
uses no pairing setup, but inherits the fork's field/FRI/transcript and leakage
questions. Hidden message certification, original SHA3 binding, canonical schema,
private rid/path, context and enrolment are missing. Effort is a major protocol and
AIR redesign, not a drop-in signature verifier. Smallest useful experiment would
first pin the fork and establish a fixed-length ZK hidden-message mode; running the
existing public-message integrity example would not resolve our main uncertainty.

### C — LaZer anonymous-credential redesign

The [current README](https://github.com/lazer-crypto/lazer/blob/fc455c3b48bfe9e4b1e0607c74ae676c04020923/README.md)
documents C/Python lattice proof and anonymous-credential examples. Its documented
build requires Linux x86-64, AVX-512 and AES, GCC≥13.2, CMake≥3.26, Sage≥10.2,
Python≥3.10/dev/CFFI and other native dependencies. This WSL CPU exposes AES/AVX2
but **not AVX-512F/BW/VL**. The documented current build is therefore not eligible
on this host. Some older/subset paths may have weaker ISA requirements; portability
would need a separate audited selection, not an assumption that the full tree works.
The README pins paper reproduction to `10eafeca4cd53ff4fc54193dce904dbd0026fefd`,
distinct from the current source reviewed here.

The [anonymous-credential code](https://github.com/lazer-crypto/lazer/blob/fc455c3b48bfe9e4b1e0607c74ae676c04020923/python/anon_cred/anon_cred.py)
uses Falcon key/preimage-sampling operations and its own blinded issuance/showing
protocol, not FIPS ML-DSA-65 certification. Its
[showing parameter input](https://github.com/lazer-crypto/lazer/blob/fc455c3b48bfe9e4b1e0607c74ae676c04020923/python/anon_cred/anon_cred_p2_params.py)
specifies degree 64, modulus 12289, dimensions (8,48), partitioned norm and binary
constraints. Those are demo relation parameters, not a complete quantum-security
account for a PQ-DID replacement. Public parameter/seed generation, rejection
sampling, accepted norm bounds and proof encoding must be fixed for a new scheme.

The [LaZer paper, ePrint 2024/1846](https://eprint.iacr.org/2024/1846.pdf)
describes linear-size lattice ZK and LaBRADOR-based succinct proofs. Table 1's
credential example reports a 29 KB credential, 0.117 s issuance and 0.198 s showing;
the authors warn that implementations/hardware differ, including AVX-512. Table 2's
smaller aggregate-signature proofs concern another workload. These are not proofs
of the full PQ-DID relation. The paper's credential assumptions include module-LWE
and a module-ISIS variant; the actual instantiated proof, estimator inputs and
quantum reduction losses require review.

**Assessment:** the most disruptive fallback. Existing algebraic lattice proofs
do not directly supply hidden standard ML-DSA/SHA3 verification or a private SHA3
Merkle path. Keep the tree only by adding its proved constraints, or separately
redesign revocation; do not silently disclose rid or change hash functions. Native
linear ZK showing is the initial candidate mode, not an assumption that every
succinct/aggregate mode is ZK. Fix witness-independent dimensions/encoding lengths
and analyse rejection/time leakage, quantum extraction, simulation and public
parameter trust; there is no reviewed mapping to Section VIII here. No Groth16 or
pairing setup is inherent, but new lattice assumptions and generated parameters are.
Effort is very high across issuance, credential bytes, enrolment, showing, revocation
and all security/comparison claims. Smallest experiment starts with an ISA-compatible,
pinned showing implementation and a mathematical same-holder/same-rid extension;
this host's current documented build prerequisite fails before that experiment.

## Preferred route and security-impact map

Proposed identity: **`PQDID-R0S-EXP1`**, a non-production proof-profile ID, separate
from the frozen credential suite. Preserve signed credential-suite bytes; never
rename them in place. A later acceptance decision must explicitly authorise this
suite/proof-profile separation. Enrolment and authentication have separate pinned
guest images. No profile registry entry, image ID or new dependency is installed by
this proposal. The exact draft journal, raw proof and presentation encodings are
in [the separate amendments](stage3_profile_spec_draft.md).

| Component | Proposed change / retained reference |
|---|---|
| Private predicate execution | Replace BC-1 CGen/auth/enrol lowering **for the new profile only** with checked guest programmes; prove signature verification and all other private checks inside them |
| Proof construction/check | Replace raw shares/tapes, 480 repetitions, commitments, trit challenge and view checks with pinned VM+recursion proving and strict Succinct verification |
| Public binding/wire | New profile/kind/image/verifier-parameter binding, deterministic public journal and bounded raw receipt envelope; retain full E(X), D/mD and existing request/state semantics |
| Credential/hash/tree | Preserve ML-DSA-65, SHA3-384, SHAKE, Mcred, contexts, 1024-byte attributes, 4-byte bounded rid, 20×48-byte path; VM proof-internal hashes add separate assumptions |
| Admission | Replace gate/view-count admission with explicit programme/version, byte/cycle/segment/memory admission; distinguish programme rejection from resource abort |
| Stage 2/lifecycle | Existing reference modules remain differential oracles; public checks and service order remain mandatory and separately implemented |

Reusable code/reference evidence: [relations](../src/pqdid/relations.py),
[bounded ML-DSA](../src/pqdid/bounded_mldsa.py),
[credentials](../src/pqdid/credentials.py), [binding](../src/pqdid/binding.py),
[Merkle](../src/pqdid/merkle.py), codecs/schema/parameters/statements/witnesses and
public policy/expiry checks. Reuse fixtures for
[relations](../tests/fixtures/relations_vectors.json),
[native ML-DSA](../tests/fixtures/mldsa65_native_vectors.json),
[credentials](../tests/fixtures/credentials_vectors.json),
[binding/Merkle](../tests/fixtures/binding_merkle_vectors.json) and
[FIPS 202](../tests/fixtures/fips202_circuit_vectors.json) as semantic byte oracles.
[Scalar vectors](../tests/fixtures/bc1_scalar_vectors.json) remain useful for integer
results/rejection; BC-1 trace identities are historical evidence for that profile,
not expected zkVM outputs. Generate new image/claim/receipt vectors only after the
port exists; a seeded test RNG must never become operational proof randomness.

Required validation includes native/reference/guest agreement on both complete
relations, exact FIPS contexts and caps; checked overflow/narrowing and malformed
private/public encodings; changed holder/message/signature/rid and cross-credential
splices; revoked/wrong-root paths; invalid disclosure/policy; context mutations for
every E(X) field; wrong kind/image/control root/hash suite/claim/journal; noncanonical,
oversized, truncated, trailing and mutated receipt bytes; Fake/Composite/Groth16 and
conditional claims; panic/failure/cycle exhaustion; unexpected output/log leakage;
fresh proof randomness and same-public-statement different-witness length checks.
Later integration must test current-state changes, expiry boundaries and concurrent
atomic replay rejection. Successful differential tests establish behaviour on
vectors, not compiler correctness, ZK, quantum security or history-preserving extraction.

### Manuscript and security obligations

| Section | Reusable contract / required change |
|---|---|
| II related work | Retain distinctions about certification, revocation and qualified privacy. Update concrete-proof comparison after evidence; no new performance claim from excluded IX+ |
| III building blocks/roles | Preserve roles, public leakage, honest-authority and corruption assumptions. Replace the concrete proof primitive's instantiation and state its additional hashes/VM assumptions |
| IV lifecycle construction | Preserve Issue/Auth/Verify, request approval, public checks, state reads and atomic expiry/consumption. Explicitly identify profile selection and how it is bound |
| V PQ-DAA relation/interfaces | Preserve BindRep/BindOpen/CredValid/NRVerify and same-witness semantics. Reinstantiate Prove/Check for both kinds and define programme identity/admission |
| VI security model | Retain freshness/actual-history games, full-witness target-preserving extraction and adaptive/historical privacy requirements. Prove the new primitive meets them; a trace-integrity proof is insufficient |
| VII concrete instantiation | Retain application bytes/primitives and SPEC-001/002. New appendix/profile replaces BC-1 and raw-view transcript/size/admission for this ID; SPEC-003/004 remain conventions for the original profile |
| VIII concrete analysis | Rework completeness, proof cost and primitive loss bounds. Retain conditional certification/binding/tree/service reasoning only where assumptions/interfaces remain identical; new backend is not covered by the old concrete theorems |

More precisely, VIII-A's bounded-operation event accounting can be reused as a
**conditional framework** if every call/cap is preserved; the signing-tail issue
DEP-001 and quantitative loss validation remain unresolved. VM execution/recursion
and resource-failure probabilities/costs are new terms. VIII-B's credential binding
and same-identifier non-revocation reasoning can use unchanged signature/hash/tree
assumptions once exact guest equivalence is justified. Tests cannot supply those
assumptions or a complete reduction.

VIII-C **Theorem 6** requires a new quantum extractor recovering the full credential
witness for a fresh target statement while preserving the actual history. VM
execution integrity or an informal knowledge claim is not that theorem.
VIII-D **Theorem 7** needs a new online complete-view simulator, including receipts,
randomness, metadata and any length leakage. Theorems **8–9** require that simulator
for the existing adaptive/historical games and all continuation queries. None is
established by this proposal. The concrete expressions
`p*=(2/3)^480+2^-544`, `epsilon_ex(Q)` and `delta_ZK(N,Q)` cannot be reused for STARK
receipts. No substitution of a vendor “bits” number into them is justified.

VIII-E **Theorems 10–11** can retain their service-order/authenticity composition
structure and unchanged service-key obligations, conditional on replacing the
primitive's extraction/simulation terms by justified new bounds. Immutable history,
post-presentation revocation/public updates, no forbidden corruption, no hidden-index
service queries and final freshness checks remain essential. Whole-system quantum
security depends on proof hashes/FRI/conjectures, ML-DSA, application hashes and
services; ML-DSA-65 alone cannot establish it. The active profile's own complete
BC-1 and security validation remains open; the proposal does not retrospectively
certify it.

### Persistent-key ML-DSA baseline

Keep the persistent-key ML-DSA-65 authentication baseline on the same host, native
backend version, context/network/freshness model and bounded-release policy, with
matching warm/cold and concurrency boundaries. Report its linkable public-key
semantics explicitly. Separate issuance/key setup amortisation, proof generation,
verification, service costs and bytes. Preserving the credential signature in B1
helps isolate the added anonymous-proof work, but programme/runtime and differing
public checks still need attribution; the systems provide different privacy.

For zkDilithium or LaZer, changing signatures, hashes, key sizes or issuance means
the measured difference includes those changes. It could no longer be attributed
solely to anonymous authentication. Retain the original persistent-key ML-DSA row
and add a matched-signature baseline if evaluating that redesign. Do not relabel a
modified Dilithium2/Falcon-style credential as ML-DSA-65.

## Next bounded work package

**Recommended after review: R0-SUCCINCT-FEASIBILITY-1.** Its question is whether a
local pinned recursive STARK can prove original same-witness credential verification
within a small controlled envelope. It does not attempt full authentication, service
integration, a new security theorem or acceptance benchmarking.

1. Review the draft changes and security exclusions first. In an isolated experimental
   directory, inventory/pin v3.0.6, guest toolchain, lockfile, licence/dependency hashes,
   CPU-only features, `disable-dev-mode`, recursion/control parameters and source/image
   identity. Authorise installation/build separately; preserve existing Python/native
   environment. No Bonsai/remote prover or Groth16 conversion. If prerequisites do not
   fit the approved envelope, stop with a dependency/resource finding.
2. Port the complete private enrolment predicate into a fixed guest using existing
   encodings and checked semantics. Compare all existing enrolment fixture outcomes
   with the Python reference. Generate at most one valid Succinct receipt initially;
   reject altered statement/image/claim and disallowed receipt kinds. This checks the
   genuine local recursion path and public binding before heavier work.
3. Port the bounded private credential-preparation + ML-DSA-65 verification fragment:
   original xH/m/rid/sigma, reconstructed B/Mcred, issuer key/context from E(X), full
   decoding/hints/norms/hashes/arithmetic/sampler bounds. Differentially execute valid,
   tampered-signature/message/holder/rid, malformed-padding and cap-boundary cases.
   Pure helpers may use synthetic exhaustion streams for unit checks; the proved
   guest uses real SHAKE and no host success oracle. Record cycle counts by stage.
4. Only if reference agreement and resource admission pass, generate at most two
   valid fragment Succinct receipts using fresh randomness; verify and mutate them.
   Prefer two valid synthetic witnesses with the same public X, constructed in a
   new experimental fixture file while retaining existing vectors. If such a pair
   is unavailable, record the matched-witness metadata test as incomplete rather
   than claiming it passed. Compare control IDs/paths and seal/envelope lengths.
   This is **not full authentication**: Merkle/disclosure composition and complete
   public/lifecycle integration still need later packages. A separately named fragment
   image/journal prevents presenting it as `auth` success under the draft profile.
5. Report stage cycles, segmentation, bytes of seal/raw envelope/encoded presentation,
   CPU/wall time, process-tree RSS/cgroup peak, rejection outcomes, public metadata and
   fixed-X witness-length observations. Stop after the feasibility report; do not
   escalate to complete authentication merely because the fragment succeeds.

Proposed future limits, **all inactive now**:

| Phase | Proposed hard envelope and admission |
|---|---|
| Build/preparation | One build at a time, at most 2 build jobs, 2 GiB process-tree/cgroup memory, 20 minutes total wall, 10 GiB ordinary-disk artefacts including toolchain/download cache. Check physical host storage as well as WSL space; no build in RAM-backed /tmp. Stop if dependency/compiler needs exceed this. |
| Guest execution/proving | One worker, at most 2 CPU threads, no GPU, **2 GiB aggregate worker memory**, no swap, 600 s wall per proved case and 30 minutes total execution/proving package wall; maximum 3 proof-generation attempts total (one enrolment, two fragment). Failed attempts consume the same three-attempt budget; no hidden retries. |
| Cycle/segment limits | Initial segment size 2^16 cycles and session cap 2^22 cycles; pin the corresponding compatible control parameters. Validate option support before execution. Cap exhaustion is an incomplete/resource result; no automatic increase. Pure software SHA3 first; introducing a specialised coprocessor requires explicit semantic/security review. |
| Verification | Sequential, ≤1 GiB aggregate memory, ≤10 s per case; malformed-input corpus capped at 100 cases and 60 s aggregate. Proof bytes ≤10 MiB, complete application presentation ≤12 MiB; reject before unbounded allocation. |
| Host/artifacts | Require at least worker allowance +2 GiB MemAvailable immediately before each phase. Enforce cgroup memory/timeout limits; if unavailable, stop to design equivalent controls before proving. Keep experiment output ≤256 MiB within the 10 GiB disk budget; diagnostics contain synthetic data only. |

At the inspected 4.82 GiB available-memory snapshot, the proposed 2 GiB worker plus
2 GiB reserve fits arithmetically; this is not a future availability guarantee.
Recursion may exceed even this limit. Do not reduce proof security or switch to
Composite/Groth16 to make it fit. A 600 s exploratory timeout is a **resource stop**,
not relaxation of the proposed 30 s generation target. Three proofs cannot establish
p95; report observations, not benchmark acceptance.

**Pass for engineering feasibility:** exact differential outcomes; genuine locally
verified Succinct enrolment and credential-fragment receipts; wrong public binding,
mode and tampering rejected; no extra public witness material; all enforced resource
limits honoured and complete artefact identities recorded. **Fail/block:** any
incorrect acceptance, omitted private check, dependency/memory/cycle/time/size limit
exceeded, unsupported enforcing controls, or need for a prohibited receipt mode.
Record the exact stop and completed scope. Execution success without a completed
Succinct receipt is partial, not a pass. Even a pass leaves complete authentication,
128-bit/QROM accounting, ZK proof and actual-history extraction/simulation unresolved.

## Review decisions and retained obligations

Review (1) whether this qualified engineering experiment is useful while security
adoption is blocked; (2) the separate proof-profile identity, guest/receipt encoding
and replacement of BC-1 for that profile only; (3) draft benchmark/network/lifetime
proposals; and (4) the future installation/build/execution envelope. Review must not
be recorded as agreement to weaker privacy or quantum security. A final production
profile requires an explicit resolved security contract, exact release/parameter
validation and full relation/lifecycle evidence.

Stage 2 bounded key generation/signing, verification before every release, revocation
and update services/integration remain open, including DEP-001/002. Stage 3 original
full hints/signature/preparation, complete authentication, proofs and full BC-1
conformance remain open. Enrolment/reference successes do not close those items.
This proposal ends at documentation and source review; replacement work awaits review.

## Validation of this package

The [documentation/data check record](data/stage3_profile_proposal_checks.json)
records local links/anchors, table shapes, JSON parsing, independent formula/encoding
arithmetic, source-cache hash checks and preservation of pre-existing files except
the explicitly updated status/traceability/issue-register documents. The selected
PDF digest is unchanged. Existing **119 focused / 1432 regression** passing tests
and Ruff evidence from the feasibility package are reused; no implementation test
rerun or new candidate proof is represented by these documentation checks.
