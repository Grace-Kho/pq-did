# R0-SUCCINCT-FEASIBILITY-1 — build passed; execution cycle stop

19 September 2026 (Asia/Singapore; raw logs use UTC). **Both experimental guests
built, but the first CredValid guest execution exhausted the authorised 2^22 user-cycle
session limit. Execution and proving stopped. Zero top-level proof attempts were
launched; no receipt was generated.** No budget increase or unchanged retry followed.
This is a result for this port and envelope, not an impossibility result for RISC Zero
or other hardware.

The user authorised this isolated engineering experiment following the
[proposal](stage3_profile_change_proposal.md). The active PQ-DID suite, manuscript,
SPEC-001–004, [draft profile](stage3_profile_spec_draft.md) and provisional
[benchmark targets](benchmark_targets.md) remain unchanged. The former 64M-gate/
2 GiB BC-1 proposal remains inactive. zkVM user cycles are not BC-1 gates.

## Outcome classification

| Question | Observed outcome |
|---|---|
| Build and execution feasibility | Host and both guests compile. One enrolment execution completes. CredValid execution stops at the hard cycle limit |
| Agreement with selected reference relations | All 29 relation cases and six separate signature-context cases match the unchanged Python reference when the Rust port runs natively. One guest enrolment comparison passes; CredValid is incomplete and the remaining 27 guest cases are unrun |
| Real succinct generation and verification | Not reached: the execution gate failed. **0/3 proof launches**, no real receipt or fresh-process receipt verification |
| Performance within this envelope | Build/setup completes within 1200 s cumulative subprocess wall and disk/memory limits. CredValid fails the 4194304-user-cycle admission limit. No proving, recursion, verification or end-to-end performance result |
| Manuscript privacy/quantum suitability | Unestablished. No profile adoption, security equivalence, Section VIII closure or zero-knowledge theorem follows |

The definitive records are the [run ledger](../experiments/r0_succinct_feasibility_1/evidence/run_ledger.json),
[execution results](../experiments/r0_succinct_feasibility_1/evidence/guest_comparisons.json),
[resource-stop marker](../experiments/r0_succinct_feasibility_1/evidence/STOP.json) and
[source/build manifest](../experiments/r0_succinct_feasibility_1/evidence/manifest.json).
The launcher refuses further build/execution/proving while this stop marker exists.
It is retained as evidence, not an invitation to remove it and resume this package.

## Contract and implemented checks

The [contract](../experiments/r0_succinct_feasibility_1/CONTRACT.md) was recorded before
implementation, with operational clarifications before execution. Review used the
implementation specification, parameter manifest, status and reference modules.
Only manuscript Sections II–VIII are authoritative. The selected PDF still hashes to
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.

One discrepancy was resolved explicitly: the proposal described an authentication
fragment reconstructing B. The requested standalone `cred_valid` contract accepts a
full Credential with an independent certificate binding, repeated attributes, rid,
empty auxiliary field and metadata. The guest therefore parses that complete private
credential and rejects inconsistent copies, rather than replacing this check with a
reconstructed binding. This is a complete port of the selected predicate, not Rauth.

The shared [relation implementation](../experiments/r0_succinct_feasibility_1/relation/src/lib.rs)
implements canonical uint32-BE length framing, exact arities/no trailing bytes,
schema/name/type/capacity/index checks, repeated-schema agreement, exact key and
namespace widths, canonical 1024-byte attributes, expected-instance binding,
SHA3-384 holder opening and bounded identifiers.

The enrolment guest implements `relations.enrol(expected_pp, statement, witness)`:
it validates every statement field and checks the private 32-byte holder secret
against the public binding and approved attributes. The state signature is checked
structurally, as in that reference predicate. Cryptographic StateAuth, controller
checks, issuance approval and currentness remain surrounding obligations. A native
case with an invalid state signature deliberately accepts, preserving this boundary.

The CredValid guest additionally builds the exact existing Mcred from the same
metadata/B/rid and invokes the [bounded ML-DSA-65 port](../experiments/r0_succinct_feasibility_1/relation/src/mldsa.rs).
It implements FIPS response/hint decoding, all 30 matrix expansions, NTT/inverse NTT,
UseHint, strict response norm and challenge comparison, using real software SHAKE.
Pure signing context processing is `0 || len(ctx) || ctx || Mcred` with
`PQ-DID/credential/v1`. No host verification Boolean, precomputed private challenge,
or unchecked cryptographic result is consumed by either guest.

RejNTTPoly counts every accepted/rejected triple and fails before reading beyond
1026 bytes. SampleInBall counts its eight sign bytes and every accepted/rejected
index, failing before byte 257. Tests exercise exact-cap success and exhaustion of
the actual implementation. Instrumentation exists only in native `#[cfg(test)]`
tests, outside the measured guest images.

Rust signed arithmetic uses explicit Euclidean residues/division for positive
moduli and checked absolute value; values are bounded before arithmetic. Release
profiles enable overflow checks. Tests cover negative residues, floor division,
`i64::MIN`, decomposition boundaries and NTT/inverse round trips. This evidence does
not establish BC-1 gate-order conformance: the active SPEC-003/004 lowering is preserved
separately. The experimental port is not a production constant-time library.

## Public input, private input and verifier policy

Both programmes read runtime length-prefixed inputs; no fixture secret is compiled
into them. The diagnostic profile is `PQDID-R0S-DIAG1`, with distinct `enrol` and
`cred-valid` operations. Using the existing LP/uint32-BE record convention:

```text
public = enc_r0-statement(profile, operation, E(expected_pp), context32, payload)
journal = enc_r0-result(profile, operation, public)
```

| Guest | Public payload | Private runtime input |
|---|---|---|
| enrol | Exact E(enrolment statement), including that relation's required public attributes/B/rid/state/nonce | 32-byte holder secret |
| cred-valid | E(expected instance metadata) | `enc_r0-credential-witness(E(full Credential), holder_secret)` |

The fixed synthetic 32-byte public context is consistently journal-bound. It is not
a full authentication context, trusted freshness source or replay defence. A changed,
well-formed context can still satisfy CredValid; a receipt for the old context must
fail verification against the new expected public record.

The [host/verifier](../experiments/r0_succinct_feasibility_1/host/src/main.rs) registers
locally built programme IDs and the pinned verifier parameters. It accepts only
Succinct, poseidon2, pruned claims and the pinned eight-level control path, then
checks the exact expected journal and calls **`Receipt::verify_with_context`** with
the trusted image ID and development mode disabled. This complete SDK API binds the
seal to `ReceiptClaim::ok(image, journal)`, including successful `Halted(0)` execution
and empty assumptions. It is not an integrity-only acceptance path. Registry values
must be trusted local configuration; accepting a claimant-supplied registry is invalid.

The diagnostic saved-receipt container uses bincode 1.3.3 fixed-width little-endian
encoding, a 10 MiB input limit, trailing-byte rejection and re-encoding equality.
This is an experiment-local SDK container, **not the proposed final presentation
adapter**. The draft format remains provisional. Native rejection checks passed for
synthetic Fake, Composite and Groth16 variants and six malformed containers; no fake
proof generation/development mode was used. Groth16 verification types are transitive
SDK dependencies, but Groth16 proving/compression is neither selected nor accepted.

The fresh-process verifier command refuses to run if either experimental private
fixtures or original project fixtures are readable. A real namespace probe confirmed
both directories were inaccessible, TCP loopback worked, and an external connection
failed with `ENETUNREACH`. The planned verifier accepts only the public record,
saved receipt and locally registered identity. **Actual saved-receipt verification,
seal/journal/image/statement/operation/context mutation tests and conditional-claim
rejection against a real receipt were not reached.** Their implementation/source
review is not reported as a passing receipt test.

## Pins, provenance and advisory review

All tools, caches, Rust manifests/locks, guests, synthetic fixtures, build products
and evidence live in [the isolated workspace](../experiments/r0_succinct_feasibility_1/).
The existing Python environment is used only for reference fixtures/check tooling.
No global defaults, production dependencies or GPU drivers were changed. The final
manifest confirms `~/.cargo`, `~/.rustup`, `~/.risc0` and `~/.rzup` remain absent.

| Component | Actual pinned/used value |
|---|---|
| SDK / local CPU `r0vm` / cargo-risczero | **3.0.6**; release source commit `1cc70cf05033a79ebc90f07c679cb4bd1cd301b9` |
| Custom compiler distribution | RISC Zero `r0.1.97.0`; rustc `1.97.0-dev`, commit `e638c6cfea1eff5fbbb24a27e60538e3760d21b8`; LLVM 22.1.6 |
| Cargo / rustup | cargo `1.97.0-dev (c980f4866 2026-06-30)`; rustup 1.28.2; isolated linked toolchain `risc0` |
| Guest platform / compatibility kernel | `risc0-zkvm-platform` **2.2.3**, `risc0-zkos-v1compat` **2.2.3** |
| Circuit crates | rv32im **4.0.5**, recursion **4.0.5**, keccak **4.0.6** |
| Core/format/proof crates | core 3.0.2; binfmt/zkp 3.0.5; build 3.0.6 |
| Software hashes | sha3 0.10.8, keccak 0.1.6; host sha2 0.10.9 |
| Execution target | `riscv32im-risc0-zkvm-elf`, WSL2 x86_64 Linux |

[Downloaded asset evidence](../experiments/r0_succinct_feasibility_1/evidence/install_assets.json)
records upstream URLs, sizes and matched SHA-256 release digests for the SDK bundle,
compiler and rustup installer. [Source evidence](../experiments/r0_succinct_feasibility_1/evidence/source_fetch.json)
pins release/commit/advisory/API records. These verify download integrity against
upstream metadata; they are not an independent reproducible-build attestation.
The compiler's successful build and initial execution are compatibility evidence,
not a formal compatibility/security certification.

The prebuilt prover embeds its recursion programmes. The recursion crate's pinned
build manifest names SHA-256
`744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849`
for `recursion_zkr.zip`. No recursion programme was exercised or independently
extracted from the binary in this stopped run. The manifest records the actual
prover/kernel/programme hashes and verifier control root rather than claiming an
independent attestation of those embedded artefacts.

The [dependency audit](../experiments/r0_succinct_feasibility_1/evidence/dependency_audit.json)
and [range review](../experiments/r0_succinct_feasibility_1/evidence/dependency_review.json)
use RustSec database commit `2b34578f89884736e0fcbd42f7ba8d6b10b4a0ce` and check cached
crate SHA-256 values against the locks. Host and guest dependency trees are retained.
The review explicitly includes transitive guest packages.

- The critical [sys_read advisory](https://github.com/risc0/risc0/security/advisories/GHSA-jqq4-c7wq-36h7)
  is addressed by SDK 3.0.6 and platform/kernel 2.2.3; an SDK pin alone would not
  establish the guest fix. The older division, RV32IM underconstraint, malicious
  syscall and instruction-mode advisories do not affect these selected versions.
- Host `anyhow` was corrected from 1.0.100 to **1.0.104** after reviewing
  [RUSTSEC-2026-0190](https://rustsec.org/advisories/RUSTSEC-2026-0190.html).
  Guest resolution already used 1.0.104. The SDK version was not substituted.
- Remaining experimental-lock findings include unmaintained bincode/derivative/paste.
  `tracing-subscriber` 0.2.25 carries the ANSI-log-injection advisory; its selected
  ark-relations dependency disables default features and does not enable the fmt
  writer. No tracing subscriber is installed by these guests. `rsa` 0.9.10 carries
  the timing/key-recovery advisory in the host build dependency chain through rzup;
  the experiment performs no RSA private-key operation. These are scoped call/feature
  observations, not blanket vulnerability clearance.
- The upstream SDK workspace lock has additional affected version ranges, listed in
  [the complete findings](../experiments/r0_succinct_feasibility_1/evidence/affected_dependency_versions.txt),
  including old anyhow, bytes, rand, keccak, tracing and other dependencies. That
  workspace lock over-approximates a prebuilt binary's dependencies; an attested
  per-binary SBOM and complete reachability review were not obtained. These findings
  remain qualifications on the pinned prebuilt tools; the local/isolated synthetic
  run is not a deployment-security approval.
- The all-version [zero-knowledge qualifications](https://github.com/risc0/risc0/security/advisories/GHSA-5xgj-pmjj-gw49)
  remain unresolved. The [upstream security model](https://dev.risczero.com/api/security-model)
  and prior proposal's concrete security accounting are not equivalent to the
  manuscript's Section VIII claims or the ML-DSA baseline.

## Identities and build recipe

The manifest's source/manifest inventory digest is
`cbd6c003b70589460c95213e23704f10bcd9ceda17460e573eb5380c518616a9`.
This workspace has no Git repository; the inventory is the local source revision
identifier. Host lock SHA-256 is
`86e6f8da9f984bb1d8c4494d6841a79a89f7a370bd7ee703e6dbbb88b1d6ce37`;
guest lock SHA-256 is
`6110756e650b8ffced46825ff3633eb4997e9def020fdef1435419ed0b1459f8`.

| Guest | Registered image ID |
|---|---|
| enrol | `66e4c8e0c468edaea2bbef55ac470fab92de3c59e8c0f352905b8a741bac160c` |
| cred-valid | `6bc26dc2988e528e155085ca960c558787e2be1c1bd0e880205cffeca1498c71` |

Verifier-parameter digest:
`ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013`.
Control root:
`a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56`.
The [public registry](../experiments/r0_succinct_feasibility_1/fixtures/public/registry.json)
also records programme paths and SHA-256 values. SDK 3 programme binaries package
the user ELF with the pinned V1Compat kernel; raw ELF alone is insufficient.

The final build used one job, opt-level 3, thin LTO, one codegen unit and overflow
checks. Guest flags reproduce the pinned risc0-build target settings:

```text
-C passes=lower-atomic -C link-arg=-Ttext=0x00200800
-C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"
```

The retained scripts and ledger provide exact historical commands. From the project
root, the decisive commands were:

```bash
.venv/bin/python experiments/r0_succinct_feasibility_1/scripts/prepare_fixtures.py
python3 experiments/r0_succinct_feasibility_1/scripts/run_limited.py \
  --seconds 600 build package-guests -- /bin/bash scripts/build.sh
python3 experiments/r0_succinct_feasibility_1/scripts/run_limited.py \
  --seconds 60 execute guest-reference-comparison -- \
  target/release/pqdid-r0-host execute-check
```

The fixture generator was run under a separate 60 s/256 MiB address-space bound;
ordinary local ML-DSA signing generated only two synthetic context fixtures. This
is not bounded protocol key generation/signing. It reuses retained fixture bytes
on a later invocation. The isolated installer validates explicit CARGO_HOME and
RUSTUP_HOME, sets no global default, and uses `--no-modify-path`. Setup/fetch scripts,
asset URLs/checksums and all failed/corrected invocation logs are retained.

For a separately authorised reproduction, use a new evidence directory/package and
retain these locks. The present ledger/run names and STOP marker deliberately block
replay in place. The planned, **unrun** guarded commands would have used phase `prove`
with 600 s/2 GiB and `prove enrol-alpha-42 receipts/enrol.bin`, followed by phase
`verify` with 10 s/1 GiB and `verify enrol fixtures/public/enrol-alpha-42.bin
receipts/enrol.bin`. They are documented API examples, not executed proof results or
authorisation to bypass the stop.

## Resource enforcement and observations

The [launcher](../experiments/r0_succinct_feasibility_1/scripts/run_limited.py) uses
systemd user transient services and a persistent serial lock/attempt ledger. Proof
launches would be counted before spawning, including failures. Limits apply to the
whole descendant cgroup, including local r0vm and recursion. MemoryMax is 2 GiB,
MemorySwapMax is zero, CPUQuota is 200%, thread pools are limited to two, and
RuntimeMaxSec/KillMode=control-group/OOMPolicy=kill bound and terminate descendants.
There is one proving worker and initially one build job.

A separate 64 MiB control probe forked two 40 MiB children and was OOM-killed at
67108864 bytes, with zero swap: expected evidence that descendants share the limit.
Its deliberate failure is neither a proof attempt nor an experiment resource failure.
Effective cgroup settings are saved. RSS is separately sampled roughly every 50 ms;
summed RSS can double-count shared mappings and miss short peaks. Kernel charged
memory includes file cache and is not virtual address space or summed RSS. The
kernel cap complements the sampled process-tree guard; no swap masks memory needs.

The host had approximately 7.57 GiB total WSL memory and sufficient available memory
for a 2 GiB worker plus 2 GiB reserve; admission is checked before each guarded phase.
Physical Windows storage was also checked (404716462080 bytes free on C: at admission),
as distinct from the WSL virtual filesystem. The disk watcher stops conservatively
at 9 GiB below the 10 GiB total allowance. Evidence/fixtures/receipts have a separate
240 MiB stop threshold below the proposal's 256 MiB output ceiling.

Finite limits were recorded before execution: setup/build 1200 s cumulative subprocess
wall; execution/proving 1800 s; 600 s per proof; at most three launches; segment 2^16
and session 2^22 user cycles; verifier 10 s/1 GiB; malformed corpus 100 cases/60 s.
Additional execution-only limits were 60 s per invocation/300 s aggregate. Ancillary
format/data checks use 60 s/256 MiB and 300 s aggregate. No limits were raised.

| Observation | Value / interpretation |
|---|---|
| Installation/dependency preparation | 231.100 s cumulative guarded wall; includes cold downloads, extraction, tool registration and fetching |
| Native/guest build and embedded native checks | 257.981 s cumulative guarded wall; includes corrected integration attempts |
| Total setup/build | **489.081 s**, within 1200 s |
| Largest sampled build process-tree RSS | 794583040 bytes; independent cgroup charged peak 1917521920 bytes for that build |
| Installation charged peak | Around 2 GiB including extraction/file cache; much lower sampled RSS. Kernel memory.max remained 2147483648 and swap zero |
| Largest sampled experimental disk | 3976253201 bytes, approximately 3.70 GiB, including tools/cache/builds |
| Execution comparison service | 0.310100 s wall; sampled RSS 56348672 bytes; kernel peak 100249600 bytes; swap zero |
| Enrolment execution call | **0.063151058 s**, `Halted(0)`, exact journal; **196311 user cycles**, 10 segments: nine at po2=16 and one at po2=15 |
| Enrolment padded segment capacity | 622592 cycles; includes padding/continuation capacity and must not be substituted for user cycles |
| CredValid execution call | **0.178673899 s to resource abort**: `Session limit exceeded: 4194304 >= 4194304`; no completed session/segment count returned |
| Proof launches / receipts | **0 / 0** |
| Proving/recursion/verification time, seal/journal/receipt sizes | **Not measured for any proof**; no zero-valued or estimated proof result substituted |
| Temporary files at stopped-run inspection | Experiment-local tmp directory empty; no proof-temporary peak exists |

The upstream executor applies the hard session cap to its user-cycle counter.
CredValid's abort is not a normal invalid-credential result and was deliberately
recorded as a failed comparison. Enrolment and CredValid timings above are execution
calls, not proof or steady-state benchmark timings. Phase costs and setup are kept
separate. Three attempts could not establish p95; this run made none.

Earlier non-resource integration errors are retained: a cargo-risczero version-CLI
syntax error, a relative launcher executable path, missing rustdoc during automatic
doctests, and raw-ELF versus SDK 3 ProgrammeBinary registration. They were corrected
within the build budget. Native library tests need no rustdoc; both guests then built,
registered and passed native checks. The later cycle exhaustion triggered the stop.

## Validation, privacy limits and preserved obligations

The focused native set covers valid credentials from both instances; malformed and
trailing/truncated encodings; incorrect holder openings; changed/padded attributes;
independent binding mismatch; modified/out-of-range identifiers; signatures/lengths;
wrong expected issuer instance and metadata; nonempty auxiliary fields; operation and
context-width mismatches; coherent attribute substitution with an old signature;
proper/wrong signing contexts; and the enrolment StateAuth boundary. All 35 native
comparisons passed. The three actual sampler/arithmetic unit tests passed. Only the
first of 29 guest cases completed before the resource stop.

Functional output review confirms that the journal construction contains only the
specified public record. The CredValid record contains no Mcred/private message hash,
signature, hidden identifier, private attributes, secret or authentication-side B as
fields. Enrolment intentionally retains its own authorised public fields. The
[public-output check](../experiments/r0_succinct_feasibility_1/evidence/public_output_review.json)
records structural/native-journal checks separately from receipt evidence.

No actual receipt metadata was available to inspect. Consequently, neither public
control-ID/segment-length leakage nor randomness/linkability across repeated receipts
was measured. Local diagnostic fixture names/cases.json identify synthetic reference
cases, and are research evidence rather than a publishable presentation bundle; such
labels must not be exported as private credential identifiers. The proposed receipt
sidecar is also diagnostic-only. A future public adapter must exclude those labels.
No complete-view zero-knowledge or unlinkability claim follows from field inspection.

Experimental Rust formatting, Python lint/format, shell syntax, JSON/TOML consistency,
source/lock/binary identity and preservation checks are retained in
[final checks](../experiments/r0_succinct_feasibility_1/evidence/final_checks.json).
The unchanged production validation is reused: 119 focused / 1432 regression tests,
no skips, and prior Ruff checks; it was not rerun to imply new proof coverage.
[Status](status.md) and [traceability](traceability.md) distinguish native agreement,
partial guest evidence and the unrun proof work.

Still open: bounded keygen/signing and release/update/revocation integration; full
authentication, selective disclosure and non-revocation composition; public StateAuth
placement, issuer/controller authorisation, request/holder approval, trusted time,
current state, pending sessions, replay and atomic final expiry/consumption; complete
BC-1 conformance and original MPC proofs; DEP-001/002; and the candidate's privacy,
concrete quantum soundness, actual-history full-witness extraction and complete-view
simulation obligations under Section VIII. No manuscript/profile change is adopted.

## One next-package recommendation

Prepare **R0-EXEC-CYCLE-1**, a separately scoped execution-only cycle-attribution
package for the unchanged complete CredValid predicate. Attribute software SHAKE,
ML-DSA arithmetic, parsing and continuation overhead under explicit finite limits,
then propose only reviewed semantics-preserving optimisations and repeat differential
checks before another proof pilot. The current evidence identifies a cycle-admission
failure, not its dominant internal cause. Keep instrumentation separate from any
future measured guest, preserve the fixed sampler/context/instance contracts, and do
not introduce a coprocessor, larger cap or replacement profile implicitly. This
package stops here.
