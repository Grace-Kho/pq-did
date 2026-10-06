# LIGETRON-FULL-PATH-ENGINEERING-1 — prospective execution proposal

Prepared 3 October 2026. **Inactive: one consolidated approval is required.**
Engineering feasibility is conditional; cryptographic/deployment admission remains
unestablished. LIGETRON-DOMAIN-MASK-CORRECTION-1 stays complete in its recorded CPU
component scope. This preparation ran no compiler, shader, functional test or proof.

## Practical finding and provenance

The pinned Ligetron README supplies a relevant Dawn revision:
`cec4482eccee45696a7c0019e750c77f101ced04`. It recommends the monolithic static
library and installation exports that satisfy `find_package(Dawn)` and
`dawn::webgpu_dawn`. These are actual CMake targets at that revision. The retained
Ligero tree declares Dawn in `.gitmodules` but contains **no gitlink**; the pin is a
README recommendation, not a verified submodule checkout. Both newly inspected
Ligero text files match their retained Git blob identities.

Base: `ligeroinc/ligero-prover`, commit
`4b1cdef1bfdf4497fb3e38170db4541fba3f6c12`, tree
`95984ef209bf37a53624d27a36905e41886dacfc`.
Apply the randomness overlay (SHA-256
`043ee96fbae51b9416b3435be7e7ad27cfc076ddb7790e14f14be6ea09c0dc3c`)
before the domain/mask overlay (SHA-256
`31f1515e498182664f51e92d91925416c0063d5b117494948e4a52dc6fcc5723`).
Keep the snapshots and patch stack immutable; new integration edits are a third,
separately sealed overlay.

`dependency-lock.proposed.json`, `package-closure.json`, pinned text sources and
`ledger.json` give exact origins, revisions, package metadata and lookup outcomes.
WABT was not pinned by Ligetron. The proposal explicitly selects WABT 1.0.36,
commit `3e826ecde1adfba5f88d10d361131405637e65a3`, resolved from official tag metadata.
This selection requires approval and compilation compatibility remains untested.
WABT's CMake source supplies the headers, static library and package exports;
its tests, libwasm and WASI are unnecessary. OpenSSL avoids its optional SHA fallback.
An Ubuntu WABT file-list lookup failed; no claim is made about that binary package's
contents, and it is not selected for provisioning.

Dawn's selected headless Vulkan closure consists of its own Tint and native code,
plus its exact DEPS pins for Abseil, Jinja2, MarkupSafe, SPIRV-Headers, SPIRV-Tools,
Vulkan-Headers and Vulkan-Utility-Libraries. The native PartitionAlloc target is
an in-tree header-only shim. GN/CIPD, Chromium compilers/sysroots, samples, GLFW,
X11/Wayland, ANGLE, SwiftShader, DXC, GoogleTest and benchmark dependencies are not
needed for these selected targets. Preserve SPIR-V validation. The installed
Vulkan loader is reused, not rebuilt. This is a source-derived closure; the full
checkouts and transitive build have not been validated by configuration.

Package metadata resolves 47 dependency entries, including reused installed
runtime/toolchain inputs. The local-prefix packages require 27,167,090 download
bytes and approximately 270,091,264 installed bytes, excluding Git sources/builds.
This is metadata arithmetic, not measured extraction. Exact versions, filenames,
SHA-256 and dependency expressions are in `package-closure.json`. No apt update,
package acquisition or installation occurred. The existing Python/liboqs
environment is untouched. Current OpenSSL runtime is 3.5.5-1ubuntu3.7: do not reuse
an older component library identity as evidence for this new complete build.

Trust distinctions: official HTTPS metadata identifies proposed revisions;
computed SHA-256 identifies retained text, not a signed upstream release.
Ligero's retained tree corroborates its README/.gitmodules blobs. Dawn/WABT Git
objects, package payload contents, ABI compatibility and native linking remain
future acquisition/build checks. No unresolved dependency may be filled by a
moving branch or guessed version.

## Observed hardware, not an adapter claim

`hardware.json` and `hardware-host.json` retain commands, exits and observations.

| Item | Observation |
| --- | --- |
| WSL | x86_64, kernel 6.18.33.2-microsoft-standard-WSL2 |
| WSL RAM | 8,126,111,744 total; 3,738,451,968 available; 2 GiB swap unused |
| Windows RAM | 16,389,632 KiB total; 2,494,772 KiB free at observation |
| CPU | i7-14650HX; 24 logical CPUs; AVX2/AES visible |
| Compiler/build tools | GCC 15.2.0; CMake 4.2.3; Ninja 1.13.2; pkg-config 2.5.1 |
| Storage | Linux virtual disk 1,006,807,961,600 available; backing C: 367,863,410,688 available |
| NVIDIA inventory | RTX 5060 Ti; driver 616.92; 8,151 MiB VRAM, 6,745 MiB free |
| WSL device | /dev/dxg present outside sandbox; /dev/dri absent |
| Vulkan | Loader and Mesa installed; lvp ICD present; no NVIDIA or Dozen ICD listed |
| Actual Dawn/WebGPU | Not installed, not enumerated, not executed |

Initial sandbox NVML/Windows-interoperability failures are retained; the same
read-only inventory outside the sandbox succeeded. `vulkaninfo` is absent.
NVIDIA visibility is **not** evidence of a Linux Vulkan/Dawn adapter. No WSL
configuration, driver change or GPU workload was used. Windows' 32-bit WMI
AdapterRAM field truncates this device; the VRAM figure above comes from NVML.

The future experiment may use an existing real Vulkan software adapter (Mesa
lavapipe), explicitly labelled **software WebGPU**, for shader and functionality
checks. It must record the selected adapter and never report this as hardware GPU
performance. No mocked executor or CPU algebra substitute counts as shader
execution. If neither real hardware nor software adapter supports the required
limits, stop device/proof work. A Windows/D3D12 port or driver provisioning is
outside this proposal.

## One implementation scope and gates

**P0 — provisioning.** Use only a new registered project-local directory
`experiments/ligetron_full_path_engineering_1/{src,prefix,downloads,build,scratch}`.
Use verified, pinned shallow checkouts without executing Git hooks, DEPS hooks or
downloaded installation scripts. Verify object types, commit trees and original
retained files before applying overlays. Download the exact package payloads,
check hashes and safe paths, extract without maintainer scripts into `prefix`.
Check all symlink destinations, architecture, headers/library versions and CMake
exports. No sudo, system package changes, global environment changes or upgrades.
Commands and acquisition checks are in `RUNBOOK.md`.

**P1 — integration corrections.** Affected existing paths are CMakeLists.txt,
src/webgpu_prover.cpp, src/webgpu_verifier.cpp, include/zkp/proof_serializer.hpp,
the Stage1/Stage2 helpers, and the existing engine/callback/shader paths only when
affected validation demonstrates a defect. New harness/contract/expectations live
under the new experiment. Keep the prior RNG/domain/mask semantics, parameters,
ML-DSA caps and retained expectations unchanged. Routine build-wiring, parser,
binding and shader/callback correspondence corrections are included; a change to
the proof protocol's masking/degree/challenge construction needs another decision.

1. Use an explicitly initialised canonical statement digest. Bind protocol and
   experimental profile/version, exact program bytes/hash, entry point and ABI,
   argument count, ordered indices/types/lengths, public/private layout and exact
   public values. The verifier supplies the expected statement from trusted
   configuration. Do not hash private values into a public identifier. Bind
   requested public application/session context as explicit typed statement data.
   Preserve the VM's actual argument indexing; reject ambiguous caller indices.
   Feed this statement into Stage1 and retain the entire Stage1 digest in Stage2.
   This is a new experimental transcript profile, not an adopted PQ-DID encoding.
2. Bound config/program reads before allocation (64 KiB JSON, 1 MiB tiny-program
   cap); reject duplicate keys, coercions and unsupported fields. Bound compressed
   offline experimental proof input at 8 MiB, decompressed envelope at 16 MiB and protobuf recursion at
   32; enforce these *during* read/decompression. Require exact fixed dimensions,
   version, digest widths and three response lengths from trusted profile data.
   Canonical field limbs must represent values below p; no implicit reduction.
   Require exact sample, row, query and Merkle sibling counts, sorted unique query
   indices equal to the transcript-derived set, exact tree shape and complete
   input consumption. Reject trailing gzip members/trailing envelope bytes,
   duplicate singular fields and unknown tags using a bounded wire scan before
   protobuf's allocating parser. Serialise with one canonical encoding; reject
   conflicts between envelope metadata and the expected statement. These are
   isolated file/harness limits; the existing 65,536-byte PQ-DID transport limit
   and production interfaces are not enlarged or connected to this experiment.
3. Exercise the generated shader selected by the runtime, not merely the packed
   source. Seal template expansion, generated bytes, loaded path and shader hash.
   Validate inverse coset scaling before folding and retained degree-check tails.
   Exercise ordinary and batched callbacks, aliases and derived rows through the
   actual executor; register row/oracle identities consistently across stages.
4. Record a symbolic buffer/row/work schedule before large allocations. Stop if
   row growth, mask replay, maximum work or actual memory cannot be bounded.
   Full-sized masks and three-stage replay must succeed before a proof attempt.

**P2 — separately gated synthetic proof only.** One explicitly new attempt, if
approved, uses a public, disclosed synthetic secret-designated input (x=7) and
public y=49 in a tiny integer-square/equality program through the actual VM and
prover/verifier. Implement its WAT and canonical arguments as part of the harness;
bound VM steps and require its generated constraint schedule to express the
equality, with no host assertion substituted for the relation. Compile/assemble
it inside the counted application build. Program parsing, callbacks, masks,
binding/parser checks and resource admission must first pass. Verification is a
fresh process with only the expected public statement and encoded proof, with no
witness file or prover in-memory state. Mutated public statement, response and
authentication path must reject. This demonstrates at most functional engineering
correspondence, not privacy, knowledge, PQ security or complete authentication.
No hidden-message ML-DSA or genuine private authentication is in this tiny scope.

Do not generate a proof to discover whether a known correctness defect matters.
Any known affected correctness defect must be corrected and revalidated first;
an unresolved semantic defect stops the proof gate. The mathematical obligations
below remain visible limitations, rather than an automatic ban on this labelled
synthetic engineering gate.

## Fixed validation plan (40 individual invocations; all currently unrun)

All expectations are independently specified before execution; preserve every
failed invocation. Reuse the existing 35 RNG and 32 component outcomes without
unaffected reruns. Each listed item is one case, not a parametrised bundle.

| ID | Required outcome |
| --- | --- |
| E01 | Enumerate/select real Dawn adapter; record backend/type/limits or stop device work |
| E02 | Exact generated/loaded shader identity and actual shader/pipeline compilation |
| E03 | Full-sized forward coset transform of one boundary vector matches independent CPU oracle |
| E04 | Inverse scaling/folding and coefficient-tail readback match oracle |
| E05 | Code-degree violation at coefficient k rejected |
| E06 | Linear-degree violation at coefficient 2k-1 rejected |
| E07 | Quadratic-degree violation at coefficient 2k-1 rejected |
| E08 | Public-coefficient row encoding matches canonical coefficient oracle |
| E09 | Actual batch initialisation uses 256 padding coordinates, 192 queries |
| E10 | Ordinary linear callback/output matches reference constraint |
| E11 | Batched linear callback/output matches reference constraint |
| E12 | Ordinary quadratic callback/output matches reference constraint |
| E13 | Batched quadratic alias/derived-row relation matches actual shared inputs |
| E14 | Full-sized code mask, retained actual seeded draw schedule and encoder agree |
| E15 | Full-sized linear mask satisfies sum and degree constraints |
| E16 | Full-sized quadratic mask satisfies required zeros and degree constraint |
| E17 | Actual three-stage row/mask replay yields identical committed/query symbols |
| E18 | Injected entropy failure aborts before commitment/publication |
| E19 | Injected backend-sampler exhaustion aborts; frozen ML-DSA caps untouched |
| E20 | Changed program identity cannot reuse an expected statement |
| E21 | Changed public argument changes the independent expected statement digest |
| E22 | Changed private/public layout rejects against trusted expected layout |
| E23 | Chosen index/type/length ambiguity has distinct canonical framing or rejects |
| E24 | Profile/dimension override rejects |
| E25 | Fixed canonical statement framing matches independent digest expectation |
| E26 | Compressed-input ceiling enforced before oversized allocation |
| E27 | Decompression-output ceiling enforced while streaming |
| E28 | Malformed metadata/tree dimensions rejected before allocation |
| E29 | Noncanonical field limb value p rejected |
| E30 | Duplicate/reordered query declaration rejected |
| E31 | Missing sibling/incorrect authentication structure rejected |
| E32 | Truncated envelope rejected |
| E33 | Extra gzip member/trailing-data fixture rejected |
| E34 | Unknown/duplicate-field ambiguity fixture rejected by wire scan |
| E35 | Incorrect response-vector length rejected |
| E36 | Gated single synthetic proof generation completes within bounds |
| E37 | Fresh-process verification of E36 succeeds with expected public statement |
| E38 | E36 with changed expected public statement rejects |
| E39 | E36 with altered response rejects |
| E40 | E36 with altered authenticated path rejects |

E23/E30/E33/E34 each use one predeclared malformed fixture, not hidden multiple
parameter cases. Additional distinct fixtures consume corrective slots only when
justified by affected implementation correction. Up to eight targeted corrective
invocations; no native retries with old reserved slots. A second proof generation
is never covered by those eight slots. Record skipped cases explicitly.

## Prospective consolidated amendment — not activated

Existing ledgers retain 1,250/1,265 invocations, 13/13 builds, and two proof
attempts used/one historically reserved unused. Exact preparation closing balances
are in `resource-closure.json`. KYC remains 383.7084432235879 seconds including its
300-second reserve. No existing reserved corrective slot is available here.

| Resource | Single requested amendment/allocation |
| --- | --- |
| Time | Add 7,200 implementation seconds outside KYC: ceiling 6,674 -> 13,874; allocate only those new seconds to this package |
| Phases | acquisition600 + integration900 + builds4500 + checks600 + correction300 + completion300 = 7200 seconds |
| Invocations | Add48: ceiling1265 -> 1313; 40 fixed + at most8 justified corrective executions |
| Builds | Add4: ceiling13 ->17; Dawn, WABT, Ligetron+harness, at most one affected corrective rebuild |
| CPU memory | New scoped build/native worker limit2 GiB; audit/preparation stays256 MiB; serial builds/runs |
| GPU memory | At most512 MiB application-owned live buffers; record adapter/device telemetry and shared-memory costs; do not confuse this with total driver residency |
| Memory admission | Windows free AND WSL available >=4 GiB before build/device launch; preserve >=2 GiB headroom for a2 GiB worker; current observation fails this gate |
| Artifact ceiling | 128 MiB ->4 GiB cumulative for pinned source/Git objects, verified downloads, local prefix, scratch, generated source and binaries |
| Artifact per-file |32 MiB ->256 MiB only for registered downloads/Git/build binaries/generated artifacts under the new isolated location |
| Temporary storage | At most512 MiB inside that4 GiB, on project filesystem, not an extra allowance or /tmp tmpfs |
| Evidence | cumulative40 ->44 MiB; shared allowance +4 MiB; allocate3 MiB new evidence, including512 KiB completion/failure reserve; preserve existing shared2 MiB reserve |
| Proof result storage | Up to8 MiB compressed plus16 MiB bounded transient decode, explicitly registered as proof-result artifacts; JSON/logs/manifests remain evidence |
| Commands | Dawn serial build up to3600 seconds, WABT300, application600; acquisition command120, individual cases<=120, generator<=120; polling/progress <=60 seconds |
| Work events | Keep existing2^32 ceiling; historical144,593,603 unchanged; at most3,000,000,000 additional conservatively bounded operations, checked before each dispatch/VM execution |
| Proof attempt | Exactly one **additional** synthetic-only attempt, ceiling3 ->4; original unused attempt remains reserved; no automatic private-proving unpause |

Time/build figures are conservative planning limits, not measurements or promises.
New Git sources/dependencies estimate0.2–0.8 GiB, prefix/packages0.3–0.6 GiB,
Dawn/WABT/application build products0.5–1.5 GiB, scratch<=0.5 GiB. Their sum with
the retained approximately75 MiB artifacts can approach3.5 GiB; enforce the4 GiB
aggregate during acquisition and build. Stop before an oversized fetch/extraction.
No shallow clone command alone guarantees a download bound: the existing guard
must monitor all repositories, packs, extracted files, scratch and diagnostics.

At n=32768 one 32-byte field codeword is1 MiB; the three response vectors alone
contain3,145,728 raw bytes. A tiny program does not shrink these fixed dimensions.
Plan <=64 simultaneously live field buffers (64 MiB), <=64 MiB hash/query/staging
buffers and up to128 MiB other application staging (256 MiB planned;512 MiB cap).
This is a **prospective buffer allowance**, not a measured live-set bound: P1 must
enumerate all engine/context/driver allocations, host GMP rows, protobuf and
readback copies before E36. Driver caches/compile memory remain uncertain; monitor
host and device telemetry and stop on unaccounted growth. Lavapipe consumes host
memory, so GPU-labelled buffers also count against its worker's CPU memory limit.
No estimate of complete-authentication proving resources follows from this model.

The prospective package explicitly reserves **300 seconds**
inside its7200 seconds for one final preservation/reporting/readback checkpoint
and a single review ZIP. All listed operations, failed acquisitions/builds/cases,
operator charges and corrective work count against the same enclosing budgets.
No allowance transfer from KYC, analysis, isolation or old proof budgets.

## Security obligations are separate from engineering gates

The review's response-translation/Vandermonde argument is conditional on fixed
independent challenges, independently padded *distinct* rows, the true alias/
derived-row relationships, independent masks in their exact subspaces, and no
additional observations. Source callbacks share buffers, and the actual view
also contains Merkle roots, authentication paths and hash-derived queries. These
objects are not simulated by the local argument. Preserve the existing algebraic
findings without asserting complete committed-view zero knowledge.

* **Degree/parameter correspondence:** native public coefficient degree<k gives
  linear degree<2k-1, not the paper's<k+ell-1. Need a demonstrated application or
  extension of the exact soundness/simulation/extraction argument for this degree
  and every ordinary/batched oracle, or a separately specified encoding change.
* **Masking:** prove the complete joint distribution, including aliases, derived
  rows, three masks/responses, shared/adaptive queries and successful bounded
  sampling. Dimension counts and marginal full rank alone are insufficient.
* **Commitment/compiler:** match early roots and authenticated openings, program/
  layout binding, the actual transcript/compiler and complete-view simulator.
  Canonical statement/parser corrections improve engineering correctness, but
  do not supply this simulator or a new commitment theorem.
* **Challenge expansion:** known public AES seeds/stream separation and bounded
  rejection/query selection require the appropriate distribution/ROM argument;
  secret-key PRG security is not automatically that argument.
* **Extraction and quantum claims:** one consistent VM/authentication assignment,
  Fiat–Shamir/QROM, quantum privacy and finite parameter losses remain open.
  The retained47-page Ligero reference and the updated theorem/Appendix C quoted
  elsewhere must not be silently mixed. Exact updated primary theorem text is
  not retained; this preflight did not acquire it or establish its applicability.

No theorem/security level is claimed. These obligations block private/deployment
admission but not the proposed explicitly non-security synthetic experiment.
Successful engineering must still be followed by a supported concrete construction
decision before hidden-message ML-DSA or complete private authentication.

## Completion and stops

Deliver exact dependency/payload seals, third overlay, build commands/results,
loaded shader identities, individual case outcomes and skipped cases, actual
CPU/GPU/live-buffer/work/storage/time measures, bounded proof/parser evidence only
if its gate passed, updated report/traceability and one verified review ZIP.
Reuse the baseline302 observations/four smoke observations and67 component checks.
No reruns of unaffected evidence. No further Binius work or standards claim.

Stop affected work for an integrity mismatch, unpinned dependency requirement,
unsupported adapter, unmet headroom, actual resource breach, exhausted correction
allowance, unresolved correctness defect or proposed change to cryptographic
semantics. Routine supported corrections and affected revalidation within the
above scope need no subtask-by-subtask approval. Preserve failures. The final
construction/security decision may remain unresolved even if every engineering
case passes. Stages2–3 and the complete original project scope remain open; the
31 October target is unchanged and is not a supported completion promise.
