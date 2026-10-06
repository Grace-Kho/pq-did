# S3-AURORA-NATIVE-DEPENDENCY-LOCK-1

## Decision and boundary

**The proposal is ready for specified project-local provisioning approval. No
provisioning, configuration, compilation or native build admission has occurred.**
The [machine-readable lock](data/s3_aurora_native_dependency_lock_1/dependency-lock.json)
and [exact runbook](proposals/s3_aurora_native_dependency_lock_1/README.md) distinguish
metadata verification from mandatory checks of artifacts after acquisition.
Preservation completion is recorded in the final appended validation result below;
it is independent of dependency readiness.

This follows the [native pilot](stage3_aurora_native_transcript_pilot.md), which
stopped without implementing EXP2 or using a build/test attempt. The existing
correction contract and 16 passing isolated Python cases remain unchanged. Only
manuscript Sections II–VIII and agreed clarifications are authoritative. The
dependency work makes no construction or proof-profile change. Stages 2–3 remain
open; AURORA-BRIDGE-001 is not closed by dependency readiness.

## Selected dependency closure

| Component | Exact selected identity | Role and verification status |
| --- | --- | --- |
| libiop | `a2ed2ec2f3e85f29b6035951553b02cb737c817a` | Pinned native hashchain and BCS caller sources; complete tree metadata, build declarations and selected headers inspected; full checkout pending |
| libff | `9769030a06b7ab933d6c064db120019decd359f1` | Top-level gitlink; real gf192 and support library; GMP and sodium dependencies |
| libfqfft | `7d460caa27b87574fe0e8144e6a3a66b7bcfe770` | Top-level gitlink; upstream iop include dependency, headers selected without its standalone build |
| libsodium-dev, amd64 | `1.0.18-2` | Cached exact archive size/hash and distribution header/static-library list verified as metadata; archive not acquired |
| libgmp-dev, amd64 | `2:6.3.0+dfsg-5ubuntu2` | Cached exact archive size/hash and distribution header/static-library list verified as metadata; archive not acquired |
| Existing C++ runtime/toolchain | Installed package versions in the lock | Unchanged compiler 15.2, CMake 4.2.3 and Ninja 1.13.2 evidence reused; no compatibility probe |

The native dependency graph is libiop → libff, libfqfft, sodium; libff → GMP,
sodium and the installed C++ runtime; libfqfft headers → selected libff/GMP.
The pinned libff `field_utils.hpp` includes bigint/prime-field declarations even
for binary-field callers, so GMP headers cannot be omitted simply because EXP2
uses gf192. Binary field code includes sodium randombytes; hashchain code uses
sodium BLAKE2b. Static C archives avoid introducing a system library installation.
The dev-package dpkg dependencies remain recorded: this private extraction/link
proposal does not pretend to install a complete dpkg package closure. The unused
GMP C++ binding and its runtime are not selected by the proposed C-only link.

The native source target is deliberately conservative: it builds the existing
upstream ff target and the same eight non-template library sources used by iop,
then a public-input harness instantiates the actual BCS/hashchain templates.
It does not implement replacement field classes or a standalone C++ transcript
model. This is the smallest selected *harness role*, not a claim that every linked
support source is indispensable or that a minimal object-level link was measured.
The ff target compiles some unused curve code; that cost is included in build
admission. A hand-pruned support library would require separate justification.

## Optional and conflicting nested pins

All top-level and inspected libff/libfqfft gitlinks are in the lock. In particular:

- Top-level xbyak is `811f4959ee0dd36a3ccedd2d4d7460472dd19a14`, whereas nested
  libff/libfqfft use `f0a8f7faa27121f28186c2a7f4222a9fc66c283d`.
- libfqfft's nested libff is `accdf9e761979ac8c95dced219cac0b4ad4a4799`, not the
  selected libiop top-level revision; its own gitlinks were inspected too.
- ate-pairing is `e69890125746cdaf25b5b51227d96678f76479fe`. Google Test pins differ
  between top-level/libff and libfqfft. The benchmark pin is also recorded exactly.

These optional trees are not acquired or built for the selected closure. The
upstream top-level libiop CMake unconditionally configures benchmarks/tests,
`zm` and Boost instrumentation. The proposed isolated target avoids that entry
point; `IS_LIBFF_PARENT=OFF`, header-only libfqfft, `WITH_PROCPS=OFF`,
`MULTICORE=OFF`, `USE_ASM=OFF` and no performance/LTO avoid unrelated support.
`CURVE=ALT_BN128` controls libff's default support type and excludes the BN128-only
ate-pairing link; it does not change the transcript's `libff::gf192` field or active
PQ-DID parameters. No OpenSSL dependency is declared by the selected build paths;
the old broad Ubuntu INSTALL command is not treated as the minimal dependency list.

The selected repository trees contain 246, 167 and 505 blobs respectively,
totalling **3,153,419 bytes** of source payload. This is tree metadata, excluding
Git storage, filesystem allocation, artifacts and optional gitlinks, not an
actual acquired checkout measurement. The two exact .deb sizes total **528,744
bytes**. Source and package identifiers are resolved; full checkout integrity,
archive members and modern compiler compatibility remain acquisition/build gates.

## Integrity and provisioning gates

The metadata responses are retained as lossless gzip files with the uncompressed
length/SHA-256 and origin URL in their results records. GitHub tree metadata is
checked for truncation and preserves file modes, blob IDs and gitlinks. Commit
IDs are pinned; no branch head was substituted. A GitHub response is not a signed
source release or an independently verified complete checkout.

The sodium archive SHA-256 is
`34e8337b30160458f44bada750c9e94ec18ec5ac087e2428043ddb04625226cc`;
GMP is `b43e38f2d5ae4aa38471e1b3f90ed63e96c2ce614ffe496cdcd72f9944e87a4a`.
These are retained cached Ubuntu package metadata values; no fresh Release-signature
verification is claimed. The public distribution file lists identify sodium's
BLAKE2b/randombytes headers and `libsodium.a`, and GMP's multiarch `gmp.h` and
`libgmp.a`. They do not establish the contents of the still-unacquired exact .debs.
The runbook requires hash, length, control fields, safe member paths/types, complete
contents and header/archive ABI checks before extraction/use. Mismatch means stop,
not replacement by another release. No dependency version or mandatory pin remains
unknown for this selected proposal; artifact and compatibility checks are pending.

The standalone build target and explicit include/library paths prevent discovery
from silently selecting another libff, global sodium or nested dependency. CMake
4.2 with old `cmake_minimum_required(VERSION 2.8)` uses the proposed command-scoped
`CMAKE_POLICY_VERSION_MINIMUM=3.5`; this has not been configured or proven compatible.
No host installation is necessary for the proposed extraction/static-link route.

## Approval and resource proposal

The runbook consolidates the requested **unprivileged fresh-prefix acquisition**
and a narrow artifact-budget clarification: source checkouts, packages/Git objects
and build outputs share the existing 128 MiB native artifact cap (32 MiB reserved
for acquisition); allow binary/Git/build artifact files up to 32 MiB each while
retaining 1 MiB source/metadata files and 2 MiB logs/reports/evidence. This per-file
exception is proposed, not active. No time or invocation increase is requested.
At most 60 seconds of future acquisition would be charged to the existing native
and implementation balances only after approval. All guard/memory/concurrency
limits and the native final 30-second reserve remain. No privilege or host effect
is requested. Provisioning time, compile time/memory and build-artifact sizes are
not measured; the runbook's 249-second worst-case reservation is an admission
envelope, not a performance forecast. Compatibility/resource failure blocks resume.

## Interrupted lookup and authorised continuation

The first execution retained **203,630 package bytes**, for **10,492,963 cumulative
bytes**, exceeding its then-applicable **10,485,760-byte** ceiling by **7,203 bytes**.
The fourth lookup exited 255 after the guard's `diagnostic/package output stop`.
This remains a resource failure. Its partial result, source/configuration, three
successful lookup records and STOP evidence are preserved without rewriting them.

The user amended only this package's cumulative ceiling to **12,386,485 bytes**;
the package 2 MiB ceiling is unchanged. Opening continuation headroom was
**1,893,522 bytes**. The [amendment](data/s3_aurora_native_dependency_lock_1/continuation-1/amendment.json)
reserved 262,144 bytes for remaining metadata and 524,288 for completion before
admission. Only six unfinished requests were resumed; the successfully retained
sodium file list was reused. The resumption passed in **3.073859 seconds**. No
archive, installation, configuration, compile/link probe or test was performed.

Analysis opening was **211.513455542 seconds**; the interrupted phase charged
**20.534696041 seconds**, leaving **190.978759501 seconds**. The continuation has
a 39.465-second cap inside the same 60-second package cap, including its ten-second
reserve. It charges five conservative operator/source/evidence/bookkeeping seconds
plus actual guarded command durations, preserving the established accounting
convention. This is charged analysis work, not elapsed conversation time. The
earlier eight-second fixed charge includes five bookkeeping seconds and three
seconds for failed web-tool metadata access.

## Sources, validation and limitations

Primary sources are the [pinned libiop build](https://github.com/scipr-lab/libiop/blob/a2ed2ec2f3e85f29b6035951553b02cb737c817a/CMakeLists.txt),
[dependency declarations](https://github.com/scipr-lab/libiop/blob/a2ed2ec2f3e85f29b6035951553b02cb737c817a/depends/CMakeLists.txt),
[pinned libff build](https://github.com/scipr-lab/libff/blob/9769030a06b7ab933d6c064db120019decd359f1/libff/CMakeLists.txt),
[GMP file list](https://packages.ubuntu.com/resolute/amd64/libgmp-dev/filelist),
[sodium file list](https://packages.ubuntu.com/resolute/amd64/libsodium-dev/filelist)
and [CMake policy setting](https://cmake.org/cmake/help/v4.2/variable/CMAKE_POLICY_VERSION_MINIMUM.html).
The lock points to all retained metadata for offline inspection. The proposed CMake
text has been source-reviewed only, not configured or syntax-tested by CMake.

The existing 16 regressions and native prerequisite evidence are reused. Static
Python formatting/lint, metadata integrity checks, inventory preparation and one
full preservation audit are the only remaining validation operations. The audit
retains the original 8,759 content comparisons, disjoint 2,142 supplemental
comparisons, historical report prefixes and every sealed repair artifact; the
old 10,901 partial comparisons are not substituted for this run.

Dependency readiness does not establish native caller correspondence, query/masking
soundness, commitment transformation, extraction/privacy, concrete-hash composition
or complete authentication. Production custody/signing, side channels, erasure and
adaptive Delta_tail remain open. CPU proving and raw-view integration stay paused;
isolation is safely stopped/unactivated. Native balances remain 291.750990099 s,
296.308369758 implementation s, two unused builds, 24 unused native invocations,
402/426 cumulative invocations; proof ledger **two used, one unused**.

The single recommended next step is approval of the exact project-local acquisition
and artifact-file delta in the runbook, followed by its admission gates. Do not
start another integration or proof package on the strength of this dependency review.


## Completed preservation and final balances

The single complete audit exited **0** and its outer guard passed: **10,901**
disjoint content comparisons (8,759 primary and 2,142 supplemental), 10,936
identity-inclusive paths, **2,790** inventory names, no missing or unexpected files.
Only the three authorised append-only tracking documents changed among baseline
files. Metadata seals, every historical repair record and the original 7,203-byte
output failure were preserved. Final inventory, report generation and readback
completed. Audit **2.655091408 s**, cgroup-v2 memory.peak
**33,660,928 bytes** under 256 MiB; sampled aggregate
tree RSS **56,336,384 bytes**. The cgroup includes
worker descendants and charged file-cache/kernel memory; the observer is outside
it. Temporary storage was zero. Focused lint/format and preparation passed; no
regressions/native invocations were rerun.

Continuation charge **11.183235503 s** including five conservative bookkeeping
seconds; combined package **31.717931544/60 s**, with **28.282068456 s** remaining
(the rounded continuation ceiling leaves 28.281764497 s). Analysis
remaining **179.795523998 s**. All native/implementation, isolation and
proof balances above are unchanged. Final byte totals, including retained failures,
new output, report and append-only tracking-document additions, are recorded in
[the closure](data/s3_aurora_native_dependency_lock_1/continuation-1/validation-closure.json).
The final additive seal protects this package's evidence; it replaces no historical
baseline. Successful preservation finalises the dependency proposal, not native
build admission, artifact compatibility or AURORA-BRIDGE-001.


## Approved local provisioning attempt — stopped on tree identity

The user approved project-local acquisition under the sealed dependency proposal,
the 60-second provisioning sub-limit and the 32 MiB binary/Git/build artifact
exception within the unchanged 128 MiB aggregate. The proposal seal
`e83682e08a9bdd8ca0b2fc542621ee87e4e8eca492ce0e2801111a2b6055ec36` and lock digest
`9f95bcb9f82d4cb5f8caaf2ca41e9e22b17ea39e8146474ca055e1d67eae617f`
were verified, including their protected inputs, before acquisition. All required
installed tool paths were present. Opening cumulative evidence was 10,689,507 bytes
against 12,386,485, leaving 1,696,978 bytes; 1 MiB work and 512 KiB finalisation
reservations fitted. Artifact acquisition reserved 32 MiB within 128 MiB; ordinary
files retained 1 MiB and audit memory 256 MiB. No limit reset occurred.

**Provisioning and native resumption are blocked.** The fresh, partial checkout is
retained at `experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1/src/libiop`.
The guard permitted network only for this acquisition; every command and exit
status is in [commands.json](data/s3_aurora_native_transcript_pilot_1/provisioning-1/commands.json).
It executed `git init`, remote registration, exact shallow fetch, detached checkout,
HEAD verification, `git fsck --full` and `git rev-parse HEAD^{tree}`. Each Git
command exited zero. The provisioning process then rejected a mismatched tree ID:

| Identity | Value | Finding |
| --- | --- | --- |
| Requested and acquired HEAD | `a2ed2ec2f3e85f29b6035951553b02cb737c817a` | Matches pinned commit; fsck passed |
| Approved lock `tree_git_sha1` | `a2ed2ec2f3e85f29b6035951553b02cb737c817a` | Equals the commit ID, copied from retained API response `sha` |
| Acquired `HEAD^{tree}` | `2e2588ccb085242dd2237875c3b9adf1a0fc958c` | Differs from approved tree field; admission failed |

The retained commit-addressed GitHub tree response itself has the commit ID in
its `sha` field. The lock construction treated that value as a root tree ID without
object-type verification. This supports a metadata-interpretation defect in the
proposal; it does **not** demonstrate a corrupted checkout or an attack. The
correct root-tree binding and complete blob/gitlink reconciliation are not yet
established. No pin, seal, metadata response or verification rule was changed to
make this attempt pass. No acquisition retry, fallback version or build followed.
The previous proposal-readiness conclusion is superseded by this failed gate.

The identity failure preceded full tree/worktree comparison, the 21 retained
snapshot comparisons and eight historical-copy comparisons. Those checks remain
unperformed on the new checkout. libff/libfqfft and both .deb files were never
acquired. The `packages`, `prefix` and `evidence` directories created under the
approved fresh root remain empty. No archive inspection/extraction, header/library
ABI verification, local dependency installation, configuration or compilation
occurred. All submodule gitlinks remain uninitialised; no complete dependency
closure is claimed.

The [individual native outcomes](data/s3_aurora_native_transcript_pilot_1/provisioning-1/native-case-outcomes.json)
record TR-01 through TR-16 as **not run — tree identity blocked**. Native builds
remain 0/2, native invocations 0/24, cumulative 402/426. No EXP2 patch, native caller,
negative control, proof or zkVM guest was executed. The 16 retained Python results
and independent expectations were reused unchanged; they establish no native
correspondence.

Provisioning's guarded duration was **1.026998700 s**, exit 1; with the five-second
conservative bookkeeping allocation, its sub-limit charge is **6.026998700/60 s**.
The failure was the identity assertion, not a resource breach. Native memory was
limited to 1 GiB with zero swap, one worker/two CPUs, a 55-second command reservation,
32 MiB binary-file ceiling and unchanged source/diagnostic limits. The worker cgroup
terminated; its service result and resource records are retained. Original attempt
sources are saved byte-for-byte as `*-at-attempt.py`; formatting-only working
copies used for static checks are not presented as the executed source.

The preservation audit separately protects the quarantined checkout as failed
acquisition evidence. Its additive artifact inventory is **not** a replacement
source baseline or a claim that the checkout passed dependency admission. No
quarantined files are deleted or moved. The original 7,203-byte dependency-review
overrun and all earlier repair evidence remain protected. Final validation and
balances are appended after the complete audit.

Recommended next package: a bounded **source/tree identity reconciliation** of the
three approved repository pins. Distinguish commit objects from root trees, compare
the complete retained tree entries with the fetched commit, and review a corrected
additive lock before any further acquisition. Do not automatically adopt this
partial checkout or rerun the fresh-only provisioner. The current acquisition
authorisation was stopped at its stated integrity boundary. Stages 2–3 and
AURORA-BRIDGE-001 remain open; query/masking, commitment transformation, extraction/
privacy, concrete-hash and complete authentication obligations persist. Isolation
stays stopped/unactivated, CPU proving paused; proof ledger two used/one unused.


### Preservation and closure of the blocked attempt

Focused lint/format and inventory preparation passed. The single complete audit
exited **0**: 8,759 primary plus 2,142 disjoint supplemental content comparisons
(**10,901** total), 10,936 identity-inclusive paths and **3,080** inventory names,
with no missing/unexpected entries. It also verified the new failed-acquisition
artifact hashes and all earlier seals/repair evidence. Final inventory, report
readback and the outer guard passed; no baseline was regenerated. Audit duration
**2.636536615 s**, peak cgroup memory **28,880,896 bytes**
under 256 MiB. Acquisition peak was **42,008,576 bytes**
under 1 GiB. These cgroup peaks cover descendants and charged file-cache/kernel
memory; sampled aggregate RSS is separately recorded. No resource limit was reached.

All guarded workers exited. Retained/quarantined artifacts comprise **255 files**,
**2,030,216 bytes**, in the isolated acquisition root; temporary data is
zero. This inventory preserves the failed attempt, not a verified dependency
checkout. The originally executed helper sources remain alongside formatted
working copies and their exact hashes. No package archive, dependency installation,
EXP2 patch, build or native case was performed. Native cases TR-01–TR-16 remain
individually unexecuted; 402/426 and both unused builds are unchanged.

Continuation charge **9.061018428 s**, including five conservative operator/
bookkeeping seconds and the failed acquisition. The provisioning sub-limit charge
is **6.026998700/60 s**; the five seconds are charged once, not twice.
Native package charge now **17.310028329/300 s**, leaving
**282.689971671 s**; implementation remaining **287.247351330 s**. The final
30-second native reserve is preserved. Analysis **179.795523998 s** and isolation
**250.22 s** are unchanged. Final evidence bytes and remaining cumulative headroom
are in the [closure](data/s3_aurora_native_transcript_pilot_1/provisioning-1/validation-closure.json).
The attempt is safely stopped and preservation is complete; provisioning, native
compilation and native correspondence remain blocked. No further package started.


## Verified dependency reconciliation and native build stop

The authorised commit/tree reconciliation passed with replacement-object substitution disabled. The libiop commit remains `a2ed2ec2f3e85f29b6035951553b02cb737c817a`; its stored tree header, `^{tree}` resolution and tree object agree on `2e2588ccb085242dd2237875c3b9adf1a0fc958c`. The same commit-versus-root-tree metadata error was verified and corrected for the selected libff and libfqfft commits. Only the three tree fields changed in a new lock version; the original lock, seals, failed acquisition and all gitlink commit IDs remain protected.

See the [v2 runbook](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/runbook-v2.md), [correction proof](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/lock-correction.json) and [provisioning result](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/provision-result.json). Corrected lock SHA-256: `0e33258c861764eacb8e4f04d21962425e7b7fedd7f27e79cecc4176deec1736`.

Project-local provisioning passed: all three selected source trees, all recorded gitlinks, 21 retained source snapshots and eight historical source copies matched. Both unchanged Debian archive hashes, members, destinations, header versions and static-library x86-64 ELF members passed inspection. Nothing was installed globally or into the existing Python/liboqs environment. Build compatibility was then tested and failed; static dependency readiness is not compilation success.

Both native build attempts are consumed. Build 1 stopped on private `bigint_repr()` access in an unused libff BLS12-381 source. The one authorised build-only correction narrowed `ff` to pinned binary-field/common sources. Build 2 built that target but stopped on non-existent `index`/`coeff` members in pinned libiop `relations/variable.tcc` (lines 63, 129, 171, 177–178). No native executable was produced. No native function/caller or negative control was executed, and no correspondence is established. The prepared patch/harness and both failures are retained. No further build was attempted.

All TR-01–TR-16 outcomes are individually [recorded as not run](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/native-case-outcomes.json). Native invocations remain 0/24; cumulative 402/426. Existing 16 Python results are reused, not rerun. DEP-001/DEP-002 and AURORA-BRIDGE-001 remain open. The exact acquisition prerequisite is now satisfied; compiler compatibility and native transcript correspondence remain unresolved.

Recommended next package: a bounded source-only native build-compatibility correction contract addressing the observed libff friend-access and libiop stale-member errors, with exact isolated changes and an explicit future build-attempt request. Do not substitute dependencies or start that package automatically. Stages 2–3 remain open; query/masking, commitment transformation, extraction/privacy, concrete hash and complete authentication obligations remain open. Only manuscript Sections II–VIII and agreed clarifications are authoritative. Isolation stays stopped/unactivated; CPU proving paused; no proofs or zkVM executions; proof ledger two used/one unused.

Final preservation/guard outcome and actual resource balances are appended below after completion.


Reconciliation/native closure: the complete preservation audit passed, exit 0,
with 10,901 disjoint baseline content comparisons, 10,936 identity-inclusive paths
and 4,884 inventory entries at audit time. Report generation/readback and outer
guard passed; audit 2.939619946 s, 30,527,488 bytes cgroup peak under
256 MiB. New artifact inventory covers 1,988 entries (1,983 regular files and five
exact symlink targets); retained artifact bytes 11,228,057 / 134,217,728. No baseline,
seal, historical failure or expected result was replaced. No resource breach.

Native builds: attempt 1 exit 1 in 1.371514156 s; attempt 2 exit 1 in
3.603540356 s. Largest native cgroup peak 258,568,192 bytes / 1 GiB;
largest sampled native tree RSS 211,906,560 bytes; sampled temporary-storage peak
669,692 bytes / 8 MiB. These are separate memory metrics, not sums. All launched
guarded workers exited and temporary work is empty. Local checkouts, archives,
static-library prefix, patched sources and partial builds remain isolated and
retained. Both build attempts used; all 24 native invocations unused; 402/426.
No executable, native transcript result, or successful caller comparison exists.

Provisioning/reconciliation sub-limit conservatively charged 18.156349560/60 s,
leaving 41.843650440 s without resetting the old charge. This continuation
charged 18.318097987 s: actual guard durations plus the existing five-second
bookkeeping convention. Native package total 35.628126316/300 s; balance
264.371873684 s, with its 30-second reserve preserved. Overall implementation
balance 268.929253343 s. Analysis 179.795523998 s and isolation 250.22 s unchanged.
The first static pass recorded E741/E501; the authorised cosmetic identifier and
string-wrapping corrections preserved runtime values, and the second lint/format
pass succeeded. Both diagnostic sets remain; static checks consumed no native cases.

The additive [closure and final output accounting](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/validation-closure.json)
and [seal](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/manifest.json)
record final inventory and bytes. Preservation is complete; the native pilot is
closed at a build blocker, not successful correspondence. A source-only compiler
compatibility correction contract is the sole next recommendation, not started.
Stages 2–3 and AURORA-BRIDGE-001 remain open. Proof ledger two used/one unused;
no proofs/zkVM, host activation or additional native work.
