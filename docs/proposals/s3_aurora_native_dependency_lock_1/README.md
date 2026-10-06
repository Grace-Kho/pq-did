# Native EXP2 dependency provisioning proposal

**Not executed. Project-local provisioning approval and the resource delta below
are required. Native build admission remains pending.**

The [proposed lock](../../data/s3_aurora_native_dependency_lock_1/dependency-lock.json)
pins libiop, the top-level libff and libfqfft revisions, two Ubuntu development
archives, selected dependency edges and unused nested gitlinks. This is not a
production dependency update. The library patch and native harness still need to
be implemented under the existing native-pilot authorisation after provisioning.

## Proposed approvals and resource admission

Approve acquisition and extraction only into the fresh directory
`experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1`. No root,
system installation, maintainer scripts, shell startup changes, `.venv` changes,
liboqs changes or service operations are proposed.

Consolidated resource delta, **inactive**: count downloaded packages, Git objects,
source checkouts and compiled outputs together under the existing 128 MiB native
artifact ceiling, with a 32 MiB acquisition reservation. Permit binary archives,
Git packs, objects and executables up to 32 MiB each; the inherited 1 MiB per-file
limit remains for source and metadata. This exception is needed because complete
static archives and Git packs are not known to fit 1 MiB; it does not increase
the aggregate 128 MiB. Keep logs/reports/evidence separately within 2 MiB and the
current cumulative evidence cap. Approve at most 60 seconds for acquisition and
its checks, charged to the existing native/implementation balances, not analysis.
No extra overall seconds, native invocations or build attempts are requested.

One worker, at most two CPUs, 1 GiB native memory, zero swap, 60-second command /
55-second child limits, 8 MiB temporary space, 60 KiB per-command diagnostic stop,
the existing 9 GiB experimental-storage stop and 256 MiB audit limit remain.
Use the native cgroup guard with the approved narrow artifact-file exception;
do not run the commands below unguarded. Stop before a command unless its deadline,
remaining work and the final 30-second native reserve fit. No automatic retries.

An admission envelope is 60 s acquisition + two 55 s build attempts + sixteen
2 s case deadlines + 17 s checks/bookkeeping/audit + 30 s reserve = 249 s, below
291.751 s. These are reservations, **not measured build or network estimates**.
The unused eight native invocations are not automatically scheduled. If acquisition
or compilation cannot fit, preserve the result and stop; no extra attempt follows.

## Acquire exact sources, only after approval

Run from the project root in one guarded shell. Refuse an existing destination:

```sh
set -eu
umask 077
task_root=/home/grace/projects/pq-did/experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1
test ! -e "$task_root"
mkdir -p "$task_root/src" "$task_root/packages" "$task_root/prefix" "$task_root/evidence"
fetch_pin() {
  repo_name=$1
  repo_commit=$2
  git -c init.templateDir= init "$task_root/src/$repo_name"
  git -C "$task_root/src/$repo_name" remote add origin "https://github.com/scipr-lab/$repo_name.git"
  git -C "$task_root/src/$repo_name" -c core.hooksPath=/dev/null fetch --no-tags --depth=1 origin "$repo_commit"
  git -C "$task_root/src/$repo_name" -c core.hooksPath=/dev/null checkout --detach "$repo_commit"
  test "$(git -C "$task_root/src/$repo_name" rev-parse HEAD)" = "$repo_commit"
  git -C "$task_root/src/$repo_name" fsck --full
}
fetch_pin libiop a2ed2ec2f3e85f29b6035951553b02cb737c817a
fetch_pin libff 9769030a06b7ab933d6c064db120019decd359f1
fetch_pin libfqfft 7d460caa27b87574fe0e8144e6a3a66b7bcfe770
```

Do not use `--recurse-submodules` or initialise optional nested dependencies.
The complete selected repository trees, including unused source files, are kept.
Their declared gitlinks must match the lock; uninitialised optional gitlinks are
explicitly accounted for, not falsely reported as a complete recursive checkout.
The libfqfft nested libff `accdf9e…` is distinct from the selected top-level libff.
The parent-disabled/header-only selection follows libiop's own dependency layout.

Verify each checkout's `git rev-parse HEAD^{tree}` and `git ls-tree -r -z HEAD`
against its retained API tree: mode, type, name, blob/gitlink ID, length and full
inventory. Independently `git hash-object --no-filters` each tracked blob and
check no missing/untracked files (`git status --porcelain --untracked-files=all`).
Require the 21 retained libiop files from both bridge `sources*.json` manifests
to match byte length, SHA-256 and Git blob SHA-1 before applying any patch. Also
compare the eight historical experiment copies. Record a new acquisition inventory;
do not replace their original manifests or modify their protected source copies.

## Acquire and inspect development packages

The following URLs, sizes and SHA-256 values come from retained Ubuntu package
metadata. They are exact pins, not a claim that archive bytes were fetched or that
the cached index signature was newly authenticated. These commands belong to the
same approved guarded session; each network command has a 10-second timeout.

```sh
curl --fail --location --max-time 10 --max-filesize 187214 \
  https://archive.ubuntu.com/ubuntu/pool/main/libs/libsodium/libsodium-dev_1.0.18-2_amd64.deb \
  -o "$task_root/packages/libsodium-dev_1.0.18-2_amd64.deb"
curl --fail --location --max-time 10 --max-filesize 341530 \
  https://archive.ubuntu.com/ubuntu/pool/main/g/gmp/libgmp-dev_6.3.0+dfsg-5ubuntu2_amd64.deb \
  -o "$task_root/packages/libgmp-dev_6.3.0+dfsg-5ubuntu2_amd64.deb"
printf '%s  %s\n' \
  34e8337b30160458f44bada750c9e94ec18ec5ac087e2428043ddb04625226cc "$task_root/packages/libsodium-dev_1.0.18-2_amd64.deb" \
  b43e38f2d5ae4aa38471e1b3f90ed63e96c2ce614ffe496cdcd72f9944e87a4a "$task_root/packages/libgmp-dev_6.3.0+dfsg-5ubuntu2_amd64.deb" \
  | sha256sum --check --strict
dpkg-deb --field "$task_root/packages/libsodium-dev_1.0.18-2_amd64.deb" Package Version Architecture Depends
dpkg-deb --field "$task_root/packages/libgmp-dev_6.3.0+dfsg-5ubuntu2_amd64.deb" Package Version Architecture Depends
dpkg-deb --contents "$task_root/packages/libsodium-dev_1.0.18-2_amd64.deb"
dpkg-deb --contents "$task_root/packages/libgmp-dev_6.3.0+dfsg-5ubuntu2_amd64.deb"
```

Stop unless package/version/architecture/size match the lock and the archive
contains the stated headers/static libraries as regular files. Inspect the full
member list and link targets before extraction: reject absolute paths, `..`, device
nodes, unexpected executable hooks or links escaping the fresh prefix. An acquired
archive's content check is required even though the distribution file lists were
successfully read. Then, and only then:

```sh
dpkg-deb --extract "$task_root/packages/libsodium-dev_1.0.18-2_amd64.deb" "$task_root/prefix"
dpkg-deb --extract "$task_root/packages/libgmp-dev_6.3.0+dfsg-5ubuntu2_amd64.deb" "$task_root/prefix"
test -f "$task_root/prefix/usr/include/sodium/crypto_generichash_blake2b.h"
test -f "$task_root/prefix/usr/include/sodium/randombytes.h"
test -f "$task_root/prefix/usr/include/x86_64-linux-gnu/gmp.h"
test -f "$task_root/prefix/usr/lib/x86_64-linux-gnu/libsodium.a"
test -f "$task_root/prefix/usr/lib/x86_64-linux-gnu/libgmp.a"
```

No `dpkg -i`, `apt install`, `ldconfig` or global environment updates. Extracting
does not install maintainer scripts or satisfy dpkg dependencies. Link the explicit
static C libraries above: unused `libgmpxx` and `.so` symlinks are not selected.
The archive package dependencies remain in the lock for transparency; this is
not a proposed partial system installation. Read sodium/version.h and GMP version
macros, inspect `ar t` and `readelf` of selected archive members and record ABI/path
agreement with the unchanged amd64 toolchain. A filename or successful extraction
alone does not establish that agreement. If `curl`, `ar` or another acquisition
tool is unavailable at admission, stop; do not install it or silently substitute.

## Resume the existing native pilot

1. Seal acquisition evidence and reconcile actual bytes/time against both the
   native and implementation ledgers. Preserve the earlier dependency-blocked
   result and STOP records. Use a separately recorded authorised continuation.
2. In the fresh checkout implement exactly EXP2's recorded native correction and
   caller adaptations; keep an unchanged commit checkout and a reviewable patch.
   Reuse the 16 definitions and independent Python expectation files. No new oracle
   output, private witnesses or stand-alone C++ substitute for the native library.
3. Copy the [proposed target](minimal-native.cmake.txt) into the isolated overlay
   as `CMakeLists.txt` only after approval. `ff` is upstream; `iop_native` uses the
   same eight C++ library sources as the pinned iop target. The complete ff target
   includes unused curve code, a conservative support-library build cost, rather
   than an unverified hand-pruned replacement. No upstream benchmarks/tests,
   procps, OpenMP, Boost instrumentation, pairing `zm` or xbyak are selected.
4. The proposed build command below runs only under the native guard. Configuration
   and all dependency compilation count together as build attempt one; a build-only
   correction may use attempt two. CMake compiler detection is part of that attempt.
   No separate uncounted compile probes or dependency build attempts.

```sh
env -u CMAKE_PREFIX_PATH -u PKG_CONFIG_PATH -u LD_LIBRARY_PATH CCACHE_DISABLE=1 \
  cmake -S "$task_root/overlay" -B "$task_root/build" -G Ninja \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_BUILD_TYPE=Release \
  '-DCMAKE_CXX_FLAGS_RELEASE=-O0 -g0' '-DCMAKE_C_FLAGS_RELEASE=-O0 -g0' \
  -DPQ_SOURCE="$task_root/src" -DPQ_PREFIX="$task_root/prefix" \
  -DPQ_HARNESS="$task_root/overlay/exp2_native.cpp"
cmake --build "$task_root/build" --target exp2_native --parallel 1
```

The old libff minimum CMake 2.8 requires the explicit policy compatibility setting
with installed CMake 4.2.3. This is a documented proposed build setting, not a
successful configuration. `CURVE_ALT_BN128` selects a support default and avoids
BN128-only pairing dependencies; transcript `FieldT` stays native `libff::gf192`.
No active scheme/field/security parameter changes. Verify preprocessor/build
commands and resolved paths; no fallback to global headers or a different libff.

5. Require real native EXP2 initialisation, BCS round absorption, separate messages
   and challenge generation; record whether `signal_prover_round_done`,
   `seal_interaction_registrations`, `run_hashchain_for_round`, message absorption
   and verifier/query challenge callers were actually reached. Test access to a
   protected method may expose the real method but must not replace it. The Aurora
   full proving wrapper remains unexecuted; compilation alone is not caller coverage.
6. Run TR-01 through TR-16 once, in order, within 24 available invocations. TR-16
   is the old native omission control if supported, not a forgery. Stop at the first
   unexpected transcript/rejection mismatch, missing real path, resource breach or
   incomplete result. Keep algebraic primary-input checks distinct from the old
   missing explicit hash-chain initialisation. No proofs or zkVM work.
7. Reserve the final 30 native seconds for reporting, cleanup and one corrected
   preservation audit at 256 MiB. Report each executed path and all untested paths;
   reuse all prior evidence, including every repair artifact in the expected inventory.

## Cleanup

Guard timeout kills only that worker cgroup and descendants. Do not use process-name
matching. After it exits, retain packages, sources, patch, failed binaries, logs,
hashes and STOP records inside the isolated prefix; record size and absence of live
worker processes. No recursive deletion of the prefix or historical artifacts is
part of this proposal. Temporary command-local scratch may be removed only from
its recorded empty/disposable paths after evidence is saved. Do not remove retained
evidence to meet a limit. An overrun stops admission and requires review.
