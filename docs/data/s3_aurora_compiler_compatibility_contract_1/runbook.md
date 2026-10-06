# Inactive single-build request

**No command below was executed in S3-AURORA-COMPILER-COMPATIBILITY-CONTRACT-1.**
Both native builds remain consumed. The user must authorise one additional attempt
and the eight additional semantic case definitions within the existing 24 unused
invocations. Source selection remains libiop
`a2ed2ec2f3e85f29b6035951553b02cb737c817a`; no dependency revision changes.

Read [the contract](../../stage3_aurora_compiler_compatibility_contract.md),
[proposal.json](proposal.json) and [reviewed-inputs.json](reviewed-inputs.json).
All patch/source artifact SHA-256 values in the proposal are authoritative inputs
for the request. Verify the new package seal plus the prior native seal
`f3125c0cdbee596222ebf0736a8647afc94d37a02e21511fec2d5dffe3d2bd56` before mutation.
Require retained canonical input files, 16 expectation digests, old CMake overlay and
patched EXP2 files to match their historical manifests. Do not regenerate old seals.

## Future preparation, only within a newly approved guard

Use a fresh child of the already designated isolated artifact root. The old acquired
and patched trees, overlay, build outputs and logs remain preserved. These commands
require all preceding hash/resource checks; `cp` copies sources, it runs no scripts.
Record their actual durations and output sizes. The existing systemd cgroup workflow
must place all preparation/build/case descendants under its approved limits.

```sh
set -eu
umask 077
cd /home/grace/projects/pq-did
task_base=/home/grace/projects/pq-did/experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1
task_contract=/home/grace/projects/pq-did/docs/data/s3_aurora_compiler_compatibility_contract_1
task_next="$task_base/compatibility-v1"
test ! -e "$task_next"
mkdir "$task_next"
cp -a "$task_base/work" "$task_next/work"
cp -a "$task_base/overlay" "$task_next/overlay"
git --no-replace-objects -C "$task_next/work/libiop" apply --check "$task_contract/variable-members.patch"
git --no-replace-objects -C "$task_next/work/libiop" apply "$task_contract/variable-members.patch"
git --no-replace-objects -C "$task_next/overlay" apply --check "$task_contract/semantic-target.patch"
git --no-replace-objects -C "$task_next/overlay" apply "$task_contract/semantic-target.patch"
cp "$task_contract/semantic_cases.cpp" "$task_next/overlay/semantic_cases.cpp"
```

Require only `libiop/relations/variable.tcc` in the copied work tree to differ from
the retained EXP2 copy, with the proposed postimage digest. The overlay differs
only by its recorded CMake addition and the new semantic driver; the copied EXP2
harness and public canonical inputs must remain byte-identical. Do not initialise
optional submodules, alter include search paths globally or install anything.

## One build attempt, configuration included

Both commands together count as the one newly requested build attempt. Use a single
55-second build deadline (60-second outer command maximum), one build worker,
1 GiB cgroup memory/zero swap, two CPUs, existing process/artifact/diagnostic limits.
Record compiler-probe and linker output within that attempt. A configure failure
also consumes it. Do not run any test target during compilation.

```sh
env -u CMAKE_PREFIX_PATH -u PKG_CONFIG_PATH -u LD_LIBRARY_PATH CCACHE_DISABLE=1 \
  cmake -S "$task_next/overlay" -B "$task_next/build" -G Ninja \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_BUILD_TYPE=Release \
  '-DCMAKE_CXX_FLAGS_RELEASE=-O0 -g0' '-DCMAKE_C_FLAGS_RELEASE=-O0 -g0' \
  -DPQ_SOURCE="$task_next/work" -DPQ_PREFIX="$task_base/prefix" \
  -DPQ_HARNESS="$task_next/overlay/exp2_native.cpp" \
  -DPQ_SEMANTICS="$task_next/overlay/semantic_cases.cpp"
env -u CMAKE_PREFIX_PATH -u PKG_CONFIG_PATH -u LD_LIBRARY_PATH CCACHE_DISABLE=1 \
  cmake --build "$task_next/build" --target exp2_native exp2_semantics --parallel 1
```

Success must produce both expected executable targets and complete linking. Verify
actual compiler/include/link command lines against the unchanged local sodium/GMP
static paths; no permissive/suppression flags or substituted FieldT. Any unexpected
error ends the attempt. No source fix, renamed target, removed translation unit or
second build follows automatically.

## Exact future invocation sequence

Only after the successful build, admit SEM-01 through SEM-08 once, sequentially,
using literal arguments 1 through 8 in order. These are eight individually recorded
processes, each with a two-second deadline, not one aggregate test. The command for
each is `"$task_next/build/exp2_semantics" N`. Stop at the first nonzero exit,
unexpected output, incomplete result or resource failure. Expected one-line output
is `SEM-N pass` plus the successful exit, with assertions inside the public driver.
Its use of characteristic two is explicit and does not cover odd-prime negation.

If all eight pass, run TR-01 through TR-16 once in order using the retained native
case-comparison worker, rebased only to the new binary/public-input/evidence paths.
Keep expected files at `docs/data/s3_aurora_transcript_regression_1/TR-NN.json` and
verify the exact hashes in the retained native case plan. Do not rewrite expected
results or Python EXP2. Commands are `"$task_next/build/exp2_native" N INPUT`, where
INPUT is `"$task_next/overlay/nonce-mutated.bin"` for N=3 and
`"$task_next/overlay/canonical.bin"` otherwise. Each exit/output is compared using
the original case definitions; TR-02 remains a counted repeat and TR-16 a labelled
omission negative control, never a forgery test. The worker must preserve both raw
native output and its independent expectation identity, with no admission after a
mismatch. A fresh guard namespace is necessary; do not bypass the old STOP records.

This proposes 24 invocations, including all comparisons and the two labelled
controls/repeat already in the matrix. Cumulative count would be 402 → 426; no
extra ceiling amendment or retries. Every failed or partially admitted case counts.
Static patch/header/artifact checks remain separately accounted and cannot conceal
compiler/native probes. Full proof generation and private witnesses are excluded.

## Consolidated approval and resource admission

Request: one extra build attempt (2 → 3), this exact library patch/CMake semantic
target/driver in the fresh isolated subtree, eight semantic cases and the existing
sixteen transcript cases. The library edit is functional and conditional on those
checks. No time, memory, output, artifact or invocation-ceiling increase is requested.

Reserve 150 seconds from existing native/implementation balances: 55 build,
48 cases, 17 preparation/static/bookkeeping, 30 final audit/report/cleanup. Use
only actually remaining balances, retaining the final 30 seconds. No borrowing from
analysis, isolation or provisioning. Current 264.371873684/268.929253343 seconds
are sufficient for admission, not evidence of completion runtime.

Reserve at most 32 MiB new artifacts under the existing aggregate 128 MiB cap,
and 393,216 new native evidence bytes under both the cumulative 12,386,485 and
native 2 MiB limits. Reconcile actual post-contract headroom first. Ordinary source,
JSON and logs keep their limits; the 32 MiB per-file exception covers only designated
binary/Git/build artifacts. All retained data continues to count. Stop before
admitting work if finalisation headroom is insufficient.

After failure or completion, stop new workload admission, retain all new/old files,
confirm guarded descendants have exited and temporary data is empty, run the
established preservation workflow under 256 MiB, and append outcome/ledgers/status.
Preservation success must not be reported as compilation or native correspondence.
No deletion of retained evidence, database operations, host activation or package
installation is part of cleanup. AURORA-BRIDGE-001 and Stages 2–3 remain open.
