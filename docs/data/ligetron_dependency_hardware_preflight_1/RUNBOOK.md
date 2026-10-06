# Inactive runbook — requires the single proposal approval

No commands below were executed during preparation. New tooling mentioned below
is an implementation deliverable, not a claim that it already exists. Use the
existing guarded-launch/accounting conventions and normal command approval path.
Keep all outputs under the registered new experiment/evidence directories. Never
run these commands against either completed overlay directory.

## 1. Admission and exact acquisition

Before a download/build, read `resource-closure.json`, the approved amendment and
`dependency-lock.proposed.json`. Recheck Windows free and WSL available memory,
backing disk space, shared evidence reserve and package balances. A2 GiB worker
requires >=4 GiB available in both host and guest. The recorded host observation
does not pass; stop until sufficient headroom is observed. No setting/driver change
is authorised by this proposal. Serial work only; no package scripts or sudo.

Proposed directory variables for each command (not shell-profile modifications):

```sh
LIG_WORK=/home/grace/projects/pq-did/experiments/ligetron_full_path_engineering_1
LIG_PREFIX="$LIG_WORK/prefix"
LIG_LIB="$LIG_PREFIX/usr/lib/x86_64-linux-gnu"
```

Acquisition harness to implement: `acquire.py --lock <dependency-lock> --packages
<package-closure> --root <LIG_WORK> --max-artifact-bytes 4294967296`. It must wrap
each network operation with120-second timeout, monitor source/Git/download/
extraction/scratch totals, verify expected commit objects and package digests,
and retain diagnostics. It must not execute DEPS, hooks or installation scripts.
The exact Git operation template for each `origin`, `commit`, `path` in the lock:

```sh
git -c core.hooksPath=/dev/null init "$LIG_WORK/src/$DEPENDENCY_PATH"
git -C "$LIG_WORK/src/$DEPENDENCY_PATH" -c core.hooksPath=/dev/null remote add origin "$PINNED_ORIGIN"
git -C "$LIG_WORK/src/$DEPENDENCY_PATH" -c core.hooksPath=/dev/null fetch --depth=1 origin "$PINNED_COMMIT"
GIT_NO_REPLACE_OBJECTS=1 git -C "$LIG_WORK/src/$DEPENDENCY_PATH" cat-file -t "$PINNED_COMMIT"
GIT_NO_REPLACE_OBJECTS=1 git -C "$LIG_WORK/src/$DEPENDENCY_PATH" cat-file -p "$PINNED_COMMIT"
GIT_NO_REPLACE_OBJECTS=1 git -C "$LIG_WORK/src/$DEPENDENCY_PATH" rev-parse "$PINNED_COMMIT^{tree}"
git -C "$LIG_WORK/src/$DEPENDENCY_PATH" fsck --full
git -C "$LIG_WORK/src/$DEPENDENCY_PATH" -c core.hooksPath=/dev/null checkout --detach "$PINNED_COMMIT"
```

Use existing verified Git data if present; no forced checkout or overwrite of
retained sources. The depth fetch may transfer large packs; filesystem monitoring
and the byte cap remain mandatory. Record commit/tree/blob membership, not merely
the checkout name. An absent exact object stops acquisition; no branch substitution.
For Dawn's seven required DEPS repositories, place them at the exact nested paths
in the lock. Do not run recursive submodule update or fetch all DEPS. Verify
transitive build metadata before configuration; only the selected exact pins may
be acquired. Extra required unpinned components stop the affected route.

For each uninstalled package in `package-closure.json`, use its recorded Origin,
Filename, exact Version, Architecture, Size and SHA256. Build the URL from its
recorded Ubuntu source URI plus Filename, not a latest-package query. Acquisition
may use HTTPS for the same official archive identity. First verify the payload
SHA256/length; inspect `dpkg-deb --info` and `dpkg-deb --fsys-tarfile` as data for
safe members and symlinks; then `dpkg-deb --extract FILE "$LIG_PREFIX"`. Do not use
`dpkg -i`, apt installation, maintainer scripts or package triggers. Preserve
downloaded originals and content manifests. Revalidate every selected dependency
constraint and all reused installed runtime versions. If the local APT index is
stale or an exact file unavailable, stop; do not update pins automatically.

Verify the two existing patch digests, original retained source bytes and patch
applicability. Apply in this order to `$LIG_WORK/src/ligero` only:

```sh
git -C "$LIG_WORK/src/ligero" apply --check /home/grace/projects/pq-did/docs/data/ligetron_correction_admission_1/reviewed-overlay.patch
git -C "$LIG_WORK/src/ligero" apply /home/grace/projects/pq-did/docs/data/ligetron_correction_admission_1/reviewed-overlay.patch
git -C "$LIG_WORK/src/ligero" apply --check /home/grace/projects/pq-did/docs/data/ligetron_domain_mask_correction_1/reviewed-overlay.patch
git -C "$LIG_WORK/src/ligero" apply /home/grace/projects/pq-did/docs/data/ligetron_domain_mask_correction_1/reviewed-overlay.patch
```

Hash and register the separately reviewed third integration overlay before its
build. For local CMake wiring replace the unpinned JSON FetchContent download with
the verified3.11.3 package's `find_package(nlohmann_json 3.11.3 CONFIG REQUIRED)`.
Guard upstream tests with BUILD_TESTING; do not build unrelated suites. Preserve
required verifier checks and compiler errors; no permissive mode or mocks.

## 2. Counted isolated builds

Each configure plus associated build/install is one counted attempt. Compiler
checks during CMake belong to that attempt. An additional configure/rebuild after
correction uses the single fourth corrective slot. Pre-configuration package
header/archive inspection is not a compiler probe. Scratch and output artifacts
stay inside the registered work root and aggregate4 GiB; logs remain evidence.
Use an existing guard with MemoryMax=2G, one build worker, monitored descendant
memory and storage, and the stated per-build timeout. GNU `timeout` alone does not
enforce aggregate memory/storage. Do not request a larger limit on failure.

**Build1: Dawn** (up to3600 seconds; includes configuration/generators).

```sh
env TMPDIR="$LIG_WORK/scratch" PYTHONDONTWRITEBYTECODE=1 \
cmake -S "$LIG_WORK/src/dawn" -B "$LIG_WORK/build/dawn" -G Ninja \
 -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc-15 -DCMAKE_CXX_COMPILER=g++-15 \
 -DCMAKE_INSTALL_PREFIX="$LIG_PREFIX" -DBUILD_SHARED_LIBS=OFF \
 -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DDAWN_ENABLE_PIC=ON \
 -DDAWN_FETCH_DEPENDENCIES=OFF -DDAWN_BUILD_MONOLITHIC_LIBRARY=STATIC \
 -DDAWN_ENABLE_INSTALL=ON -DDAWN_ENABLE_VULKAN=ON -DDAWN_ENABLE_SPIRV_VALIDATION=ON \
 -DDAWN_ENABLE_D3D11=OFF -DDAWN_ENABLE_D3D12=OFF -DDAWN_ENABLE_METAL=OFF \
 -DDAWN_ENABLE_NULL=OFF -DDAWN_ENABLE_DESKTOP_GL=OFF -DDAWN_ENABLE_OPENGLES=OFF \
 -DDAWN_ENABLE_WEBGPU_ON_WEBGPU=OFF -DDAWN_ENABLE_SWIFTSHADER=OFF \
 -DDAWN_USE_GLFW=OFF -DDAWN_USE_X11=OFF -DDAWN_USE_WAYLAND=OFF \
 -DDAWN_BUILD_SAMPLES=OFF -DDAWN_BUILD_TESTS=OFF -DDAWN_BUILD_BENCHMARKS=OFF \
 -DDAWN_BUILD_NODE_BINDINGS=OFF -DDAWN_BUILD_PROTOBUF=OFF \
 -DTINT_BUILD_CMD_TOOLS=OFF -DTINT_BUILD_TESTS=OFF -DTINT_BUILD_BENCHMARKS=OFF \
 -DTINT_BUILD_FUZZERS=OFF -DTINT_BUILD_IR_BINARY=OFF -DTINT_BUILD_TINTD=OFF \
 -DTINT_BUILD_SPV_READER=ON -DTINT_BUILD_SPV_WRITER=ON -DTINT_BUILD_WGSL_READER=ON \
 -DTINT_BUILD_GLSL_WRITER=OFF -DTINT_BUILD_GLSL_VALIDATOR=OFF \
 -DTINT_BUILD_HLSL_WRITER=OFF -DTINT_BUILD_MSL_WRITER=OFF
env TMPDIR="$LIG_WORK/scratch" cmake --build "$LIG_WORK/build/dawn" --target webgpu_dawn --parallel 1
cmake --install "$LIG_WORK/build/dawn"
```

Verify that install does not demand unbuilt unrelated targets. If it does, use
the counted correction slot for supported install-target wiring, not an uncounted
second build. Check all passed options exist and take effect; unsupported options
are a build-wiring problem, not permission for silent default dependency expansion.
Keep the installed full Dawn header/API and static library from this same build.

**Build2: WABT** (up to300 seconds; no test, WASI or wasm-c-api dependency).

```sh
env TMPDIR="$LIG_WORK/scratch" LD_LIBRARY_PATH="$LIG_LIB" \
cmake -S "$LIG_WORK/src/wabt" -B "$LIG_WORK/build/wabt" -G Ninja \
 -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc-15 -DCMAKE_CXX_COMPILER=g++-15 \
 -DCMAKE_INSTALL_PREFIX="$LIG_PREFIX" -DCMAKE_PREFIX_PATH="$LIG_PREFIX/usr" \
 -DOPENSSL_ROOT_DIR="$LIG_PREFIX/usr" -DBUILD_TESTS=OFF -DBUILD_LIBWASM=OFF \
 -DBUILD_TOOLS=ON -DBUILD_FUZZ_TOOLS=OFF -DWITH_WASI=OFF \
 -DUSE_INTERNAL_SHA256=OFF -DWABT_INSTALL_RULES=ON
env TMPDIR="$LIG_WORK/scratch" cmake --build "$LIG_WORK/build/wabt" --parallel 1
cmake --install "$LIG_WORK/build/wabt"
```

Build the supplied ordinary tools once to satisfy their install rules; no test
execution. Check that OpenSSL was actually found, otherwise stop instead of using
unacquired PicoSHA2. WABT source/tag identity does not establish Ligetron API
compatibility. Do not change the WABT revision to obtain a compile pass.

**Build3: Ligetron and focused harness** (up to600 seconds).
Implement the third overlay and `ligetron_path_checks` target first. Protobuf
generator and headers must both be3.21.12-15ubuntu1. Keep all process environment
changes scoped; do not replace system libraries or the existing Python environment.

```sh
env TMPDIR="$LIG_WORK/scratch" LD_LIBRARY_PATH="$LIG_LIB" \
cmake -S "$LIG_WORK/src/ligero" -B "$LIG_WORK/build/ligero" -G Ninja \
 -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc-15 -DCMAKE_CXX_COMPILER=g++-15 \
 -DCMAKE_PREFIX_PATH="$LIG_PREFIX;$LIG_PREFIX/usr;$LIG_PREFIX/usr/lib/x86_64-linux-gnu/cmake" \
 -DCMAKE_INCLUDE_PATH="$LIG_PREFIX/usr/include;$LIG_PREFIX/usr/include/x86_64-linux-gnu" \
 -DCMAKE_LIBRARY_PATH="$LIG_LIB;$LIG_PREFIX/lib" \
 -DOPENSSL_ROOT_DIR="$LIG_PREFIX/usr" \
 -DProtobuf_PROTOC_EXECUTABLE="$LIG_PREFIX/usr/bin/protoc" \
 -DBUILD_TESTING=OFF -DPQDID_BUILD_FOCUSED_PATH_CHECKS=ON
env TMPDIR="$LIG_WORK/scratch" LD_LIBRARY_PATH="$LIG_LIB" \
cmake --build "$LIG_WORK/build/ligero" \
 --target webgpu_prover webgpu_verifier ligetron_path_checks --parallel 1
```

The focused target name/option is new approved-scope wiring to implement, not an
existing upstream target. Assembly of the tiny WAT is part of this build. Seal
all binary/library/header/shader inputs. No additional syntax-only probes.

## 3. Explicit checks and proof gate

Implement `cases.py --case E01 ... --case E40` as **separate invocations**, each
with frozen independent expectations, bounded output and resource accounting.
The actual command interface for the new harness is:

```sh
env LD_LIBRARY_PATH="$LIG_LIB:$LIG_PREFIX/lib" \
 "$LIG_WORK/build/ligero/ligetron_path_checks" --case E01 \
 --shader-dir "$LIG_WORK/build/ligero/shader" --expectations "$LIG_WORK/expectations.json"
```

E01 must report actual Dawn adapter identity, backend/type, features and limits;
no successful empty/no-op/mock result. If software Vulkan is selected, record it
on every result. Optional command-scoped VK_ICD_FILENAMES may select the *existing*
read-back-verified lvp ICD; do not alter system configuration. No software adapter
result may be relabelled hardware GPU. Lack of any eligible adapter stops E02–E19
and the proof gate; independent CPU parser/binding work may finish within scope.

E02–E35 use the exact matrix in PROPOSAL.md, sequentially, recording full outcomes
including expected rejections. Cases needing a failed predecessor stay unrun.
New native resource bounds must fit before every admission and preserve300 seconds
for finalisation. Derive a conservative operation count from VM steps, rows,
transform butterflies, field operations, sampler attempts and dispatch dimensions;
do not count one GPU dispatch as one work event. Historical usage is never reset.

E36 may run only if the one *new* synthetic proof attempt is approved, all applicable
E01–E35 checks pass, the complete tiny program constraint/buffer schedule fits and
no known correctness issue affects it. The new driver calls the actual
`webgpu_prover` with a bounded canonical JSON configuration, x=7 private-designated
but publicly documented, y=49 public, fixed compiled program and expected statement.
Record stdout/stderr and encoded proof separately. E37 invokes the standalone
`webgpu_verifier` in a fresh process with the public configuration and proof only;
E38–E40 reuse that same proof with their specified one mutation. No additional
proof generation to retry or manufacture an expected rejection.

## 4. Finalisation

One consolidated preservation checkpoint, inventories, report seals/readback,
precise consumed/unused allocations, and one ZIP containing the new report, exact
patch stack/provenance, dependency lock, commands, harness, expected values, all
outcomes/failures, closures and README/checksums. No historical test reruns merely
for preservation. Stop/terminate workers and remove only registered expendable
scratch if needed; retain unsuccessful results and partial build evidence.
