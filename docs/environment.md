# Verified development environment

Inspected and smoke-tested on 17 September 2026 (Asia/Singapore). This records
environment readiness, not protocol correctness, a security proof or performance.

## Execution environment and resources

This workspace is `/home/grace/projects/pq-did` in the user's local Ubuntu WSL2
distribution. VS Code runs on Windows and connects through its WSL server; this is
not an independently provisioned remote research server. Commands issued by the
assistant additionally ran under a filesystem/network sandbox. Network downloads,
VS Code IPC and Windows host inventory required execution outside that sandbox.

| Item | Observed value |
|---|---|
| Windows host | Windows 11 Home, 10.0.26200; WSL reports build 26200.9457 |
| Physical processor | Intel Core i7-14650HX; Windows reports 16 cores / 24 logical processors |
| Host usable RAM | 16,389,632 KiB, approximately 15.63 GiB; approximately 3.53 GiB free at inspection |
| Windows C: free space | 408,980,226,048 bytes, approximately 380.9 GiB at inspection |
| WSL | 2.7.14.0; `wsl.exe --list --verbose` reports Ubuntu Running, version 2 |
| Guest OS | Ubuntu 26.04.1 LTS, x86_64; glibc 2.43 |
| Guest kernel | 6.18.33.2-microsoft-standard-WSL2 |
| Guest processor view | 24 logical CPUs; virtual topology reports 12 cores × 2 threads, distinct from host topology |
| Guest memory | 8,126,111,744 bytes (7.57 GiB); 5,883,547,648 bytes (5.48 GiB) available after setup |
| Swap | 2 GiB, unused at inspection |
| Project filesystem | `/dev/sdd`; about 951.5 GiB available in the virtual filesystem after setup |
| `/tmp` | RAM-backed tmpfs, about 3.78 GiB capacity |
| Process cgroup | `/init.scope`; `memory.max=max`, `memory.high=max`, `cpu.max=max 100000` |

The virtual filesystem's reported free space is not a physical host storage guarantee.
The Windows disk backing the distribution has less free space. No additional cgroup
memory/CPU quota was found for this process; the WSL guest limit still applies.
No `/mnt/c/Users/Grace/.wslconfig` was present; no resource limits were changed.

Both native build invocations explicitly use `--parallel 2`; VS Code also sets
`CMAKE_BUILD_PARALLEL_LEVEL=2`. No proving process or benchmark was run. The plan's
tentative 8 GiB prover budget cannot fit within the current guest's entire 7.57 GiB
RAM allocation; choose measured memory/scratch budgets before future circuit work.
Do not store large future proofs in the RAM-backed `/tmp`.

## Tools and dependencies

| Tool | Verified version |
|---|---|
| CPython | 3.14.4, `/usr/bin/python3.14`; reused, not downloaded |
| Project interpreter | `/home/grace/projects/pq-did/.venv/bin/python`, Python 3.14.4 |
| Git | 2.53.0 |
| GCC / G++ | 15.2.0, Ubuntu build `15.2.0-16ubuntu1` |
| GNU Make | 4.4.1 |
| CMake | 4.2.3 |
| Ninja | 1.13.2 |
| pkg-config | 2.5.1 |
| uv | 0.12.15, `.tools/uv`, wheel SHA-256 checked by `bootstrap_uv.py` |
| Hash backend | Python `hashlib`, `_hashlib` / OpenSSL 3.5.5 (27 January 2026) |
| VS Code | 1.137.0, commit `645f29cc3176500b4b5762ba887cf2a7f0ffdf2c` |

Exact installed Python packages: `pqdid==0.0.1` (editable), `liboqs-python==0.16.0`,
`pytest==9.1.1`, `ruff==0.16.8`, `iniconfig==2.3.0`, `packaging==26.3`,
`pluggy==1.6.0`, `pygments==2.21.0`, `hatchling==1.32.0`, `editables==0.5`,
`pathspec==1.1.1`, `tomlkit==0.15.1`, `trove-classifiers==2026.6.1.19`.
Hatchling, editables and their dependencies are the locked build toolchain, installed
before `--no-build-isolation` builds. `colorama==0.4.6` appears in the cross-platform
lock as a Windows-only pytest dependency and is not installed on Linux.
No application server, database, circuit/proof framework or benchmark dependency
was installed. A temporary, checksum-verified pypdf 6.19.0 wheel in `/tmp` was used
to read the manuscript before Poppler became available; it is not a project dependency.

The user executed the Ubuntu prerequisite installation after sudo requested interactive
authentication. Package presence and subsequent compilation were independently verified:

```text
build-essential  12.12ubuntu2.26.04.2
gcc, g++         4:15.2.0-5ubuntu1 (metapackages)
binutils         2.46-3ubuntu2
libc6-dev        2.43-2ubuntu2.4
make             4.4.1-3
cmake            4.2.3-2ubuntu2
ninja-build      1.13.2-1
pkg-config       2.5.1-4
python3-venv     3.14.3-0ubuntu2 (metapackage)
python3.14       3.14.4-1ubuntu0.2
python3.14-venv  3.14.4-1ubuntu0.2
poppler-utils    26.01.0-2ubuntu0.1
git              1:2.53.0-1ubuntu1
```

OS packages are recorded, not frozen to a container/snapshot. `uv.lock` locks Python
sources/wheels with hashes; `.python-version` records the exact interpreter;
`native/dependencies.json` locks native source and build options. This reproduces the
selected dependencies/build configuration, not a claim of bit-identical OS binaries.

## ML-DSA backend decision

Selected the matching official **liboqs 0.16.0 / liboqs-python 0.16.0** releases after
source inspection and successful execution. This integration met the requested API
requirements, so a replacement backend was unnecessary. liboqs itself vendors
mldsa-native for ML-DSA in this release; no second standalone copy or `cryptography`
package was installed. See the official [liboqs release](https://github.com/open-quantum-safe/liboqs/releases/tag/0.16.0)
and [binding release](https://github.com/open-quantum-safe/liboqs-python/releases/tag/0.16.0).

| Source | Exact commit |
|---|---|
| liboqs | `5a1a854b0dc9f2141bdc771c555ee60c37950183` |
| liboqs-python | `c6378cd5c8db74c0adf34ddcfbb96ee9c99f8061` |
| Vendored mldsa-native, as recorded by liboqs | `9b0ee84f4cf399043eca59eca4e5f8531ca1d61b` |

Archive SHA-256 values:

```text
liboqs         83c6e6cff490638312e1e20ed5de593fb5d7bfab162235f6238f519d6a1feafb
liboqs-python  3de72cde836a72e4584dad6415a41610f980f924cae95a3848011fcb4f3a3b05
```

The binding's `sign_with_ctx_str(message, context)` and
`verify_with_ctx_str(message, signature, context, public_key)` call the corresponding
native OQS APIs. The pinned ML-DSA implementation constructs FIPS 204's domain
separation prefix `0x00 || len(ctx) || ctx` for ordinary ML-DSA and rejects contexts
over 255 bytes. This is genuine external-context processing. Source evidence:
[binding API](https://github.com/open-quantum-safe/liboqs-python/blob/c6378cd5c8db74c0adf34ddcfbb96ee9c99f8061/oqs/oqs.py),
[liboqs ML-DSA-65 dispatch](https://github.com/open-quantum-safe/liboqs/blob/5a1a854b0dc9f2141bdc771c555ee60c37950183/src/sig/ml_dsa/sig_ml_dsa_65.c),
[vendored signing implementation](https://github.com/open-quantum-safe/liboqs/blob/5a1a854b0dc9f2141bdc771c555ee60c37950183/src/sig/ml_dsa/mldsa-native_ml-dsa-65_x86_64/mldsa/src/sign.c).
The tests additionally reject context/message boundary substitution and ordinary
signatures made by merely prepending the context to the message.

Representation checked: 1,952-byte public key, 3,309-byte detached signature and
4,032-byte expanded secret-key metadata. No secret-key seed representation is used.
Key generation and signing use the library's normal randomness, not deterministic
test seeds; test keys are never serialised or logged.

Ordinary ML-DSA functionality is separate from the manuscript's bounded operations.
The 1,026-byte RejNTTPoly, 512-byte RejBoundedPoly, 256-byte SampleInBall and
1,024-signing-iteration caps, pre-release bounded verification and abort accounting
are **pending implementation/validation**. These smoke tests do not establish those
properties, full FIPS conformance or FIPS module certification. The reference is
August 2024 FIPS 204; NIST's [publication page](https://csrc.nist.gov/pubs/fips/204/final)
currently notes potential errata (31 July 2026). Errata disposition belongs in the
unresolved specification work; no downstream cryptographic corrections were applied.

## Native build configuration

`scripts/build_native.py` emits and executes these commands (with absolute paths).
`$PWD` below assumes the project root. The verified source archive is extracted into
`native/.deps/src` before configuration:

```bash
cmake -S native/.deps/src/liboqs-5a1a854b0dc9f2141bdc771c555ee60c37950183 \
  -B native/build/liboqs -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=/usr/bin/gcc \
  -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_MINIMAL_BUILD=SIG_ml_dsa_65 -DOQS_DIST_BUILD=ON -DOQS_USE_OPENSSL=OFF \
  -DCMAKE_INSTALL_PREFIX="$PWD/native/.deps/install"
cmake --build native/build/liboqs --parallel 2
cmake --install native/build/liboqs
cmake -S native -B native/build/smoke -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=/usr/bin/gcc \
  -DCMAKE_CXX_COMPILER=/usr/bin/g++ -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_PREFIX_PATH="$PWD/native/.deps/install"
cmake --build native/build/smoke --parallel 2
ctest --test-dir native/build/smoke --output-on-failure
```

Release flags are `-O3 -DNDEBUG`; shared objects use PIC. The minimal build exposes
only ML-DSA-65, with portable and x86_64 implementations and runtime CPU dispatch.
No GPU backend or manuscript-specific source modifications are used. OpenSSL is
disabled inside liboqs to avoid requiring its development headers; Python's separate
hashlib backend still uses its installed OpenSSL. `ldd` confirmed the installed
liboqs depends only on libc and the Linux loader. Full compiler commands are in
`native/build/liboqs/compile_commands.json` and `native/build/smoke/compile_commands.json`.
Build options follow the pinned [upstream configuration reference](https://github.com/open-quantum-safe/liboqs/blob/5a1a854b0dc9f2141bdc771c555ee60c37950183/CONFIGURE.md).

Only `native/.deps/install` is installed to; no `ldconfig`, system library changes or
global Python installation is required. The guarded loader checks library presence,
loadability, version and the binding's actual loaded path. Missing/unloadable native
libraries fail before upstream import; dedicated negative tests cover both cases.
Normal project runtime never invokes upstream's automatic downloader. Direct `import oqs`
outside the guarded project path still retains upstream's auto-install behaviour.

## VS Code configuration

There were no pre-existing workspace editor settings. New settings select the WSL
`.venv`, pytest discovery, Ruff formatting and a Bash terminal. Tasks use explicit
Linux executables. Their commands, test discovery and JSON syntax were checked;
interactive GUI clicks/format-on-save were not visually exercised.

Verified installed WSL extensions: Python `2026.4.0`, Ruff `2026.82.0`, plus Python's
dependencies debugpy `2026.6.0`, Pylance `2026.3.1` and Python Environments `1.36.0`.
The pre-existing `openai.chatgpt@26.908.40401` was preserved. The CLI connected to
the WSL server successfully outside the assistant sandbox.

## Executed commands and outcomes

Inventory used `uname -a`, `/etc/os-release`, `lscpu`, `free`, `df`, tool `--version`
commands, `dpkg-query`, `ldd`, `wsl.exe --list --verbose`, `wsl.exe --version`, and
read-only PowerShell CIM/disk queries. `pdfinfo`, `pdftotext` and temporary pypdf
extraction inspected the manuscript; `sha256sum` identified both supplied files.

| Command/action actually run | Outcome |
|---|---|
| `sudo -n true` | Password required; user performed the prerequisite apt installation, then tools were verified |
| `python3 scripts/bootstrap_uv.py` | Installed checksum-verified local uv 0.12.15 |
| `.tools/uv lock` | Created `uv.lock`; final lock resolves 14 entries, including the Windows-only entry |
| `bash scripts/setup.sh` | Installed 13 Linux packages including the editable project; dependency check passed |
| `python3 scripts/build_native.py`; later `.venv/bin/python scripts/build_native.py` | Native liboqs build/install succeeded with two jobs; C/C++ CTest 1/1 passed on both runs |
| `code --install-extension ms-python.python` | Python extension and its dependencies installed successfully in WSL |
| `code --install-extension charliermarsh.ruff` | Ruff extension installed successfully in WSL |
| `code --list-extensions --show-versions` | Confirmed the versions above |
| `.venv/bin/python scripts/verify_environment.py` | Passed: exact interpreter, locked package versions, Linux build tools, local native library/context API |
| `.venv/bin/python -m pytest tests/smoke -q` | **14 passed**, no failures or skips |
| `.venv/bin/python -m pytest --collect-only -q` | Discovered 14 tests |
| `.venv/bin/ruff check .` | Passed |
| `.venv/bin/ruff format --check .` | Passed after applying `.venv/bin/ruff format .` |
| `bash -n scripts/setup.sh`; parse `.vscode/*.json` | Passed |
| `UV_OFFLINE=true bash scripts/setup.sh` | Passed using the populated project cache |

Final verification also executed the verification, smoke-test, lint and formatting
commands directly from `.vscode/tasks.json`; all passed. The native task's command
was executed separately and passed. Both supplied document hashes remained unchanged.

A fresh second venv was also installed offline at `/tmp/pqdid-repro-cOO6f0/.venv` with:

```bash
UV_PROJECT_ENVIRONMENT=/tmp/pqdid-repro-cOO6f0/.venv .tools/uv sync \
  --locked --offline --group build --no-install-project --no-install-package liboqs-python
UV_PROJECT_ENVIRONMENT=/tmp/pqdid-repro-cOO6f0/.venv .tools/uv sync \
  --locked --offline --group build --no-build-isolation
/tmp/pqdid-repro-cOO6f0/.venv/bin/python -m pytest tests/smoke -q
.tools/uv pip check --python /tmp/pqdid-repro-cOO6f0/.venv/bin/python
```

All 14 tests and the dependency check passed. This reused the verified local native
library and cached Python build artefacts; it was not a second independent native build.
uv copied files instead of hard-linking across the tmpfs boundary, which is expected.

Resolved setup issues: uv initially rejected the extensionless codeload binding URL;
the equivalent commit-specific GitHub `.tar.gz` URL fixed it and produced the same
archive hash. The first editable build exposed a missing `editables` build dependency;
it is now explicitly pinned and locked. The initial formatter check found three files;
formatting was applied. No outstanding installation or smoke-test failure remains.

The directory is not yet a Git repository: `git rev-parse --is-inside-work-tree`
failed both inside and outside the sandbox. No Git history was created or altered;
`.gitignore` is ready for future version control. No `AGENTS.md`, existing code,
existing editor settings or LaTeX source was found in the project/ancestor instructions.
The supplied plan and PDF were preserved byte-for-byte.

## Smoke-test coverage and vector sources

Eight ML-DSA cases cover local loading/versions/representation, key generation and
sign/verify, altered message/signature and truncated signature rejection, four
external contexts (empty, non-empty, binary/NUL, 255 bytes), wrong-context rejection,
context/message boundary separation and 256-byte-context rejection. Two loader tests
check missing/unloadable libraries. Four hash checks use fixed expected bytes:

| Algorithm/input | Primary source |
|---|---|
| SHA3-384, empty | [NIST SHA3-384 Msg0](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_Msg0.pdf) |
| SHA3-384, 200 × `A3` | [NIST SHA3-384 1600-bit example](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_1600.pdf) |
| SHAKE256, empty, 128-byte output | First 128 bytes of [NIST SHAKE256 Msg0](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg0.pdf) |
| SHAKE256, 200 × `A3`, 128-byte output | First 128 bytes of [NIST SHAKE256 Msg1600](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg1600.pdf) |

The fixed vectors include inputs spanning multiple absorption blocks. Expected outputs
are stored in the tests, not generated by the implementation under test. The full
liboqs upstream test suite, independent ML-DSA interoperability/conformance testing,
bounded operations, circuits, security validation and benchmarks remain outside these checks.
