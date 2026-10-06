# PQ-DID research environment

Stage 1 is complete: the verified environment, specification, parameter manifest,
encoding examples and traceability are recorded, with SPEC-001/002 agreed by the user.
Stage 2 codecs, schema, public-policy and expiry helpers, holder-binding consistency
and depth-20 Merkle primitives, typed parameter/certificate/credential structures and
exact Mcred construction are implemented and tested. The separate bounded Python
ML-DSA-65 verifier, complete local CredValid and executable enrolment/authentication
reference relations are implemented. Typed statements/witnesses, bounded state
authentication and disclosed-policy checks preserve the public/private boundary.
Stage 3 is in progress: a bounded circuit foundation now provides deterministic
emission/evaluation, materialised/counting/streaming modes, checked 64-bit arithmetic,
selectors, active rejection and integer-only proof-size projections. Full 24-round
SHA3/SHAKE gadgets, enrolment's canonical public parsing boundary and the complete
enrolment relation compiler use the user-agreed SPEC-003 initialisers. All 17 deferred
private hash/XOF tests and nine diagnostic probes now complete under the approved
extended profile. Authentication witness/attribute parsing and checked division,
residue and scalar ring helpers are implemented. Private signature/hint decoding and
same-witness credential-message input wiring are now implemented and tested at their
component boundaries. SPEC-004 is now agreed, including explicit sign-correction
wiring. Its adoption validation passed 241 focused / 1421 regression tests. A counting-only
preflight completes message preparation at 2034776 gates; full hints, signature with
norm and preparation with decoding each stop at 32000000 gates. Those prefixes are
not complete counts or functional evaluations. Ordinary evaluation limits are unchanged.
Full authentication and proofs remain unimplemented; full canonical BC-1 conformance
remains unverified.
The subsequent bounded message-preparation pilot passes all nine cases with the same
count/fingerprint. The [feasibility review](docs/stage3_feasibility_review.md) attributes
the hint-prefix cost to the current lowering and records a conditional 3.253 GB
authentication proof projection. A reviewed concrete-profile change is recommended
before larger integration; no replacement construction has been adopted. The latest
119 focused / 1432 regression tests pass without skips; Ruff lint/format pass.
Stage 2 remains in progress: bounded key generation/signing and remaining release and
revocation/update work are separate obligations. KYC services and benchmarks remain work.
See [codec APIs and evidence](docs/stage2_codec.md),
[holder-binding/Merkle evidence](docs/stage2_binding_merkle.md),
[credential structure evidence](docs/stage2_credentials.md),
[bounded verifier and CredValid evidence](docs/stage2_bounded_mldsa.md),
[relation contracts and evidence](docs/stage2_relations.md),
[BC-1 foundation and resource evidence](docs/stage3_bc1_foundation.md),
[hash/enrolment evidence and limitations](docs/stage3_hash_enrolment.md),
[authentication parsing and scalar arithmetic](docs/stage3_auth_parsing_arithmetic.md),
[private signature/input preparation and limits](docs/stage3_signature_inputs.md),
[SPEC-004 adoption and resource preflight](docs/stage3_resource_preflight.md),
[bounded-verifier plan](docs/bounded_mldsa_plan.md) and [status](docs/status.md).

The selected source is `docs/manuscript/PQ_DID__Implementation.pdf`, identified by
SHA-256 in [project status](docs/status.md). **Only Sections II–VIII are authoritative**;
the abstract, Section I and Sections IX onwards are unrevised and excluded from
requirements, consistency checks, parameters and performance evidence. See
[AGENTS.md](AGENTS.md) for the persistent project rules.

The environment uses Python 3.14.4, GCC/G++ 15.2.0, and project-local liboqs 0.16.0
with liboqs-python 0.16.0. The smoke suite runs real ML-DSA-65 operations, including
FIPS 204 external contexts, and fixed SHA3-384/SHAKE256 known-answer checks.
These checks establish environment readiness only; they do not validate PQ-DAA,
its security proof, manuscript-specific operation bounds or performance.

## Open the workspace

The existing WSL2 and VS Code WSL connection were verified. No reboot or new WSL
installation is needed. From Windows PowerShell, if starting a new session:

```powershell
wsl -d Ubuntu
```

Then, in Ubuntu:

```bash
cd /home/grace/projects/pq-did
code .
```

Keep the window connected to **WSL: Ubuntu**. The Python and Ruff extensions are
installed on the WSL side. If the existing window has not picked them up, run
**Developer: Reload Window**. If VS Code retains an earlier interpreter selection,
use **Python: Select Interpreter → Enter interpreter path** and select
`/home/grace/projects/pq-did/.venv/bin/python`.

Open a new integrated terminal and, if it is not already activated, run:

```bash
source .venv/bin/activate
python -c 'import sys; print(sys.executable)'
```

The result should be `/home/grace/projects/pq-did/.venv/bin/python`. All workspace
tasks explicitly select that interpreter, independently of terminal activation.

## Reproduce the installation

The Ubuntu prerequisites below were installed by the user and subsequently verified.
On a fresh Ubuntu installation, this is the only step that needs a sudo password:

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build python3-venv pkg-config poppler-utils
```

`poppler-utils` is for manuscript inspection. The remaining packages supply the C/C++
compiler, linker, headers, build tools and Python venv support. Reuse `/usr/bin/python3.14`
with version **3.14.4** for this recorded environment; an OS update changing Python
requires a reviewed version update and rerun of the checks. Python downloads are disabled.

From the project root:

```bash
python3 scripts/bootstrap_uv.py
bash scripts/setup.sh
.venv/bin/python scripts/build_native.py
.venv/bin/python scripts/verify_environment.py
.venv/bin/python -m pytest tests/smoke -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

The bootstrap verifies a pinned uv wheel hash and installs only `.tools/uv`.
`setup.sh` creates `.venv`, installs the hash-locked build dependencies, then builds
the project and binding without isolated dependency resolution. It consumes `uv.lock`
with `--locked`; do not regenerate the lock for routine setup. Caches are project-local.
The native script checks the pinned source archive hash and installs under
`native/.deps/install`, always using **two build jobs**. It also builds and runs a
small C/C++ linkage test. No system liboqs installation or `sudo cmake --install` is used.

Internet access is needed for first-time source/package downloads. Later smoke tests
and environment verification make no downloads. `UV_OFFLINE=true bash scripts/setup.sh`
also works once the required package cache is populated.

To restore the two main editor extensions at the versions inspected here:

```bash
code --install-extension ms-python.python@2026.4.0
code --install-extension charliermarsh.ruff@2026.82.0
```

## Stage 2–3 checks

```bash
.venv/bin/python -m pytest tests/unit tests/integration tests/smoke/test_hashes.py -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

The preserved default pytest/VS Code test selection still targets `tests/smoke`.
Use the explicit paths above for the Stage 2–3 tests; no environment rebuild is needed.
The current supervised extended regression passes 1323 tests with no skips; the
new parsing/arithmetic suite passes 217 focused tests; all 36 diagnostic probes complete.
Routine defaults remain unchanged and still gate 17 larger-profile cases; use the supervised validation
commands in [the report](docs/stage3_auth_parsing_arithmetic.md#commands-results-and-preservation)
for that profile. Earlier foundation and relation checks remain covered.
Deterministic sampler tests exercise
the real 1026-/256-byte limits; native fixtures independently cross-check verification.
Fixture signing is ordinary and uncapped. Local CredValid checks a supplied holder
opening and bounded signature. The complete local authentication relation additionally
checks the same certified identifier's zero-leaf path, disclosed values, public policy
and state signature. It receives a local witness and is not a remote proof verifier.
Canonical statement bytes prepare future proof binding; freshness, trusted-time expiry
and atomic challenge consumption remain lifecycle responsibilities.

Run just the foundation checks or repeat the small component probes:

```bash
.venv/bin/python -m pytest tests/unit/test_bc1_emitter.py tests/unit/test_bc1_words.py tests/unit/test_bc1_control.py tests/unit/test_bc1_accounting.py -q
.venv/bin/python scripts/measure_bc1_foundation.py --suite --output /tmp/pqdid-bc1-measurements.json
```

The probe uses one worker, 200000 gates, 8 MiB output, 10 s generation, 5 s evaluation
and 256 MiB process address space. Limits are configurable CLI arguments. Materialised
multiplication's demonstration predicate used 47643 gates (21322 AND), 810020 trace
bytes and 24.664 MiB peak RSS in the recorded instrumented run. These component counts
are neither authentication counts nor automatic lower bounds. No proof-sized buffer
or complete authentication circuit is built.

Run the current hash/enrolment checks and original-budget probes:

```bash
.venv/bin/python -m pytest tests/unit/test_keccak_circuit.py tests/unit/test_enrolment_circuit.py tests/unit/test_spec003_alternatives.py -q
.venv/bin/python scripts/measure_hash_enrolment.py --suite --output /tmp/pqdid-hash-enrolment.json
```

The measured enrolment circuit uses 194691 gates (38787 AND), 3309836 trace bytes
and 32.637 MiB peak RSS, with instrumented generation/evaluation of 1.039/0.617 s.
Its provisional d=256 proof-size calculation is 9587104 bytes; no proof was generated.
The nine original 200000-gate terminations are preserved historical evidence. All nine
now complete under the separately approved 2000000-gate/41943040-byte profile, one
worker, unchanged 10/5-second generation/evaluation controls, retained 256 MiB address
space and a sampled 128 MiB RSS watchdog. Both historical multiplication and enrolment
traces/counts/fingerprints reproduce unchanged under the agreed initialisers.
That validation package is complete. The subsequent authentication parsing and scalar
arithmetic package is recorded below; full BC-1 conformance and proofs remain open.

## Authentication parsing and scalar arithmetic

[The package report](docs/stage3_auth_parsing_arithmetic.md) documents the fixed
5329-byte private witness parser, canonical attribute/type/length/padding checks,
same-field disclosure linkage, checked signed64 public-constant division/divmod and
canonical/centred residues, scalar ring operations, FIPS Decompose/UseHint/norm helpers
and one forward NTT butterfly. Signature bytes stay connected to the future verifier;
parsing success is not signature validity or complete authentication. No private
quotient/remainder advice, narrowed coefficients or arithmetic replacement is added.

Use the approved supervised runner, with a freshly inspected host snapshot:

```bash
.venv/bin/python scripts/validate_auth_arithmetic.py --host-snapshot /tmp/pqdid-arithmetic-host.json --output /tmp/pqdid-arithmetic-focused.json --tests tests/unit/test_auth_parsing_circuit.py tests/unit/test_bc1_division.py tests/unit/test_scalar_ring_circuit.py
.venv/bin/python scripts/validate_auth_arithmetic.py --host-snapshot /tmp/pqdid-arithmetic-host.json --output /tmp/pqdid-arithmetic-measurements.json
```

The snapshot used for the recorded run is embedded in its JSON evidence. Output files
must be new, preserving prior evidence. Limits are unchanged: one worker, up to
2000000 gates / 41943040 trace bytes, 256 MiB address space, sampled 128 MiB RSS,
10-second generation / 5-second evaluation and a 30-second per-case wall watchdog.
SPEC-004's exact restoring-division recipe is now user-agreed. Its adopted trace
fingerprints and dependent measurements supersede the historical provisional ones;
gate counts are unchanged. See the [resource preflight](docs/stage3_resource_preflight.md)
for the separate counting-only profile, completed/capped counts and proposed evaluation
budgets. The [feasibility review](docs/stage3_feasibility_review.md) now includes a
successful bounded message pilot and recommends a reviewed profile-change proposal
before full hint/signature/preparation evaluation. Sampler/NTT integration and proofs
remain open.

## Existing environment checks

```bash
.venv/bin/python scripts/verify_environment.py
.venv/bin/python -m pytest tests/smoke -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
ctest --test-dir native/build/smoke --output-on-failure
```

VS Code's **Terminal → Run Task** exposes environment verification, smoke tests,
native builds, lint and formatting checks. Test discovery targets `tests/smoke`.
Python files use the locked `.venv/bin/ruff` for formatting on save.

Use `from pqdid.backend import load_backend` for backend access. The loader checks
the local library before importing the binding and rejects a different loaded library.
Direct upstream `import oqs` can trigger its automatic installer when liboqs is absent;
native tests and the environment verifier use the guarded loader. The separate bounded
verifier does not call liboqs. Fixture signing keys exist only in memory; frozen fixtures
contain public keys/signatures and explicitly synthetic public holder openings.

## Contents and scope

| Path | Purpose |
|---|---|
| `src/pqdid/` | Canonical codecs, schema/policy/expiry, binding/Merkle, pp/cert/vc, bounded signatures, typed statements/witnesses, public checks and complete local reference relations |
| `src/pqdid/circuits/` | Bounded emitter/evaluator, arithmetic/control, full SHA3/SHAKE schedules, enrolment compiler, authentication parsing, checked division/residues/scalar ring and size accounting; SPEC-003/004 agreed, full conformance unverified |
| `native/` | Pinned source/build manifest and C/C++ linkage smoke check |
| `tests/smoke/` | Existing cryptographic/environment smoke checks |
| `tests/unit/` | Stage 2 reference tests, real signed credentials, sampler-boundary tests and Stage 3 circuit truth tables/traces/limits |
| `tests/integration/` | Native interoperability and bounded/native verification plus independent SHAKE differential checks |
| `tests/fixtures/`, `tests/reference/` | Frozen labelled vectors, independent sparse-tree/framing expectations and ordinary native signature fixture generators/provenance |
| `scripts/` | Reproducible setup, native build and environment verification |
| `configs/` | Confirmed parameter manifest, separate implementation evidence and canonical encoding vectors |
| `docs/` | Specification, traceability, issue decisions, environment evidence and status |
| `benchmarks/` | Explicitly unimplemented future work |

See [environment details and executed commands](docs/environment.md),
[implementation specification](docs/implementation_spec.md),
[parameter manifest](configs/suite.json), [traceability](docs/traceability.md),
[encoding examples](docs/encoding_examples.md), [project status](docs/status.md), and the original
[implementation plan](PQ_DID_Implementation_Plan_v1.md).
