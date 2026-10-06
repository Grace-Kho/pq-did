#!/bin/bash
set -eu
../../.venv/bin/ruff check scripts
../../.venv/bin/ruff format --check scripts
tooling/guest-r0.1.97.0/bin/rustfmt --check --edition 2021 relation/src/lib.rs relation/src/mldsa.rs host/src/main.rs methods/guest/src/lib.rs methods/guest/src/bin/enrol.rs methods/guest/src/bin/cred_valid.rs
python3 scripts/audit_dependencies.py --offline > evidence/dependency_audit_summary.json
python3 scripts/review_advisories.py > evidence/affected_dependency_versions.txt
cargo +risc0 tree --locked --offline -e normal,build > evidence/host_dependency_tree.txt
cargo +risc0 tree --locked --offline --target riscv32im-risc0-zkvm-elf --manifest-path methods/guest/Cargo.toml -e normal,build > evidence/guest_dependency_tree.txt
python3 scripts/final_checks.py
