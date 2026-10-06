#!/bin/bash
set -eu
../../.venv/bin/ruff check scripts
../../.venv/bin/ruff format --check scripts
rustfmt --check --edition 2021 host/src/main.rs relation/src/*.rs
for script in scripts/*.sh; do bash -n "$script"; done
python3 scripts/final_audit.py
