#!/bin/bash
set -eu
../../.venv/bin/ruff check scripts
../../.venv/bin/ruff format --check scripts
rustfmt --check --edition 2021 relation/src/*.rs host/src/*.rs methods/guest/src/lib.rs methods/guest/src/bin/*.rs
for script in scripts/*.sh; do bash -n "$script"; done
python3 scripts/final_audit.py
