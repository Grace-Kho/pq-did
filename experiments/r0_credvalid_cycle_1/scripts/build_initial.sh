#!/bin/bash
set -eu
# Resolve only local path/feature edges against the copied cache; no package upgrades.
cargo metadata --offline --format-version 1 > /dev/null
cargo metadata --offline --format-version 1 --manifest-path methods/guest/Cargo.toml > /dev/null
cargo test --lib --locked --offline -p pqdid-r0-relation
cargo build --locked --offline --release -p pqdid-r0-host
CARGO_TARGET_DIR="$PWD/target/guest" RUSTFLAGS='-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"' cargo build --locked --offline --release --target riscv32im-risc0-zkvm-elf --manifest-path methods/guest/Cargo.toml --bin cred_valid --features diagnostics
target/release/pqdid-r0-host register baseline-diag target/guest/riscv32im-risc0-zkvm-elf/release/cred_valid diagnostics
target/release/pqdid-r0-host native-check
