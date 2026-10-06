#!/bin/bash
set -eu
cargo +risc0 generate-lockfile --offline
cargo +risc0 test --lib --locked --offline -p pqdid-r0-relation
cargo +risc0 build --locked --offline --release -p pqdid-r0-host
# These guest flags reproduce the pinned risc0-build encode_rust_flags function.
# TEXT_START=0x00200800 is from pinned risc0-zkvm-platform 2.2.3 memory.rs.
CARGO_TARGET_DIR="$PWD/target/guest" RUSTFLAGS='-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"' cargo +risc0 build --locked --offline --release --target riscv32im-risc0-zkvm-elf --manifest-path methods/guest/Cargo.toml
target/release/pqdid-r0-host register
target/release/pqdid-r0-host native-check
target/release/pqdid-r0-host reject-check
