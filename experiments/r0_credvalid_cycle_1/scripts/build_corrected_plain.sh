#!/bin/bash
set -eu
CARGO_TARGET_DIR="$PWD/target/guest" RUSTFLAGS='-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"' cargo build --locked --offline --release --target riscv32im-risc0-zkvm-elf --manifest-path methods/guest/Cargo.toml --bin cred_valid --no-default-features
target/release/pqdid-r0-host register corrected-plain target/guest/riscv32im-risc0-zkvm-elf/release/cred_valid none
