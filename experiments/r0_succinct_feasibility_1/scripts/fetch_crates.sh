#!/bin/bash
set -eu
cargo +risc0 fetch --locked
cargo +risc0 generate-lockfile --manifest-path methods/guest/Cargo.toml
cargo +risc0 fetch --locked --manifest-path methods/guest/Cargo.toml
