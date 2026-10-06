#!/bin/bash
set -eu
root=$(pwd)
# run_limited.py supplies these; independently reject any global destination.
test "$CARGO_HOME" = "$root/tooling/cargo"
test "$RUSTUP_HOME" = "$root/tooling/rustup"
"$CARGO_HOME/bin/rustup" toolchain link risc0 "$root/tooling/guest-r0.1.97.0"
"$CARGO_HOME/bin/rustup" run risc0 rustc --version --verbose
"$CARGO_HOME/bin/rustup" run risc0 cargo --version
"$root/tooling/sdk-3.0.6/r0vm" --version
"$root/tooling/sdk-3.0.6/cargo-risczero" risczero --version
