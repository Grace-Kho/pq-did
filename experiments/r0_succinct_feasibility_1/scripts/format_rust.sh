#!/bin/bash
set -eu
tooling/guest-r0.1.97.0/bin/rustfmt --edition 2021 relation/src/lib.rs relation/src/mldsa.rs host/src/main.rs methods/guest/src/lib.rs methods/guest/src/bin/enrol.rs methods/guest/src/bin/cred_valid.rs
