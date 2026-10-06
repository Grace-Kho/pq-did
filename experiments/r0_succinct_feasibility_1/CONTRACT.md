# R0-SUCCINCT-FEASIBILITY-1 — pre-implementation contract

Authorised 19 September 2026 by the attached work package. Experimental only;
PQDID-R0S-EXP1 and benchmark targets remain provisional. Preserve active suite,
SPEC-001–004, production modules, dependencies, vectors and historical evidence.

## Selected predicates and discrepancy resolution

`relations.enrol(expected_pp, statement, witness)` validates the complete canonical
enrolment statement against expected parameters, then checks the public certified
binding against the runtime private 32-byte holder secret and approved attributes.
Its state signature is structurally checked, not cryptographically verified: public
StateAuth and lifecycle checks are outside this selected reference predicate.

`credentials.cred_valid(expected_pp, credential, holder_secret)` validates the full
private Credential, including independent certificate binding, repeated attributes,
empty auxiliary field, bounded rid and expected metadata; checks the opening; builds
exact Mcred; verifies ML-DSA-65 with context PQ-DID/credential/v1 and exact sampler caps.
The earlier proposal's reconstructed-B authentication fragment would not exercise
an independently supplied inconsistent B. This experiment instead takes the full
canonical encoded Credential privately, preserving that CredValid rejection case.
It is not the full Rauth predicate and proves no disclosure, Merkle, freshness or
issuer-authorisation-history claim. Wrong public parameters are checked against
externally expected parameters bound in the verifier's expected public statement.

## Public/private partition (before any proof)

Use diagnostic profile `PQDID-R0S-DIAG1`, separate operations `enrol` and `cred-valid`.
The canonical public record is:

    enc_r0-statement(profile, operation, E(expected_pp), context32, payload)

All encodings use LP(tag), uint32-BE field count, then LP fields (LP has uint32-BE
byte length). context32 is an exactly 32-byte synthetic public experiment challenge,
not a complete authentication context or freshness guarantee. Enrolment payload is
the exact existing E(enrolment statement). CredValid payload is E(expected metadata).
Every byte of this public record is committed as raw journal bytes in:

    enc_r0-result(profile, operation, public_record)

Enrolment private input is the 32-byte secret. CredValid private input is:

    enc_r0-credential-witness(E(credential), holder_secret)

Thus sigma, rid, private attributes, B, Mcred and all its hashes remain private for
CredValid. Enrolment's own attributes/B/rid are public as in its reference. Fixture
secrets must be runtime inputs, never guest compile-time constants. Invalid input
must cause guest failure, not a success receipt carrying a false Boolean.

## Receipt and execution contract

Use exact SDK 3.0.6, native Succinct STARK, poseidon2, pinned expected image and
verifier parameters. No dev/Fake, Composite, Groth16, remote prover, GPU changes,
unchecked host results or unresolved assumptions. Verify saved receipts in a fresh
process with public input and registered identity only, using full receipt
verification and exact expected journal. Execution-only differential tests must
pass before any proof launch. Inspect control metadata/lengths; no ZK theorem follows.

## Finite resource limits

Initially one build job. CPU-only, one worker, at most two CPU threads. Build/setup:
1200 s cumulative subprocess wall, 2 GiB cgroup memory (includes all descendants),
no swap, 10 GiB total experimental disk, including toolchains/cache/target/tmp.
Proving: three launches total including failures/interruption; persist launch count
before spawn; 600 s per launch, 1800 s cumulative execution/proving wall, segment
2^16 and session 2^22 cycles. Never repeat an unchanged resource failure.
Verification: 1 GiB, 10 s each, 100 cases/60 s total malformed corpus. Execution-only
checks: 60 s per invocation, 300 s aggregate initially, within the 1800 s total.
Ancillary metadata/source review: 128 MiB per process, 30 s per URL, at most 64 MiB
per source/archive fetch unless a reviewed installation asset is explicitly admitted.
Formatting/unit/data checks: 256 MiB, 60 s each, 300 s aggregate. These conservative
ancillary limits are recorded before the corresponding execution.

Use systemd user transient services: MemoryMax, MemorySwapMax=0, CPUQuota=200%,
RuntimeMaxSec, KillMode=control-group, OOMPolicy=kill; record effective cgroup values.
Sample process-tree RSS separately; virtual address space is not RSS. The cgroup
memory charge includes anonymous memory and file cache, unlike summed RSS. Require
worker allowance +2 GiB MemAvailable before large work. Reserve physical disk as
well as WSL filesystem space. Watch disk growth and stop at a conservative 9 GiB
threshold to leave margin below 10 GiB. No toolchain default changes; all installation
homes/caches/tmp are experiment-local. Do not activate the earlier BC-1 64M proposal.

Operational clarification before execution/proving: SDK 3 host IPC uses TCP loopback.
Non-download phases therefore use a private network namespace (loopback only),
validated by a real local socket and failed external route. Verification also hides
the original project test fixtures, which contain copies of synthetic witness data.
The proposal's 256 MiB output limit applies to evidence/fixtures/receipts; a
conservative 240 MiB watcher stops below it. Build products, public sources and
installation caches remain within the separate 10 GiB total disk limit.
