# R0-ENROL-PO17-1

One enrolment-only execution at executor segment po2 17, followed conditionally by
one local CPU Succinct/poseidon2 proof, cumulative attempt 2 of the original 3.
Same guest, image, enrol-alpha-42 fixture, expected journal, 2^22 SDK user-cycle cap,
prover binary, verifier parameters, CPU settings and cryptographic parameters.
The prover's supported maximum is independent of the executor segment setting and
is not raised. No CredValid proving or guest/prover build in this package.

Execution must complete, match the expected journal, reduce the measured segment
count below 10 and use supported segment sizes, without a known configuration or
resource incompatibility. Otherwise stop before consuming a proof attempt.
Execution memory does not establish proving memory.

One worker; 2 GiB descendant cgroup MemoryMax and no swap; two CPU threads and
200% quota; 128 tasks. Execution: 60 seconds, existing 300-second aggregate ceiling.
Proof: 600 seconds for the complete execution/segment/lift/join/receipt pipeline.
Existing 1800-second aggregate execution/proving and 1200-second preparation/build
ceilings are retained. No per-segment deadline reset, retry or limit increase.
All failures and interruptions after proof launch consume cumulative attempt 2;
this package cannot consume attempt 3. Historical ledgers remain unchanged; a new
cumulative ledger references their immutable identities and advances before spawn.

Storage: 10 GiB experimental total, stop at 9 GiB; output 256 MiB/240 MiB stop;
diagnostics 64 MiB/60 MiB stop and bounded 64 KiB stream retention. Receipt input
10 MiB, complete presentation admission 12 MiB. Verification 1 GiB/10 seconds;
tamper corpus <=100 cases/60 seconds; ancillary checks 256 MiB/60 seconds with
300 seconds cumulative checks. WSL admission requires allowance plus 2 GiB reserve.

No dev/fake mode, external network, GPU or Groth16. Same restricted SDK debug logs
and bounded stream/phase capture as the first attempt. Fresh receipt verification
hides private fixtures, execution temporary files, original test fixtures and all
previous experiment directories. Only expected public inputs, registered identities
and receipt are used. Full verify_with_context checks success, no assumptions, image,
verifier parameters and exact journal; component/intermediate proofs are not receipts.

Only manuscript Sections II–VIII are authoritative. Active suite, production code,
locks, vectors, manuscript and historical evidence are preserved. Reference/native
validation is reused. Authentication, CredValid proving, lifecycle integration,
privacy/security, Section VIII and outstanding Stage 2 work remain open.
