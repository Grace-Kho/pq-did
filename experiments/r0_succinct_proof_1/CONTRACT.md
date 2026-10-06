# R0-SUCCINCT-PROOF-1

The user's 19 September 2026 instruction authorises up to three sequential local CPU
Succinct/poseidon2 proof attempts: enrol-alpha-42, then corrected cred-alpha-42,
then optionally the identical CredValid fixture with fresh prover randomness.
The earlier alpha-43 proposal is superseded. Every pipeline launch consumes an
attempt, including failure/interruption. Advancement requires successful generation,
fresh isolated verification and tamper rejection. Stop on any hard resource or
correctness/verification failure; never retry or change limits.

config.json fixes the envelope before launch. Whole descendant cgroup: 2 GiB,
zero swap, two CPU threads, one worker, 600 seconds per COMPLETE proof pipeline,
1800 seconds aggregate execution/proving. Internal segment/lift/join calls share
that deadline. Enrol user-cycle cap remains 2^22; CredValid remains 2^24; segment
exponent remains 16. No guest rebuild or cryptographic change. Setup/build has a
separate 1200-second aggregate budget. Storage: 10 GiB/9 GiB conservative stop;
output: 256 MiB/240 MiB stop; diagnostics: 64 MiB/60 MiB stop and 64 KiB retained
per stream (first 48 KiB plus last 16 KiB, with bounded aggregate phase counters).
Receipt bound 10 MiB, complete presentation admission 12 MiB. Verification uses
1 GiB/10 seconds per positive case; tamper corpus at most 100 cases/60 seconds.
Checks share a 300-second aggregate allowance. Admission reserves another 2 GiB
of WSL MemAvailable. Network namespaces allow loopback IPC only; devices are private.

The registered images and expected journals are frozen in evidence/baseline.json.
Private fixtures are inaccessible to fresh verifier processes. Only Succinct receipts
with the registered poseidon2 verifier/control parameters, pruned unconditional
successful claim, correct image and exact public journal pass full verify_with_context.
No Fake, Composite or Groth16 acceptance, remote service, GPU or automatic retry.

SDK logs supply bounded phase-start observations; the external API's timing is
combined execution/segment proving/recursion when separate timers are unavailable.
Saved journals alone are not receipts. The diagnostic profile does not implement
full authentication or close privacy, quantum security, Section VIII or Stage 2.
