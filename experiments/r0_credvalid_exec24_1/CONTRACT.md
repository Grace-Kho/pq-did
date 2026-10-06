# R0-CREDVALID-EXEC24-1

Authorised 19 September 2026: reuse the immutable corrected, uninstrumented release
guest from R0-CREDVALID-CYCLE-1. No guest build or optimisation. The only changed
executor setting is session_limit 2^22 -> 2^24 user cycles, with the pinned meaning.
Segment exponent remains 16; all cryptographic parameters and runtime input bytes
are preserved. SDK 3.0.6 and the existing compiler/cache are reused offline for the
small host adaptation only. All historical workspaces are read-only in services.

At most two execution launches, counted before spawn including failures. Slot 1 is
cred-alpha-42 once. Slot 2 is allowed only after a completed/accepted valid execution
with the exact expected journal, and uses an existing canonical signature-invalid
fixture independently confirmed with the reference. A cap, memory, time, disk or
diagnostic limit ends this package; no same-target retry or compensating limit rise.
No proving APIs/commands, remote services, fake receipts or development mode.

Keep 2 GiB aggregate cgroup memory, no swap, one worker, two CPU threads, 60 s per
execution, 300 s cumulative execution, 1200 s build/preparation, 60 s/256 MiB per
ancillary check and 300 s aggregate checks. Require worker allowance +2 GiB available
WSL memory before each worker. Existing 10 GiB disk/9 GiB conservative stop across
all experiments; diagnostics 64 MiB/60 MiB conservative stop and 64 KiB streams.

Retain at most 256 individual segment metadata records, then aggregate counts and
cycle capacities without retaining further per-segment records. This preserves the
diagnostic storage bound without confusing it with the executor's segment setting.
Persist a small running aggregate so resource stops retain completed-prefix counts.
Never retain segment assets, witness/register/memory traces or full instructions.
The unchanged guest emits no phase counters, so an interrupted phase is unknown.

Record summed process-tree RSS samples separately from exact cgroup memory.peak
(which includes charged cache), swap and temporary storage. The service wrapper
checks controls before starting the target and retains cgroup peaks before exit.
Execution journals are unchecked local outputs, not cryptographic receipts.

Reuse six native tests and 35 comparisons only after checking their code/build/input
identities. Validate the selected negative case with the unchanged Python reference;
no renewed native suite or guest modification. Final documentation/configuration,
identity/preservation and sequence checks, then close the package and stop.
