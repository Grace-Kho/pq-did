# S3-AURORA-NATIVE-TRANSCRIPT-PILOT-1

Isolated public-input native pilot preparation. `upstream/` contains unchanged,
commit-addressed files copied from the sealed source review, including its MIT
licence. It is a partial snapshot, **not a complete checkout or patched library**.

Native admission requires the real libiop/libff headers and pinned dependencies,
including libsodium development headers. No header stubs, handwritten ABI
declarations or standalone replacement hash-chain implementation are permitted.
The retained EXP2 Python cases and independent expected outputs are inputs for
future native comparison; no passing native result is inferred from them.

See the [report](../../docs/stage3_aurora_native_transcript_pilot.md) and
[admission limits](../../docs/data/s3_aurora_native_transcript_pilot_1/admission.json).
No build target is admitted while dependency closure is unavailable. There is no
proof interface, private input, active-profile registration or service activation.
