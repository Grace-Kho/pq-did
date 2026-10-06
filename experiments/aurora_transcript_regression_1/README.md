# Isolated EXP2 public transcript harness

Source-faithful Python reimplementation of the approved
[correction contract](../../docs/stage3_aurora_transcript_correction_contract.md),
with independent straight-line expected traces. This does **not** execute a native
libiop patch. The snapshot at `a2ed2ec2f3e85f29b6035951553b02cb737c817a` is preserved.
There is no accepted proof backend, proof object, signing, private witness or IOP.

The one authorised execution uses the bounded package runner:

```sh
.venv/bin/python -I -B docs/data/s3_aurora_transcript_regression_1/run_checks.py cases
```

The runner refuses repeats. Cases TR-01–TR-16 have individual admission/outcome
rows; the first unexpected result stops the group. TR-02 is the explicitly counted
deterministic repeat. TR-16 models the old input-span omission; it is not a forgery.
Only public synthetic diagnostics expose full preimages/states. Existing primitive
and typed-object modules are reused without changing signatures or parameters.

Trusted `BASE` and `GROUPED` descriptors are selected locally; only TR-08 uses the
second descriptor. They cannot be supplied through serialized proof metadata.
This is a local research API, not a Python-process security boundary. Integer
counters reject booleans; existing boolean policy attributes remain valid.
The typed object capacity walk precedes canonical encoding; it bounds depth,
nodes, collections and bytes. Canonical encoders still allocate their bounded
output. Fixture reads are capped before JSON parsing; JSON objects themselves
are not streamed. No contexts, schemas, keys or status URLs are resolved.

No regression result establishes knowledge/privacy, concrete-hash composition or
native integration. AURORA-BRIDGE-001 and Stages 2–3 remain open.
