# Reproduction index — retained evidence, no reruns

Use the project root `/home/grace/projects/pq-did`. The existing environment is
recorded in [environment.md](../../environment.md); active pins remain in the
unchanged suite, dependency files and per-job environment records. No installation
or global environment change is needed to inspect retained results. This directory
contains documentary checks only, not a new benchmark runner.

## Identities and the latest result

- Comparison: [OCT31-KYC-NATIVE-MILESTONE-1/v1](../oct31_auth_relation_integration_1/comparison-point.json).
  It pins 362 dataset/evidence files and 21 baseline/native source/binary files.
- Final milestone manifest:
  `b81bacf5bddb6d371f0ad50120291d039194f2f490718a9179b3a7d6708a3ba7`.
  Final closure:
  `7a4ab57cb54185bf49fe60f1c5bd4e52dc68d000904c9a8dd879c7b4e7089723`.
- Final `aurora_masking_native` binary:
  `52e210b488f7ccf0df4aa477aa7f66c65764f511b5532403a02ef322df94e827`;
  `exp2_native`:
  `65c24a731b68a58ba903abf0de9e64b576087e0df056cfcc354028407e1b4af2`.
  The [native report](../../stage3_aurora_masking_native.md) records build settings,
  patches, selected callers and final-binary versus earlier-binary outcomes.
- [Measured source reconstruction](../oct31_kyc_native_milestone_1/benchmark-source-provenance.json)
  explains the test-only post-measurement digest change. Do not substitute current
  hashes into old observations. There is no project Git revision; manifests are
  the content identities. Native upstream commits remain separately pinned.
- [Pooled summary](../oct31_kyc_native_milestone_1/benchmarks/oct31-reference-01/summary.json)
  and its `sessions/` siblings retain all JSONL/CSV records, manifests, summaries,
  configurations and disposition records. Twelve sessions each contain 23 records;
  276 total includes all cold and warm-up observations.

## Exact historical commands and results

[reproduction-index.json](reproduction-index.json) retains exact argv, shell-display
forms, phase/time limits, status and SHA-256 of the authoritative job records.
It includes failed builds/cases and their subsequent explicitly scoped corrections.
These commands describe prior execution; **do not replay them into the closed
ledger or existing output paths**. A future authorised reproduction needs fresh
output/store/config identities, counted admission and the same resource guard.
It must preserve all previous records rather than reset counters or overwrite data.

Representative retained worker commands (they ran inside the recorded guard):

```sh
.venv/bin/python -I -B experiments/kyc_milestone_1/tasks.py cases B 20 48
.venv/bin/python -I -B experiments/kyc_milestone_1/tasks.py cases N 1 24
.venv/bin/python -I -B experiments/kyc_milestone_1/tasks.py cases TR 1 16
.venv/bin/python -I -B experiments/kyc_milestone_1/tasks.py cases C 9 9
```

The first line is a historical correction range, **not** the whole baseline suite.
The index preserves all B ranges and failed outcomes. `native-final-cases`,
`native-final-transcripts` and `native-final-c09` are the final-binary pass records;
`native-cases-01` belongs to the earlier binary. The index also preserves the three
native build commands and outcomes; builds are not authorised by this document.

Each benchmark session used this form with its exact immutable config path:

```sh
.venv/bin/python -I -B experiments/kyc_milestone_1/measurement.py session docs/data/oct31_kyc_native_milestone_1/benchmarks/oct31-reference-01/configs/issue-s1.json
```

All twelve scenario/session argv lists and configs are in the index/retained tree.
The `measurement.py aggregate` command rewrites pooled summaries and therefore
must **not** be used to inspect the frozen dataset. Read the existing summary.
Its recorded aggregate job is retained for provenance. The
[benchmark README](../../../benchmarks/kyc_milestone_1/README.md) documents the
worker protocol, per-trial reservation, schema and readback API; it does not grant
fresh execution allowance. The older top-level benchmarks README is a preserved
pre-implementation placeholder; the versioned report and child README supersede
that dated state without rewriting it.

## Conditions for a later comparison

Record the exact workload/fixture transformation, compiler/binary/source hashes,
dependency paths, CPU/WSL/affinity/power conditions, setup boundary, public caching,
clock/session lifetime, store ownership and instrument versions. Existing trials
use synthetic epoch 1,800,000,000 plus monotonic time, validUntil=base+86,400,
120-second sessions and no DID network resolution. Warm n=60/scenario follows
three independent processes, each one cold, two warm-ups and twenty warm trials.

Reuse unchanged validation and measurement identities. Shared runtime/input or
measurement-condition changes require a justified separately labelled comparison;
a test-only change does not justify silently discarding the retained measured
snapshot. Do not rerun an unaffected baseline to manufacture matching timestamps.
No private-authentication overhead ratio exists until a comparable complete
private implementation has admitted measurements. The reference baseline reveals
the full credential/path and is linkable; its PRESENT latency is not proving time.

## This consolidation's checks

Scoped lint/format, retained-seal/documentary-coverage readback, one inherited full
preservation audit and final inventory/report readback are recorded in `jobs/`.
They run under the existing 256 MiB guard. They do not call any of the functional
commands above. All 276 observations and all previous regression results are reused.
