# Counted ML-DSA reference benchmark

This isolated harness measures the approved `pqdid-mldsa-reference-1` baseline
with real bounded ML-DSA-65 signatures. It discloses the complete attributes,
DID/version, persistent holder public key, issuer signature, revocation identifier
and path. Presentations are linkable. It implements neither private authentication
nor a W3C securing mechanism, and computes no full PQ-DID/PQ-DAA overhead ratio.

The coordinator is `experiments/kyc_milestone_1/run.py`; it owns resource admission,
the 600-slot milestone allocation, historical consumption and every actual outcome.
This directory never admits extra work or changes a budget. Only guarded jobs may
execute the commands below. No additional proof attempt is used.

## Exact workload and API

`scenarios.schedule()` returns exactly 276 distinct trials: ISSUE, PRESENT-A,
PRESENT-B and REVOKE-UPDATE, each with three sessions of one cold-process trial,
two recorded warm-ups and twenty warm measured trials. Each session runs in a new
process; warm trials retain loaded code and public parameters but generate fresh
signatures and use fresh isolated stores. There is no cache dropping, network
activation, cached acceptance or retry substitution.

`run_bench.run_session(config, reserve_trial)` calls the coordinator's callback
before each trial. Its argument is a `scenarios.Trial` with `scenario`, `session`,
`phase`, `index` and stable `name`. The callback must atomically reserve a single
invocation and return this receipt:

```json
{"invocation_id":"M1-0101","case_id":"ISSUE-s1-cold-00","ordinal":101,"cumulative_invocations":549}
```

No code in this harness creates a valid admission receipt. Exclusive claim files
prevent duplicate consumption, including races. A failed measured trial remains
in its original denominator and stops the session for a counted correction.

The callback entry point requires one fresh process per session. The equivalent
long-lived guarded worker protocol is:

```sh
.venv/bin/python -I -B benchmarks/kyc_milestone_1/run_bench.py worker --config SESSION.json
```

Send one JSON line containing `trial` (the four dataclass fields) and `receipt` for
each separately admitted trial. The worker returns a small JSON status line. Send
`{"command":"finish"}` to finalise the outputs. A subsequent session needs a new
process and fresh output and store directories.

Configuration contains `run_id`, `scenario`, `session` (1–3), `output`,
`claims_root`, `store_root`, `lock_path`, `epoch_base`, `deadline_seconds`,
`guard` (actual coordinator limits and job reference) and optional
`dispose_trial_stores: true`. Output/store parents and the lock parent must exist;
the output/store leaf directories must not. Use only the coordinator's registered
project-local synthetic-store root under
`docs/data/oct31_kyc_native_milestone_1/stores`.

The baseline adapter calls `Scenario.material(epoch_base)` once per loaded
session, `Scenario.create(root, epoch_base=..., material=...)`,
`setup_for(scenario)` and `run(scenario)`. The backend exposes `capabilities`,
`setup`, `issue`, `present`, `verify` and `revoke_update`. It deliberately has no
`prove_auth` or `verify_auth_proof` method. Their output metrics are null with the
explicit reason that the complete private-authentication backend is unimplemented.

## Measurement and retention

The enclosing monotonic duration is the end-to-end sample. Named nested stages
are retained with parent relationships and never summed into another end-to-end
value. Key generation and prerequisite issuance are outside operation latency,
inside setup/resource accounting. The semantic fixture is
`alpha-42-old-002c`; fresh instance keys and the approved `epoch_base + 86400`
validity substitution are hashed and recorded. Session lifetime is 120 seconds,
the clock is synthetic epoch plus monotonic elapsed, and DID resolution is off.

Every JSONL/CSV row retains identities, environment, actual payload sizes,
signing-attempt availability, warm-up/cold status, outcome and reserved counter.
Canonical and transport sizes are separate fields. Local transport carries the
canonical binary message directly; no network envelope or WAN latency is implied.
No private keys or real user records enter the exports. Process RSS is explicitly
a lifetime high-water mark. Cgroup measurements include setup and descendants;
post-exit authoritative peaks belong to the coordinator's job record. No per-trial
memory attribution is claimed.

Successful disposable synthetic stores may be removed only when the coordinator
sets `dispose_trial_stores` explicitly. A bounded disposition log preserves every
file's relative name, byte count and non-secret hash before removal and records
completion. Secret-key file hashes are unavailable with an explicit reason.
Failed stores remain for diagnosis. Source, historical stores and all measurement
evidence are retained. Typically only one trial's stores need exist at a time;
the real footprint is measured and charged by the guard, never assumed free.

`export.validate_record` implements the supplied `schema.json` plus monotonic,
nested-timing, classification, identity and unavailable-metric invariants. JSONL
and CSV stream to chunks of at most 1 MiB; ordinary row estimates are 6–15 KiB
depending on source identity count. A row exceeding the cap fails before writing.
Fresh output IDs are mandatory. `summary.md`, `summary.json` and the hash manifest
are exclusively created. `export.readback` checks every file hash, every record,
all CSV fields and recomputed statistics.

Statistics report per-session and pooled cold, warm-up and warm populations,
planned/observed denominators, successes, failures, missing attempts and censoring.
Warm-up rows are excluded only from warm statistics. Min, median, nearest-rank
p95 and max use successful uncensored observations; no failure is replaced.
Pooled warm n=60 and cold n=3 are achieved only after all scheduled trials succeed.
These observations describe this host, not a population p95, throughput or SLA.

## Counted validation

Each following command executes exactly one frozen validation ID:

```sh
.venv/bin/python -I -B benchmarks/kyc_milestone_1/cases.py --case H-01 --root REGISTERED_FRESH_ROOT
.venv/bin/python -I -B benchmarks/kyc_milestone_1/integration_cases.py --case C-01 --root REGISTERED_FRESH_ROOT
```

H-01–16 exercise schema, timing, byte distinctions, warm-up/failure denominators,
censoring, unavailable fields, identities, exclusive output/measurement handling,
chunking, evidence classification, nearest-rank quantiles and duplicate-receipt
races. Their small observations are labelled `synthetic-validation`, never measured
cryptographic results. C-01–08 use actual signatures and durable baseline stores;
C-09 requires actual passed native caller coverage; C-10 checks reuse invalidation;
C-11 checks coordinator accounting, real guard limits and output roles; C-12 checks
real baseline export/readback with unavailable proof metrics. C-12 additionally
requires `--config` containing the actual `guard` and counted `receipt`.

Outputs, manifests, CSV/JSONL chunks, disposition hashes and validation reports are
evidence. The registered fresh key/wallet/SQLite stores are synthetic artifacts.
All are charged by the coordinator; warm-up and failed trials are counted too.
