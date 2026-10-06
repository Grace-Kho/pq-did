# KYC-TESTBED-DELIVERY-1

This package supplies a reproducible **genuine disclosed ML-DSA baseline** and
versioned benchmark exports. It is not complete private authentication, a deployed
service, a W3C cryptosuite or a production-security release. Only manuscript
Sections II–VIII and SPEC-001–004 are authoritative. The full project scope and
31 October target remain unchanged; current evidence does not support committing
to complete private authentication by that date. Stages 2–3 remain open.

## Implemented delivery boundary

`experiments/kyc_testbed_delivery_1/demo.py` reuses the existing Application,
issuer-v2 journal, manager-v2 store, public-history pages and disclosed-baseline
holder/verifiers. New code is isolated; historical baseline and production proof
code are unchanged. Fresh synthetic keys use the actual bounded ML-DSA-65 core.
There is no synthetic proof-acceptance adapter in the baseline path.

D-01 issues and accepts the credential after authenticated DID resolution. D-02
reopens the holder and issuer using the **v2 IssuerJournal** and the independently
retained pre-reopen ticket, then retrieves exactly the committed delivery. It
never calls the historical v1-selecting `Scenario.reopen()`. D-03/D-04 accept at
independent verifier stores and check that the other store is unchanged. D-05
and D-06 reject replay and cross-audience use without mutation.

D-07 creates seven public updates by revoking other synthetic holders. A deliberately
interrupted second page leaves the wallet bytes unchanged. D-08 collects the complete
fixed-target history and applies one atomic replacement, then reopens the wallet.
D-09 revokes the principal holder at epoch eight and checks rejection with unchanged
wallet bytes. D-10 confirms the ordinary unsupported private-proof verifier rejects
and exposes no enabled prove/verify capability. These are ten distinct counted
cases, not one case concealing ten observations.

Public history queries contain namespace, epoch and target state, never the holder's
identifier. The 65,536-byte response limit is unchanged. This demonstration reaches
eight updates; the retained scaling evidence also reaches eight. No capacity beyond
that boundary, durable registry, cross-store ACID, secure external-head custody,
power-loss durability or hostile-owner isolation is established. The DID registry
is the existing in-memory reference registry. The disclosed holder's atomic wallet
file and persistent authentication key are **not** the private PQ-DID reference
wallet in `src/pqdid/holder_wallet.py`; the latter's completed recovery tests are reused.

The disclosed presentation exposes complete attributes, DID/version, persistent
holder key, issuer signature, revocation identifier and path. It is linkable. It
must not be described as PQ-DAA, private PQ-DID performance or privacy overhead.

## Runner, evidence and exports

`benchmarks/kyc_testbed_delivery_1/runner.py` performs exactly four separately admitted
v2 smoke observations: ISSUE, PRESENT-A, PRESENT-B and REVOKE-UPDATE. Each has fresh
synthetic material/stores. Setup is outside the operation interval and inside all
resource accounting. Revocation uses bounded public paging and authenticated rejection
of the affected holder. Environment, source/case identities, message/storage sizes,
setup/operation durations and cgroup/process memory scopes are recorded. These four
observations validate the runner; they do not establish percentiles or throughput.

`export.py` produces a **derived catalogue**, preserving pointers/hashes to authoritative
raw records. It verifies retained record hashes, invocation status, per-series summaries
and exact counts before accepting the expected 302. It does not recreate old expected
hashes from today's changed source tree. The existing measured-source reconstruction
is retained and verified for v1. Missing/altered source evidence is an integrity failure,
not permission to force the expected count.

| Separate series | Retained successful observations | Interpretation |
| --- | ---: | --- |
| Original comparison point v1 | 276 | 12 cold-process, 24 warm-up, 240 warm; historical descriptive distributions |
| KYC testbed observations | 19 | 18 serial active-operation observations plus one one-record catch-up |
| Issuer-v2 | 3 | Separate small scaling observations; manager was still v1 |
| Manager-v2 | 4 | One/four/eight updates with bounded paging; two eight-update observations |
| Delivery-v2 smoke | 4 planned new | Runner validation only; separately labelled, never pooled |

Original raw records, CSV/JSONL, summaries and failures remain immutable. The new
catalogue includes dataset, observation ID, timing definition/phase, operation/setup
nanoseconds, storage versions and exact source locator/SHA-256. Full message/storage
and environment detail remains in those linked raw records; absence is not filled
with invented zeroes. Historical failed validation/integration invocations are indexed
separately and do not enter the 302 successful-observation count. No original benchmark
trial failure is invented: all 276 original trials passed.

Bounded JSONL/CSV chunks are at most 256 KiB. Export cases cover roundtrip/provenance,
duplicate identities, attempted promotion to private-proof measurements and refusal
to overwrite existing outputs. Component results remain a separately labelled reference
to the retained component catalogue, never baseline rows. Proof generation/verification
time, proof size, private peak memory/throughput and privacy overhead remain **null
with explicit unavailable reasons**. Original active-operation rates exclude setup
and inter-case bookkeeping; they are not wall-window saturation rates. No new rate
is claimed from the smoke measurements.

## Exact commands and reproduction admission

From `/home/grace/projects/pq-did`, the executed guarded phase interface is:

```sh
.venv/bin/python -I -B experiments/kyc_testbed_delivery_1/run.py static
.venv/bin/python -I -B experiments/kyc_testbed_delivery_1/run.py preflight
.venv/bin/python -I -B experiments/kyc_testbed_delivery_1/run.py demo
.venv/bin/python -I -B experiments/kyc_testbed_delivery_1/run.py export
.venv/bin/python -I -B experiments/kyc_testbed_delivery_1/run.py benchmark
.venv/bin/python -I -B experiments/kyc_testbed_delivery_1/run.py prepare
.venv/bin/python -I -B experiments/kyc_testbed_delivery_1/run.py full-audit
.venv/bin/python -I -B experiments/kyc_testbed_delivery_1/run.py readback
```

`run.py all` dispatches static, preflight, demo, export and benchmark in order and
stops on failure. It does not claim preservation/report closure. Finalisation requires
the prepared report snapshot and explicit final checkpoint above. Closed historical
job names/output paths refuse reuse. A future reproduction needs a fresh registered
run directory/policy linked to this checkpoint and new invocation/time admission;
there is no unguarded bypass or automatic budget reset. Fresh randomness reproduces
behaviour/conditions, not identical keys/signatures. Full argv, limits and source
paths are retained in `docs/data/kyc_testbed_delivery_1/jobs/*.input.json`.

The retained v1 reproduction API and 276-trial schedule remain unchanged in
`benchmarks/kyc_milestone_1/README.md`; this package does not authorise replaying it.
Current exports are under `docs/data/kyc_testbed_delivery_1/exports/`; the package
export index distinguishes retained observations and smoke outputs.

## Resources, corrections and Preservation

The authoritative predecessor had 589.7847020792524 overall implementation seconds,
443.3903556420428 KYC seconds, and 146.39434643720955 outside KYC. The approved
**20-second conservative preparation charge** is recorded once, outside KYC and
separately from measured execution. The **80-second transfer** increases KYC to
523.3903556420428 seconds and leaves 46.39434643720955 outside KYC, without increasing
the overall balance (569.7847020792524 after preparation).

The package ceiling is 220 seconds, including 30 for finalisation; KYC's existing
300-second reserve remains protected. A conservative 100-second operator charge
covers implementation, source reads, documentation and direct bookkeeping; guarded
elapsed times are additional and charged once. Invocations start at 1,165; 18 fixed
plus at most four targeted corrections fit the new 1,190 ceiling, preserving three
embedding-only slots. Builds stay 10/13; no builds/acquisitions/installations/proofs/
zkVM runs are authorised or performed.

The 2 MiB package evidence limit includes sources, synthetic SQLite databases/journals,
exports, logs, inventories and final reports. Initial prospective peak admission was
1,150,000 bytes for simultaneous synthetic stores/journals, 380,000 for other work,
and 524,288 for completion: 2,054,288 bytes within 2,097,152. Actual storage is monitored
throughout. Successful new stores are removed only by the existing exact owned-file
cleanup after outcomes and inventories are retained; historical stores and failed
fixtures are never removed to gain headroom. Everything remains evidence, not newly
reclassified artifacts. Shared headroom opened at 5,940,496 bytes; its separate
2,097,152-byte reserve and the 40 MiB cumulative ceiling remain protected.

One serial worker uses 256 MiB cgroup-v2 memory, zero swap, two CPUs and existing
command/process/temp/store limits. Metrics distinguish worker cgroup memory including
descendants/cache/kernel from sampled process RSS. The final corrected auditor retains
all original content comparisons, seals, required names and explicit report prefixes.
The validation/resource closures determine final completion.

The first static pass found line-length and loop-binding diagnostics. The second
passed after wrapping strings and explicitly binding synchronous callback variables.
Both records and their resource charges remain; no functional invocation was spent
on static checks. Additional outcomes/corrections and final accounting follow below.

CV-ONLINE-SAME-OBJECT-1 remains unresolved and its analysis package closed. Binius64
proving and isolation remain paused, ordinary private verification fail-closed.
Adaptive-tail, complete knowledge/privacy, concrete-hash, finite-security, production
custody/entropy/erasure/side-channel and standards obligations remain open. Proof
ledger: **two used, one unused**. This closes baseline delivery only after its final
checkpoint; no subsequent package is launched.


## Individual delivery outcomes

| ID | Outcome | Case seconds | Purpose |
| --- | --- | ---: | --- |
| D-01 | pass | 0.932558 | issue and durable acceptance |
| D-02 | pass | 0.079389 | v2 recovery and exact redelivery |
| D-03 | pass | 0.560689 | verifier A acceptance |
| D-04 | pass | 0.576876 | independent verifier B acceptance |
| D-05 | pass | 0.122009 | replay rejection |
| D-06 | pass | 0.110740 | cross-audience rejection |
| D-07 | pass | 9.364090 | missing second page leaves wallet unchanged |
| D-08 | pass | 0.610233 | complete two-page atomic catch-up |
| D-09 | pass | 1.774160 | revoked holder rejection |
| D-10 | pass | 0.495799 | private backend fail-closed |
| E-01 | pass | 0.005738 | export roundtrip/provenance |
| E-02 | pass | 0.000179 | duplicate identity rejection |
| E-03 | pass | 0.000011 | category promotion rejection |
| E-04 | pass | 0.000236 | existing output refused |
| B-01 | pass | 0.868202 | ISSUE |
| B-02 | pass | 1.247395 | PRESENT-A |
| B-03 | pass | 1.463650 | PRESENT-B |
| B-04 | pass | 1.762428 | REVOKE-UPDATE |

All 18 fixed invocations passed once; no functional correction or repeat was needed.
Cumulative invocations are **1,183/1,190**: four delivery corrective slots unused,
three embedding-only slots preserved. Builds remain 10/13. D-08's seven updates
used **55,041 and 43,874-byte** responses and one wallet replacement; D-09 then
reached epoch eight and rejected the revoked holder without changing its wallet.

Retained export readback confirmed **276 + 19 + 3 + 4 = 302** historical successful
observations and separately indexed **seven failed historical invocations** (including
validation history, not seven failed benchmark trials). Four new smoke rows are in
a different directory/dataset; total catalogue rows are **306**, without pooled
statistics. Case/resource timers are distinct: case durations below include setup
and assertions; operation durations in raw B records use the declared inner interval.

| New smoke | Operation ms | Setup ms |
| --- | ---: | ---: |
| ISSUE | 231.000 | 626.364 |
| PRESENT-A | 505.801 | 735.570 |
| PRESENT-B | 451.941 | 1005.716 |
| REVOKE-UPDATE | 458.866 | 1297.807 |

These four observations validate the new interface only. Historical statistics and
small scaling observations remain unchanged, including historical failures. The
21 complete-authentication relation checks remain unrun. Synthetic stores were
charged as evidence while live, and successful stores were disposed through the
existing owned-file cleanup after case/disposition recording. SQLite transient
journal usage was enforced but its exact peak is not separately retained by the
inherited monitor; no stronger peak-storage measurement is claimed.

## Consolidated preservation checkpoint

The first audit stopped at the primary comparison because this package's approved
`benchmarks/README.md` appendix was absent from the inherited primary comparison
permission list. Its complete 211-byte historical prefix matches the retained seal
`2d926b72011d15ad08b377cd7039e8641bc519a06961a6b98453f1cce478abf6`.
This was a scope-registration omission, not an unexplained content replacement.
The exact filename was added to that comparison's documentation permission list;
the historical-prefix check and every immutable baseline/hash remain unchanged.
No broad documentation exception was introduced. The before-helper, preparation,
inventory, phases and failure are retained in `audit-correction-1/` and `jobs/`.

The corrected helper passed its affected static checks, corrected preparation passed,
and the complete audit exited zero: **10,901** disjoint content comparisons,
**10,936** identity-inclusive paths, all sealed inputs and historical prefixes,
1,914 local links, then report write/readback. The earlier primary comparison is
partial failed evidence, never substituted for this complete pass. This checkpoint
therefore contains one retained failed comparison attempt and one successful full
audit. No functional case was repeated. All inputs to the 18 functional cases remain
unchanged; only the preservation adapter was corrected afterward.

The exact additional correction commands were:

```sh
.venv/bin/python -I -B experiments/kyc_testbed_delivery_1/run.py job static-audit-fix tool 5 -- .venv/bin/python -I -B experiments/kyc_testbed_delivery_1/tooling.py static
.venv/bin/python -I -B experiments/kyc_testbed_delivery_1/run.py job prepare-2 audit 4 -- .venv/bin/python -I -B experiments/kyc_testbed_delivery_1/preservation.py prepare
.venv/bin/python -I -B experiments/kyc_testbed_delivery_1/run.py job full-audit-2 audit 10 -- .venv/bin/python -I -B experiments/kyc_testbed_delivery_1/preservation.py full-audit
```

[Validation closure](data/kyc_testbed_delivery_1/validation-closure.json) records
final inventory/readback and termination. [Resource closure](data/kyc_testbed_delivery_1/resource-closure.json)
records the final measured guard times, conservative charges, byte counts and balances.
[Export index](data/kyc_testbed_delivery_1/export-index.json) identifies the separate
datasets; [outcomes](data/kyc_testbed_delivery_1/outcomes.json) contains every fixed result.

KYC delivery implementation/validation is complete when the final closure passes.
CV-ONLINE-SAME-OBJECT-1, complete private authentication, production custody/security,
standards conformance and the unresolved acquisition-memory observation remain open.
The historical 21 full-relation checks remain unrun. No subsequent package was started.
