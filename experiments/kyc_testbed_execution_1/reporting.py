"""Derived evidence only: no tests, signing, proofs or service mutations."""

import hashlib
import json
import platform
import sqlite3
import sys
import tarfile
from collections import Counter
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.kyc_testbed_execution_1 import run as guard  # noqa: E402
from pqdid.persistence.codec import decode  # noqa: E402


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while data := stream.read(65536):
            h.update(data)
    return h.hexdigest()


def main():
    d = guard.D
    ledger = guard.read(d / "ledger.json")
    rows = [guard.read(d / "cases" / (r["invocation_id"] + ".json")) for r in ledger["invocations"]]
    latest = {r["case_id"]: r for r in rows}
    plan = guard.read(d / "execution-plan.json")
    outcomes = []
    for case in plan["cases"]:
        r = latest.get(case["id"])
        outcomes.append(
            dict(
                id=case["id"],
                outcome="unrun" if r is None else r["status"],
                invocations=[x["invocation_id"] for x in rows if x["case_id"] == case["id"]],
            )
        )
    guard.write(
        d / "outcomes.json",
        dict(
            cases=outcomes,
            invocation_statuses=dict(Counter(r["status"] for r in rows)),
            total_invocations=len(rows),
            cumulative_invocations=974 + len(rows),
            counts_include_failures_and_repeats=True,
            unrun_reasons={
                "R-1-8": "Eight records exceed manager checkpoint lower bound",
                "R-2-1": "Further scaling stopped after R-1-4 bounded issuer storage rejection",
                "R-2-4": "Same setup route blocked; not repeated",
                "R-2-8": "Eight records exceed manager checkpoint lower bound",
            },
            builds=0,
        ),
    )
    trials = [r for r in rows if r["case_id"].startswith(("T-", "R-")) and r["status"] == "pass"]
    windows = []
    for session in (1, 2, 3):
        for audience in ("A", "B"):
            selected = [r for r in trials if r["case_id"].startswith(f"T-{session}-{audience}-")]
            ns = sum(r["details"]["operation_ns"] for r in selected)
            windows.append(
                dict(
                    session=session,
                    audience=audience,
                    operations=len(selected),
                    active_operation_ns=ns,
                    active_operation_rate_per_second=len(selected) * 1e9 / ns,
                )
            )
    guard.write(
        d / "measurements.json",
        dict(
            version="kyc-completion-observations-v1",
            source_case_files=[
                str((d / "cases" / (r["invocation_id"] + ".json")).relative_to(P)) for r in trials
            ],
            successful_observations=len(trials),
            throughput_observations=18,
            catchup_observations=1,
            windows=windows,
            metric=(
                "Sequential active-operation throughput, "
                "3/sum(request+present+verify/atomic-consume seconds). Setup,"
                " inter-case ledger/reporting and storage scans excluded; not"
                " a continuous wall-window or capacity estimate."
            ),
            scaling="One 1-record observation only; no scaling curve or percentile inference",
            private_proof_measurements=None,
            baseline_v1_unchanged=276,
            environment=dict(
                python=sys.version,
                sqlite=sqlite3.sqlite_version,
                platform=platform.platform(),
                cpu_info=[
                    x
                    for x in Path("/proc/cpuinfo").read_text().splitlines()
                    if x.startswith(("model name", "flags"))
                ][:2],
                memory_info=[
                    x
                    for x in Path("/proc/meminfo").read_text().splitlines()
                    if x.startswith(("MemTotal:", "MemAvailable:", "SwapTotal:"))
                ],
            ),
            source_sha256={str(p.relative_to(P)): digest(p) for p in sorted(guard.N.glob("*.py"))},
            randomness=(
                "Fresh bounded ML-DSA key generation/signing; no seeded or "
                "reused random tapes. Recorded session fixture identities are"
                " in each case; exact random outputs are not a replay "
                "promise."
            ),
            timing=(
                "time.monotonic_ns; serial guarded Python reference "
                "implementation on two allowed CPUs; public synthetic epoch "
                "1800000000 plus elapsed real monotonic time"
            ),
        ),
    )
    # Static inspection of retained database images, no lifecycle re-execution/admission.
    with tarfile.open(d / "failed-R-1-4.tar.xz", "r:xz") as archive:
        with archive.extractfile("issuer/issuer.sqlite3") as stream:
            raw = stream.read(524289)
        assert len(raw) <= 524288
        con = sqlite3.connect(":memory:")
        con.deserialize(raw)
        con.execute("PRAGMA query_only=1")
        sessions = con.execute("SELECT data FROM sessions").fetchall()
        phases = Counter(decode(row[0])[0].decode("ascii") for row in sessions)
        lengths = [len(row[0]) for row in sessions]
        meta = con.execute("SELECT seq,generation FROM meta WHERE id=1").fetchone()
        con.close()
    guard.write(
        d / "failure-analysis.json",
        dict(
            case="R-1-4",
            phase=(
                "setup; issuer certification transaction before complete head"
                " encoding and before replacement SQL writes"
            ),
            expected=False,
            exception="Unavailable: payload-cap",
            source="experiments/kyc_milestone_1/baseline/storage.py:IssuerJournal.transition",
            storage_image_analysis_only=True,
            retained_issuer_phases=dict(phases),
            retained_session_payload_lengths=lengths,
            retained_sequence=meta[0],
            retained_generation=meta[1],
            meaning=(
                "Failed credential remains SIGNING, not "
                "CERTIFIED/retrievable. Permanent manager allocation is "
                "retained. No successful catch-up timing was measured."
            ),
            worker_memory_or_disk_guard_breach=False,
            bounded_application_storage_rejection=True,
            future_decision=(
                "If larger durable histories are required, authorise "
                "separately versioned incremental authenticated "
                "issuer/manager storage with unchanged per-message cap and "
                "fresh recovery/fencing/atomicity validation; preserve v1. "
                "Raising only the nominal session limit cannot fix the "
                "complete-encoding cap."
            ),
        ),
    )
    old = guard.read(P / "docs/data/implementation_consolidation_1/coverage.json")
    additions = {
        "R-012": "F-07 authenticated DID/controller key bound before disclosed-baseline enrolment",
        "R-013": "F-07/F-08/F-09 genuine bounded record signatures; local reference registry",
        "R-014": "Existing DID recovery evidence reused; no new durable registry claim",
        "R-015": "F-07 and M-05/M-06 trusted resolver metadata; not W3C key-suite conformance",
        "R-016": "F-01/F-02/F-13 context/policy/time binding; genuine baseline",
        "R-017": "F-11 authenticated revocation state and catch-up, separate current reads",
        "R-018": "F-01/F-05/F-06 existing permanent allocation and recipient delivery",
        "R-019": (
            "Trusted local issuer/DID mapping and approved attributes; "
            "real-world KYC not implemented"
        ),
        "R-020": (
            "Genuine baseline holder ML-DSA possession; private PQ-DID enrolment proof unavailable"
        ),
        "R-021": "F-05/F-06 exact certification/redelivery; R-1-4 retained SIGNING failure",
        "R-022": "Existing abort evidence reused; no new abort test",
        "R-028": (
            "F-01..F-04 two independent verifier stores, exactly-once acceptance/replay denial"
        ),
        "R-029": "W-04 exact updated path checked against independent sparse-tree fixture",
        "R-030": "F-11 genuine revocation; R-1-4 exposes bounded issuer setup scalability gap",
        "R-031": (
            "W-01..W-24 durable private snapshot/recovery/fencing; 1-record baseline timing only"
        ),
        "R-052": (
            "M-01..M-10 approved local mappings only; standard "
            "key/securing/private status unresolved"
        ),
    }
    guard.write(
        d / "coverage.json",
        dict(
            previous_complete_index="docs/data/implementation_consolidation_1/coverage.json",
            requirements={
                k: dict(
                    title=v,
                    new_evidence=additions.get(
                        k, "Unchanged evidence/obligations; see retained complete index"
                    ),
                    original_scope_closed=False,
                )
                for k, v in old["titles"].items()
            },
            categories=dict(
                working_baseline=(
                    "Connected genuine disclosed ML-DSA baseline; local trusted "
                    "coordinator, fresh synthetic keys"
                ),
                local_pqdid_reference=(
                    "Validated durable holder credential/witness/state storage; "
                    "existing executable relations reused"
                ),
                synthetic_proof_scenarios=(
                    "Historical labelled fixtures only; none on new baseline acceptance path"
                ),
                genuine_private_authentication=(
                    "Unavailable, normal private-proof verification fail-closed"
                ),
            ),
            original_programme_complete=False,
            stages_2_3_open=True,
            unchanged_private_relation_cases=old["unrun_relation_cases"],
            private_proof_measurements=None,
        ),
    )
    summary = dict(
        invocations=len(rows),
        passed=sum(r["status"] == "pass" for r in rows),
        failed=sum(r["status"] == "failed" for r in rows),
        successful_measurements=len(trials),
        rates=[round(w["active_operation_rate_per_second"], 3) for w in windows],
        presentation_sizes=sorted(
            {r["details"]["presentation_bytes"] for r in trials if r["case_id"].startswith("T-")}
        ),
        request_sizes=sorted(
            {r["details"]["request_bytes"] for r in trials if r["case_id"].startswith("T-")}
        ),
        catchup_ms=[
            r["details"]["operation_ns"] / 1e6 for r in trials if r["case_id"].startswith("R-")
        ],
        failed_store_phases=dict(phases),
        usage=guard.storage(),
    )
    guard.write(d / "derived-summary.json", summary)
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
