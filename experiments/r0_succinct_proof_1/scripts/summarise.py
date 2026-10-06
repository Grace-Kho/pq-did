"""Summarise actual attempts without converting partial work into a complete cost."""

import hashlib
import json
import re
from pathlib import Path

R = Path(__file__).resolve().parents[1]


def read(name):
    return json.loads((R / name).read_text())


ledger = read("evidence/run_ledger.json")
workload = read("evidence/preflight.result.json")["workload"]
fixtures = {c["name"]: c for c in read("fixtures/cases.json")["cases"]}
rows = []
for resource in ledger["runs"]:
    if resource["phase"] != "prove":
        continue
    n = resource["slot"]
    name = "enrol-alpha-42" if n == 1 else "cred-alpha-42"
    op = "enrol" if n == 1 else "cred-valid"
    fixture = fixtures[name]
    progress = read(f"evidence/attempt{n}.sdk-progress.json")
    events = progress["events"]
    log = (R / f"evidence/attempt{n}.log").read_text()
    match = re.search(r'exit_code = (.*?), journal = Some\("([0-9a-f]+)"\), segments: (\d+)', log)
    execution = None
    if match:
        journal = bytes.fromhex(match[2])
        execution = {
            "exit_code": match[1],
            "segments": int(match[3]),
            "journal_bytes": len(journal),
            "journal_sha256": hashlib.sha256(journal).hexdigest(),
            "journal_matches_expected": journal == (R / fixture["expected_journal"]).read_bytes(),
            "source": "retained SDK prove_session log; not a receipt or returned ProveInfo.stats",
        }
        assert execution["journal_matches_expected"]
    receipt = R / f"receipts/attempt{n}.bin"
    returned = read(f"receipts/attempt{n}.bin.json") if receipt.exists() else None
    state = resource["systemd_final_properties"]
    outcome = (
        "succinct_generated_self_verified"
        if returned
        else "timed_out"
        if "Result=timeout" in state
        else "memory_limited"
        if "oom" in state or "memory" in (resource["stop_reason"] or "")
        else "failed"
    )
    counts = {k: v["count"] for k, v in events.items()}
    row = {
        "attempt": n,
        "fixture": name,
        "outcome": outcome,
        "last_observed_phase": progress.get("last_event"),
        "phase_event_counts": counts,
        "phase_event_times": events,
        "execution_from_log": execution,
        "prior_execution_workload": workload[op],
        "completed_segment_proofs": workload[op]["segment_count"]
        if counts.get("lift_start")
        else None,
        "complete_pipeline_wall_seconds": resource["wall_seconds"],
        "SDK_complete_combined_seconds": returned["pipeline_including_recursion_seconds"]
        if returned
        else None,
        "actual_returned_session_stats": returned["stats"] if returned else None,
        "seal_bytes": returned["seal_bytes"] if returned else None,
        "receipt_journal_bytes": returned["journal_bytes"] if returned else None,
        "serialized_receipt_bytes": receipt.stat().st_size if returned else None,
        "fresh_verification": read(f"evidence/verify{n}.json")
        if (R / f"evidence/verify{n}.json").exists()
        else None,
        "tamper_verification": read(f"evidence/tamper{n}.json")
        if (R / f"evidence/tamper{n}.json").exists()
        else None,
        "resources": resource,
        "timing_note": "Observed log boundaries; incomplete total costs stay unmeasured",
    }
    if counts.get("lift_start"):
        row["observed_segment_phase_seconds"] = (
            events["lift_start"]["first_seconds"]
            - events["segment_preflight_start"]["first_seconds"]
        )
        row["observed_recursion_before_return_or_stop_seconds"] = (
            resource["wall_seconds"] - events["lift_start"]["first_seconds"]
        )
    rows.append(row)
summary = {
    "package": "R0-SUCCINCT-PROOF-1",
    "attempts": rows,
    "proof_attempts_used": ledger["proof_attempts"],
    "proof_attempts_unused": 3 - ledger["proof_attempts"],
    "actual_succinct_receipts": [str(p.relative_to(R)) for p in (R / "receipts").glob("*.bin")],
    "setup_build_service_seconds": sum(
        r["wall_seconds"] for r in ledger["runs"] if r["phase"] in ["setup", "build"]
    ),
    "complete_cold_subprocess_seconds": sum(
        r["wall_seconds"] for r in ledger["runs"] if "wall_seconds" in r
    ),
    "cold_cost_definition": "Service sum; excludes authoring and reused installation",
    "not_run": ["CredValid and optional repeat: prerequisite enrolment failed"]
    if rows and rows[0]["outcome"] != "succinct_generated_self_verified"
    else [],
}
(R / "evidence/results.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps({k: v for k, v in summary.items() if k != "attempts"}, indent=2))
