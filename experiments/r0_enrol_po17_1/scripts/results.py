"""Collate observed execution/proof/verification evidence, without timeout speedups."""

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

R = Path(__file__).resolve().parents[1]


def read(name):
    return json.loads((R / name).read_text())


ledger = read("evidence/run_ledger.json")
execution = read("evidence/execution.result.json")
record = {
    "package": "R0-ENROL-PO17-1",
    "execution": execution,
    "execution_resources": read("evidence/execution.json"),
    "execution_timing_scope": "Execute excludes client creation; baseline timer included it",
    "previous_result": read("evidence/baseline.json")["previous_results"]["attempts"][0],
    "cumulative_budget": read("evidence/cumulative_attempt_ledger.json"),
    "overall_speedup": None,
    "overall_speedup_reason": "Previous complete proof time unavailable: timeout",
    "setup_build_seconds": sum(
        r["wall_seconds"] for r in ledger["runs"] if r["phase"] in ["setup", "build"]
    ),
    "proof": None,
}
if (R / "evidence/attempt2.json").exists():
    resource = read("evidence/attempt2.json")
    progress = read("evidence/attempt2.sdk-progress.json")
    info = read("receipts/attempt2.bin.json") if (R / "receipts/attempt2.bin").exists() else None
    observed = []
    pending = {}
    log = re.sub(r"\x1b\[[0-9;]*m", "", (R / "evidence/attempt2.log").read_text())
    for line in log.splitlines():
        stamp = re.match(r"(\d{4}-\d\d-\d\dT[0-9:.]+Z)", line)
        if not stamp:
            continue
        t = datetime.fromisoformat(stamp[1]).timestamp()
        for kind, start, finish in [
            ("lift", "Proving lift:", "Proving lift finished:"),
            ("join", "Proving join: a.claim", "Proving join finished:"),
        ]:
            if start in line:
                pending[kind] = (t, stamp[1])
            if finish in line and kind in pending:
                began, utc = pending.pop(kind)
                observed.append(
                    {
                        "operation": kind,
                        "started_utc": utc,
                        "completed_utc": stamp[1],
                        "seconds": t - began,
                    }
                )
    row = {
        "resources": resource,
        "SDK_result": info,
        "SDK_phase_observations": progress,
        "completed_recursion_intervals": observed,
        "independent_verification": None,
        "tamper_checks": None,
        "outcome": "completed_succinct" if info else "incomplete",
        "last_observed_phase": progress.get("last_event"),
    }
    if info:
        assert info["stats"]["segments"] == execution["segments"]
        assert info["stats"]["user_cycles"] == execution["user_cycles"]
        assert info["stats"]["total_cycles"] == execution["padded_capacity"]
        row["receipt_sha256"] = hashlib.file_digest(
            (R / "receipts/attempt2.bin").open("rb"), "sha256"
        ).hexdigest()
        row["pipeline_margin_seconds"] = 600 - info["pipeline_including_recursion_seconds"]
    for key, path in [
        ("independent_verification", "evidence/verify.result.json"),
        ("tamper_checks", "evidence/adversarial.result.json"),
    ]:
        if (R / path).exists():
            row[key] = read(path)
    events = progress["events"]
    if "lift_start" in events:
        row["observed_segment_phase_seconds"] = (
            events["lift_start"]["first_seconds"]
            - events["segment_preflight_start"]["first_seconds"]
        )
    if "join_complete" in events:
        row["observed_recursion_phase_seconds"] = (
            events["join_complete"]["last_seconds"] - events["lift_start"]["first_seconds"]
        )
    record["proof"] = row
(R / "evidence/results.json").write_text(json.dumps(record, indent=2) + "\n")
print(
    json.dumps(
        {
            "proof_outcome": record["proof"]["outcome"] if record["proof"] else "not_launched",
            "segments": execution["segments"],
            "cumulative_budget": record["cumulative_budget"],
        },
        indent=2,
    )
)
