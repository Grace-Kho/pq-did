"""Decide proof admission using the single completed execution and pinned support."""

import json
from pathlib import Path

R = Path(__file__).resolve().parents[1]


def read(name):
    return json.loads((R / name).read_text())


execution = read("evidence/execution.result.json")
preflight = read("evidence/preflight.result.json")
resources = read("evidence/execution.json")
sizes = [s["po2"] for s in execution.get("segment_records", [])]
checks = {
    "execution_success": execution.get("accepted") is True,
    "exact_journal": execution.get("journal_matches_expected") is True,
    "segment_count_decreased": 0 < execution.get("segments", 10) < 10,
    "supported_sizes": bool(sizes) and all(p in preflight["supported_segment_po2"] for p in sizes),
    "configuration_compatible": preflight["configuration_compatible"],
    "execution_within_envelope": resources["status"] == "pass",
}
record = {
    "proof_admitted": all(checks.values()),
    "checks": checks,
    "segments": execution.get("segments"),
    "segment_po2": sizes,
    "previous_segments": 10,
    "supported_prover_maximum": 22,
    "note": "Execution memory is not proving memory; proof keeps 2 GiB/600 s",
}
(R / "evidence/admission.result.json").write_text(json.dumps(record, indent=2) + "\n")
if not record["proof_admitted"]:
    (R / "evidence/STOP.json").write_text(
        json.dumps(
            {
                "reason": "execution admission failed",
                "checks": checks,
                "proof_attempts_used_cumulative": 1,
                "remaining": 2,
            },
            indent=2,
        )
        + "\n"
    )
print(json.dumps(record, indent=2))
