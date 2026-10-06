"""Decode only bounded phase records and aggregate already-saved segment metadata."""

import argparse
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument("name")
a = p.parse_args()
labels = json.loads((ROOT / "evidence/phase_labels.json").read_text())
data = (ROOT / f"evidence/{a.name}.markers").read_bytes()
assert len(data) <= 65536 and len(data) % 16 == 0
markers = []
for magic, phase, cycle in struct.iter_unpack("<4sIQ", data):
    assert magic == b"CYC1" and str(phase) in labels
    markers.append({"phase": labels[str(phase)], "id": phase, "user_cycle": cycle})
assert all(x["user_cycle"] < y["user_cycle"] for x, y in zip(markers, markers[1:], strict=False))
intervals = [
    {
        "start": x["phase"],
        "end": y["phase"],
        "start_cycle": x["user_cycle"],
        "end_cycle": y["user_cycle"],
        "raw_user_cycles": y["user_cycle"] - x["user_cycle"],
    }
    for x, y in zip(markers, markers[1:], strict=False)
]
result = json.loads((ROOT / f"evidence/{a.name}.result.json").read_text())
if result["status"] == "cycle_limit" and markers:
    intervals.append(
        {
            "start": markers[-1]["phase"],
            "end": "hard_cap",
            "start_cycle": markers[-1]["user_cycle"],
            "end_cycle": 4194304,
            "raw_user_cycles": 4194304 - markers[-1]["user_cycle"],
            "partial": True,
        }
    )
calibration = [
    row["raw_user_cycles"]
    for row in intervals
    if row["start"] in ("calibration_0", "calibration_1")
]
segments = result["completed_segment_metadata"]
user = sum(x["user_cycles"] for x in segments)
padded = sum(1 << x["po2"] for x in segments)
summary = {
    "name": a.name,
    "status": result["status"],
    "marker_count": len(markers),
    "markers": markers,
    "intervals": intervals,
    "empty_marker_intervals": calibration,
    "completed_segment_count": len(segments),
    "completed_segment_user_cycles": user,
    "completed_segment_padded_capacity": padded,
    "completed_segment_other_capacity": padded - user,
    "active_phase_at_cap": markers[-1]["phase"]
    if result["status"] == "cycle_limit" and markers
    else None,
    "measurement_note": (
        "Raw intervals include one marker and any intervening glue. "
        "Paging/reserved/padding are not individually exposed by Execute IPC. "
        "Capped prefix and isolated components are not full relation totals."
    ),
}
(ROOT / f"evidence/{a.name}.analysis.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps({k: v for k, v in summary.items() if k not in ("markers", "intervals")}, indent=2))
for row in intervals:
    print(row["start"], row["end"], row["raw_user_cycles"])
