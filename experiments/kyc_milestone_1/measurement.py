"""One exclusive guarded benchmark session; reserve every trial before execution."""

import json
import sys
import traceback
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from benchmarks.kyc_milestone_1.export import readback, statistics  # noqa: E402
from benchmarks.kyc_milestone_1.run_bench import (  # noqa: E402
    ExclusiveMeasurement,
    SessionRunner,
)
from experiments.kyc_milestone_1 import run as guard  # noqa: E402


def session(config_path):
    config = guard.read(Path(config_path))
    with ExclusiveMeasurement(config["lock_path"]):
        runner = SessionRunner(config)
        try:
            for trial in runner.trials:
                receipt = guard.reserve_case(trial.name)
                record_path = guard.D / "cases" / (receipt["invocation_id"] + ".json")
                try:
                    result = runner.trial(trial, receipt)
                    if result["outcome"] != "accepted":
                        raise RuntimeError("unexpected benchmark outcome: " + result["outcome"])
                    guard.write(
                        record_path,
                        {
                            **receipt,
                            "status": "pass",
                            "benchmark_output": config["output"],
                            "attempt_id": trial.name,
                            "operation_outcome": result["outcome"],
                            "duration_ns": result["duration_ns"],
                        },
                    )
                    guard.finish_case(receipt, "pass")
                except BaseException as error:
                    guard.write(
                        record_path,
                        {
                            **receipt,
                            "status": "failed",
                            "benchmark_output": config["output"],
                            "attempt_id": trial.name,
                            "error": str(error),
                            "traceback": traceback.format_exc(limit=12),
                            "last_operation_record": getattr(runner, "last_record", None),
                        },
                    )
                    guard.finish_case(receipt, "failed")
                    raise
                print(
                    json.dumps(
                        {
                            "case": trial.name,
                            "invocation": receipt["invocation_id"],
                            "status": "pass",
                        }
                    ),
                    flush=True,
                )
        finally:
            runner.finalise()
        rows = readback(Path(config["output"]))
        assert len(rows) == 23
        print(json.dumps({"session_records": len(rows), "complete_readback": True}))


def aggregate(run_root):
    root = Path(run_root)
    configs = sorted((root / "configs").glob("*.json"))
    rows = []
    sessions = []
    for path in configs:
        config = guard.read(path)
        output = Path(config["output"])
        values = readback(output)
        rows.extend(values)
        sessions.append({"output": str(output.relative_to(P)), "records": len(values)})
    assert len(configs) == 12 and len(rows) == 276
    assert len({row["attempt_id"] for row in rows}) == 276
    stats = statistics(rows)
    guard.write(
        root / "summary.json",
        {
            "sessions": sessions,
            "statistics": stats,
            "actual_counted_trials": 276,
            "warm_samples_per_scenario": 60,
            "cold_process_samples_per_scenario": 3,
            "private_authentication": "unavailable",
            "raw_records": (
                "Retained session JSONL/CSV; pooled summary does not duplicate raw outputs"
            ),
        },
    )
    lines = [
        "# Measured isolated ML-DSA reference workload",
        "",
        "All 276 trials retained: 12 cold-process, 24 warm-up and 240 warm measurements.",
        "Setup/key generation are excluded from operation latency "
        "and included in resource accounting.",
        "",
        "| Scenario | Warm n | Median (ms) | Nearest-rank p95 (ms) |",
        "| --- | ---: | ---: | ---: |",
    ]
    for row in stats:
        if row["session"] == "pooled" and row["phase"] == "warm":
            lines.append(
                f"| {row['scenario']} | {row['successful_samples']} | "
                f"{row['median_ns'] / 1e6:.3f} | {row['nearest_rank_p95_ns'] / 1e6:.3f} |"
            )
    lines += [
        "",
        "These are descriptive local observations, not population percentiles or throughput.",
        "Private authentication/proof timings and sizes are unavailable, never zero.",
    ]
    (root / "summary.md").write_text("\n".join(lines) + "\n")
    assert guard.read(root / "summary.json")["actual_counted_trials"] == 276


if __name__ == "__main__":
    {"session": session, "aggregate": aggregate}[sys.argv[1]](sys.argv[2])
