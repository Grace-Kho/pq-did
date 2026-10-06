"""Public milestone commands over the same guarded jobs and retained evidence."""

import hashlib
import json
import re
import sys
import time
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.kyc_milestone_1 import run as guard  # noqa: E402


def verify_plan(path):
    path = Path(path).resolve()
    expected_path = P / "docs/data/october_implementation_milestone_1/execution-plan.json"
    assert path == expected_path
    approval = guard.read(guard.D / "approval.json")
    assert hashlib.sha256(path.read_bytes()).hexdigest() == approval["plan_sha256"]
    assert approval["approved"] is True
    return guard.read(path)


def admit(args):
    plan = verify_plan(args.plan)
    ledger = guard.read(guard.D / "ledger.json")
    value = {
        "approved": True,
        "plan": plan["milestone"],
        "storage": guard.storage(),
        "implementation_remaining_seconds": 4274 - guard.consumed(ledger),
        "milestone_invocations_used": len(ledger["invocations"]),
        "milestone_invocations_remaining": 600 - len(ledger["invocations"]),
        "builds_remaining": 8 - len(ledger["builds"]),
    }
    print(json.dumps(value))
    return 0


def validation_status(args):
    plan = verify_plan(args.plan)
    latest = {row["case_id"]: row for row in guard.read(guard.D / "ledger.json")["invocations"]}
    expected = [
        row["id"]
        for key in ("native_new_cases", "baseline_cases", "harness_cases", "integration_cases")
        for row in plan[key]
    ]
    expected += plan["native_exp2_cases"]
    pending = [case for case in expected if latest.get(case, {}).get("status") != "pass"]
    print(
        json.dumps(
            {
                "passed_case_ids": [c for c in expected if c not in pending],
                "pending": pending,
                "new_executions": 0,
                "meaning": (
                    "Recorded case results only; input reuse/native identities separately audited"
                ),
            }
        )
    )
    return int(bool(pending))


def benchmark(args):
    verify_plan(args.plan)
    assert re.fullmatch(r"[A-Za-z0-9_-]{1,60}", args.run_id)
    root = Path(args.output).resolve()
    assert root == guard.D / "benchmarks" / args.run_id
    latest = {row["case_id"]: row for row in guard.read(guard.D / "ledger.json")["invocations"]}
    required = [f"B-{i:02d}" for i in range(1, 49)] + [f"H-{i:02d}" for i in range(1, 17)]
    required += [f"C-{i:02d}" for i in [*range(1, 9), 10, 11, 12]]
    assert all(latest.get(case, {}).get("status") == "pass" for case in required)
    root.mkdir(parents=True, exist_ok=True)
    (root / "configs").mkdir(exist_ok=True)
    (root / "sessions").mkdir(exist_ok=True)
    scenarios = (
        [args.scenario] if args.scenario else ["ISSUE", "PRESENT-A", "PRESENT-B", "REVOKE-UPDATE"]
    )
    sessions = [args.session] if args.session else [1, 2, 3]
    started = time.monotonic()
    for scenario in scenarios:
        for session in sessions:
            if time.monotonic() - started + 120 >= 300:
                raise RuntimeError(
                    "coordinator command admission: resume unstarted session explicitly"
                )
            name = scenario.lower() + "-s" + str(session)
            config = root / "configs" / (name + ".json")
            assert not config.exists(), "no implicit repeat of a session"
            job_name = "bench-" + name
            store = guard.D / "stores" / (args.run_id + "-" + name)
            value = {
                "run_id": args.run_id,
                "scenario": scenario,
                "session": session,
                "output": str(root / "sessions" / name),
                "store_root": str(store),
                "claims_root": str(root / "claims"),
                "lock_path": str(guard.D / "measurement.lock"),
                "epoch_base": 1_800_000_000,
                "deadline_seconds": 120,
                "dispose_trial_stores": True,
                "guard": {
                    "phase": "python",
                    "memory_limit_bytes": 268435456,
                    "job_record": str((guard.D / "jobs" / (job_name + ".json")).relative_to(P)),
                    "aggregate_memory_limit_bytes": 2147483648,
                    "swap_bytes": 0,
                    "exclusive_measurement": True,
                    "post_exit_peak_in_job_record": True,
                },
            }
            guard.write(config, value)
            result = guard.job(
                job_name,
                "python",
                120,
                [
                    str(P / ".venv/bin/python"),
                    "-I",
                    "-B",
                    str(P / "experiments/kyc_milestone_1/measurement.py"),
                    "session",
                    str(config),
                ],
            )
            if result:
                return result
    return 0


def finalise(args):
    verify_plan(args.plan)
    script = str(P / "experiments/kyc_milestone_1/preservation.py")
    for name, phase, task in (
        ("prepare", "tool", "prepare"),
        ("full-audit", "audit", "full-audit"),
        ("final-readback", "tool", "readback"),
    ):
        result = guard.job(
            name,
            phase,
            30,
            [str(P / ".venv/bin/python"), "-I", "-B", script, task],
            completion=True,
        )
        if result:
            return result
    return 0
