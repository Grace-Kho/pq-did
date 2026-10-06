"""Guarded work dispatch; each functional invocation is reserved individually."""

import argparse
import importlib
import json
import subprocess
import sys
import time
import traceback
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.kyc_milestone_1 import run as coordinator  # noqa: E402

D = coordinator.D


def quality():
    paths = [
        P / "experiments/kyc_milestone_1",
        P / "benchmarks/kyc_milestone_1",
        P / "experiments/aurora_masking_milestone_1/cases.py",
    ]
    for flags in (
        ("check", "--select", "I,F", "--fix"),
        ("format",),
        ("check",),
        ("format", "--check"),
    ):
        subprocess.run(
            [str(P / ".venv/bin/ruff"), *flags, "--no-cache", *map(str, paths)],
            check=True,
            timeout=20,
        )


def cases(group, first, last):
    material = None
    modules = {
        "H": "benchmarks.kyc_milestone_1.cases",
        "C": "benchmarks.kyc_milestone_1.integration_cases",
        "B": "experiments.kyc_milestone_1.baseline.cases",
        "N": "experiments.aurora_masking_milestone_1.cases",
        "TR": "experiments.aurora_masking_milestone_1.cases",
    }
    for index in range(first, last + 1):
        case = f"{group}-{index:02d}"
        receipt = coordinator.reserve_case(case)
        root = D / "stores" / receipt["invocation_id"]
        root.parent.mkdir(exist_ok=True)
        start = time.monotonic()
        scenario = None
        try:
            module = importlib.import_module(modules[group])
            if group == "B":
                if material is None:
                    material = module.Scenario.material()
                scenario = module.Scenario.create(root, material=material)
                notes = module.case(case, scenario)
                result = {"passed": True, "notes": notes, "state": scenario.snapshot()}
            elif group == "C":
                result = module.run_case(
                    case,
                    root,
                    config={
                        "receipt": receipt,
                        "guard": {
                            "phase": "python",
                            "memory_limit_bytes": 268435456,
                            "scope": "whole guarded process tree including setup",
                        },
                    },
                )
            else:
                result = module.run_case(case, root)
            status = "pass"
        except Exception as error:
            result = {
                "passed": False,
                "error": type(error).__name__,
                "message": str(error),
                "traceback": traceback.format_exc(limit=12),
            }
            status = "failed"
            if scenario is not None:
                try:
                    result["state"] = scenario.snapshot()
                except Exception as state_error:
                    result["state_unavailable"] = type(state_error).__name__
        record = {
            **receipt,
            "result": result,
            "status": status,
            "seconds": time.monotonic() - start,
        }
        (D / "cases").mkdir(exist_ok=True)
        coordinator.write(D / "cases" / (receipt["invocation_id"] + ".json"), record)
        coordinator.finish_case(receipt, status)
        if group in {"N", "TR"}:
            import hashlib

            path = D / "native-coverage.json"
            coverage = coordinator.read(path) if path.exists() else {"cases": []}
            coverage["cases"].append(
                {
                    "case_id": case,
                    "invocation_id": receipt["invocation_id"],
                    "status": status,
                    "actual_calls": result.get("actual_calls", []),
                    "binary_sha256": result.get("binary_sha256"),
                    "source_manifest_sha256": hashlib.sha256(
                        (coordinator.N / "overlay/patch-manifest.json").read_bytes()
                    ).hexdigest(),
                }
            )
            coordinator.write(path, coverage)
        print(
            json.dumps(
                {
                    "case": case,
                    "invocation": receipt["invocation_id"],
                    "status": status,
                    "seconds": record["seconds"],
                }
            ),
            flush=True,
        )
        if status != "pass":
            raise RuntimeError("case failed; inspect retained record before correction")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("task", choices=("quality", "cases"))
    parser.add_argument("group", nargs="?", choices=("H", "B", "C", "N", "TR"))
    parser.add_argument("first", nargs="?", type=int, default=1)
    parser.add_argument("last", nargs="?", type=int, default=1)
    args = parser.parse_args()
    if args.task == "quality":
        quality()
    else:
        cases(args.group, args.first, args.last)


if __name__ == "__main__":
    main()
