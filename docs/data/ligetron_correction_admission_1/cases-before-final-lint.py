"""Run only the frozen fixed cases, sequentially, with per-case reservations."""

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.ligetron_correction_admission_1 import run as guard  # noqa: E402

D = guard.D


def main():
    build = guard.read(D / "build-1-result.json")
    binary = P / build["binary"]
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == build["sha256"]
    expected = guard.read(D / "expectations.json")
    seal = guard.read(D / "expectation-seal.json")
    assert hashlib.sha256((D / "expectations.json").read_bytes()).hexdigest() == seal["sha256"]
    assert list(expected) == guard.read(D / "execution-plan.json")["cases"]
    (D / "cases").mkdir(exist_ok=True)
    outcomes = []
    for case in expected:
        ledger = guard.read(D / "ledger.json")
        if guard.consumed(ledger) + 2 + 60 > guard.POLICY["implementation_ceiling_seconds"]:
            raise RuntimeError("case completion reserve")
        receipt = guard.reserve_case(case, work_reservation=1000000)
        started = time.monotonic()
        record = {
            "id": case,
            "invocation": receipt,
            "status": "incomplete",
            "binary_sha256": build["sha256"],
            "expected_sha256": seal["sha256"],
        }
        try:
            proc = subprocess.run([str(binary), case], capture_output=True, text=True, timeout=2)
            record.update(exit_code=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
            assert len(proc.stdout.encode()) + len(proc.stderr.encode()) <= 8192
            assert proc.returncode == 0, proc.stderr
            actual = json.loads(proc.stdout)
            assert actual["case"] == case and actual["data"] == expected[case], (case, actual)
            record["status"] = "pass"
        except Exception as exc:
            record.update(status="failed", error=repr(exc))
        record["seconds"] = time.monotonic() - started
        guard.write(D / "cases" / (receipt["invocation_id"] + ".json"), record)

        def close(value):
            row = value["invocations"][receipt["ordinal"] - 1]
            row.update(status=record["status"], work_events_charged_upper_bound=1000000)
            value["work_events_reserved"] -= 1000000
            value["work_events"] += 1000000

        guard.change_ledger(close)
        outcomes.append(
            {
                "id": case,
                "status": record["status"],
                "seconds": record["seconds"],
                "record": str((D / "cases" / (receipt["invocation_id"] + ".json")).relative_to(P)),
            }
        )
        guard.write(
            D / "outcomes.json",
            {
                "outcomes": outcomes,
                "unrun": [k for k in expected if k not in {r["id"] for r in outcomes}],
                "native_layer": "CPU shared components; full WebGPU callers unrun",
            },
        )
        print(case, record["status"], flush=True)
        if record["status"] != "pass":
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
