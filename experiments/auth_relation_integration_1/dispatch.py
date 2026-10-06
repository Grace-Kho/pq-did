"""Individually accounted approved cases, with no automatic retries."""

import json
import sys
import time
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.auth_relation_integration_1 import admission  # noqa: E402
from experiments.auth_relation_integration_1 import run as guard  # noqa: E402
from experiments.auth_relation_integration_1.work import EventMeter  # noqa: E402


def execute(case_id):
    plan = guard.read(P / "docs/data/oct31_auth_relation_integration_1/cases.json")
    permitted = {row["id"] for row in plan["cases"]}
    if case_id not in permitted:
        raise ValueError("case outside approved matrix")
    ledger = guard.read(guard.D / "ledger.json")
    if any(row["case_id"] == case_id for row in ledger["invocations"]):
        raise RuntimeError("no automatic repeat")
    reservation = min(100_000_000, guard.POLICY["work_event_ceiling"] - ledger["work_events"])
    receipt = guard.reserve_case(case_id, reservation)
    meter = EventMeter(reservation)
    start = time.monotonic()
    result = {"case_id": case_id, "invocation_id": receipt["invocation_id"], "status": "failed"}
    try:
        if case_id == "Q-04":
            detail = admission.capacity_case(meter)
        elif case_id == "Q-01":
            from experiments.auth_relation_integration_1.count_case import run_case

            detail = run_case(meter)
        elif case_id.startswith(("P-", "W-", "M-")):
            from experiments.auth_relation_integration_1.relation_cases import case

            detail = case(case_id, meter)
        elif case_id.startswith("N-"):
            from experiments.auth_relation_integration_1.native_cases import run_case

            detail = run_case(case_id, meter)
        elif case_id.startswith("B-"):
            from experiments.auth_relation_integration_1.boundary_cases import run_case

            detail = run_case(case_id, meter)
        elif case_id.startswith("G-"):
            from experiments.auth_relation_integration_1.resource_cases import run_case

            detail = run_case(case_id, meter)
        else:
            raise ValueError("case implementation not admitted yet")
        result.update(status="pass", details=detail)
    except BaseException as error:
        result.update(error=type(error).__name__, message=str(error)[:3000])
        raise
    finally:
        result.update(seconds=time.monotonic() - start, work_events=meter.events)
        guard.write(guard.D / "cases" / (receipt["invocation_id"] + ".json"), result)

        def close(value):
            value["work_events"] += meter.events
            value["work_events_reserved"] -= reservation
            row = value["invocations"][receipt["ordinal"] - 1]
            row.update(status=result["status"], work_events=meter.events)

        guard.change_ledger(close)
    print(json.dumps(result))


if __name__ == "__main__":
    if sys.argv[1] == "preflight":
        admission.preflight()
    else:
        for case in sys.argv[1:]:
            execute(case)
