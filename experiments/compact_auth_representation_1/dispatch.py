"""Single admission per declared case; bounded failures retained without retries."""

import json
import sys
import time
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.auth_relation_integration_1.work import EventMeter  # noqa: E402
from experiments.compact_auth_representation_1 import admission  # noqa: E402
from experiments.compact_auth_representation_1 import run as guard  # noqa: E402


def execute(case_id):
    permitted = {
        "Q-01",
        *(f"C-{n:02d}" for n in range(1, 25)),
        *(f"N-{n:02d}" for n in range(1, 5)),
    }
    if case_id not in permitted:
        raise ValueError("outside explicit compact case matrix")
    ledger = guard.read(guard.D / "ledger.json")
    if any(r["case_id"] == case_id for r in ledger["invocations"]):
        raise RuntimeError("no automatic repeats")
    reservation = min(50000000, guard.POLICY["work_event_ceiling"] - ledger["work_events"])
    receipt = guard.reserve_case(case_id, reservation)
    meter = EventMeter(reservation)
    started = time.monotonic()
    result = {"case_id": case_id, "invocation_id": receipt["invocation_id"], "status": "failed"}
    try:
        if case_id == "Q-01":
            detail = admission.workload(meter)
        elif case_id.startswith("C-"):
            from experiments.compact_auth_representation_1.cases import case

            detail = case(case_id, meter)
        else:
            from experiments.compact_auth_representation_1.native_cases import case

            detail = case(case_id, meter)
        result.update(status="pass", details=detail)
    except BaseException as error:
        result.update(error=type(error).__name__, message=str(error)[:3000])
        raise
    finally:
        result.update(seconds=time.monotonic() - started, work_events=meter.events)
        guard.write(guard.D / "cases" / (receipt["invocation_id"] + ".json"), result)

        def close(value):
            value["work_events"] += meter.events
            value["work_events_reserved"] -= reservation
            value["invocations"][receipt["ordinal"] - 1].update(
                status=result["status"], work_events=meter.events
            )

        guard.change_ledger(close)
    print(
        json.dumps(
            {
                "case": case_id,
                "status": result["status"],
                "seconds": result["seconds"],
                "work_events": meter.events,
            }
        )
    )


if __name__ == "__main__":
    if sys.argv[1] == "preflight":
        admission.preflight()
    else:
        for case_id in sys.argv[1:]:
            execute(case_id)
