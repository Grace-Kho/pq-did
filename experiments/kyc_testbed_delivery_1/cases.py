"""Fixed counted delivery matrix; no historical re-execution or silent retries."""

import json
import signal
import sys
import time
import traceback
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from benchmarks.kyc_testbed_delivery_1 import export, runner  # noqa: E402
from experiments.kyc_testbed_delivery_1 import run as guard  # noqa: E402
from experiments.kyc_testbed_delivery_1.demo import Demo  # noqa: E402


def expired(_sig, _frame):
    raise TimeoutError("case deadline")


def execute(case, operation, cleanup=None):
    plan = {x["id"]: x for x in guard.read(guard.D / "execution-plan.json")["cases"]}
    assert case in plan
    prior = [x for x in guard.read(guard.D / "ledger.json")["invocations"] if x["case_id"] == case]
    if prior:
        allowed = guard.read(guard.D / "corrections.json").get(case)
        assert allowed and prior[-1]["status"] == "failed" and len(prior) <= allowed["reruns"]
    receipt = guard.reserve_case(case, 0)
    row = dict(receipt, status="failed")
    started = time.monotonic()
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(plan[case]["max_seconds"])
    try:
        row["details"] = operation()
        row["status"] = "pass"
    except BaseException as error:
        row.update(error=type(error).__name__, diagnostic=traceback.format_exc(limit=6)[-5500:])
        raise
    finally:
        signal.alarm(0)
        row.update(seconds=time.monotonic() - started, work_events=0)
        guard.write(guard.D / "cases" / (receipt["invocation_id"] + ".json"), row)
        guard.finish_case(receipt, row["status"])
        print(
            json.dumps({"case": case, "status": row["status"], "seconds": row["seconds"]}),
            flush=True,
        )
    if cleanup is not None:
        cleanup()
    return row


def demo():
    d = Demo(guard.D / "tmp/demo")
    for i in range(1, 11):
        execute(f"D-{i:02d}", lambda i=i: d.run(i))
    guard.write(guard.D / "demo-disposition.json", d.app.scenario.storage_inventory())
    d.app.scenario.cleanup()


def export_cases():
    from experiments.kyc_testbed_delivery_1.preservation import historical_scope

    rows, failures, _ = export.retained(historical_scope()["frozen_package_inputs"])
    root = guard.D / "exports"
    root.mkdir()
    output = root / "retained"

    def roundtrip():
        meta = export.write(output, rows, failures)
        assert export.readback(output) == rows
        return {
            "counts": meta["counts"],
            "failures_indexed": len(failures),
            "private_metrics_null": True,
        }

    execute("E-01", roundtrip)

    def rejection(fn):
        try:
            fn()
        except ValueError as e:
            return {"expected_rejection": str(e)}
        raise AssertionError("bad export accepted")

    execute("E-02", lambda: rejection(lambda: export.validate(rows + [rows[0]])))
    changed = [dict(rows[0], category="private-proof-measured")]
    execute("E-03", lambda: rejection(lambda: export.validate(changed)))

    def existing():
        before = export.digest(output / "manifest.json")
        try:
            export.write(output, rows, failures)
        except FileExistsError:
            pass
        else:
            raise AssertionError("existing output replaced")
        assert export.digest(output / "manifest.json") == before
        return {"existing_output_refused": True, "manifest_unchanged": True}

    execute("E-04", existing)


def benchmark():
    rows = []
    for i, scenario in enumerate(("ISSUE", "PRESENT-A", "PRESENT-B", "REVOKE-UPDATE"), 1):
        retained = {}

        def operation(i=i, scenario=scenario, retained=retained):
            details, s = runner.measure(guard.D / "tmp" / f"smoke-{i}", scenario, guard.POLICY)
            retained["scenario"] = s
            return details

        def cleanup(i=i, retained=retained):
            s = retained["scenario"]
            guard.write(guard.D / f"smoke-{i}-disposition.json", s.storage_inventory())
            s.cleanup()

        result = execute(f"B-{i:02d}", operation, cleanup)
        name = (guard.D / "cases" / (result["invocation_id"] + ".json")).relative_to(P).as_posix()
        x = result["details"]
        rows.append(
            dict(
                zip(
                    export.FIELDS,
                    (
                        "delivery-v2-smoke",
                        result["invocation_id"],
                        scenario,
                        "disclosed-baseline",
                        "smoke",
                        x["operation_ns"],
                        x["setup_ns"],
                        name,
                        export.digest(P / name),
                        "details",
                        2,
                        2,
                    ),
                    strict=True,
                )
            )
        )
    meta = export.write(guard.D / "exports/smoke", rows, [])
    assert export.readback(guard.D / "exports/smoke") == rows
    guard.write(
        guard.D / "export-index.json",
        {
            "historical_counts": export.EXPECTED,
            "historical_total": 302,
            "smoke_counts": meta["counts"],
            "total_rows": 306,
            "exports": ["exports/retained", "exports/smoke"],
            "component_results": (
                "Retained reference/component catalogue; not mixed with baseline rows"
            ),
            "private_proof_metrics": meta["private_proof_metrics"],
        },
    )


if __name__ == "__main__":
    {"demo": demo, "export": export_cases, "benchmark": benchmark}[sys.argv[1]]()
