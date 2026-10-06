"Explicit counted cases, with failure evidence retained and no automatic retries."

import hashlib
import json
import shutil
import signal
import sys
import time
import traceback
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.kyc_manager_incremental_storage_1 import run as guard  # noqa: E402


def expiry(_signum, _frame):
    raise TimeoutError("individual case deadline")


def execute(case, operation):
    plan = {r["id"]: r for r in guard.read(guard.D / "execution-plan.json")["cases"]}
    assert case in plan
    prior = [r for r in guard.read(guard.D / "ledger.json")["invocations"] if r["case_id"] == case]
    if prior:
        correction = guard.read(guard.D / "corrections.json")[case]
        assert prior[-1]["status"] == "failed" and len(prior) <= correction["authorised_reruns"]
    receipt = guard.reserve_case(case, 0)
    start = time.monotonic()
    result = dict(receipt, status="failed")
    signal.signal(signal.SIGALRM, expiry)
    signal.alarm(plan[case]["max_seconds"])
    try:
        result["details"] = operation()
        result["status"] = "pass"
    except BaseException as error:
        result.update(error=type(error).__name__, diagnostic=traceback.format_exc(limit=8)[-6000:])
        raise
    finally:
        signal.alarm(0)
        result.update(
            seconds=time.monotonic() - start,
            work_events=0,
            work_accounting=(
                "No gate/row emissions; full host setup and validation charged to guarded time."
            ),
        )
        (guard.D / "cases").mkdir(exist_ok=True)
        guard.write(guard.D / "cases" / (receipt["invocation_id"] + ".json"), result)
        guard.finish_case(receipt, result["status"])

        def annotate(ledger):
            ledger["invocations"][receipt["ordinal"] - 1]["work_events"] = 0

        guard.change_ledger(annotate)
        print(
            json.dumps(dict(case=case, status=result["status"], seconds=result["seconds"])),
            flush=True,
        )


def focused(group, start, end):
    from experiments.kyc_manager_incremental_storage_1 import cases, history_cases

    root = guard.D / "tmp" / group
    root.mkdir(mode=0o700, exist_ok=True)
    cache = {}
    for i in range(start, end + 1):

        def operation(i=i):
            if "app" not in cache:
                cache["app"] = (cases if group == "S" else history_cases).fixture(root / "base")
            child = root / str(i)
            result = (
                cases.run(i, child, cache["app"])
                if group == "S"
                else history_cases.run(i, child, cache["app"], cache)
            )
            shutil.rmtree(child)
            return result

        execute(f"{group}-{i:02d}", operation)
    guard.write(guard.D / (group + "-store-inventory.json"), cache["app"].scenario.cleanup())
    root.rmdir()


def measure(case):
    from experiments.kyc_manager_incremental_storage_1.history import baseline_catch_up
    from experiments.kyc_manager_incremental_storage_1.integration import create
    from pqdid.statements import decode_state
    from pqdid.witness_updates import UpdateStatus

    length = int(case.split("-")[-1])

    def operation():
        begin = time.monotonic_ns()
        app = create(guard.D / "tmp" / case)
        app.issue()
        s = app.scenario
        growth = [dict(revocations=0, storage=s.storage_inventory())]
        for n in range(length):
            holder = s.add_holder()
            s.revoke(holder.credential.identifier)
            growth.append(dict(revocations=n + 1, storage=s.storage_inventory()))
        setup = time.monotonic_ns() - begin
        target = decode_state(s.pp, s.manager.snapshot()[1].state.state)
        begin = time.monotonic_ns()
        result, sizes, records = baseline_catch_up(s.holder, s.manager, target)
        elapsed = time.monotonic_ns() - begin
        assert result.status is UpdateStatus.UPDATED
        assert len(records) == length and s.holder.checkpoint.state.epoch == length
        data = dict(
            workload="public-history-pages-verify-atomic-wallet-catch-up",
            history_length=length,
            issuer_sessions=len(s.issuer.journal.snapshot()),
            setup_ns=setup,
            operation_ns=elapsed,
            page_bytes=sizes,
            page_count=len(sizes),
            record_bytes=sum(map(len, records)),
            storage=s.storage_inventory(),
            storage_growth=growth,
            messages=s.message_bytes.copy(),
            fixture_sha256=s.data.fixture_sha256,
            issuer_storage_version=2,
            manager_storage_version=2,
            privacy="fully disclosed genuine ML-DSA baseline; no private proof",
            concurrency=1,
            timestamp_model="synthetic epoch plus monotonic elapsed",
            wallet_commits=1,
        )
        s.cleanup()
        return data

    execute(case, operation)


def preflight():
    from experiments.kyc_manager_incremental_storage_1.preservation import historical
    from scripts.preservation_audit import digest_file

    seals = historical()
    prefixes = guard.read(guard.D / "prefixes.json")
    for name, digest in seals.items():
        if name in prefixes:
            with (P / name).open("rb") as stream:
                assert hashlib.sha256(stream.read(prefixes[name]["bytes"])).hexdigest() == digest, (
                    name
                )
        else:
            assert digest_file(P / name) == digest, name
    opening = guard.read(guard.D / "opening.json")["prior_resources"]
    p = guard.POLICY
    assert p["historical_seconds"] == opening["implementation_aggregate_charged_seconds"]
    assert p["historical_invocations"] == 1091 and p["milestone_invocations"] == 55
    assert p["new_evidence_cap_bytes"] == opening["shared_evidence_remaining_bytes"]
    plan = guard.read(guard.D / "execution-plan.json")
    assert len(plan["cases"]) <= 55
    assert (
        plan["evidence_estimate_bytes"] + p["evidence_completion_reserve_bytes"]
        < p["new_evidence_cap_bytes"]
    )
    guard.write(
        guard.D / "preflight.json",
        dict(
            passed=True,
            programme_complete=False,
            historical_seals_verified=len(seals),
            storage=guard.storage(),
            memory_available=guard.available(),
            manuscript_authority="II–VIII and SPEC001–004",
            previous_8_record_encoding_bound=89296,
            unchanged_object_and_response_cap=65536,
            unchanged_per_call_records=16,
            complete_path_admission=(
                "Bounded DAG, <=4 update records per encoded page, <=16 collected"
                " records; actual DB cap enforced, no capacity claim before "
                "measurement"
            ),
        ),
    )
    print(
        "Prior seals, ledger, planned cases, object/transport limits and "
        "complete-path admission checked"
    )


if __name__ == "__main__":
    command = sys.argv[1]
    if command == "preflight":
        preflight()
    elif command == "focused":
        focused(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    elif command == "measure":
        measure(sys.argv[2])
    else:
        raise ValueError(command)
