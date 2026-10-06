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
from experiments.kyc_issuer_incremental_storage_1 import run as guard  # noqa: E402


def expiry(_signum, _frame):
    raise TimeoutError("individual case deadline")


def execute(case, operation):
    plan = {r["id"]: r for r in guard.read(guard.D / "execution-plan.json")["cases"]}
    assert case in plan and plan[case]["admitted"]
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
    from experiments.kyc_issuer_incremental_storage_1 import cases, integration

    root = guard.D / "tmp" / group
    root.mkdir(mode=0o700, exist_ok=True)
    cache = {}
    for i in range(start, end + 1):

        def operation(i=i):
            if group == "S":
                child = root / str(i)
                result = cases.run(i, child)
                shutil.rmtree(child)  # Only this fresh case's disposable copy.
                return result
            return integration.run(i, root / "application", cache)

        execute(f"{group}-{i:02d}", operation)
    if group == "I":
        guard.write(guard.D / "integration-store-inventory.json", cache["app"].scenario.cleanup())
    root.rmdir()


def measure(case):
    from experiments.kyc_issuer_incremental_storage_1.integration import upgrade
    from experiments.kyc_testbed_execution_1.application import Application
    from pqdid.witness_updates import UpdateStatus

    _, session, length = case.split("-")
    length = int(length)

    def operation():
        start = time.monotonic_ns()
        app = Application.create(guard.D / "tmp" / case)
        migrated = time.monotonic_ns()
        plan = upgrade(app)
        migration_ns = time.monotonic_ns() - migrated
        app.issue()
        s = app.scenario
        growth = [dict(revocations=0, storage=s.storage_inventory())]
        for n in range(length):
            holder = s.add_holder()
            s.revoke(holder.credential.identifier)
            growth.append(dict(revocations=n + 1, storage=s.storage_inventory()))
        setup = time.monotonic_ns() - start
        begin = time.monotonic_ns()
        outcome = s.synchronise()
        elapsed = time.monotonic_ns() - begin
        assert outcome.status is UpdateStatus.UPDATED
        page = s.holder.last_history.page
        assert len(page.records) == length and s.holder.checkpoint.state.epoch == length
        result = dict(
            operation="public-history-fetch-verify-and-atomic-wallet-update",
            session=int(session),
            history_length=length,
            issuer_sessions=len(s.issuer.journal.snapshot()),
            setup_ns=setup,
            migration_ns=migration_ns,
            operation_ns=elapsed,
            record_bytes=sum(map(len, page.records)),
            messages=s.message_bytes.copy(),
            storage=s.storage_inventory(),
            storage_growth=growth,
            fixture_sha256=s.data.fixture_sha256,
            schema=2,
            migration_head=plan.after[2].hex(),
            concurrency=1,
            privacy="fully disclosed ML-DSA baseline; no private proof",
            clock="synthetic epoch plus monotonic elapsed",
            comparison="new series; v1 and previous 19 observations unchanged",
        )
        s.cleanup()
        return result

    execute(case, operation)


def preflight():
    from experiments.kyc_issuer_incremental_storage_1.preservation import historical
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
    a = guard.read(guard.D / "amendment.json")
    p = guard.POLICY
    assert (
        a["shared_remaining_after"]
        == a["shared_remaining_before"] + a["shared_increase_bytes"]
        == p["new_evidence_cap_bytes"]
    )
    assert (
        a["cumulative_evidence_after"]
        - p["historical_evidence_bytes"]
        - a["shared_remaining_after"]
        == a["unallocated_headroom_unchanged"]
    )
    assert p["implementation_ceiling_seconds"] == 6074 and p["invocation_ceiling"] == 1146
    plan = guard.read(guard.D / "execution-plan.json")
    assert (
        len(plan["cases"]) <= 101
        and plan["estimated_evidence_bytes"] + p["evidence_completion_reserve_bytes"]
        < p["new_evidence_cap_bytes"]
    )
    # Read-only bound on unchanged manager checkpoint; no scaling execution is concealed here.
    bounds = dict(
        history_records=8,
        minimum_record_bytes=11162,
        update_payload_lower_bound=8 * 11162,
        checkpoint_codec_cap=65536,
    )
    assert bounds["update_payload_lower_bound"] > bounds["checkpoint_codec_cap"]
    guard.write(
        guard.D / "preflight.json",
        dict(
            passed=True,
            programme_complete=False,
            historical_paths_verified=len(seals),
            storage=guard.storage(),
            mem_available_bytes=guard.available(),
            unadmitted_scaling={"R-1-8": bounds, "R-2-8": bounds},
            reason=(
                "Unchanged manager checkpoint serialises all history; lower bound"
                " alone exceeds its PQL1 cap. Issuer correction does not authoris"
                "e manager architecture changes."
            ),
        ),
    )
    print("sealed inputs, amended balances, planned cases and scaling admission checked")


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
