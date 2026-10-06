"""Literal case/measurement dispatcher. Reproduction is explicit and ledger guarded."""

import argparse
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
from experiments.kyc_testbed_execution_1 import run as guard  # noqa: E402


def expiry(_signum, _frame):
    raise TimeoutError("individual admitted case deadline")


def execute(case, operation):
    plan = {r["id"]: r for r in guard.read(guard.D / "execution-plan.json")["cases"]}
    assert case in plan
    ledger = guard.read(guard.D / "ledger.json")
    prior = [r for r in ledger["invocations"] if r["case_id"] == case]
    if prior:
        repairs = guard.read(guard.D / "corrections.json")
        assert case in repairs and prior[-1]["status"] in repairs[case].get(
            "prior_statuses", ["failed"]
        )
        assert len(prior) <= repairs[case]["authorised_reruns"]
    receipt = guard.reserve_case(case, 0)
    start = time.monotonic()
    row = dict(receipt, status="failed")
    signal.signal(signal.SIGALRM, expiry)
    signal.alarm(plan[case]["max_seconds"])
    try:
        row["details"] = operation()
        row["status"] = "pass"
    except BaseException as error:
        row.update(error=type(error).__name__, diagnostic=traceback.format_exc(limit=8)[-6000:])
        raise
    finally:
        signal.alarm(0)
        row.update(
            seconds=time.monotonic() - start,
            work_events=0,
            work_accounting=(
                "No gate/row emissions or evaluations. "
                "Host setup included in time and resource guard."
            ),
        )
        (guard.D / "cases").mkdir(exist_ok=True)
        guard.write(guard.D / "cases" / (receipt["invocation_id"] + ".json"), row)

        def close(value):
            value["invocations"][receipt["ordinal"] - 1].update(status=row["status"], work_events=0)

        guard.change_ledger(close)
        print(json.dumps(dict(case=case, status=row["status"], seconds=row["seconds"])), flush=True)
    return row


def focused(group):
    from experiments.kyc_testbed_execution_1 import flow_cases, mapping_cases, wallet_cases
    from experiments.kyc_testbed_execution_1.application import Application
    from experiments.kyc_testbed_execution_1.fixtures import WalletFixture

    root = guard.D / "tmp" / group
    cache = {}
    for i in range(1, {"W": 24, "F": 14, "M": 10}[group] + 1):

        def operation(i=i):
            if group == "W":
                if not cache:
                    cache["fixture"] = WalletFixture()
                child = root / str(i)
                root.mkdir(exist_ok=True, mode=0o700)
                value = wallet_cases.run(i, child, cache["fixture"])
                shutil.rmtree(child)  # Only fresh literal per-case disposable fixtures.
                return value
            if not cache:
                cache["app"] = Application.create(root)
                if group == "M":
                    cache["app"].issue()
                    cache["resolution"] = cache["app"].resolver.resolve(
                        cache["app"].scenario.pp, cache["app"].did
                    )
            return (flow_cases if group == "F" else mapping_cases).run(i, cache["app"], cache)

        execute(f"{group}-{i:02d}", operation)
    if group != "W":
        inventory = cache["app"].scenario.cleanup()
        guard.write(guard.D / (group + "-store-inventory.json"), inventory)
    else:
        root.rmdir()


def measurements(group, session):
    from experiments.kyc_milestone_1.baseline.records import encode_presentation, encode_request
    from experiments.kyc_milestone_1.baseline.verifier import Verdict
    from experiments.kyc_testbed_execution_1.application import Application
    from pqdid.witness_updates import UpdateStatus

    cache = {}
    if group == "T":
        for audience in ("A", "B"):
            for trial in range(1, 4):

                def operation(audience=audience):
                    setup = time.monotonic_ns()
                    if not cache:
                        app = Application.create(guard.D / "tmp" / f"T-{session}")
                        app.issue()
                        cache["app"] = app
                    setup = time.monotonic_ns() - setup
                    s = cache["app"].scenario
                    start = time.monotonic_ns()
                    request = s.request(audience)
                    t1 = time.monotonic_ns()
                    presentation = s.present(request)
                    t2 = time.monotonic_ns()
                    assert s.verify(request, presentation) is Verdict.ACCEPTED
                    stop = time.monotonic_ns()
                    return dict(
                        operation="request-present-verify-and-atomic-consume",
                        audience=audience,
                        operation_ns=stop - start,
                        request_ns=t1 - start,
                        presentation_ns=t2 - t1,
                        verification_ns=stop - t2,
                        setup_ns=setup,
                        request_bytes=len(encode_request(s.pp, request)),
                        presentation_bytes=len(encode_presentation(s.pp, presentation)),
                        messages=s.message_bytes.copy(),
                        storage=s.storage_inventory(),
                        fixture_sha256=s.data.fixture_sha256,
                        epoch_base=s.data.epoch_base,
                        timestamp_model="synthetic epoch plus monotonic elapsed",
                        privacy="fully disclosed baseline; no private proof",
                        concurrency=1,
                    )

                execute(f"T-{session}-{audience}-{trial}", operation)
        cache["app"].scenario.cleanup()
    else:
        for length in (1, 4):

            def operation(length=length):
                setup = time.monotonic_ns()
                app = Application.create(guard.D / "tmp" / f"R-{session}-{length}")
                app.issue()
                s = app.scenario
                for _ in range(length):
                    holder = s.add_holder()
                    s.revoke(holder.credential.identifier)
                setup = time.monotonic_ns() - setup
                start = time.monotonic_ns()
                outcome = s.synchronise()
                stop = time.monotonic_ns()
                assert outcome.status is UpdateStatus.UPDATED
                page = s.holder.last_history.page
                assert len(page.records) == length and s.holder.checkpoint.state.epoch == length
                result = dict(
                    operation="public-history-fetch-verify-and-atomic-wallet-update",
                    history_length=length,
                    operation_ns=stop - start,
                    setup_ns=setup,
                    record_bytes=sum(map(len, page.records)),
                    messages=s.message_bytes.copy(),
                    storage=s.storage_inventory(),
                    fixture_sha256=s.data.fixture_sha256,
                    privacy="fully disclosed baseline; no private proof",
                    concurrency=1,
                )
                s.cleanup()
                return result

            execute(f"R-{session}-{length}", operation)


def preflight():
    from experiments.kyc_testbed_execution_1.preservation import historical
    from scripts.preservation_audit import digest_file

    seals = historical()
    prefixes = guard.read(guard.D / "prefixes.json")
    for name, digest in seals.items():
        if name in prefixes:
            with (P / name).open("rb") as f:
                assert hashlib.sha256(f.read(prefixes[name]["bytes"])).hexdigest() == digest
        else:
            assert digest_file(P / name) == digest, name
    p = guard.POLICY
    amendment = guard.read(guard.D / "amendment.json")
    assert (
        amendment["shared_after_bytes"]
        == amendment["prior_shared_headroom_bytes"] + amendment["transfer_bytes"]
    )
    assert amendment["unallocated_before_bytes"] - amendment["transfer_bytes"] == 448679
    assert (
        p["new_evidence_cap_bytes"] + 448679
        == p["evidence_ceiling_bytes"] - p["historical_evidence_bytes"]
    )
    usage = guard.storage()
    assert (
        usage["new_evidence_bytes"] + 600000 + p["evidence_completion_reserve_bytes"]
        < p["new_evidence_cap_bytes"]
    )
    assert len(guard.read(guard.D / "execution-plan.json")["cases"]) == 72
    guard.write(
        guard.D / "preflight.json",
        dict(
            passed=True,
            programme_complete=False,
            prior_seals_checked=len(seals),
            storage=usage,
            ordinary_execution_admitted=True,
            completion_reserve_bytes=p["evidence_completion_reserve_bytes"],
            planned_case_limit=72,
            affected_reruns_max=4,
            assumptions=(
                "Serial Python reference flows; no build, proof, native probe or circuit work. "
                "Scoped ephemeral user guard, not host isolation activation."
            ),
        ),
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("group", choices=("preflight", "W", "F", "M", "T", "R", "promoted"))
    parser.add_argument("session", nargs="?", type=int)
    args = parser.parse_args()
    if args.group == "preflight":
        preflight()
    elif args.group == "promoted":
        from experiments.kyc_testbed_execution_1 import wallet_cases
        from experiments.kyc_testbed_execution_1.fixtures import WalletFixture
        from pqdid import holder_wallet

        wallet_cases.w = holder_wallet

        def promoted():
            assert (P / "src/pqdid/holder_wallet.py").read_bytes() == (
                guard.N / "wallet.py"
            ).read_bytes()
            root = guard.D / "tmp/promoted-wallet"
            result = wallet_cases.run(2, root, WalletFixture())
            shutil.rmtree(root)
            return dict(result, module="pqdid.holder_wallet", byte_identical_promotion=True)

        execute("W-02", promoted)
    elif args.group in ("W", "F", "M"):
        focused(args.group)
    else:
        assert args.session in ((1, 2, 3) if args.group == "T" else (1, 2))
        measurements(args.group, args.session)
