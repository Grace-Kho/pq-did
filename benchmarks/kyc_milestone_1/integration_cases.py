"""One frozen integration case per guarded invocation; actual baseline signatures."""

import argparse
import json
import sys
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "benchmarks.kyc_milestone_1"

from .cases import fixture
from .export import Exporter, readback, require
from .measure import (
    ROOT,
    environment,
    input_identities,
    resource_observation,
    sha256_file,
    validate_reuse,
)


def _rejects(function):
    from pqdid.codec import EncodingError
    from pqdid.persistence.codec import Unavailable

    try:
        function()
    except EncodingError, Unavailable, OSError:
        return
    raise AssertionError("operation unexpectedly released a result")


def _normal_verifier(scenario):
    from pqdid.verifier_state import ReferenceVerifier

    verifier = scenario.verifiers["A"]
    return ReferenceVerifier(
        parameters=scenario.pp,
        audience=verifier.audience,
        request_public_key=verifier.store._deps.request_key,
        clock=scenario.clock,
        store=verifier.challenges,
        provider=verifier.provider,
    )


def run_case(case, root, *, evidence=None, config=None):
    root = Path(root)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    details = {}
    if case in {f"C-{index:02d}" for index in range(1, 9)} or case == "C-12":
        from experiments.kyc_milestone_1.baseline.scenario import Scenario
        from experiments.kyc_milestone_1.baseline.verifier import Verdict

        setup_start = time.monotonic_ns()
        material = Scenario.material(1800000000)
        keygen_ns = time.monotonic_ns() - setup_start
        scenario = Scenario.create(root / "scenario", epoch_base=1800000000, material=material)
        if case != "C-06" and case != "C-12":
            scenario.issue()
    if case == "C-01":
        request = scenario.request("A")
        presentation = scenario.present(request)
        assert presentation.credential.holder_public_key == scenario.holder.public_key
        wrong = replace(
            presentation,
            signature=bytes([presentation.signature[0] ^ 1]) + presentation.signature[1:],
        )
        assert scenario.verify(request, wrong) is Verdict.HOLDER
        assert scenario.verifiers["A"].snapshot()["consumed"] == 0
        assert scenario.verify(request, presentation) is Verdict.ACCEPTED
    elif case == "C-02":
        original = scenario.holder.credential
        for audience in ("A", "B"):
            request = scenario.request(audience)
            presentation = scenario.present(request)
            assert presentation.credential == original
            assert scenario.verify(request, presentation) is Verdict.ACCEPTED
        a, b = scenario.verifiers["A"], scenario.verifiers["B"]
        assert a.store is not b.store and a.audience != b.audience
        assert a.store._deps.request_key != b.store._deps.request_key
        assert a.snapshot()["consumed"] == b.snapshot()["consumed"] == 1
    elif case == "C-03":
        original_key, original_credential = scenario.holder.public_key, scenario.holder.credential
        presentations = []
        for audience in ("A", "B"):
            request = scenario.request(audience)
            presentation = scenario.present(request)
            assert scenario.verify(request, presentation) is Verdict.ACCEPTED
            presentations.append((request, presentation))
        reopened = scenario.reopen()
        if reopened is not None:
            scenario = reopened
        assert scenario.holder.public_key == original_key
        assert scenario.holder.credential == original_credential
        for request, presentation in presentations:
            assert scenario.verify(request, presentation) is Verdict.REPLAY
        for audience in ("A", "B"):
            request = scenario.request(audience)
            assert scenario.verify(request, scenario.present(request)) is Verdict.ACCEPTED
    elif case == "C-04":
        other = scenario.add_holder()
        request = scenario.request("A")
        presentation = scenario.present(request)
        scenario.revoke(other.credential.identifier)
        assert scenario.verify(request, presentation) is Verdict.STATE
        assert scenario.verifiers["A"].snapshot()["consumed"] == 0
    elif case == "C-05":
        from pqdid.witness_updates import UpdateStatus

        other = scenario.add_holder()
        scenario.revoke(scenario.holder.credential.identifier)
        assert scenario.synchronise(scenario.holder).status is UpdateStatus.REVOKED
        assert scenario.synchronise(other).status is UpdateStatus.UPDATED
        request = scenario.request("A")
        assert scenario.verify(request, other.present(request)) is Verdict.ACCEPTED
        _rejects(lambda: scenario.holder.present(request))
    elif case == "C-06":
        from experiments.kyc_milestone_1.baseline import storage
        from pqdid.persistence import sqlite_store
        from pqdid.persistence.codec import Unavailable

        challenge = scenario.issuer.begin(
            scenario.issuer.approved_attributes,
            scenario.holder.public_key,
            scenario.issuer.recipient,
        )
        signature = scenario.holder.enrol(challenge)

        def fail_certification(point):
            if point == "certification-before-commit":
                raise Unavailable("test-only-certification-fault")

        with patch.object(storage, "_fault", fail_certification):
            _rejects(lambda: scenario.issuer.complete(challenge.session, signature))
        _rejects(lambda: scenario.issuer.retrieve(challenge.operation, scenario.issuer.recipient))
        assert scenario.holder.credential is None
        scenario.issue()
        request = scenario.request("A")
        presentation = scenario.present(request)
        challenge_store = scenario.verifiers["A"].challenges
        consume = challenge_store.consume

        def fail_commit(point):
            if point == "rows-before-commit":
                raise Unavailable("test-only-consumption-fault")

        def guarded_consume(*args):
            with patch.object(sqlite_store, "_fault", fail_commit):
                return consume(*args)

        with patch.object(challenge_store, "consume", guarded_consume):
            assert scenario.verify(request, presentation) is Verdict.FAILURE
        assert scenario.verifiers["A"].snapshot()["consumed"] == 0
        assert scenario.verify(request, presentation) is Verdict.ACCEPTED
        details["fault_model"] = "injected pre-commit failures; no power-loss guarantee"
    elif case == "C-07":
        from pqdid.schema import project_attributes
        from pqdid.verifier_state import Decision, Presentation, UnsupportedProofVerifier

        request = scenario.request("A")
        baseline = scenario.present(request)
        ordinary = _normal_verifier(scenario)
        assert type(ordinary.proof_verifier) is UnsupportedProofVerifier
        wrapped = Presentation(
            request.context.policy.disclosed,
            project_attributes(
                scenario.pp.schema, baseline.credential.attributes, request.context.policy.disclosed
            ),
            b"unavailable-backend-boundary-probe",
        )
        assert (
            ordinary.verify(
                session=request.context.session, context=request.context, presentation=wrapped
            )
            is Decision.UNSUPPORTED
        )
        assert scenario.verifiers["A"].snapshot()["consumed"] == 0
    elif case == "C-08":
        from pqdid.verifier_state import Decision

        request = scenario.request("A")
        presentation = scenario.present(request)
        ordinary = _normal_verifier(scenario)
        assert (
            ordinary.verify(
                session=request.context.session, context=request.context, presentation=presentation
            )
            is Decision.PUBLIC
        )
        assert not hasattr(presentation, "proof")
        assert scenario.verifiers["A"].snapshot()["consumed"] == 0
    elif case == "C-09":
        evidence = evidence or ROOT / "docs/data/oct31_kyc_native_milestone_1/native-coverage.json"
        report = json.loads(Path(evidence).read_text())
        # Qualify short PATH names by the concrete case that actually emitted
        # them; a same-named method from another component cannot satisfy them.
        required = {
            "N-02": {
                "batch_sumcheck_protocol::register_masking_polynomial",
                "register_challenge",
                "register_proof",
                "submit_masking_polynomial",
                "calculate_and_submit_proof",
                "construct_verifier_state",
                "sumcheck_g_oracle::evaluated_contents",
                "evaluation_at_point",
            },
            "N-09": {"iop_protocol::submit_prover_message length rejection"},
            "N-10": {
                "combined_LDT_virtual_oracle::set_random_coefficients",
                "evaluated_contents",
                "evaluation_at_point",
                "LDT_instance_reducer::register_interactions",
                "submit_masking_polynomial",
            },
            "N-18": {
                "FRI_protocol::register_interactions",
                "get_oracle_degree",
                "calculate_and_submit_proof",
                "evaluate_next_f_i_over_entire_domain",
                "receive_prover_message",
            },
            "N-20": {
                "multi_lincheck::register_challenge",
                "register_proof",
                "submit_sumcheck_masking_polynomials",
                "calculate_and_submit_proof",
                "construct_verifier_state",
                "multi_lincheck_virtual_oracle::set_challenge",
                "evaluated_contents",
            },
            "N-21": {
                "aurora_iop::constructor",
                "register_interactions",
                "encoded_aurora_protocol::constructor",
                "multi_lincheck::constructor",
                "LDT_instance_reducer::constructor",
                "FRI_protocol::register_interactions",
            },
        }
        by_case = {}
        seen_invocations = set()
        for row in report["cases"]:
            require(row["status"] in {"pass", "failed", "blocked"}, "native case outcome")
            require(row["invocation_id"] not in seen_invocations, "duplicate native invocation")
            seen_invocations.add(row["invocation_id"])
            by_case.setdefault(row["case_id"], []).append(row)
        native_root = ROOT / "experiments/aurora_masking_milestone_1"
        current_binary = sha256_file(native_root / "build/aurora_masking_native")
        current_manifest = sha256_file(native_root / "overlay/patch-manifest.json")
        checks = []
        for identifier, expected in required.items():
            require(identifier in by_case, "missing native component coverage")
            eligible = [
                row
                for row in by_case[identifier]
                if row["status"] == "pass"
                and row["binary_sha256"] == current_binary
                and row["source_manifest_sha256"] == current_manifest
            ]
            require(bool(eligible), "no passed caller case matching current native inputs")
            row = eligible[-1]
            for identity in ("source_manifest_sha256", "binary_sha256"):
                value = row[identity]
                require(
                    type(value) is str
                    and len(value) == 64
                    and all(c in "0123456789abcdef" for c in value),
                    "native input identity",
                )
            require(expected <= set(row["actual_calls"]), "native caller coverage incomplete")
            checks.append(
                {
                    "case_id": identifier,
                    "invocation_id": row["invocation_id"],
                    "actual_calls": sorted(expected),
                    "source_manifest_sha256": row["source_manifest_sha256"],
                    "binary_sha256": row["binary_sha256"],
                    "retained_attempts_for_case": len(by_case[identifier]),
                }
            )
        details["coverage_sha256"] = sha256_file(evidence)
        details["qualified_call_checks"] = checks
    elif case == "C-10":
        source = root / "changed-input.txt"
        source.write_text("original synthetic source\n")
        previous = sha256_file(source)
        assert validate_reuse({source.name: previous}, root=root)
        source.write_text("changed synthetic source\n")
        try:
            validate_reuse({source.name: previous}, root=root)
        except ValueError:
            pass
        else:
            raise AssertionError("changed source was eligible for evidence reuse")
        details["measurement_origin"] = "synthetic-validation"
    elif case == "C-11":
        from experiments.kyc_milestone_1.run import output_role

        directory = ROOT / "docs/data/oct31_kyc_native_milestone_1"
        evidence = evidence or directory / "ledger.json"
        report = json.loads(Path(evidence).read_text())
        policy = json.loads((directory / "policy.json").read_text())
        invocations = report["invocations"]
        ids = [row["invocation_id"] for row in invocations]
        require(len(ids) == len(set(ids)), "duplicate charged invocation")
        for ordinal, row in enumerate(invocations, 1):
            require(
                row["ordinal"] == ordinal
                and row["cumulative_invocations"] == policy["historical_invocations"] + ordinal,
                "uncharged or reset invocation",
            )
        require(policy["historical_invocations"] == 448, "historical invocation reset")
        require(policy["historical_seconds"] == 562.1783621237846, "historical time reset")
        require(policy["historical_builds"] == 5, "historical builds reset")
        require(policy["aggregate_memory_bytes"] == 2 * 1024**3, "aggregate memory")
        roles = {
            directory / "stores/synthetic.sqlite3": "synthetic-store-artifact",
            directory / "stores/metadata.json": "evidence",
            directory / "benchmarks/trials.jsonl": "evidence",
            directory / "stores/renamed-binary.dat": "evidence",
            ROOT / "experiments/aurora_masking_milestone_1/build/unregistered.o": "evidence",
            ROOT
            / "experiments/aurora_masking_milestone_1/build"
            / "aurora_masking_native": "build-artifact",
        }
        for path, expected in roles.items():
            require(output_role(path)[0] == expected, "incorrect output role")
        completed = [job for job in report["jobs"] if "worker" in job]
        require(bool(completed), "no actual guarded jobs")
        for job in completed:
            require(
                job["memory_limit_bytes"] == policy["phase_memory"][job["phase"]],
                "phase limit mismatch",
            )
            require(
                int(job["worker"]["before"]["memory.max"]) == job["memory_limit_bytes"],
                "actual worker ceiling mismatch",
            )
            require(job["worker"]["before"]["memory.swap.max"] == "0", "worker swap")
        details["accounting_sha256"] = sha256_file(evidence)
        details["checked_completed_jobs"] = len(completed)
    elif case == "C-12":
        require(config is not None and config.get("guard"), "integration guard metadata required")
        scenario.setup_for("ISSUE")
        start = time.monotonic_ns()
        result = scenario.run("ISSUE")
        end = time.monotonic_ns()
        start = result.get("operation_start_monotonic_ns", start)
        end = result.get("operation_end_monotonic_ns", end)
        assert result["outcome"] == "accepted"
        row = fixture()
        row.update(
            {
                "run_id": "integration-C-12",
                "attempt_id": "C-12",
                "invocation_id": config["receipt"]["invocation_id"],
                "category": "mldsa_reference_measured",
                "measurement_origin": "actual",
                "capability": scenario.capabilities(),
                "start_monotonic_ns": start,
                "end_monotonic_ns": end,
                "duration_ns": end - start,
                "stages_ns": result["stages_ns"],
                "stage_parents": result.get(
                    "stage_parents", {name: None for name in result["stages_ns"]}
                ),
                "setup_ns": start - setup_start,
                "keygen_ns": keygen_ns,
                "message_bytes": result["message_bytes"],
                "identities": input_identities(),
                "fixture_sha256": result["fixture_sha256"],
                "instance_sha256": result["instance_sha256"],
                "resources": resource_observation(),
                "environment": environment(config["guard"]),
                "counters": {**config["receipt"], "reserved": True},
                "signing": result.get(
                    "signing",
                    {
                        "attempts": None,
                        "exhaustion": None,
                        "reason": "not exported by bounded core",
                    },
                ),
                "details": {"integration": True, "setup_timing": "excluded; ledger charged"},
            }
        )
        row["message_bytes"] = {
            name: {"canonical": size, "transport": size} if type(size) is int else size
            for name, size in row["message_bytes"].items()
        }
        exporter = Exporter(root / "export")
        exporter.append(row)
        exporter.finalise()
        loaded = readback(exporter.root)
        assert loaded == [row]
        assert all(
            item["seconds"] is None and item["bytes"] is None for item in loaded[0]["unavailable"]
        )
    else:
        raise ValueError("unknown integration case")
    return {"case_id": case, "passed": True, "category": "reference_lifecycle", "details": details}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=[f"C-{i:02d}" for i in range(1, 13)], required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--config", type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text()) if args.config else None
    print(
        json.dumps(
            run_case(args.case, args.root, evidence=args.evidence, config=config), sort_keys=True
        )
    )


if __name__ == "__main__":
    main()
