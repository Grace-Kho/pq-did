"""Four individually admitted v2 smoke measurements, never a campaign."""

import time

from benchmarks.kyc_milestone_1.measure import environment, resource_observation
from experiments.kyc_manager_incremental_storage_1 import history
from experiments.kyc_manager_incremental_storage_1.integration import create
from experiments.kyc_milestone_1.baseline.verifier import Verdict
from pqdid.witness_updates import UpdateStatus


def measure(root, scenario, guard):
    setup_start = time.monotonic_ns()
    app = create(root)
    s = app.scenario
    if scenario != "ISSUE":
        app.issue()
    if scenario == "REVOKE-UPDATE":
        other = s.add_holder()
    setup_ns = time.monotonic_ns() - setup_start
    pages = []
    start = time.monotonic_ns()
    if scenario == "ISSUE":
        app.issue()
    elif scenario in ("PRESENT-A", "PRESENT-B"):
        request = s.request(scenario[-1])
        presentation = s.present(request)
        assert s.verify(request, presentation) is Verdict.ACCEPTED
    elif scenario == "REVOKE-UPDATE":
        target = s.revoke(other.credential.identifier)
        result, pages, _ = history.baseline_catch_up(s.holder, s.manager, target)
        assert result.status is UpdateStatus.UPDATED
        rejected, _, _ = history.baseline_catch_up(other, s.manager, target)
        assert rejected.status is UpdateStatus.REVOKED
    else:
        raise ValueError("smoke workload")
    end = time.monotonic_ns()
    result = {
        "scenario": scenario,
        "operation_ns": end - start,
        "start_ns": start,
        "end_ns": end,
        "setup_ns": setup_ns,
        "outcome": "accepted",
        "messages": s.message_bytes.copy(),
        "page_bytes": pages,
        "storage": s.storage_inventory(),
        "issuer_storage_version": 2,
        "manager_storage_version": 2,
        "fixture_sha256": s.data.fixture_sha256,
        "environment": environment(guard),
        "resources": resource_observation(),
        "meaning": (
            "runner smoke; fresh synthetic material; setup excluded from operation "
            "and included in resources; no population claim"
        ),
        "private_proof_metrics": None,
        "private_reason": "complete private authentication unavailable",
        "disclosure": "full disclosed ML-DSA baseline; not anonymous",
    }
    return result, s
