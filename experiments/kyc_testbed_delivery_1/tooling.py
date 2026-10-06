"""Scoped static checks and retained-data admission; no uncounted crypto execution."""

import json
import subprocess
import sys
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from benchmarks.kyc_testbed_delivery_1 import export  # noqa: E402
from experiments.kyc_testbed_delivery_1 import run as guard  # noqa: E402
from experiments.kyc_testbed_delivery_1.preservation import (  # noqa: E402
    historical,
    historical_scope,
)
from scripts.preservation_audit import digest_file  # noqa: E402


def static():
    files = [str(f) for root in (guard.N, guard.B) for f in sorted(root.glob("*.py"))]
    for flags in [
        ("check", "--select", "I", "--fix"),
        ("format",),
        ("check", "--fix"),
        ("format",),
        ("check",),
        ("format", "--check"),
    ]:
        subprocess.run(
            [str(P / ".venv/bin/ruff"), *flags, "--no-cache", *files], check=True, timeout=3
        )


def preflight():
    prefixes = guard.read(guard.D / "prefixes.json")
    for path, h in historical().items():
        assert (
            digest_file(
                P / path, prefix_bytes=prefixes[path]["bytes"] if path in prefixes else None
            )
            == h
        ), path
    assert (
        digest_file(P / "docs/manuscript/PQ_DID__Implementation.pdf")
        == "d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca"
    )
    opening = guard.read(guard.D / "opening.json")
    assert (
        opening["preparation_charge_seconds"] == 20
        and opening["transfer_outside_KYC_to_KYC_seconds"] == 80
    )
    assert opening["KYC_after_transfer"] - 220 >= 300
    assert opening["prior_resources"]["storage"]["shared_headroom_bytes"] - 2097152 >= 2097152
    plan = guard.read(guard.D / "execution-plan.json")
    assert len(plan["cases"]) == 18 and plan["targeted_corrective_reruns_max"] == 4
    assert plan["evidence_admission"]["planned_peak_total"] < 2097152
    rows, failures, identities = export.retained(historical_scope()["frozen_package_inputs"])
    guard.write(
        guard.D / "retained-observations.json",
        {
            "counts": export.EXPECTED,
            "total": len(rows),
            "failed_invocations_separately_indexed": len(failures),
            "sha256": identities,
            "source_identity_meaning": (
                "Sealed source records and retained measured-source reconstruction; "
                "not recomputing old source-tree hashes from changed current trees"
            ),
        },
    )
    guard.write(
        guard.D / "preflight.json",
        {
            "passed": True,
            "programme_complete": False,
            "retained_observations_verified": len(rows),
            "storage": guard.storage(),
            "plan": plan["evidence_admission"],
            "versioned_comparison_points_unchanged": True,
            "memory_available": guard.available(),
        },
    )
    print(
        json.dumps({"passed": True, "retained_count": len(rows), "failures_indexed": len(failures)})
    )


if __name__ == "__main__":
    {"static": static, "preflight": preflight}[sys.argv[1]]()
