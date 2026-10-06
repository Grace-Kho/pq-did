"""Read-only identity admission for the directly confirmed final native cases."""

import sys
from pathlib import Path

C = Path(__file__).resolve().parent
D = C.parent
P = D.parents[2]
sys.path.insert(0, str(P))
from experiments.kyc_milestone_1 import run as guard  # noqa: E402
from scripts.preservation_audit import digest_file  # noqa: E402


def main():
    opening = guard.read(C / "opening.json")
    seal = D / "manifest.json"
    assert digest_file(seal) == opening["prior_manifest_sha256"]
    manifest = guard.read(seal)["sha256"]
    ledger_name = str((D / "ledger.json").relative_to(P))
    for name, expected in manifest.items():
        target = C / "prior-ledger.json" if name == ledger_name else P / name
        assert digest_file(target) == expected, name
    old, live = guard.read(C / "prior-ledger.json"), guard.read(D / "ledger.json")
    for key in ("jobs", "invocations", "builds", "bookkeeping"):
        assert live[key][: len(old[key])] == old[key], key
    assert len(live["invocations"]) == 378 and len(live["builds"]) == 3
    plan_path = P / "docs/data/october_implementation_milestone_1/execution-plan.json"
    assert digest_file(plan_path) == guard.read(D / "approval.json")["plan_sha256"]
    plan = guard.read(plan_path)
    assert [row["id"] for row in plan["native_new_cases"]] == [f"N-{i:02d}" for i in range(1, 25)]
    assert plan["native_exp2_cases"] == [f"TR-{i:02d}" for i in range(1, 17)]
    assert (
        next(row for row in plan["integration_cases"] if row["id"] == "C-09")["case"]
        == "native-caller-coverage-export"
    )
    build = guard.read(D / "native-build-3-commands.json")
    assert build["outcomes"] == [0, 0]
    for name, expected in build["inputs"].items():
        assert digest_file(guard.N / "overlay" / name) == expected, name
    patch = guard.read(guard.N / "overlay/patch-manifest.json")
    origin = P / patch["source_origin"]
    count = 0
    for path in (guard.N / "work").rglob("*"):
        if not path.is_file():
            continue
        count += 1
        relative = path.relative_to(guard.N).as_posix()
        original = origin / path.relative_to(guard.N / "work")
        if relative in patch["changes"]:
            item = patch["changes"][relative]
            assert digest_file(original) == item["before_sha256"]
            assert digest_file(path) == item["after_sha256"]
        else:
            assert digest_file(path) == digest_file(original), relative
    assert count == 919
    case_plan = guard.read(P / "docs/data/s3_aurora_native_transcript_pilot_1/case-plan.json")
    for case in case_plan["cases"]:
        assert digest_file(P / case["retained_expectation"]) == case["retained_sha256"]
    binaries = {
        name: digest_file(guard.N / "build" / name)
        for name in ("aurora_masking_native", "exp2_native")
    }
    usage = guard.storage()
    assert usage["evidence_bytes"] + 2097152 < guard.POLICY["evidence_ceiling_bytes"]
    assert 4274 - guard.consumed(live) > 300 + 180
    guard.write(
        C / "confirmed-inputs.json",
        {
            "passed": True,
            "previous_full_seal": opening["prior_manifest_sha256"],
            "verified_previous_entries": len(manifest),
            "verified_native_source_files": count,
            "build_record": "native-build-3-commands.json",
            "binary_sha256": binaries,
            "build_inputs": build["inputs"],
            "independent_expectations_checked": len(case_plan["cases"]),
            "plan_sha256": digest_file(plan_path),
            "storage": usage,
            "new_builds": 0,
            "new_test_invocations": 0,
            "no_baseline_or_benchmark_repetition": True,
        },
    )
    print("Final build inputs, retained binary identities and independent expectations verified")


if __name__ == "__main__":
    main()
