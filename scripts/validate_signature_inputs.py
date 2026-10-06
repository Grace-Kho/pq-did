#!/usr/bin/env python3
"""One-worker signature/input preparation validation using the approved operational profile."""

import argparse
import hashlib
import json
import os
import resource
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from validate_hash_enrolment import Recorder
from validation_support import ROOT, extended_profile, supervise

sys.path.insert(0, str(ROOT))


def child(args, profile):
    resource.setrlimit(resource.RLIMIT_AS, (profile["address_space_bytes"],) * 2)
    started = time.perf_counter()
    result = {"case": args.case, "profile": profile}
    try:
        if args.case == "pytest":
            import pytest

            os.environ["PQDID_HASH_EXTENDED_BUDGET"] = "1"
            recorder = Recorder(args.heartbeat)
            code = pytest.main(
                [*args.tests, *args.pytest_arg, "-q", "--tb=short"], plugins=[recorder]
            )
            result.update(
                outcome="passed" if code == 0 else "pytest_failure",
                pytest_returncode=int(code),
                reports=recorder.reports,
                exceptions=recorder.exceptions,
            )
            if any(r["outcome"] == "skipped" for r in recorder.reports):
                result["outcome"] = "incomplete_skipped_tests"
            if any(x["resource_limit"] for x in recorder.exceptions):
                result["outcome"] = "resource_limit"
        else:
            from measure_signature_inputs import probe

            component, mode = args.case.split("/")
            result.update(probe(component, mode, profile))
    except Exception as error:
        from pqdid.circuits.emitter import ResourceLimit

        result.update(
            outcome="resource_limit"
            if isinstance(error, (ResourceLimit, MemoryError))
            else "error",
            error_type=type(error).__name__,
            reason=str(error),
        )
    result.update(
        child_seconds=time.perf_counter() - started,
        peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
    )
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n")


def run(args):
    profile = extended_profile()
    host = json.loads(Path(args.host_snapshot).read_text())
    # Re-check current available memory as well as the recorded inspection.
    available = next(
        int(line.split()[1]) * 1024
        for line in Path("/proc/meminfo").read_text().splitlines()
        if line.startswith("MemAvailable:")
    )
    headroom = min(host["memory_bytes"]["MemAvailable"], available)
    profile["rss_ceiling_bytes"] = min(profile["rss_ceiling_bytes"], headroom // 4)
    if headroom < 2 * profile["address_space_bytes"]:
        raise RuntimeError("insufficient inspected/current memory headroom")
    if args.tests:
        cases = (
            ["pytest:" + target for target in args.tests]
            if args.separate_test_targets
            else ["pytest"]
        )
    else:
        from measure_signature_inputs import COMPONENTS

        cases = args.cases or [
            f"{c}/{m}" for c in COMPONENTS for m in ("materialised", "count", "stream")
        ]
    results = []
    with tempfile.TemporaryDirectory(prefix="pqdid-signature-") as scratch:
        scratch = Path(scratch)
        effective = scratch / "profile.json"
        effective.write_text(json.dumps(profile))
        for i, case in enumerate(cases):
            is_pytest = case == "pytest" or case.startswith("pytest:")
            output, log, heartbeat = (
                scratch / f"{i}.json",
                scratch / f"{i}.log",
                scratch / f"{i}.beat",
            )
            command = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--child",
                "--case",
                "pytest" if is_pytest else case,
                "--effective-profile",
                str(effective),
                "--output",
                str(output),
                "--heartbeat",
                str(heartbeat),
            ]
            if args.tests:
                targets = (
                    [case.removeprefix("pytest:")] if case.startswith("pytest:") else args.tests
                )
                command += ["--tests", *targets]
                command += ["--pytest-arg=" + value for value in args.pytest_arg]
            supervision = supervise(
                command, profile=profile, log=log, heartbeat=heartbeat if is_pytest else None
            )
            result = (
                json.loads(output.read_text())
                if output.exists()
                else {"case": case, "outcome": "process_failure"}
            )
            if supervision["reason"]:
                result.update(outcome="resource_limit", reason=supervision["reason"])
            result.update(supervision=supervision, command=command, log=log.read_text()[-20000:])
            result["case"] = case
            results.append(result)
            print(f"{case}: {result['outcome']}", flush=True)
    sources = [
        *sorted((ROOT / "src/pqdid/circuits").glob("*.py")),
        Path(__file__).resolve(),
        ROOT / "scripts/measure_signature_inputs.py",
        ROOT / "configs/validation_profiles.json",
    ]
    record = {
        "recorded_at_utc": datetime.now(UTC).isoformat(),
        "host_snapshot": host,
        "launch_mem_available_bytes": available,
        "profile": profile,
        "workers": 1,
        "sequential_process_isolation": args.separate_test_targets,
        "results": results,
        "source_sha256": {
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sources
            if p.exists()
        },
        "scope": "signature inputs; SPEC-004 agreed; full BC-1 unverified; no auth proof/count",
    }
    with Path(args.output).open("x") as output:
        output.write(json.dumps(record, indent=2) + "\n")
    return all(r["outcome"] == "passed" for r in results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--case")
    parser.add_argument("--tests", nargs="+")
    parser.add_argument("--cases", nargs="+")
    parser.add_argument("--pytest-arg", action="append", default=[])
    parser.add_argument("--separate-test-targets", action="store_true")
    parser.add_argument("--effective-profile")
    parser.add_argument("--heartbeat")
    parser.add_argument("--host-snapshot")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.child:
        child(args, json.loads(Path(args.effective_profile).read_text()))
    else:
        if not args.host_snapshot:
            parser.error("--host-snapshot is required")
        raise SystemExit(0 if run(args) else 1)


if __name__ == "__main__":
    main()
