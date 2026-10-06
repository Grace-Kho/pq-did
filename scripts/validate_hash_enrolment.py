#!/usr/bin/env python3
"""Sequential, supervised completion of the 17 deferred tests and nine probes.

Historical evidence is read-only. Operational metadata never enters circuit bytes.
"""

import argparse
import hashlib
import io
import json
import os
import resource
import sys
import tempfile
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from validation_support import ROOT, extended_profile, supervise

sys.path.insert(0, str(ROOT))

TEST_FILE = "tests/unit/test_keccak_circuit.py"
DEFERRED = [
    *[
        f"test_official_vectors_with_private_messages[{case}]"
        for case in (
            "SHA3_384-832",
            "SHA3_384-1672",
            "SHAKE128-1344",
            "SHAKE128-1352",
            "SHAKE256-1088",
            "SHAKE256-1096",
        )
    ],
    *[
        f"test_multiple_absorption_blocks_private[{algorithm}-{n}]"
        for algorithm in ("SHA3_384", "SHAKE128", "SHAKE256")
        for n in (1, 2)
    ],
    *[
        f"test_squeeze_boundaries_and_callsite_lengths[{case}]"
        for case in (
            "SHAKE128-169",
            "SHAKE128-1026",
            "SHAKE256-137",
            "SHAKE256-256",
            "SHAKE256-512",
        )
    ],
]


def circuit_record(circuit):
    result = {
        "counts": asdict(circuit.counts),
        "gates": circuit.counts.gates,
        "wires": circuit.counts.wires,
        "serialised_bytes": circuit.serialised_bytes,
        "stored_trace_bytes": circuit.stored_bytes,
        "fingerprint": circuit.fingerprint,
        "generation_seconds": circuit.generation_seconds,
        "retained_trace_bytes": circuit.retained_trace_bytes,
        "folded_operations": list(circuit.folded_operations),
    }
    if circuit.serialised is not None:
        result["gate_records_sha256"] = hashlib.sha256(
            memoryview(circuit.serialised)[56:-33]
        ).hexdigest()
    return result


class Recorder:
    """Observe original tests without changing assertions, emitters or evaluators."""

    def __init__(self, heartbeat=None):
        self.circuits = []
        self.evaluations = []
        self.reports = []
        self.exceptions = []
        self.heartbeat = heartbeat

    def install(self):
        from pqdid.circuits import emitter

        original_finish, original_evaluate = emitter.Emitter.finish, emitter.evaluate

        def finish(e, output):
            circuit = original_finish(e, output)
            self.circuits.append(circuit_record(circuit))
            return circuit

        def evaluate(*args, **kwargs):
            started = time.perf_counter()
            entry = {
                "max_seconds": kwargs.get("max_seconds", 5.0),
                "max_wires": kwargs.get("max_wires", 300000),
            }
            try:
                result = original_evaluate(*args, **kwargs)
                entry.update(asdict(result), outcome="completed")
                return result
            except emitter.ResourceLimit as error:
                entry.update(outcome="resource_limit", reason=error.reason)
                raise
            finally:
                entry["observed_seconds"] = time.perf_counter() - started
                self.evaluations.append(entry)

        emitter.Emitter.finish, emitter.evaluate = finish, evaluate

    def pytest_runtest_logstart(self, nodeid, location):
        if self.heartbeat:
            Path(self.heartbeat).write_text(nodeid)

    def pytest_runtest_makereport(self, item, call):
        if call.excinfo:
            from pqdid.circuits.emitter import ResourceLimit

            error = call.excinfo.value
            self.exceptions.append(
                {
                    "nodeid": item.nodeid,
                    "type": type(error).__name__,
                    "reason": str(error)[:500],
                    "resource_limit": isinstance(error, (ResourceLimit, MemoryError)),
                }
            )

    def pytest_runtest_logreport(self, report):
        if report.when == "call" or report.failed or report.skipped:
            self.reports.append(
                {
                    "nodeid": report.nodeid,
                    "phase": report.when,
                    "outcome": report.outcome,
                    "seconds": report.duration,
                }
            )


def stability(component, profile):
    from pqdid.circuits.emitter import Limits, evaluate

    if component == "mul64":
        from measure_bc1_foundation import build, example_witness

        def construct(limits, mode="materialised", sink=None):
            return build("mul64", mode, limits, sink)[0]

        witness = example_witness("mul64")
        historical = json.loads((ROOT / "docs/data/stage3_bc1_measurements.json").read_text())
        old = next(
            r
            for r in historical["runs"]
            if r["component"] == "mul64" and r["mode"] == "materialised"
        )
    else:
        from measure_hash_enrolment import sample

        from pqdid.circuits.enrolment import compile_enrolment

        pp, statement, witness = sample()

        def construct(limits, mode="materialised", sink=None):
            return compile_enrolment(pp, statement, limits=limits, mode=mode, sink=sink)

        historical = json.loads(
            (ROOT / "docs/data/stage3_hash_enrolment_measurements.json").read_text()
        )
        old = next(
            r
            for r in historical["runs"]
            if r["component"] == "enrolment" and r["mode"] == "materialised"
        )
    limits = Limits(max_gates=profile["max_gates"], max_output_bytes=profile["max_output_bytes"])
    original = construct(Limits())
    extended = construct(limits)
    assert original.serialised == extended.serialised
    evaluations = []
    for circuit in (original, extended):
        assert circuit.fingerprint == old["fingerprint"]
        assert asdict(circuit.counts) == old["counts"]
        assert circuit.serialised_bytes == old["serialised_bytes"]
        evaluation = evaluate(circuit, witness)
        assert evaluation.output == 1
        evaluations.append(asdict(evaluation))
    sink = io.BytesIO()
    streamed = construct(limits, "stream", sink)
    counted = construct(limits, "count")
    assert sink.getvalue() == original.serialised
    assert streamed.counts == counted.counts == original.counts
    assert streamed.fingerprint == counted.fingerprint == original.fingerprint
    return {
        "outcome": "passed",
        "component": component,
        "historical_comparison": "fingerprint/counts/length match; old full trace not stored",
        "current_profiles": "literal material/stream equality; count fingerprint/count equality",
        "original": circuit_record(original),
        "extended": circuit_record(extended),
        "stream": circuit_record(streamed),
        "count": circuit_record(counted),
        "evaluations": evaluations,
    }


def child(args, profile):
    # Kernel address-space bound retained independently of parent RSS watchdog.
    resource.setrlimit(resource.RLIMIT_AS, (profile["address_space_bytes"],) * 2)
    started = time.perf_counter()
    recorder = Recorder(args.heartbeat)
    result = {
        "identifier": args.identifier,
        "kind": args.kind,
        "effective_profile": profile,
        "convention": "SPEC-003 user-agreed",
        "full_BC1_conformance": "unverified",
    }
    try:
        if args.kind in ("test", "regression"):
            import pytest

            os.environ["PQDID_HASH_EXTENDED_BUDGET"] = "1"
            if args.kind == "test":
                recorder.install()
                selection = [TEST_FILE + "::" + args.identifier]
            else:
                selection = ["tests/unit", "tests/integration", "tests/smoke/test_hashes.py"]
            code = pytest.main([*selection, "-q", "--tb=short"], plugins=[recorder])
            outcome = (
                "passed"
                if code == 0 and not any(r["outcome"] == "skipped" for r in recorder.reports)
                else "pytest_failure"
            )
            if any(x["resource_limit"] for x in recorder.exceptions):
                outcome = "resource_limit"
            elif any(x["type"] == "AssertionError" for x in recorder.exceptions):
                outcome = "assertion_failure"
            result.update(
                outcome=outcome,
                pytest_returncode=int(code),
                reports=recorder.reports,
                exceptions=recorder.exceptions,
                circuits=recorder.circuits,
                evaluations=recorder.evaluations,
            )
        elif args.kind == "probe":
            # Instrumentation/order are the same as the historical probe. Observe
            # completion hashes without changing construction or evaluation limits.
            recorder.install()
            import measure_hash_enrolment as previous

            component, mode = args.identifier.split("/")
            value = previous.probe(
                argparse.Namespace(
                    component=component,
                    mode=mode,
                    max_gates=profile["max_gates"],
                    max_output_bytes=profile["max_output_bytes"],
                )
            )
            value["canonical_identity"] = "SPEC-003 folds agreed; full BC-1 conformance unverified"
            result.update(
                outcome="passed" if value["complete"] else "resource_limit",
                probe=value,
                circuits=recorder.circuits,
                evaluations=recorder.evaluations,
            )
        else:
            result.update(stability(args.identifier, profile))
    except Exception as error:
        from pqdid.circuits.emitter import ResourceLimit

        outcome = (
            "resource_limit"
            if isinstance(error, (ResourceLimit, MemoryError))
            else ("assertion_failure" if isinstance(error, AssertionError) else "error")
        )
        result.update(outcome=outcome, exception_type=type(error).__name__, reason=str(error)[:500])
    result.update(
        child_seconds=time.perf_counter() - started,
        peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
    )
    Path(args.result).write_text(json.dumps(result, indent=2) + "\n")


def run(args, profile):
    initial = json.loads(Path(args.host_snapshot).read_text())
    # Do not infer an unexposed cgroup limit. Use inspected WSL available memory
    # conservatively; process AS stays at the stricter existing 256 MiB.
    headroom = initial["memory_bytes"]["MemAvailable"]
    profile["rss_ceiling_bytes"] = min(profile["rss_ceiling_bytes"], headroom // 4)
    if headroom < 2 * profile["address_space_bytes"]:
        raise RuntimeError("insufficient memory headroom for retained process limit")
    cases = [("test", name) for name in DEFERRED]
    cases += [
        ("probe", f"{c}/{mode}")
        for c in ("sha3-multiple", "shake128-1026", "shake256-512")
        for mode in ("materialised", "count", "stream")
    ]
    cases += [("stability", "mul64"), ("stability", "enrolment")]
    if args.regression:
        cases = [("regression", "unit-integration-fixed-hash")]
    results = []
    with tempfile.TemporaryDirectory(prefix="pqdid-confirmed-") as scratch:
        scratch = Path(scratch)
        effective = scratch / "profile.json"
        effective.write_text(json.dumps(profile))
        for number, (kind, identifier) in enumerate(cases):
            result_path, log = scratch / f"{number}.json", scratch / f"{number}.log"
            heartbeat = scratch / "heartbeat"
            heartbeat.unlink(missing_ok=True)
            command = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--child",
                "--kind",
                kind,
                "--identifier",
                identifier,
                "--result",
                str(result_path),
                "--effective-profile",
                str(effective),
                "--heartbeat",
                str(heartbeat),
            ]
            supervision = supervise(
                command,
                profile=profile,
                log=log,
                heartbeat=heartbeat if kind == "regression" else None,
            )
            if result_path.exists():
                value = json.loads(result_path.read_text())
            else:
                value = {
                    "kind": kind,
                    "identifier": identifier,
                    "outcome": "resource_limit" if supervision["reason"] else "process_failure",
                }
            if supervision["reason"]:
                value.update(outcome="resource_limit", reason=supervision["reason"])
            value["supervision"] = supervision
            value["command"] = command
            value["log"] = log.read_text()[-10000:]
            results.append(value)
            print(f"{kind}: {identifier}: {value['outcome']}", flush=True)
    sources = [
        *sorted((ROOT / "src/pqdid/circuits").glob("*.py")),
        Path(__file__).resolve(),
        ROOT / "scripts/validation_support.py",
        ROOT / "configs/validation_profiles.json",
    ]
    record = {
        "recorded_at_utc": datetime.now(UTC).isoformat(),
        "profile": profile,
        "host_before_launch": initial,
        "workers": 1,
        "results": results,
        "source_sha256": {
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources
        },
        "scope": "validation only; agreed initialisers do not establish full BC-1 conformance",
    }
    Path(args.output).write_text(json.dumps(record, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--regression", action="store_true")
    parser.add_argument("--kind", choices=("test", "probe", "stability", "regression"))
    parser.add_argument("--identifier")
    parser.add_argument("--result")
    parser.add_argument("--heartbeat")
    parser.add_argument("--effective-profile")
    parser.add_argument("--host-snapshot")
    parser.add_argument("--output")
    args = parser.parse_args()
    profile = (
        json.loads(Path(args.effective_profile).read_text()) if args.child else extended_profile()
    )
    if args.child:
        child(args, profile)
    else:
        if not args.output or not args.host_snapshot:
            parser.error("--output and --host-snapshot are required")
        run(args, profile)


if __name__ == "__main__":
    main()
