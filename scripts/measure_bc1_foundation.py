#!/usr/bin/env python3
"""One-worker component probes. These never construct an authentication circuit.

--suite runs fresh sequential subprocesses with a 30 s wall timeout each. Resource
limits are engineering budgets; projections accept assumed full-auth AND counts.
"""

import argparse
import hashlib
import json
import platform
import resource
import subprocess
import sys
import tempfile
import time
import tracemalloc
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from pqdid.circuits import words as w
from pqdid.circuits.accounting import authentication_proof_bytes
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import Emitter, Limits, ResourceLimit, evaluate

ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = ("add64", "sub64", "mul64", "select4")
MODES = ("materialised", "count", "stream")


def build(component, mode, limits, sink):
    count = 128 if component != "select4" else 64 + 4 * 8
    emitter = Emitter(
        count, limits=limits, mode=mode, sink=sink, public_data=component.encode("ascii")
    )
    scope = Scope(emitter)
    if component == "select4":
        index = w.from_serialised(emitter, emitter.inputs[:64])
        cells = tuple(
            w.from_serialised(emitter, emitter.inputs[64 + 8 * i : 72 + 8 * i]) for i in range(4)
        )
        value = scope.read(cells, index)
        target = w.constant(emitter, 0xA5, 8)
    else:
        left = w.from_serialised(emitter, emitter.inputs[:64])
        right = w.from_serialised(emitter, emitter.inputs[64:])
        operation = {"add64": w.add64, "sub64": w.sub64, "mul64": w.mul64}[component]
        value = scope.checked(operation(emitter, left, right))
        target = w.constant(
            emitter, {"add64": 5, "sub64": -1, "mul64": 6}[component], 64, signed=True
        )
    circuit = emitter.finish(scope.output((w.equal(emitter, value, target),)))
    return circuit, emitter


def example_witness(component):
    # Witness bytes enter evaluation only, after construction has completed.
    if component == "select4":
        return (2).to_bytes(8, "big") + bytes([0x81, 0x36, 0xA5, 0xFA])
    return (2).to_bytes(8, "big", signed=True) + (3).to_bytes(8, "big", signed=True)


def probe(args):
    # Linux RLIMIT_AS bounds virtual address space, not RSS or free WSL RAM.
    resource.setrlimit(resource.RLIMIT_AS, (args.address_space_bytes, args.address_space_bytes))
    limits = Limits(args.max_gates, args.max_output_bytes, args.max_seconds, args.max_inputs)
    result = {
        "component": args.component,
        "mode": args.mode,
        "scope": "component predicate only; neither full authentication nor its lower bound",
        "complete": False,
        "limits": asdict(limits),
        "evaluation_max_seconds": args.eval_seconds,
        "evaluation_max_wires": args.eval_wires,
        "address_space_limit_bytes": args.address_space_bytes,
        "tracemalloc_enabled": True,
    }
    with tempfile.TemporaryFile(mode="w+b", dir="/tmp") as stream:
        tracemalloc.start()
        started = time.perf_counter()
        try:
            circuit, emitter = build(
                args.component, args.mode, limits, stream if args.mode == "stream" else None
            )
            current, peak = tracemalloc.get_traced_memory()
            result.update(
                generation_complete=True,
                generation_seconds=circuit.generation_seconds,
                counts=asdict(circuit.counts),
                gates=circuit.counts.gates,
                wires=circuit.counts.wires,
                fingerprint=circuit.fingerprint,
                folded_operations=list(circuit.folded_operations),
                serialised_bytes=circuit.serialised_bytes,
                stored_trace_bytes=circuit.stored_bytes,
                retained_trace_bytes=circuit.retained_trace_bytes,
                retained_input_handles_bytes=sys.getsizeof(emitter.inputs)
                + sum(sys.getsizeof(bit) for bit in emitter.inputs),
                generation_traced_retained_bytes=current,
                generation_traced_peak_bytes=peak,
                evaluation=None,
            )
            if args.mode == "stream":
                stream.flush()
                result["stream_file_bytes"] = stream.tell()
                stream.seek(0)
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
                if (
                    digest != circuit.fingerprint
                    or result["stream_file_bytes"] != circuit.stored_bytes
                ):
                    raise RuntimeError("streamed trace differs from canonical trace")
            if args.mode == "materialised":
                evaluation = evaluate(
                    circuit,
                    example_witness(args.component),
                    max_seconds=args.eval_seconds,
                    max_wires=args.eval_wires,
                )
                result["evaluation"] = asdict(evaluation)
                if evaluation.output != 1:
                    raise RuntimeError("independent example result rejected")
            result["complete"] = True
        except ResourceLimit as exc:
            result.update(reason=exc.reason, progress=exc.progress)
        except (MemoryError, OSError) as exc:
            result.update(reason=type(exc).__name__)
        finally:
            result["probe_seconds"] = time.perf_counter() - started
            result["probe_traced_peak_bytes"] = tracemalloc.get_traced_memory()[1]
            result["peak_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
            tracemalloc.stop()
    return result


def host_snapshot():
    names = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        name, value = line.split(":", 1)
        if name in names:
            memory[name] = int(value.split()[0]) * 1024
    import os

    storage = {}
    for path in (ROOT, Path("/tmp")):
        stat = os.statvfs(path)
        storage[str(path)] = {
            "available_bytes": stat.f_bavail * stat.f_frsize,
            "total_bytes": stat.f_blocks * stat.f_frsize,
        }
    return {
        "recorded_at_utc": datetime.now(UTC).isoformat(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "memory_bytes": memory,
        "storage": storage,
    }


def suite(args):
    flags = [
        "--max-gates",
        str(args.max_gates),
        "--max-output-bytes",
        str(args.max_output_bytes),
        "--max-seconds",
        str(args.max_seconds),
        "--max-inputs",
        str(args.max_inputs),
        "--eval-seconds",
        str(args.eval_seconds),
        "--eval-wires",
        str(args.eval_wires),
        "--address-space-bytes",
        str(args.address_space_bytes),
    ]
    runs = []
    for component in COMPONENTS:
        for mode in MODES:
            command = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--component",
                component,
                "--mode",
                mode,
                *flags,
            ]
            completed = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if completed.returncode:
                raise RuntimeError(
                    f"probe failed: {command!r}: {completed.stdout} {completed.stderr}"
                )
            runs.append(json.loads(completed.stdout))
        comparable = (
            "counts",
            "gates",
            "wires",
            "fingerprint",
            "serialised_bytes",
            "folded_operations",
        )
        for field in comparable:
            if any(run[field] != runs[-3][field] for run in runs[-2:]):
                raise RuntimeError(f"mode disagreement: {component} {field}")
    failures = []
    for limit in (["--max-gates", "3"], ["--max-output-bytes", "60"], ["--max-seconds", "0"]):
        command = [
            sys.executable,
            str(Path(__file__).resolve()),
            "--component",
            "add64",
            "--mode",
            "materialised",
            *flags,
            *limit,
        ]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=30)
        failure = json.loads(completed.stdout)
        if completed.returncode != 2 or failure["complete"]:
            raise RuntimeError("limit probe did not report clean non-completion")
        failures.append(failure)
    sources = [*sorted((ROOT / "src/pqdid/circuits").glob("*.py")), Path(__file__).resolve()]
    return {
        "recorded_at_utc": datetime.now(UTC).isoformat(),
        "workers": 1,
        "child_wall_timeout_seconds": 30,
        "host_before_budget_selection": json.loads(args.host_snapshot.read_text())
        if args.host_snapshot
        else None,
        "host_at_measurement": host_snapshot(),
        "source_sha256": {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sources
        },
        "runs": runs,
        "limit_probes": failures,
        "authentication_size_projections": [
            {
                "assumed_full_auth_and_gates": g,
                "projected_proof_bytes": authentication_proof_bytes(g),
                "label": "projection from an assumed full authentication AND count; not measured",
            }
            for g in (0, 1_000_000, 10_000_000)
        ],
        "limitations": [
            "One instrumented run per component/mode; timings include tracemalloc overhead.",
            "Peak RSS is Linux process high-water RSS, includes imports and allocator state.",
            "Traced memory excludes interpreter/native allocations before tracing; "
            "retained trace and inputs are subsets.",
            "Count mode emits no output bytes; serialised_bytes is the logical trace length.",
            "Streaming bounds gate records, not caller live words, inputs or future compiler data.",
            "Clocks are cooperative checks; timeout and RLIMIT_AS also bound probe processes.",
            "No full relation/proof/feasibility result; SPEC-003 recipe identity remains open.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", action="store_true")
    parser.add_argument("--component", choices=COMPONENTS, default="add64")
    parser.add_argument("--mode", choices=MODES, default="materialised")
    parser.add_argument("--max-gates", type=int, default=200_000)
    parser.add_argument("--max-output-bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--max-seconds", type=float, default=10.0)
    parser.add_argument("--max-inputs", type=int, default=65536)
    parser.add_argument("--eval-seconds", type=float, default=5.0)
    parser.add_argument("--eval-wires", type=int, default=300000)
    parser.add_argument("--address-space-bytes", type=int, default=256 * 1024 * 1024)
    parser.add_argument("--host-snapshot", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = suite(args) if args.suite else probe(args)
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
    else:
        print(encoded, end="")
    return 0 if args.suite or result["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
