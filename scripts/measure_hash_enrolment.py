#!/usr/bin/env python3
"""One-worker fresh circuit probes; default limits unchanged, larger profile opt-in."""

import argparse
import hashlib
import json
import resource
import subprocess
import sys
import tempfile
import time
import tracemalloc
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from pqdid.binding import encode_holder_input
from pqdid.circuits.emitter import Emitter, Limits, ResourceLimit, evaluate
from pqdid.circuits.enrolment import compile_enrolment
from pqdid.circuits.enrolment_accounting import enrolment_proof_bytes, enrolment_view_bytes
from pqdid.circuits.keccak import keccak_f1600, sha3_384, shake128, shake256
from pqdid.circuits.parsing import equal_bytes, holder_message, parse_enrolment_public, public_bytes
from pqdid.parameters import decode_parameters
from pqdid.statements import encode_enrol_statement

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))  # Measurement-only access to the independent test oracle.
COMPONENTS = ("permutation", "sha3-short", "shake128-short", "shake256-128", "parsing", "enrolment")
LARGE = ("sha3-multiple", "shake128-1026", "shake256-512")


def sample():
    record = json.loads((ROOT / "tests/fixtures/relations_vectors.json").read_text())
    instance = next(x for x in record["instances"] if x["name"] == "alpha")
    item = next(x for x in record["enrolment"] if x["credential"] == "alpha-42")
    pp = decode_parameters(bytes.fromhex(instance["parameters"]))
    statement, _ = parse_enrolment_public(pp, bytes.fromhex(item["statement"]))
    return pp, statement, bytes.fromhex(item["witness"])


def prepare(component):
    # Synthetic example selection/expected targets, OUTSIDE timed construction.
    if component in ("enrolment", "parsing"):
        pp, statement, witness = sample()
        target = (
            statement.binding.holder_value
            if component == "enrolment"
            else encode_holder_input(pp.domain, witness)
        )
        return {"pp": pp, "statement": statement, "target": target}, witness
    if component == "permutation":
        from tests.reference.keccak_reference import permutation

        witness = bytes(range(200))
        return {"target": permutation(witness), "input_bytes": 200}, witness
    witness = (
        bytes(range(32)) if component != "sha3-multiple" else bytes(i % 256 for i in range(209))
    )
    if component.startswith("sha3"):
        target = hashlib.sha3_384(witness).digest()
    elif component.startswith("shake128"):
        target = hashlib.shake_128(witness).digest(1026 if component.endswith("1026") else 32)
    else:
        target = hashlib.shake_256(witness).digest(512 if component.endswith("512") else 128)
    return {"target": target, "input_bytes": len(witness)}, witness


def build(component, public, mode, limits, sink):
    if component == "enrolment":
        return compile_enrolment(
            public["pp"], public["statement"], limits=limits, mode=mode, sink=sink
        )
    n = 32 if component == "parsing" else public["input_bytes"]
    e = Emitter(
        8 * n,
        limits=limits,
        mode=mode,
        sink=sink,
        public_data=component.encode() + public["target"],
    )
    if component == "parsing":
        # Public parser runs as part of this component; framing emits wires only.
        pp = public["pp"]
        parse_enrolment_public(pp, encode_enrol_statement(pp, public["statement"]))
        output = holder_message(e, pp.domain, e.inputs)
    elif component == "permutation":
        output = keccak_f1600(e, e.inputs)
    elif component.startswith("sha3"):
        output = sha3_384(e, e.inputs)
    elif component.startswith("shake128"):
        output = shake128(e, e.inputs, len(public["target"]))
    else:
        output = shake256(e, e.inputs, len(public["target"]))
    return e.finish(equal_bytes(e, output, public_bytes(e, public["target"])))


def probe(args):
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
    public, witness = prepare(args.component)
    limits = Limits(max_gates=args.max_gates, max_output_bytes=args.max_output_bytes)
    result = {
        "component": args.component,
        "mode": args.mode,
        "complete": False,
        "canonical_identity": "provisional; SPEC-003 pending",
        "construction": "fresh",
        "limits": asdict(limits),
        "evaluation_seconds_limit": 5,
        "evaluation_wire_limit": args.max_gates + 65538,
        "address_space_limit_bytes": 256 * 1024 * 1024,
        "private_input_bytes": len(witness),
        "public_expected_output_bytes": len(public["target"]),
        "tracemalloc_enabled": True,
    }
    with tempfile.TemporaryFile(mode="w+b", dir="/tmp") as sink:
        tracemalloc.start()
        started = time.perf_counter()
        try:
            circuit = build(
                args.component, public, args.mode, limits, sink if args.mode == "stream" else None
            )
            result.update(
                generation_complete=True,
                counts=asdict(circuit.counts),
                gates=circuit.counts.gates,
                wires=circuit.counts.wires,
                serialised_bytes=circuit.serialised_bytes,
                stored_trace_bytes=circuit.stored_bytes,
                fingerprint=circuit.fingerprint,
                generation_seconds=circuit.generation_seconds,
                fresh_construction_seconds=time.perf_counter() - started,
                retained_trace_bytes=circuit.retained_trace_bytes,
                generation_traced_retained_bytes=tracemalloc.get_traced_memory()[0],
                generation_traced_peak_bytes=tracemalloc.get_traced_memory()[1],
                folded_operations=list(circuit.folded_operations),
            )
            if args.mode == "stream":
                sink.flush()
                result["file_bytes"] = sink.tell()
                sink.seek(0)
                if hashlib.file_digest(sink, "sha256").hexdigest() != circuit.fingerprint:
                    raise RuntimeError("stream fingerprint mismatch")
            if args.mode == "materialised":
                result["evaluation"] = asdict(
                    evaluate(circuit, witness, max_wires=args.max_gates + 65538)
                )
                if result["evaluation"]["output"] != 1:
                    raise RuntimeError("example predicate rejected")
                if args.component == "enrolment":
                    result["reuse_wrong_opening"] = asdict(
                        evaluate(circuit, bytes(32), max_wires=args.max_gates + 65538)
                    )
                    if result["reuse_wrong_opening"]["output"] != 0:
                        raise RuntimeError("wrong enrolment opening accepted")
            if args.component == "enrolment":
                result["calculated_enrolment_view_bytes"] = enrolment_view_bytes(
                    circuit.counts.and_
                )
                result["projected_enrolment_proof_bytes"] = enrolment_proof_bytes(
                    circuit.counts.and_
                )
                result["proof_status"] = (
                    "calculated for provisional circuit, d=256; no proof generated"
                )
            result["complete"] = True
        except ResourceLimit as exc:
            result.update(reason=exc.reason, progress=exc.progress)
        except (MemoryError, OSError) as exc:
            result.update(reason=type(exc).__name__)
        finally:
            result.update(
                probe_seconds=time.perf_counter() - started,
                peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
                probe_traced_peak_bytes=tracemalloc.get_traced_memory()[1],
            )
            tracemalloc.stop()
    return result


def suite(args):
    from measure_bc1_foundation import host_snapshot

    runs = []
    # The original cap is exercised first, even if the extended profile is requested.
    for component, gate_cap, storage_cap in [
        *[(c, 200000, 8 * 1024 * 1024) for c in (*COMPONENTS, *LARGE)],
        *([(c, 2000000, 40 * 1024 * 1024) for c in LARGE] if args.extended else []),
    ]:
        for mode in ("materialised", "count", "stream"):
            command = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--component",
                component,
                "--mode",
                mode,
                "--max-gates",
                str(gate_cap),
                "--max-output-bytes",
                str(storage_cap),
            ]
            child = subprocess.run(command, capture_output=True, text=True, timeout=30, cwd=ROOT)
            if child.returncode not in (0, 2):
                raise RuntimeError(f"probe error: {child.stdout} {child.stderr}")
            run = json.loads(child.stdout)
            if (child.returncode == 0) != run["complete"]:
                raise RuntimeError("inconsistent completion report")
            runs.append(run)
        completed = [r for r in runs[-3:] if r.get("generation_complete")]
        if completed:
            for key in ("counts", "fingerprint", "serialised_bytes", "folded_operations"):
                if any(r[key] != completed[0][key] for r in completed[1:]):
                    raise RuntimeError("mode disagreement")
    sources = [
        *sorted((ROOT / "src/pqdid/circuits").glob("*.py")),
        Path(__file__).resolve(),
        ROOT / "tests/reference/keccak_reference.py",
    ]
    return {
        "recorded_at_utc": datetime.now(UTC).isoformat(),
        "workers": 1,
        "child_wall_timeout_seconds": 30,
        "host": host_snapshot(),
        "initial_host": json.loads(args.host_snapshot.read_text()) if args.host_snapshot else None,
        "source_sha256": {
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources
        },
        "extended_profile": args.extended,
        "runs": runs,
        "limitations": [
            "Instrumented single runs; RSS includes interpreter/native allocations.",
            "Retained traced memory excludes pre-trace allocations; no whole-compiler bound.",
            "Full hash rounds retained on success; aborted output is never a completed circuit.",
            "Enrolment fresh generation and evaluation reuse are distinct; no cache.",
            "SPEC-003 pending; counts/identity/proof-size calculations are provisional.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", action="store_true")
    parser.add_argument("--extended", action="store_true")
    parser.add_argument("--component", choices=(*COMPONENTS, *LARGE), default="permutation")
    parser.add_argument(
        "--mode", choices=("materialised", "count", "stream"), default="materialised"
    )
    parser.add_argument("--max-gates", type=int, default=200000)
    parser.add_argument("--max-output-bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--host-snapshot", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = suite(args) if args.suite else probe(args)
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end="")
    return 0 if args.suite or result["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
