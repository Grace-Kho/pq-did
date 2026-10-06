#!/usr/bin/env python3
"""Actual incremental counting, one supervised worker; no enlarged evaluation."""

import argparse
import hashlib
import json
import resource
import shutil
import sys
import tempfile
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pqdid.circuits.emitter import Emitter, Limits, ResourceLimit  # noqa: E402
from scripts.validation_support import extended_profile, supervise  # noqa: E402

TARGETS = (
    "message-preparation",
    "hints-complete",
    "signature-with-norm",
    "preparation-with-decode-and-norm",
)
ARITHMETIC = (
    "divmod-q",
    "canonical-q",
    "centred-even",
    "ring-add",
    "ring-subtract",
    "ring-multiply",
    "ring-public-multiply",
    "decompose",
    "use-hint",
    "ntt-butterfly",
)


class CountingEmitter(Emitter):
    """Canonical emitter plus a logical-byte guard and bounded progress reporting.

    Never changes the opcode/operand stream, folding or numbering. Emitter's
    ordinary max_output_bytes bounds actual stored bytes, so count mode needs the
    separate logical guard. No sink, graph, trace buffer or evaluation is created.
    """

    def __init__(self, inputs, *, limits, public_data=b"", checkpoint=None):
        self._logical_limit = limits.max_output_bytes
        self._checkpoint = checkpoint
        self._next_checkpoint = 1_000_000
        self.diagnostic_write_bytes = 0
        super().__init__(inputs, limits=limits, mode="count", public_data=public_data)

    def _write(self, record):
        if self._serialised_bytes + len(record) > self._logical_limit:
            self._abort("logical trace-size limit")
        super()._write(record)

    def progress(self):
        return {**super().progress(), "counts": asdict(self.counts)}

    def _operation(self, opcode, a, b):
        result = super()._operation(opcode, a, b)
        if self.counts.gates >= self._next_checkpoint:
            self._next_checkpoint += 1_000_000
            if self._checkpoint is not None:
                payload = json.dumps(
                    {
                        **self.progress(),
                        "elapsed_seconds": time.perf_counter() - self._started,
                        "complete": False,
                    }
                )
                self._checkpoint.write_text(payload)
                self.diagnostic_write_bytes += len(payload.encode())
        return result


def host_snapshot():
    memory = {
        line.split(":")[0]: int(line.split()[1]) * 1024
        for line in Path("/proc/meminfo").read_text().splitlines()
        if len(line.split()) == 3
    }
    return {
        "memory_bytes": memory,
        "disk_bytes": dict(zip(("total", "used", "free"), shutil.disk_usage(ROOT), strict=True)),
        "wsl_kernel": Path("/proc/sys/kernel/osrelease").read_text().strip(),
    }


def effective_profile(arithmetic=False):
    profiles = json.loads((ROOT / "configs/validation_profiles.json").read_text())
    profile = dict(
        profiles["hash_enrolment_extended_v1" if arithmetic else "signature_count_preflight_v1"]
    )
    host = host_snapshot()
    available = host["memory_bytes"]["MemAvailable"]
    if available < 2 * profile["address_space_bytes"]:
        raise RuntimeError("insufficient current WSL memory headroom")
    if host["disk_bytes"]["free"] < 2 * 10 * 1024**2:
        raise RuntimeError("insufficient diagnostic storage headroom")
    ordinary = extended_profile()
    profile["rss_ceiling_bytes"] = min(
        profile["rss_ceiling_bytes"], ordinary["rss_ceiling_bytes"], available // 4
    )
    profile["address_space_bytes"] = min(
        profile["address_space_bytes"], ordinary["address_space_bytes"]
    )
    return profile, host


def message_preparation(scope, pp, statement, inputs):
    """The counted message-only core, also used by the authorised evaluation pilot."""
    from pqdid.circuits.auth_parsing import link_disclosure, parse_auth_witness
    from pqdid.circuits.signature_inputs import (
        certified_message,
        decode_expected_public_key,
        message_representative,
    )

    parsed = parse_auth_witness(scope, pp.schema, inputs)
    link_disclosure(scope, pp.schema, parsed, statement.disclosed, statement.disclosed_attributes)
    certified = certified_message(scope, pp, statement.metadata, parsed)
    key = decode_expected_public_key(scope.e, pp)
    phase = scope.e.progress()
    representative = message_representative(scope, pp, certified)
    return certified, key, representative, phase


def count_target(target, profile, checkpoint):
    from pqdid.circuits.control import Scope
    from pqdid.circuits.signature import decode_hints, decode_signature, response_norm
    from pqdid.circuits.signature_inputs import (
        prepare_verifier_inputs,
    )
    from pqdid.statements import encode_auth_statement
    from tests.unit.relation_cases import auth_case

    pp, statement, _ = auth_case()  # Private fixture values are never passed to construction.
    encoded = encode_auth_statement(pp, statement)
    result = {
        "target": target,
        "mode": "count",
        "fixture": "alpha-42-old-002c",
        "fixture_file": "tests/fixtures/relations_vectors.json",
        "fixture_sha256": hashlib.sha256(
            (ROOT / "tests/fixtures/relations_vectors.json").read_bytes()
        ).hexdigest(),
        "public_statement_hex": encoded.hex(),
        "public_statement_sha256": hashlib.sha256(encoded).hexdigest(),
        "private_inputs": 42632,
        "private_layout_bytes": {
            "holder_secret": [0, 32],
            "attributes": [32, 1056],
            "rid": [1056, 1060],
            "signature": [1060, 4369],
            "siblings": [4369, 5329],
        },
        "classification": (
            "expected pp/key/schema/X public; original witness positions private; no advice"
        ),
        "additional_test_comparison_gates": 0,
        "generation_complete": False,
        "phases": {},
    }
    limits = Limits(
        max_gates=profile["max_gates"],
        max_output_bytes=profile["max_logical_trace_bytes"],
        max_seconds=profile["generation_seconds"],
        max_inputs=profile["max_inputs"],
    )
    e = CountingEmitter(42632, limits=limits, public_data=encoded, checkpoint=checkpoint)
    scope = Scope(e)
    stage = "construction"
    try:
        if target == "message-preparation":
            stage = "message representative"
            _, _, _, phase = message_preparation(scope, pp, statement, e.inputs)
            result["phases"]["through_holder_and_public_key"] = phase
        elif target == "hints-complete":
            stage = "hint reconstruction"
            decode_hints(scope, e.inputs[8 * (1060 + 3248) : 34952])
        elif target == "signature-with-norm":
            stage = "signature decoding (hints before norm)"
            decoded = decode_signature(scope, e.inputs[8480:34952])
            result["phases"]["through_signature_decoding"] = e.progress()
            stage = "response norm"
            scope.require(response_norm(scope, decoded.responses).within_bound)
        elif target == "preparation-with-decode-and-norm":
            stage = "preparation with full signature decoding"
            prepared = prepare_verifier_inputs(scope, pp, statement, e.inputs)
            result["phases"]["through_preparation"] = e.progress()
            stage = "response norm"
            scope.require(response_norm(scope, prepared.signature.responses).within_bound)
        else:
            raise ValueError(target)
        circuit = e.finish(scope.output(()))
        assert (
            circuit.serialised is None and circuit.stored_bytes == circuit.retained_trace_bytes == 0
        )
        result.update(
            outcome="passed",
            generation_complete=True,
            fingerprint=circuit.fingerprint,
            generation_seconds=circuit.generation_seconds,
            logical_trace_bytes=circuit.serialised_bytes,
            folded_operations=circuit.folded_operations,
        )
    except ResourceLimit as error:
        result.update(
            outcome="resource_limit",
            reason=error.reason,
            stopped_in=stage,
            prefix_progress=error.progress,
        )
    assert e._buffer is None and e._sink is None
    result.update(
        counts=asdict(e.counts),
        gates=e.counts.gates,
        and_gates=e.counts.and_,
        wires=e.counts.wires,
        logical_trace_bytes=e.progress()["serialised_bytes_so_far"],
        stored_trace_bytes=e.progress()["stored_bytes"],
        elapsed_seconds=time.perf_counter() - e._started,
        diagnostic_checkpoint_write_bytes=e.diagnostic_write_bytes,
        no_full_graph_retained=True,
        full_wire_value_array_allocated=False,
    )
    return result


def child(args):
    profile = json.loads(Path(args.profile).read_text())
    resource.setrlimit(resource.RLIMIT_AS, (profile["address_space_bytes"],) * 2)
    started = time.perf_counter()
    result = {"target": args.target}
    try:
        if args.arithmetic:
            from measure_auth_parsing_arithmetic import probe

            component, mode = args.target.split("/")
            result.update(probe(component, mode, profile))
        else:
            result.update(count_target(args.target, profile, Path(args.checkpoint)))
    except (ResourceLimit, MemoryError) as error:
        result.update(outcome="resource_limit", reason=str(error), generation_complete=False)
        if Path(args.checkpoint).exists():
            result["last_checkpoint_only"] = json.loads(Path(args.checkpoint).read_text())
    except Exception as error:
        result.update(outcome="error", reason=str(error), error_type=type(error).__name__)
    result.update(
        child_seconds=time.perf_counter() - started,
        peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
    )
    payload = json.dumps(result, indent=2) + "\n"
    # Reserve the entire retained log allowance plus bounded checkpoint output.
    ceiling = profile.get("max_diagnostic_bytes", 10 * 1024**2)
    if (
        len(payload.encode())
        + profile["case_log_bytes"]
        + result.get("diagnostic_checkpoint_write_bytes", 0)
        > ceiling
    ):
        raise RuntimeError("diagnostic output limit")
    Path(args.output).write_text(payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--arithmetic", action="store_true")
    parser.add_argument("--target")
    parser.add_argument("--profile")
    parser.add_argument("--checkpoint")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.child:
        child(args)
        return
    targets = (
        [f"{c}/{m}" for c in ARITHMETIC for m in ("materialised", "count", "stream")]
        if args.arithmetic
        else list(TARGETS)
    )
    rows = []
    with tempfile.TemporaryDirectory(prefix="pqdid-preflight-") as folder:
        folder = Path(folder)
        for target in targets:
            profile, host = effective_profile(args.arithmetic)
            p, result_file, checkpoint, log = (
                folder / name for name in ("profile.json", "result.json", "progress.json", "log")
            )
            result_file.unlink(missing_ok=True)
            checkpoint.unlink(missing_ok=True)
            p.write_text(json.dumps(profile))
            command = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--child",
                "--target",
                target,
                "--profile",
                str(p),
                "--checkpoint",
                str(checkpoint),
                "--output",
                str(result_file),
            ]
            if args.arithmetic:
                command.append("--arithmetic")
            supervision = supervise(command, profile=profile, log=log)
            result = (
                json.loads(result_file.read_text())
                if result_file.exists()
                else {"target": target, "outcome": "process_failure", "generation_complete": False}
            )
            if supervision["reason"]:
                result.update(
                    outcome="resource_limit",
                    reason=supervision["reason"],
                    generation_complete=False,
                )
            if not result_file.exists() and checkpoint.exists():
                result["last_checkpoint_only"] = json.loads(checkpoint.read_text())
            result.update(
                profile=profile,
                host_snapshot=host,
                supervision=supervision,
                command=command,
                log=log.read_text(),
                diagnostic_stored_bytes=sum(
                    x.stat().st_size for x in (result_file, checkpoint, log) if x.exists()
                ),
            )
            rows.append(result)
            print(f"{target}: {result['outcome']}", flush=True)
    sources = [
        *sorted((ROOT / "src/pqdid/circuits").glob("*.py")),
        Path(__file__).resolve(),
        ROOT / "configs/validation_profiles.json",
        ROOT / "scripts/validation_support.py",
    ]
    record = {
        "recorded_at_utc": datetime.now(UTC).isoformat(),
        "workers": 1,
        "results": rows,
        "source_sha256": {
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources
        },
        "scope": "SPEC-004 adoption component measurements"
        if args.arithmetic
        else ("counting-only preflight; no evaluation, graph, wire-value array or proof"),
    }
    with Path(args.output).open("x") as output:
        output.write(json.dumps(record, indent=2) + "\n")
    raise SystemExit(0 if all(r["outcome"] == "passed" for r in rows) else 1)


if __name__ == "__main__":
    main()
