#!/usr/bin/env python3
"""Bounded message pilot and attributed hint count; no proof or larger integration."""

import argparse
import hashlib
import json
import os
import resource
import signal
import sys
import tempfile
import time
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pqdid.circuits.emitter import Emitter, Limits, ResourceLimit, evaluate  # noqa: E402
from scripts.preflight_signature_inputs import (  # noqa: E402
    CountingEmitter,
    host_snapshot,
    message_preparation,
)
from scripts.validation_support import resident_bytes, supervise  # noqa: E402

PILOTS = (
    "valid",
    "attribute-length",
    "attribute-padding",
    "identifier-range",
    "disclosure-mismatch",
    "holder-mutation",
    "hidden-attribute-mutation",
    "identifier-mutation",
    "signature-mutation",
)
NAMES = (
    "holder_preimage",
    "holder_value",
    "binding",
    "mcred",
    "formatted_message",
    "public_key_hash",
    "representative_preimage",
    "fips_representative",
)


@contextmanager
def deadline(seconds):
    def stop(*_):
        raise ResourceLimit("evaluation/observation-time limit", {})

    previous = signal.signal(signal.SIGALRM, stop)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def mutated(case, raw, schema, disclosed):
    value = bytearray(raw)
    offsets, offset = [], 32
    for field in schema.fields:
        offsets.append(offset)
        offset += 2 + field.capacity
    changes = {
        "attribute-length": (32, 255),
        "attribute-padding": (1055, 1),
        "identifier-range": (1056, 255),
        "disclosure-mismatch": (offsets[disclosed[0] - 1] + 2, None),
        "holder-mutation": (0, None),
        "hidden-attribute-mutation": (34, None),
        "identifier-mutation": (1059, None),
        "signature-mutation": (1060, None),
    }
    if case != "valid":
        position, replacement = changes[case]
        value[position] = value[position] ^ 1 if replacement is None else replacement
    return bytes(value)


def checkpoint(result, path):
    path.write_text(json.dumps(result, indent=2) + "\n")


def pilot(case, profile, result, path):
    from pqdid.binding import create_binding
    from pqdid.circuits.control import Scope
    from pqdid.credentials import build_mcred
    from pqdid.parameters import encode_instance_metadata
    from pqdid.schema import project_attributes
    from pqdid.statements import encode_auth_statement
    from pqdid.witnesses import decode_auth_witness, encode_auth_witness
    from tests.reference.preparation_oracle import preparation_bytes
    from tests.reference.signature_oracle import observed
    from tests.unit.relation_cases import auth_case

    pp, statement, witness = auth_case()
    public = encode_auth_statement(pp, statement)
    original = encode_auth_witness(pp.schema, witness)
    raw = mutated(case, original, pp.schema, statement.disclosed)
    result.update(
        fixture="alpha-42-old-002c",
        synthetic_fixture_outputs_only=True,
        public_statement_hex=public.hex(),
        public_statement_sha256=hashlib.sha256(public).hexdigest(),
        witness_sha256=hashlib.sha256(raw).hexdigest(),
        mutations=[(i, a, b) for i, (a, b) in enumerate(zip(original, raw, strict=True)) if a != b],
        baseline_rss_bytes=resident_bytes(os.getpid()),
        baseline_vm_size_bytes=next(
            int(line.split()[1]) * 1024
            for line in Path("/proc/self/status").read_text().splitlines()
            if line.startswith("VmSize:")
        ),
        generation_complete=False,
        evaluation_complete=False,
        additional_test_comparison_gates=0,
    )
    checkpoint(result, path)
    if result["baseline_rss_bytes"] >= profile["rss_ceiling_bytes"]:
        raise ResourceLimit("baseline RSS ceiling", {})
    e = Emitter(
        42632,
        limits=Limits(
            max_gates=profile["max_gates"],
            max_output_bytes=profile["max_output_bytes"],
            max_seconds=profile["generation_seconds"],
        ),
        public_data=public,
    )
    scope = Scope(e)
    message, key, representative, phase = message_preparation(scope, pp, statement, e.inputs)
    circuit = e.finish(scope.output(()))
    result.update(
        generation_complete=True,
        counts=asdict(circuit.counts),
        gates=circuit.counts.gates,
        wires=circuit.counts.wires,
        fingerprint=circuit.fingerprint,
        folded_operations=circuit.folded_operations,
        trace_bytes=circuit.serialised_bytes,
        retained_trace_bytes=circuit.retained_trace_bytes,
        generation_seconds=circuit.generation_seconds,
        through_holder_and_key=phase,
        post_generation_rss_bytes=resident_bytes(os.getpid()),
    )
    checkpoint(result, path)
    previous = json.loads((ROOT / "docs/data/stage3_signature_count_preflight.json").read_text())[
        "results"
    ][0]
    assert circuit.fingerprint == previous["fingerprint"]
    assert asdict(circuit.counts) == previous["counts"]
    assert list(circuit.folded_operations) == previous["folded_operations"]
    byte_strings = (
        message.holder_preimage,
        message.holder_value,
        message.encoded_binding,
        message.certified_message,
        message.formatted_message,
        representative.public_key_hash,
        representative.representative_preimage,
        representative.fips_message_representative,
    )
    start = time.perf_counter()
    with deadline(profile["evaluation_seconds"]):
        evaluated = evaluate(
            circuit,
            raw,
            max_seconds=profile["evaluation_seconds"],
            max_wires=2 + 42632 + profile["max_gates"],
        )
        _, outputs, flags = observed(
            circuit,
            raw,
            byte_strings=byte_strings,
            flags=(message.valid, key.valid, representative.valid),
        )
        expected = preparation_bytes(
            pp.suite, encode_instance_metadata(pp, statement.metadata), pp.issuer_public_key, raw
        )
        expected_valid = int(case not in PILOTS[1:5])
        assert evaluated.output == expected_valid
        assert flags == (expected_valid, 1, expected_valid)
        assert outputs == expected
        # The independent encoder also agrees with the Stage 2 production reference
        # on structurally valid witnesses; malformed outputs remain unusable.
        if case not in PILOTS[1:4]:
            decoded = decode_auth_witness(pp.schema, raw)
            assert (
                int(
                    project_attributes(pp.schema, decoded.attributes, statement.disclosed)
                    == statement.disclosed_attributes
                )
                == expected_valid
            )
            binding = create_binding(pp.domain, decoded.holder_secret, decoded.attributes)
            assert expected[3] == build_mcred(
                pp, statement.metadata, binding, decoded.revocation_identifier
            )
    result.update(
        evaluation_complete=True,
        evaluation=asdict(evaluated),
        evaluation_and_observation_seconds=time.perf_counter() - start,
        validity_flags=dict(zip(("message", "public_key", "representative"), flags, strict=True)),
        outputs_hex=dict(zip(NAMES, (v.hex() for v in outputs), strict=True)),
        reference_matches=True,
        outcome="passed",
    )


class AttributedEmitter(CountingEmitter):
    """Observe canonical emissions only; categories never affect operands or folding."""

    def __init__(self, *args, **kwargs):
        self.category = "initialisation"
        self.emitted = defaultdict(lambda: [0, 0, 0])
        self.folded = defaultdict(lambda: [0, 0, 0])
        super().__init__(*args, **kwargs)

    def _operation(self, opcode, a, b):
        folded = a.public is not None and b.public is not None
        try:
            result = super()._operation(opcode, a, b)
        except ResourceLimit:
            self.stopped_category = self.category
            raise
        (self.folded if folded else self.emitted)[self.category][opcode - 1] += 1
        return result


@contextmanager
def attribution(e, events):
    from pqdid.circuits import signature as sig
    from pqdid.circuits import words as w
    from pqdid.circuits.control import Scope

    @contextmanager
    def label(name):
        old, e.category = e.category, name
        try:
            yield
        finally:
            e.category = old

    def wrap(function, name):
        def call(*args, **kwargs):
            with label(name):
                return function(*args, **kwargs)

        return call

    original_equal, original_mux = w.equal, w.mux_word

    def selector(*args, **kwargs):
        name = e.category + "/selectors" if e.category in ("read", "write") else e.category
        with label(name):
            return original_equal(*args, **kwargs)

    def mux(*args, **kwargs):
        name = e.category + "/mux" if e.category in ("read", "write") else e.category
        with label(name):
            return original_mux(*args, **kwargs)

    original_iteration, original_boundary = sig._hint_iteration, sig._hint_boundary

    def boundary(scope, cells, index, row):
        events["row"] = row
        events["started_in_row"] = 0
        return wrap(original_boundary, "boundary")(scope, cells, index, row)

    def iteration(*args):
        events["started_in_row"] += 1
        events["iterations_started"] += 1
        result = wrap(original_iteration, "step-control")(*args)
        events["iterations_completed"] += 1
        return result

    # Scope imports equality/mux names directly; patch both bindings, restoring all
    # on exit. The small-trace tests verify byte-for-byte identity and category sums.
    from contextlib import ExitStack

    import pqdid.circuits.control as control

    with ExitStack() as stack:
        for obj, name, value in (
            (Scope, "read", wrap(Scope.read, "read")),
            (Scope, "write", wrap(Scope.write, "write")),
            (w, "equal", selector),
            (control, "equal", selector),
            (w, "mux_word", mux),
            (control, "mux_word", mux),
            (sig, "_hint_boundary", boundary),
            (sig, "_hint_iteration", iteration),
            (sig, "_hint_padding", wrap(sig._hint_padding, "padding")),
        ):
            stack.enter_context(patch.object(obj, name, value))
        yield


def hint_audit(profile, result, path):
    from pqdid.circuits.control import Scope
    from pqdid.circuits.signature import decode_hints
    from pqdid.statements import encode_auth_statement
    from tests.unit.relation_cases import auth_case

    pp, statement, _ = auth_case()
    public = encode_auth_statement(pp, statement)
    e = AttributedEmitter(
        42632,
        limits=Limits(
            max_gates=profile["max_gates"],
            max_output_bytes=profile["max_logical_trace_bytes"],
            max_seconds=profile["generation_seconds"],
        ),
        public_data=public,
    )
    events = {"iterations_started": 0, "iterations_completed": 0}
    result.update(baseline_rss_bytes=resident_bytes(os.getpid()), generation_complete=False)
    checkpoint(result, path)
    start = time.perf_counter()
    try:
        with attribution(e, events):
            decode_hints(Scope(e), e.inputs[34464:34952])
    except ResourceLimit as error:
        result.update(outcome="resource_limit", reason=error.reason, prefix_progress=error.progress)
    else:
        raise AssertionError("expected the unchanged hint construction to reach its gate cap")
    result.update(
        counts=asdict(e.counts),
        gates=e.counts.gates,
        wires=e.counts.wires,
        logical_trace_bytes=e.progress()["serialised_bytes_so_far"],
        stored_trace_bytes=e.progress()["stored_bytes"],
        prefix_only_sha256=e._hash.hexdigest(),
        fingerprint=None,
        elapsed_seconds=time.perf_counter() - start,
        events=events,
        stopped_category=e.stopped_category,
        emitted_by_category=dict(e.emitted),
        public_folded_by_category=dict(e.folded),
        additional_test_comparison_gates=0,
        public_statement_sha256=hashlib.sha256(public).hexdigest(),
    )
    previous = json.loads((ROOT / "docs/data/stage3_signature_count_preflight.json").read_text())[
        "results"
    ][1]
    assert result["counts"] == previous["counts"]
    assert result["logical_trace_bytes"] == previous["logical_trace_bytes"]
    assert (
        tuple(map(sum, zip(*e.emitted.values(), strict=True)))
        == tuple(asdict(e.counts).values())[:3]
    )
    result["historical_prefix_counts_reproduced"] = True


def child(args):
    profile = json.loads(Path(args.profile).read_text())
    resource.setrlimit(resource.RLIMIT_AS, (profile["address_space_bytes"],) * 2)
    result = {"case": args.case, "profile": profile, "outcome": "started"}
    start = time.perf_counter()
    path = Path(args.output)
    try:
        (hint_audit if args.kind == "hints" else lambda p, r, f: pilot(args.case, p, r, f))(
            profile, result, path
        )
    except (ResourceLimit, MemoryError) as error:
        result.update(outcome="resource_limit", reason=str(error))
    except Exception as error:
        result.update(
            outcome="correctness_failure", error_type=type(error).__name__, reason=str(error)
        )
    result.update(
        child_seconds=time.perf_counter() - start,
        peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
    )
    checkpoint(result, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("pilot", "hints"), required=True)
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--case")
    parser.add_argument("--profile")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.child:
        child(args)
        return
    if Path(args.output).exists():
        raise FileExistsError(args.output)
    profiles = json.loads((ROOT / "configs/validation_profiles.json").read_text())
    profile = profiles[
        "message_preparation_pilot_v1" if args.kind == "pilot" else "signature_count_preflight_v1"
    ]
    results = []
    with tempfile.TemporaryDirectory(prefix="pqdid-review-") as folder:
        folder = Path(folder)
        for case in PILOTS if args.kind == "pilot" else ("hints-prefix-attribution",):
            host = host_snapshot()
            if host["memory_bytes"]["MemAvailable"] < 2 * profile["address_space_bytes"]:
                raise RuntimeError("insufficient WSL memory headroom")
            if host["disk_bytes"]["free"] < 40 * 1024**2:
                raise RuntimeError("insufficient diagnostic disk headroom")
            output, log, effective = (folder / name for name in ("case.json", "log", "profile"))
            output.unlink(missing_ok=True)
            effective.write_text(json.dumps(profile))
            command = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--child",
                "--kind",
                args.kind,
                "--case",
                case,
                "--profile",
                str(effective),
                "--output",
                str(output),
            ]
            supervision = supervise(command, profile=profile, log=log)
            result = json.loads(output.read_text()) if output.exists() else {"case": case}
            if supervision["reason"]:
                result.update(outcome="resource_limit", reason=supervision["reason"])
            elif supervision["returncode"]:
                result.update(outcome="process_failure")
            result.update(
                supervision=supervision, host_snapshot=host, command=command, log=log.read_text()
            )
            results.append(result)
            print(f"{case}: {result.get('outcome')}", flush=True)
            # Valid-first is an admission pilot, not permission to retry/escalate.
            if args.kind == "pilot" and result.get("outcome") != "passed":
                break
    sources = [
        *sorted((ROOT / "src/pqdid/circuits").glob("*.py")),
        Path(__file__).resolve(),
        ROOT / "scripts/preflight_signature_inputs.py",
        ROOT / "tests/reference/preparation_oracle.py",
        ROOT / "configs/validation_profiles.json",
        ROOT / "tests/fixtures/relations_vectors.json",
    ]
    record = {
        "recorded_at_utc": datetime.now(UTC).isoformat(),
        "kind": args.kind,
        "workers": 1,
        "results": results,
        "source_sha256": {
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources
        },
        "scope": "bounded preparation evaluation/hint attribution; no full authentication or proof",
    }
    with Path(args.output).open("x") as f:
        f.write(json.dumps(record, indent=2) + "\n")
    raise SystemExit(0 if all(r.get("outcome") == "passed" for r in results) else 1)


if __name__ == "__main__":
    main()
