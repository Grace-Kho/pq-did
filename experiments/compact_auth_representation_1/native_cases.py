"""Four public compact-matrix checks using the sealed, unchanged native loader."""

import hashlib
import json
import subprocess
from dataclasses import asdict

from experiments.auth_relation_integration_1.native_cases import encode
from experiments.auth_relation_integration_1.r1cs import evaluate_row, multiply
from experiments.auth_relation_integration_1.stream import CountedEmitter
from pqdid.circuits.emitter import Limits

from . import run as guard
from .admission import digest
from .affine import AffineSink
from .cases import IDENTITY, PUBLIC, TINY_ASSIGNMENT, TINY_ROWS, _tiny


def case(case_id, meter):
    if case_id not in {"N-01", "N-02", "N-03", "N-04"}:
        raise ValueError("native case outside matrix")
    if case_id == "N-04":
        rows = []
        sink = AffineSink(
            IDENTITY,
            charge=lambda _kind, count: meter(count),
            witness_bits=b"\x01" + bytes(64),
            max_rows=100,
            max_wire_forms=140,
            max_term_entries=5000,
            max_columns=100,
            row_consumer=rows.append,
        )
        emitter = CountedEmitter(65, sink=sink, public_data=PUBLIC, limits=Limits(max_gates=100))
        parity = emitter.inputs[0]
        for bit in emitter.inputs[1:]:
            parity = emitter.xor(parity, bit)
        emitter.finish(parity)
        descriptor = sink.completed()
        # Independent complete parity-matrix specification, not derived from sink.
        expected_rows = [(((i, 1),), ((0, 1), (i, 1)), ()) for i in range(2, 67)]
        expected_rows += [
            (tuple((i, 1) for i in range(2, 67)), ((0, 1),), ((67, 1),)),
            (((67, 1),), ((0, 1),), ((1, 1),)),
            (((1, 1),), ((0, 1),), ((0, 1),)),
        ]
        assert rows == expected_rows
        assignment = list(sink.assignment)
        assert assignment == [1, 1, *([0] * 64), 1]
        assignment[1] = 0  # All true inputs now zero, but claimed spill/output remains one.
    else:
        _, descriptor = _tiny(meter, retained=True)
        rows = list(TINY_ROWS)
        assignment = list(TINY_ASSIGNMENT)
        if case_id == "N-02":
            assignment[1] = 2
        elif case_id == "N-03":
            assignment[-1] = 0
    expected_values = [evaluate_row(row, assignment) for row in rows]
    meter(len(rows))
    expected = all(multiply(a, b) == c for a, b, c in expected_values)
    assert expected is (case_id == "N-01")
    payload = encode(
        rows, assignment[:1], assignment[1:], variables=descriptor.variables, identity=IDENTITY
    )
    target = guard.D / "cases" / (case_id + ".matrix")
    with target.open("xb") as stream:
        stream.write(payload)
    binary = guard.P / "experiments/auth_relation_integration_1/build/relation_adapter"
    recorded = guard.read(
        guard.P / "docs/data/oct31_auth_relation_integration_run_1/build-result.json"
    )["binary_sha256"]
    assert digest(binary) == recorded
    meter(2 * len(rows))  # Both native evaluation passes, conservative on early rejection.
    completed = subprocess.run(
        [str(binary), str(target), IDENTITY.hex()],
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    )
    assert not completed.stderr and len(completed.stdout) <= 16384
    native = json.loads(completed.stdout)
    assert native["status"] == "loaded" and native["satisfied"] == expected
    assert native["field_bytes"] == 24 and native["rows"] == len(rows)
    for index, key in enumerate(("az", "bz", "cz")):
        assert native[key] == [f"{values[index]:048x}" for values in expected_values]
    return {
        "expected": expected,
        "actual": native,
        "compact_descriptor": asdict(descriptor),
        "native_binary_sha256": recorded,
        "input_sha256": hashlib.sha256(payload).hexdigest(),
        "public_synthetic": True,
        "full_authentication": False,
        "builds": 0,
        "native_paths": [
            "add_term",
            "add_constraint",
            "A/B/C_matrix",
            "create_Az_Bz_Cz_from_variable_assignment",
            "is_satisfied",
            "gf192 operators",
        ],
    }
