"""Sixteen distinct public native loader/row cases; only the coordinator executes."""

import hashlib
import json
import struct
import subprocess
from pathlib import Path

from .r1cs import evaluate_row, gate_row, input_row, multiply

ROOT = Path(__file__).resolve().parents[2]
IDENTITY = hashlib.sha256(b"public-nontrivial-R1CS-fixture-v1").digest()


def fixture():
    # Explicit equations independent of the Boolean compiler and native operators.
    rows = [
        (((2, 1),), ((0, 1), (2, 1)), ()),
        (((3, 1),), ((0, 1), (3, 1)), ()),
        (((2, 1), (3, 1)), ((0, 1),), ((4, 1),)),
        (((2, 1),), ((3, 1),), ((5, 1),)),
        (((4, 1), (5, 1)), ((0, 1),), ((6, 1),)),
        (((6, 1),), ((0, 1),), ((1, 1),)),
        (((1, 1),), ((0, 1),), ((0, 1),)),
        (((2, 1 << 191),), ((0, 2),), ((2, 0x87),)),
    ]
    return rows, [1], [1, 1, 0, 1, 1]


def encode(rows, primary, auxiliary, *, variables=6, identity=IDENTITY):
    data = bytearray(b"PQR1C001" + identity)
    data.extend(struct.pack(">IIIII", variables, 1, len(rows), len(primary), len(auxiliary)))
    for value in primary + auxiliary:
        data.extend(value.to_bytes(24, "little"))
    for row in rows:
        for terms in row:
            data.extend(struct.pack(">I", len(terms)))
            for column, coefficient in terms:
                data.extend(struct.pack(">I", column))
                data.extend(coefficient.to_bytes(24, "little"))
    data.extend(b"END!")
    return bytes(data)


def run_case(case_id, meter, *, binary=None, output_directory=None):
    number = int(case_id.removeprefix("N-"))
    if case_id != f"N-{number:02d}" or not 1 <= number <= 16:
        raise ValueError("unknown native case")
    rows, primary, auxiliary = fixture()
    if number == 1:
        lowered = [input_row(2), input_row(3)] + [
            gate_row(1, 2, 3, 4),
            gate_row(2, 2, 3, 5),
            gate_row(1, 4, 5, 6),
        ]
        meter(len(lowered))
        assert lowered == rows[:5], "compiler rows differ from independent explicit equations"
    expected_rejection = None
    identity = IDENTITY
    if number == 2:
        auxiliary[0] = 0
    elif number == 3:
        auxiliary[0] = 2
    elif number == 4:
        auxiliary[2] = 1
    elif number == 5:
        primary[0] = 0
    elif number == 6:
        primary = []
        expected_rejection = "primary-length"
    elif number == 7:
        auxiliary = auxiliary[:-1]
        expected_rejection = "auxiliary-length"
    elif number == 8:
        rows.append((((6, 1),), ((0, 1),), ((0, 1),)))
    elif number == 9:
        rows.append((((7, 1),), ((0, 1),), ((0, 1),)))
        expected_rejection = "column-range"
    elif number == 10:
        rows.append((((2, 1), (2, 1)), ((0, 1),), ()))
        expected_rejection = "column-order-or-duplicate"
    elif number == 11:
        rows.append((((3, 1), (2, 1)), ((0, 1),), ()))
        expected_rejection = "column-order-or-duplicate"
    elif number == 12:
        rows.append((((2, 0),), ((0, 1),), ()))
        expected_rejection = "zero-coefficient"
    elif number == 13:
        rows.append(((), ((0, 1),), ()))
    elif number == 15:
        # Defined producer at column6 is replaced by the other partition's column4.
        rows[5] = (((4, 1),), ((0, 1),), ((1, 1),))
    elif number == 16:
        identity = bytes([IDENTITY[0] ^ 1]) + IDENTITY[1:]
        expected_rejection = "public-identity"
    payload = encode(rows, primary, auxiliary, identity=identity)
    if number == 14:
        payload = payload[:-1]
        expected_rejection = "truncated"
    binary = binary or ROOT / "experiments/auth_relation_integration_1/build/relation_adapter"
    directory = output_directory or (
        ROOT / "docs/data/oct31_auth_relation_integration_run_1/cases/native-inputs"
    )
    directory.mkdir(exist_ok=True, parents=True)
    path = directory / f"{case_id}.matrix"
    with path.open("xb") as stream:
        stream.write(payload)
    meter(len(rows))  # emitted synthetic rows, including malformed fixture rows
    expected = None
    if expected_rejection is None:
        expected = [evaluate_row(row, primary + auxiliary) for row in rows]
        meter(len(rows))
    # Charge complete native row evaluation reservation before executing; malformed
    # admission may visit a prefix only, so accounting deliberately overcharges it.
    meter(2 * len(rows))
    completed = subprocess.run(
        [str(binary), str(path), IDENTITY.hex()],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if len(completed.stdout) > 16_384 or completed.stderr:
        raise AssertionError("unexpected native diagnostics")
    actual = json.loads(completed.stdout)
    if expected_rejection is not None:
        assert actual == {"status": "rejected", "reason": expected_rejection}
    else:
        satisfaction = all(multiply(a, b) == c for a, b, c in expected)
        assert satisfaction is (number in (1, 8, 13)), "independent fixture outcome changed"
        assert actual["status"] == "loaded" and actual["satisfied"] is satisfaction
        assert actual["rows"] == len(rows) and actual["variables"] == 6
        assert actual["nonzero_terms"] == sum(len(lc) for row in rows for lc in row)
        assert actual["field_bytes"] == 24
        for side, label in enumerate(("az", "bz", "cz")):
            assert actual[label] == [f"{values[side]:048x}" for values in expected]
    return {
        "case_id": case_id,
        "passed": True,
        "complete": True,
        "native": actual,
        "fixture_sha256": hashlib.sha256(payload).hexdigest(),
        "fixture": str(path.relative_to(ROOT)),
        "public_synthetic_only": True,
        "paths": [
            "r1cs_constraint_system<gf192>::add_constraint",
            "A_matrix/B_matrix/C_matrix",
            "create_Az_Bz_Cz_from_variable_assignment",
            "is_satisfied(primary,auxiliary)",
            "gf192 field operators",
        ]
        if expected_rejection is None
        else ["checked native input loader before unsafe calls"],
        "proof_generated": False,
        "full_authentication": False,
        "native_evaluated_rows_charge": "2*rows upper bound: Az/Bz/Cz and satisfaction",
    }
