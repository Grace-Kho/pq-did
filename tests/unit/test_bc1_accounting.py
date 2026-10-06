"""Integer-only projections; no generated full authentication circuit or proof."""

import json
from pathlib import Path

import pytest

from pqdid.circuits.accounting import (
    authentication_count_admitted,
    authentication_proof_bytes,
    authentication_view_bytes,
)


@pytest.mark.parametrize("g", [0, 1, 2, 3, 4, 5, 7, 8, 9, 1_000_000, 10**30, 10**100])
def test_equivalent_frozen_formulas_without_float_or_buffer(g):
    assert authentication_proof_bytes(g) == 5_363_104 + 960 * ((g + 3) // 4)
    assert authentication_proof_bytes(g) == 64 + 480 * (515 + 2 * authentication_view_bytes(g))


def test_preserved_authentication_arithmetic_vectors():
    path = Path(__file__).resolve().parents[2] / "configs/encoding_examples.json"
    examples = json.loads(path.read_text())["proof_size_arithmetic"]
    for case in examples["cases"]:
        if case["d"] == 42632:
            assert authentication_proof_bytes(case["g"]) == case["proof_bytes"]


def test_encoding_admission_is_not_resource_feasibility():
    bound = (8 * ((1 << 32) - 1) - 42632) // 2
    assert authentication_count_admitted(bound)
    assert not authentication_count_admitted(bound + 1)
    assert authentication_proof_bytes(bound) > 10**12


@pytest.mark.parametrize("g", [-1, True, 1.5, "1", None])
def test_invalid_counts(g):
    with pytest.raises(ValueError):
        authentication_proof_bytes(g)
