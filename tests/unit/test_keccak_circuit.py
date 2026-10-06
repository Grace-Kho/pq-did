"""Official byte KATs and independent native expectations on PRIVATE input wires."""

import hashlib
import io
import json
import os
import struct
from pathlib import Path

import pytest

from pqdid.circuits.emitter import Emitter, Limits, ResourceLimit, evaluate
from pqdid.circuits.keccak import ROUND_CONSTANTS, _round, keccak_f1600, sha3_384, shake256
from pqdid.circuits.parsing import equal_bytes, public_bytes, reverse_byte_bits
from tests.reference.keccak_reference import permutation

from .hash_circuit_cases import digest, hash_predicate

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "tests/fixtures/fips202_circuit_vectors.json").read_text())
RATES = {"SHA3_384": 104, "SHAKE128": 168, "SHAKE256": 136}


def extended_limits():
    if os.environ.get("PQDID_HASH_EXTENDED_BUDGET") != "1":
        pytest.skip("larger component test profile requires PQDID_HASH_EXTENDED_BUDGET=1")
    return Limits(max_gates=2_000_000, max_output_bytes=40 * 1024 * 1024)


def test_official_provenance_and_original_empty_message_sentinel():
    assert len(VECTORS["cases"]) == 15
    assert (
        VECTORS["extractor_sha256"]
        == hashlib.sha256(
            (ROOT / "tests/reference/extract_fips202_vectors.py").read_bytes()
        ).hexdigest()
    )
    for case in VECTORS["cases"]:
        assert len(bytes.fromhex(case["message"])) * 8 == case["length_bits"]
        if case["length_bits"] == 0:
            assert case["source_msg"] == "00" and case["message"] == ""


@pytest.mark.parametrize(
    "case", VECTORS["cases"], ids=lambda x: f"{x['algorithm']}-{x['length_bits']}"
)
def test_official_vectors_with_private_messages(case):
    message = bytes.fromhex(case["message"])
    expected = bytes.fromhex(case["output"])
    algorithm = case["algorithm"]
    limits = extended_limits() if len(message) >= RATES[algorithm] else Limits()
    circuit = hash_predicate(algorithm, len(message), expected, limits=limits)
    assert evaluate(circuit, message, max_wires=limits.max_gates + 65538).output == 1
    assert digest(algorithm, message, len(expected)) == expected
    if message:
        assert circuit.counts.inputs == 8 * len(message) and circuit.counts.and_ > 35000
        changed = bytes([message[0] ^ 1]) + message[1:]
        assert evaluate(circuit, changed, max_wires=limits.max_gates + 65538).output == 0
    else:
        assert circuit.counts.inputs == 0 and circuit.counts.gates == 0


@pytest.mark.parametrize("algorithm,multiple", [(a, n) for a in RATES for n in (1, 2)])
def test_multiple_absorption_blocks_private(algorithm, multiple):
    limits = extended_limits()
    message = bytes((i * 37 + 11) % 256 for i in range(multiple * RATES[algorithm] + 1))
    expected = digest(algorithm, message, 48)
    circuit = hash_predicate(algorithm, len(message), expected, limits=limits)
    assert evaluate(circuit, message, max_wires=2_100_000).output == 1


@pytest.mark.parametrize(
    "algorithm,length",
    [
        ("SHAKE128", 168),
        ("SHAKE128", 169),
        ("SHAKE128", 1026),
        ("SHAKE256", 0),
        ("SHAKE256", 32),
        ("SHAKE256", 48),
        ("SHAKE256", 64),
        ("SHAKE256", 128),
        ("SHAKE256", 136),
        ("SHAKE256", 137),
        ("SHAKE256", 256),
        ("SHAKE256", 512),
    ],
)
def test_squeeze_boundaries_and_callsite_lengths(algorithm, length):
    limits = extended_limits() if length > RATES[algorithm] else Limits()
    message = bytes(range(32))
    expected = digest(algorithm, message, length)
    circuit = hash_predicate(algorithm, len(message), expected, limits=limits)
    assert circuit.counts.and_ > 35000  # d=0 still runs the full absorption.
    assert evaluate(circuit, message, max_wires=2_100_000).output == 1


def test_hash_materialised_count_stream_identical_including_domain():
    target = hashlib.sha3_384(b"abc").digest()
    material = hash_predicate("SHA3_384", 3, target)
    sink = io.BytesIO()
    for mode in ("count", "stream"):
        circuit = hash_predicate(
            "SHA3_384", 3, target, mode=mode, sink=sink if mode == "stream" else None
        )
        assert circuit.counts == material.counts
        assert circuit.fingerprint == material.fingerprint
    assert sink.getvalue() == material.serialised
    assert hashlib.shake_256(b"abc").digest(48) != target


def test_mixed_public_private_multiple_blocks_with_original_budget():
    prefix = bytes(range(208))  # Two entirely public blocks, then private message.
    secret = bytes(range(32))
    target = hashlib.sha3_384(prefix + secret).digest()
    circuit = hash_predicate("SHA3_384", 32, target, prefix=prefix)
    assert circuit.counts.and_ > 35000
    assert evaluate(circuit, secret).output == 1
    assert evaluate(circuit, secret[::-1]).output == 0


def test_original_budget_terminates_private_two_block_hash():
    with pytest.raises(ResourceLimit, match="gate-count") as exc:
        hash_predicate("SHA3_384", 104, bytes(48))
    assert exc.value.progress["gates"] == 200000
    assert exc.value.progress["complete"] is False


def test_literal_first_theta_and_chi_gate_order():
    e = Emitter(1600, limits=Limits())
    bits = reverse_byte_bits(e, e.inputs)
    a = tuple(
        tuple(bits[64 * (5 * y + x) : 64 * (5 * y + x + 1)] for y in range(5)) for x in range(5)
    )
    out = _round(e, a, 0)
    circuit = e.finish(out[0][0][0])
    gates = list(struct.iter_unpack(">BQQ", circuit.serialised[56:-33]))
    # C[0,0]: serial bits for z=0 at bytes 0,40,80,120,160 -> wires 9,329,...
    assert gates[:4] == [(1, 9, 329), (1, 1602, 649), (1, 1603, 969), (1, 1604, 1289)]
    # Theta = 1280+320+1600 gates, followed by literal XOR-with-1, AND, XOR chi.
    assert gates[3200][0] == 1 and gates[3200][2] == 1
    assert [item[0] for item in gates[3200:3203]] == [1, 2, 1]
    assert len(gates) == 8064 and circuit.counts.and_ == 1600 and circuit.counts.not_ == 0
    assert all(item[0] == 1 for item in gates[-64:])  # Full iota, including XOR zero.


def test_round_constants_public_rc_and_full_permutation_structure():
    # Independent published Keccak-f[1600] constants, FIPS 202 Algorithms 5/6.
    assert ROUND_CONSTANTS == (
        0x1,
        0x8082,
        0x800000000000808A,
        0x8000000080008000,
        0x808B,
        0x80000001,
        0x8000000080008081,
        0x8000000000008009,
        0x8A,
        0x88,
        0x80008009,
        0x8000000A,
        0x8000808B,
        0x800000000000008B,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x800A,
        0x800000008000000A,
        0x8000000080008081,
        0x8000000000008080,
        0x80000001,
        0x8000000080008008,
    )
    e = Emitter(1600, limits=Limits())
    out = keccak_f1600(e, e.inputs)
    circuit = e.finish(out[0])
    assert circuit.counts.gates == 24 * 8064 and circuit.counts.and_ == 24 * 1600


@pytest.mark.parametrize("message", [bytes(200), bytes(range(200))])
def test_permutation_on_private_full_state_against_independent_lane_oracle(message):
    e = Emitter(1600, limits=Limits())
    expected = permutation(message)
    if message == bytes(200):
        assert expected[:8].hex() == "e7dde140798f25f1"
    circuit = e.finish(equal_bytes(e, keccak_f1600(e, e.inputs), public_bytes(e, expected)))
    assert circuit.counts.gates == 193536 + 4800
    assert evaluate(circuit, message).output == 1
    assert evaluate(circuit, bytes([message[0] ^ 1]) + message[1:]).output == 0


@pytest.mark.parametrize("bad", [-1, True, 1.5, 65537])
def test_public_output_length_validation(bad):
    e = Emitter(8, limits=Limits())
    with pytest.raises(ValueError):
        shake256(e, e.inputs, bad)


def test_partial_byte_input_rejected_before_hash_emission():
    e = Emitter(7, limits=Limits())
    with pytest.raises(ValueError):
        sha3_384(e, e.inputs)
    assert e.counts.gates == 0
