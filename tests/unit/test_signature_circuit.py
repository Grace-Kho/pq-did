"""Private decode boundaries; synthetic encodings do not assert authenticity."""

from dataclasses import replace

import pytest

from pqdid import bounded_mldsa as reference
from pqdid.circuits import words as w
from pqdid.circuits.auth_parsing import parse_auth_witness
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import Emitter, ResourceLimit, evaluate
from pqdid.circuits.signature import (
    GAMMA1,
    _hint_boundary,
    _hint_cells,
    _hint_iteration,
    _hint_padding,
    _unsigned,
    decode_hints,
    decode_responses,
    decode_signature,
    response_norm,
    unpack_unsigned,
)
from pqdid.witnesses import encode_auth_witness
from tests.reference.signature_oracle import hint_encoding, observed, synthetic_signature

from .auth_arithmetic_cases import extended_limits
from .mldsa_cases import load_cases, vector_arguments
from .relation_cases import auth_case


def run(circuit, raw):
    return evaluate(circuit, raw, max_seconds=5, max_wires=2_065_538).output


def response_circuit(*, with_norm=False, with_parser=False):
    e = Emitter(42632 if with_parser else 3309 * 8, limits=extended_limits())
    scope = Scope(e)
    signature = (
        parse_auth_witness(scope, auth_case()[0].schema, e.inputs).signature
        if with_parser
        else e.inputs
    )
    result = decode_responses(scope, signature)
    if with_norm:
        norm = response_norm(scope, result.responses)
        scope.require(norm.within_bound)
    return e.finish(scope.output(())), result


@pytest.mark.parametrize("name", ["alpha-42-old-002c", "alpha-43-new-0034", "beta-42-new-002c"])
def test_genuine_relation_responses_and_fixed_witness(name):
    # Use fixture names below rather than manufacturing new signatures.
    from .relation_cases import FIXTURE

    candidates = [
        x["name"]
        for x in FIXTURE["authentication"]
        if x["name"].startswith(name.split("-old")[0].split("-new")[0])
    ]
    pp, _, witness = auth_case(candidates[0])
    e = Emitter(42632, limits=extended_limits())
    scope = Scope(e)
    parsed = parse_auth_witness(scope, pp.schema, e.inputs)
    result = decode_responses(scope, parsed.signature)
    assert parsed.signature == e.inputs[8480:34952]
    assert result.challenge_hash == parsed.signature[:384]
    assert result.encoded_hints == parsed.signature[25984:]
    circuit = e.finish(scope.output(()))
    raw = encode_auth_witness(pp.schema, witness)
    assert run(circuit, raw) == 1
    challenge, responses, _ = reference._decode_signature(witness.signature)
    values, strings, flags = observed(
        circuit,
        raw,
        words=tuple(x for p in result.responses for x in p),
        byte_strings=(result.challenge_hash, result.encoded_hints),
        flags=(result.valid,),
    )
    assert values == tuple(x for p in responses for x in p)
    assert strings == (challenge, witness.signature[3248:]) and flags == (1,)
    assert circuit.counts.inputs == 42632 and len(raw) == 5329


@pytest.mark.parametrize("item", load_cases()["vectors"], ids=lambda x: x["name"])
def test_existing_native_signature_response_decode(item):
    key, message, signature, context = vector_arguments(item)
    assert reference.bounded_verify_mldsa65(key, message, signature, context=context)
    circuit, result = response_circuit()
    values, _, flags = observed(
        circuit,
        signature,
        words=tuple(x for p in result.responses for x in p),
        flags=(result.valid,),
    )
    assert values == tuple(x for p in reference._decode_signature(signature)[1] for x in p)
    assert flags == (1,) and run(circuit, signature) == 1


def test_all_encoding_endpoints_and_cross_byte_packing_are_not_norm_rejections():
    examples = [-GAMMA1 + 1, -524092, -524091, -1, 0, 1, 524091, 524092, GAMMA1]
    expected = tuple(examples[i % len(examples)] for i in range(1280))
    encoded = synthetic_signature(expected)
    circuit, decoded = response_circuit()
    actual, _, flags = observed(
        circuit,
        encoded,
        words=tuple(x for p in decoded.responses for x in p),
        flags=(decoded.valid,),
    )
    assert actual == expected and flags == (1,) and run(circuit, encoded) == 1
    assert reference._decode_signature(encoded)[1] == [
        list(expected[i : i + 256]) for i in range(0, 1280, 256)
    ]
    assert not reference._norm_ok([list(expected)])


@pytest.mark.parametrize(
    "coefficient,valid",
    [(0, 1), (524091, 1), (-524091, 1), (524092, 0), (-524092, 0), (524288, 0), (-524287, 0)],
)
def test_strict_norm_is_separate_from_decode(coefficient, valid):
    circuit, decoded = response_circuit(with_norm=True)
    values = [0] * 1280
    values[-1] = coefficient
    raw = synthetic_signature(values)
    _, _, flags = observed(circuit, raw, flags=(decoded.valid,))
    assert flags == (1,) and run(circuit, raw) == valid


def test_decodable_challenge_mutation_is_not_signature_verification():
    pp, statement, witness = auth_case()
    from pqdid.binding import create_binding
    from pqdid.credentials import CREDENTIAL_SIGNING_CONTEXT, build_mcred

    message = build_mcred(
        pp,
        statement.metadata,
        create_binding(pp.domain, witness.holder_secret, witness.attributes),
        witness.revocation_identifier,
    )
    bad = bytes((witness.signature[0] ^ 1,)) + witness.signature[1:]
    reference._decode_signature(bad)  # Complete reference decoder accepts the encoding.
    assert not reference.bounded_verify_mldsa65(
        pp.issuer_public_key, message, bad, context=CREDENTIAL_SIGNING_CONTEXT
    )
    circuit, _ = response_circuit(with_parser=True)
    raw = encode_auth_witness(pp.schema, witness)
    changed = encode_auth_witness(pp.schema, replace(witness, signature=bad))
    identity = circuit.fingerprint
    assert run(circuit, raw) == run(circuit, changed) == 1
    malformed = bytearray(changed)
    malformed[32:34] = b"\xff\xff"
    assert run(circuit, bytes(malformed)) == 0
    assert circuit.fingerprint == identity


def boundary_circuit():
    e = Emitter(61 * 8, limits=extended_limits())
    scope = Scope(e)
    cells = _hint_cells(e, e.inputs)
    index = w.constant(e, 0, 64)
    for row in range(6):
        index = _hint_boundary(scope, cells, index, row)
    return e.finish(scope.output(()))


@pytest.mark.parametrize(
    "ends,valid",
    [
        ([0] * 6, 1),
        ([55] * 6, 1),
        ([0, 1, 1, 40, 54, 55], 1),
        ([1, 0, 0, 0, 0, 0], 0),
        ([0, 0, 0, 0, 56, 56], 0),
        ([255] * 6, 0),
        ([55, 55, 55, 55, 55, 54], 0),
    ],
)
def test_hint_boundaries_all_rows_and_capacity(ends, valid):
    circuit = boundary_circuit()
    assert run(circuit, bytes(55) + bytes(ends)) == valid


@pytest.fixture(scope="module")
def iteration_case():
    # Isolated step input state is diagnostic ONLY, never authentication advice.
    e = Emitter((61 + 24 + 256 * 8) * 8, limits=extended_limits())
    scope = Scope(e)
    cells = _hint_cells(e, e.inputs[:488])
    index, first, end = (
        w.from_serialised(e, e.inputs[488 + i * 64 : 552 + i * 64]) for i in range(3)
    )
    polynomial = tuple(
        w.from_serialised(e, e.inputs[680 + i * 64 : 744 + i * 64]) for i in range(256)
    )
    index, polynomial = _hint_iteration(scope, cells, index, first, end, polynomial)
    return e.finish(scope.output(())), index, polynomial


def step_raw(encoded, index, first, end, polynomial):
    return encoded + b"".join(
        v.to_bytes(8, "big", signed=True) for v in (index, first, end, *polynomial)
    )


@pytest.mark.parametrize(
    "rows",
    [
        "alpha-42-old-002c",
        "beta-42-old-002c",
        ((),) * 6,
        ((0,), (), (0,), (), (), (255,)),
        (tuple(range(55)), (), (), (), (), ()),
        ((), (), (), (), (), tuple(range(201, 256))),
    ],
)
def test_encoding_semantics_via_independently_executed_steps(iteration_case, rows):
    if isinstance(rows, str):
        _, _, witness = auth_case(rows)
        encoded = witness.signature[3248:]
        rows = tuple(
            tuple(i for i, value in enumerate(row) if value)
            for row in reference._decode_hints(encoded)
        )
        assert hint_encoding(rows) == encoded
    else:
        encoded = hint_encoding(rows)
    expected = reference._decode_hints(encoded)
    assert run(boundary_circuit(), encoded) == 1
    circuit, next_index, result = iteration_case
    index = 0
    reconstructed = []
    for row in rows:
        first, end = index, index + len(row)
        polynomial = [0] * 256
        # Evaluate actual populated steps plus a terminated step. Full 6*55
        # unrolling is tested as a clean resource non-completion separately.
        for _ in range(len(row) + 1):
            raw = step_raw(encoded, index, first, end, polynomial)
            assert run(circuit, raw) == 1
            values, _, _ = observed(circuit, raw, words=(next_index, *result))
            index, *polynomial = values
        reconstructed.append(polynomial)
    assert reconstructed == expected
    assert index == sum(map(len, rows))


@pytest.mark.parametrize(
    "positions,index,first,end,valid",
    [
        ([0, 1], 1, 0, 2, 1),
        ([255, 255], 1, 0, 2, 0),
        ([2, 1], 1, 0, 2, 0),
        ([0, 0], 1, 1, 2, 1),
        ([255], 0, 0, 1, 1),
        ([0], 0, 0, 1, 1),
        ([2, 1], 1, 0, 1, 1),
        ([0], 61, 61, 62, 0),
        ([0], -1, -1, 1, 0),
    ],
)
def test_ordering_first_position_inactive_and_invalid_reads(
    iteration_case, positions, index, first, end, valid
):
    encoded = bytes(positions).ljust(55, b"\0") + bytes(6)
    circuit, after, polynomial = iteration_case
    before = [0] * 256
    before[42] = 1
    raw = step_raw(encoded, index, first, end, before)
    assert run(circuit, raw) == valid
    values, _, _ = observed(circuit, raw, words=(after, *polynomial))
    if (not valid and 0 <= index < 61) or index >= end:
        assert values == (index, *before)  # Failed/terminated source returns do not write.


@pytest.mark.parametrize(
    "end,bad_position,valid",
    [
        (0, None, 1),
        (55, None, 1),
        (1, 0, 1),
        (55, 54, 1),
        (0, 0, 0),
        (0, 54, 0),
        (1, 1, 0),
        (54, 54, 0),
    ],
)
def test_unused_byte_check_uses_private_counter(end, bad_position, valid):
    e = Emitter(61 * 8, limits=extended_limits())
    scope = Scope(e)
    cells = _hint_cells(e, e.inputs)
    _hint_padding(scope, cells, _unsigned(e, cells[-1]))
    circuit = e.finish(scope.output(()))
    raw = bytearray(55) + bytearray([end] * 6)
    if bad_position is not None:
        raw[bad_position] = 17
    assert run(circuit, bytes(raw)) == valid


def test_first_step_true_branch_order_and_private_scans(monkeypatch):
    calls = []
    read, write = Scope.read, Scope.write

    def record_read(self, cells, index):
        calls.append(("read", len(cells), len(index)))
        return read(self, cells, index)

    def record_write(self, cells, index, value):
        calls.append(("write", len(cells), len(index), len(value)))
        return write(self, cells, index, value)

    monkeypatch.setattr(Scope, "read", record_read)
    monkeypatch.setattr(Scope, "write", record_write)
    e = Emitter(488, limits=extended_limits())
    scope = Scope(e)
    cells = _hint_cells(e, e.inputs)
    index = w.constant(e, 0, 64)
    end = _hint_boundary(scope, cells, index, 0)
    _hint_iteration(
        scope, cells, index, index, end, tuple(w.constant(e, 0, 64) for _ in range(256))
    )
    assert calls == [("read", 61, 64)] * 3 + [("write", 256, 64, 64)]


@pytest.mark.parametrize("decoder,nbytes", [(decode_hints, 61), (decode_signature, 3309)])
def test_complete_decoders_stop_at_authorised_gate_limit(decoder, nbytes):
    e = Emitter(nbytes * 8, limits=extended_limits(), mode="count")
    with pytest.raises(ResourceLimit, match="gate-count limit") as failure:
        decoder(Scope(e), e.inputs)
    assert failure.value.progress["complete"] is False
    assert e.counts.gates == 2_000_000


def test_byte_width_and_foreign_wire_errors_are_api_errors():
    e = Emitter(8, limits=extended_limits())
    with pytest.raises(ValueError):
        decode_responses(Scope(e), e.inputs)
    with pytest.raises(ValueError):
        decode_hints(Scope(e), e.inputs)
    with pytest.raises(ValueError):
        unpack_unsigned(e, e.inputs, 19)
    with pytest.raises(ValueError):
        response_norm(Scope(e), ())
