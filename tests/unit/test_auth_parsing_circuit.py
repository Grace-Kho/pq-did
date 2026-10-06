"""Private protocol parsing/disclosure, explicitly separate from signature validity."""

import io
from dataclasses import replace

import pytest

from pqdid.circuits.auth_parsing import compile_auth_parsing, parse_auth_witness
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import Emitter, Limits, ResourceLimit, evaluate
from pqdid.codec import EncodingError
from pqdid.public_checks import pub_ok, public_policy_ok
from pqdid.relations import auth_private
from pqdid.schema import AttributeField, Schema, decode_attributes, project_attributes
from pqdid.witnesses import decode_auth_witness, encode_auth_witness

from .auth_arithmetic_cases import extended_limits
from .relation_cases import FIXTURE, auth_case


def reference_parsing(pp, statement, raw):
    try:
        witness = decode_auth_witness(pp.schema, raw)
        return (
            project_attributes(pp.schema, witness.attributes, statement.disclosed)
            == statement.disclosed_attributes
        )
    except EncodingError:
        return False


def run(circuit, raw):
    return evaluate(circuit, raw, max_wires=2_065_538).output


@pytest.fixture(scope="module")
def parsed_case():
    pp, statement, witness = auth_case()
    raw = encode_auth_witness(pp.schema, witness)
    return pp, statement, raw, compile_auth_parsing(pp, statement, limits=extended_limits())


@pytest.mark.parametrize("name", [x["name"] for x in FIXTURE["authentication"]])
def test_existing_fixture_parsing_reference_and_fixed_input_count(name):
    pp, statement, witness = auth_case(name)
    raw = encode_auth_witness(pp.schema, witness)
    circuit = compile_auth_parsing(pp, statement, limits=extended_limits())
    assert circuit.counts.inputs == 42632 and len(raw) == 5329
    assert run(circuit, raw) == int(reference_parsing(pp, statement, raw)) == 1


def test_raw_wire_slices_keep_same_secret_attributes_signature_identifier_and_path():
    pp, _, _ = auth_case()
    e = Emitter(42632, limits=extended_limits())
    scope = Scope(e)
    parsed = parse_auth_witness(scope, pp.schema, e.inputs)
    fields = (
        parsed.holder_secret,
        parsed.attributes,
        parsed.identifier_bytes,
        parsed.signature,
        *(parsed.siblings),
    )
    assert tuple(bit for field in fields for bit in field) == e.inputs
    assert [len(x) // 8 for x in fields[:4]] == [32, 1024, 4, 3309]
    assert len(parsed.siblings) == 20 and all(len(x) == 384 for x in parsed.siblings)
    assert parsed.identifier[:32] == tuple(reversed(parsed.identifier_bytes))
    assert parsed.identifier[32:] == (e.zero,) * 32
    # No signature decoding circuit hides behind protocol-level parsing.
    signature_positions = {b.index for b in parsed.signature}
    assert len(signature_positions) == 3309 * 8


def test_private_attribute_malformations_do_not_change_construction(parsed_case):
    pp, statement, raw, circuit = parsed_case
    mutations = []
    offset = 32
    for field in pp.schema.fields:
        for length in (field.capacity + 1, 65535):
            mutations.append(raw[:offset] + length.to_bytes(2, "big") + raw[offset + 2 :])
        actual = int.from_bytes(raw[offset : offset + 2], "big")
        if field.type_code in (1, 2):
            for length in (0, actual - 1, actual + 1):
                mutations.append(raw[:offset] + length.to_bytes(2, "big") + raw[offset + 2 :])
        if field.type_code == 1:
            for value in (2, 128, 255):
                mutations.append(raw[: offset + 2] + bytes([value]) + raw[offset + 3 :])
        if actual < field.capacity:
            bad = bytearray(raw)
            bad[offset + 2 + actual] = 1
            mutations.append(bytes(bad))
        offset += 2 + field.capacity
    if pp.schema.used_bytes < 1024:
        for i in (32 + pp.schema.used_bytes, 1055):
            bad = bytearray(raw)
            bad[i] = 1
            mutations.append(bytes(bad))
    identity = circuit.fingerprint
    for bad in mutations:
        assert not reference_parsing(pp, statement, bad)
        assert run(circuit, bad) == 0
        assert circuit.fingerprint == identity
    assert run(circuit, raw) == 1


@pytest.mark.parametrize("identifier", [0, (1 << 20) - 1, 1 << 20, (1 << 32) - 1])
def test_identifier_endpoints_remain_private_checks(parsed_case, identifier):
    pp, statement, raw, circuit = parsed_case
    changed = raw[:1056] + identifier.to_bytes(4, "big") + raw[1060:]
    assert (
        run(circuit, changed)
        == int(reference_parsing(pp, statement, changed))
        == int(identifier < 1 << 20)
    )


@pytest.mark.parametrize("field", ["secret", "signature", "path", "hidden_attribute", "rid"])
def test_validly_encoded_changes_pass_parsing_but_not_full_private_relation(parsed_case, field):
    pp, statement, raw, circuit = parsed_case
    changed = bytearray(raw)
    if field == "secret":
        changed[:32] = bytes(32)
    elif field == "signature":
        changed[1060:4369] = bytes(3309)
    elif field == "path":
        changed[4369] ^= 1
    elif field == "rid":
        changed[1056:1060] = (999).to_bytes(4, "big")
    else:
        assert 1 not in statement.disclosed
        changed[34] ^= 1  # Opaque DID bytes: canonical encoding still valid.
    changed = bytes(changed)
    witness = decode_auth_witness(pp.schema, changed)
    assert reference_parsing(pp, statement, changed) and run(circuit, changed) == 1
    assert not auth_private(pp, statement, witness)


def test_disclosed_fields_compare_complete_certified_bytes(parsed_case):
    pp, statement, raw, circuit = parsed_case
    offset = 32
    for index, field in enumerate(pp.schema.fields, 1):
        if index in statement.disclosed:
            bad = bytearray(raw)
            bad[offset + 2] ^= 1
            # Keep canonical type representation; for Boolean flip 0<->1.
            decode_attributes(pp.schema, bytes(bad[32:1056]))
            assert run(circuit, bytes(bad)) == 0
            assert not reference_parsing(pp, statement, bytes(bad))
        offset += 2 + field.capacity


def test_public_disclosure_mutation_and_bad_mask_are_separate_boundaries(parsed_case):
    pp, statement, raw, _ = parsed_case
    disclosed = bytearray(statement.disclosed_attributes)
    disclosed[2] ^= 1
    changed = replace(statement, disclosed_attributes=bytes(disclosed))
    circuit = compile_auth_parsing(pp, changed, limits=extended_limits())
    assert run(circuit, raw) == 0
    for bad in (replace(statement, disclosed=(17,)), replace(statement, disclosed_attributes=b"")):
        with pytest.raises(EncodingError):
            compile_auth_parsing(pp, bad, limits=extended_limits())


def test_public_state_and_policy_not_moved_into_parser(parsed_case):
    pp, statement, raw, _ = parsed_case
    bad_signature = replace(statement, state=replace(statement.state, signature=bytes(3309)))
    assert not pub_ok(pp, bad_signature)
    circuit = compile_auth_parsing(pp, bad_signature, limits=extended_limits())
    assert run(circuit, raw) == 1
    assert public_policy_ok(pp, statement)


def test_empty_disclosure_and_uint64_max_are_supported(parsed_case):
    pp, statement, raw, _ = parsed_case
    from pqdid.policy import Policy

    empty = replace(
        statement,
        disclosed=(),
        disclosed_attributes=b"",
        context=replace(statement.context, policy=Policy((), ())),
    )
    circuit = compile_auth_parsing(pp, empty, limits=extended_limits())
    changed = bytearray(raw)
    offset = 32
    for field in pp.schema.fields:
        if field.type_code == 2:
            changed[offset + 2 : offset + 10] = b"\xff" * 8
        offset += 2 + field.capacity
    assert run(circuit, bytes(changed)) == 1
    assert reference_parsing(pp, empty, bytes(changed))


def test_fixed_witness_length_and_inactive_parser_faults(parsed_case):
    pp, _, raw, circuit = parsed_case
    for wrong in (raw[:-1], raw + b"\0"):
        with pytest.raises(ValueError, match="length"):
            run(circuit, wrong)
    e = Emitter(42632, limits=extended_limits())
    inactive = Scope(e, active=e.zero)
    parse_auth_witness(inactive, pp.schema, e.inputs)
    inactive_circuit = e.finish(inactive.output(()))
    assert run(inactive_circuit, bytes(5329)) == 1
    fresh = Emitter(42632, limits=extended_limits())
    with pytest.raises(ValueError):
        parse_auth_witness(Scope(fresh), pp.schema, fresh.inputs[:-8])


def test_schema_extreme_capacity_zero_capacity_and_padding():
    from pqdid.circuits.auth_parsing import parse_attributes
    from pqdid.schema import encode_attributes

    schema = Schema(
        (
            AttributeField("did", 0, 171),
            AttributeField("version", 0, 56),
            AttributeField("empty", 0, 0),
            AttributeField("full", 0, 789),
        ),
        1,
        2,
    )
    assert schema.used_bytes == 1024
    e = Emitter(8192, limits=extended_limits())
    scope = Scope(e)
    parse_attributes(scope, schema, e.inputs)
    circuit = e.finish(scope.output(()))
    for payload in (b"", b"x", b"x" * 789):
        raw = encode_attributes(schema, (b"", b"", b"", payload))
        assert run(circuit, raw) == 1
    malformed = bytearray(raw)
    malformed[231:233] = b"\0\1"  # zero-capacity field length
    assert run(circuit, bytes(malformed)) == 0


def test_parser_modes_budget_stability_and_resource_noncompletion(parsed_case):
    pp, statement, raw, material = parsed_case
    sink = io.BytesIO()
    for mode in ("count", "stream"):
        circuit = compile_auth_parsing(
            pp,
            statement,
            limits=extended_limits(),
            mode=mode,
            sink=sink if mode == "stream" else None,
        )
        assert circuit.counts == material.counts and circuit.fingerprint == material.fingerprint
    assert sink.getvalue() == material.serialised
    fresh = compile_auth_parsing(pp, statement, limits=extended_limits())
    assert fresh.serialised == material.serialised
    assert run(fresh, raw) == 1 and run(fresh, bytes(5329)) == 0
    with pytest.raises(ResourceLimit) as caught:
        compile_auth_parsing(pp, statement, limits=Limits(max_gates=3))
    assert not caught.value.progress["complete"]
