"""Independent statement bytes, fixed witness layout and strict nested domains."""

import hashlib
import inspect
import json
from dataclasses import FrozenInstanceError, fields, replace

import pytest

from pqdid.codec import EncodingError, decode_record, encode_record
from pqdid.parameters import decode_instance_metadata
from pqdid.policy import Equality, Policy, Range
from pqdid.statements import (
    AuthenticationStatement,
    build_state_message,
    decode_auth_statement,
    decode_context,
    decode_enrol_statement,
    decode_state,
    decode_state_reference,
    encode_auth_statement,
    encode_context,
    encode_enrol_statement,
    encode_state,
    encode_state_reference,
    validate_auth_statement,
)
from pqdid.witnesses import (
    AUTH_FIELD_WIDTHS,
    AUTH_WITNESS_BITS,
    AUTH_WITNESS_BYTES,
    ENROL_WITNESS_BITS,
    ENROL_WITNESS_BYTES,
    AuthenticationWitness,
    decode_auth_witness,
    decode_enrol_witness,
    encode_auth_witness,
    encode_enrol_witness,
    witness_bits,
)

from .binding_merkle_reference import SparseReferenceTree
from .relation_cases import CREDENTIALS, FIXTURE, INSTANCES, ROOT, auth_case, enrol_case, parameters


def test_provenance_and_independent_tree_expectations():
    provenance = FIXTURE["provenance"]
    for filename, key in [
        (provenance["generator"], "generator_sha256"),
        ("tests/unit/binding_merkle_reference.py", "tree_builder_sha256"),
        ("tests/fixtures/binding_merkle_vectors.json", "prior_fixture_sha256"),
    ]:
        assert hashlib.sha256((ROOT / filename).read_bytes()).hexdigest() == provenance[key]
    assert provenance["native_dependencies"] == json.loads(
        (ROOT / "native/dependencies.json").read_text()
    )
    assert not provenance["bounded_keygen_or_signing"]
    assert not provenance["relation_filtering_or_retry"]
    assert not provenance["signing_secrets_saved"]
    source = (ROOT / provenance["generator"]).read_text()
    assert "pqdid.relations" not in source and "pqdid.statements" not in source
    for instance in INSTANCES.values():
        pp = parameters(instance["name"])
        meta = bytes.fromhex(instance["metadata"])
        for item in instance["states"].values():
            tree = SparseReferenceTree(pp.suite, meta, item["revoked"])
            assert tree.root.hex() == item["root"]
            for rid, path in item["paths"].items():
                assert tree.path(int(rid)).hex() == path
    for case in FIXTURE["authentication"]:
        credential = CREDENTIALS[case["credential"]]
        state = INSTANCES[credential["instance"]]["states"][case["tree"]]
        assert case["expected"] == (credential["rid"] not in state["revoked"])


@pytest.mark.parametrize("item", FIXTURE["authentication"], ids=lambda item: item["name"])
def test_independently_encoded_authentication(item):
    pp, statement, witness = auth_case(item["name"])
    assert encode_auth_statement(pp, statement).hex() == item["statement"]
    assert encode_auth_witness(pp.schema, witness).hex() == item["witness"]
    assert encode_context(pp, statement.context).hex() == item["context"]
    assert statement.disclosed == tuple(item["disclosed"])
    assert statement.disclosed_attributes.hex() == item["disclosed_attributes"]


@pytest.mark.parametrize("item", FIXTURE["enrolment"], ids=lambda item: item["credential"])
def test_independently_encoded_enrolment(item):
    pp, statement, witness = enrol_case(item["credential"])
    assert encode_enrol_statement(pp, statement).hex() == item["statement"]
    assert encode_enrol_witness(witness).hex() == item["witness"]


def test_witness_sizes_offsets_and_msb_first_bits():
    manifest = json.loads((ROOT / "configs/suite.json").read_text())["confirmed"]["relation"]
    assert AUTH_FIELD_WIDTHS == tuple(item["bytes"] for item in manifest["auth_witness_fields"])
    assert AUTH_WITNESS_BYTES == sum(AUTH_FIELD_WIDTHS) == 5329
    assert AUTH_WITNESS_BITS == 8 * AUTH_WITNESS_BYTES == 42632
    assert (
        ENROL_WITNESS_BYTES == sum(item["bytes"] for item in manifest["enrol_witness_fields"]) == 32
    )
    assert ENROL_WITNESS_BITS == 8 * ENROL_WITNESS_BYTES == 256
    pp, _, witness = auth_case()
    raw = encode_auth_witness(pp.schema, witness)
    assert raw[:32] == witness.holder_secret
    assert raw[32:1056] == witness.attributes
    assert raw[1056:1060] == b"\x00\x00\x00\x2a"
    assert raw[1060:4369] == witness.signature
    assert raw[4369:] == witness.path
    bits = witness_bits(raw)
    assert len(bits) == 42632
    assert (
        bytes(sum(bits[i + j] << (7 - j) for j in range(8)) for i in range(0, len(bits), 8)) == raw
    )
    assert witness_bits(b"\x81" + bytes(31))[:8] == (1, 0, 0, 0, 0, 0, 0, 1)
    assert [f.name for f in fields(AuthenticationWitness)] == [
        "holder_secret",
        "attributes",
        "revocation_identifier",
        "signature",
        "path",
    ]


def test_all_witness_truncations_and_extra_bytes_reject():
    pp, _, witness = auth_case()
    raw = encode_auth_witness(pp.schema, witness)
    for length in range(len(raw)):
        with pytest.raises(EncodingError):
            decode_auth_witness(pp.schema, raw[:length])
    for raw_enrol in (b"", bytes(31), bytes(33)):
        with pytest.raises(EncodingError):
            decode_enrol_witness(raw_enrol)
    with pytest.raises(EncodingError):
        decode_auth_witness(pp.schema, raw + b"\x00")
    with pytest.raises(EncodingError):
        witness_bits(bytes(33))


@pytest.mark.parametrize("value", [None, b"", bytearray(32), memoryview(bytes(32)), "x"])
def test_witness_immutable_byte_domains(value):
    with pytest.raises(EncodingError):
        decode_enrol_witness(value)
    with pytest.raises(EncodingError):
        decode_auth_witness(parameters().schema, value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("holder_secret", bytes(31)),
        ("holder_secret", bytearray(32)),
        ("attributes", bytes(1023)),
        ("signature", bytes(3308)),
        ("path", bytes(959)),
        ("path", bytes(961)),
        ("revocation_identifier", -1),
        ("revocation_identifier", 1 << 20),
        ("revocation_identifier", True),
    ],
)
def test_witness_record_domains(field, value):
    pp, _, witness = auth_case()
    with pytest.raises(EncodingError):
        encode_auth_witness(pp.schema, replace(witness, **{field: value}))


@pytest.mark.parametrize("offset,value", [(32 + 172, 1), (32 + 258, 1), (32 + 233, 2), (1056, 1)])
def test_private_padding_boolean_and_high_identifier_bits(offset, value):
    pp, _, witness = auth_case()
    raw = bytearray(encode_auth_witness(pp.schema, witness))
    # DID is full capacity, so use its two-byte length to create non-zero field padding.
    if offset == 32 + 172:
        raw[32:34] = (170).to_bytes(2, "big")
    raw[offset] = value
    with pytest.raises(EncodingError):
        decode_auth_witness(pp.schema, bytes(raw))


@pytest.mark.parametrize("instance", ["alpha", "beta"])
@pytest.mark.parametrize("tree", ["empty", "old", "updated"])
def test_independent_state_and_signed_body(instance, tree):
    pp = parameters(instance)
    item = INSTANCES[instance]["states"][tree]
    state = decode_state(pp, bytes.fromhex(item["encoded"]))
    assert encode_state(pp, state).hex() == item["encoded"]
    assert build_state_message(pp, state).hex() == item["message"]
    reference = encode_state_reference(pp, state.reference)
    assert decode_state_reference(pp, reference) == state.reference
    assert state.signature not in build_state_message(pp, state)


@pytest.mark.parametrize(
    "field,value",
    [
        ("audience", b""),
        ("audience", bytes(257)),
        ("session", b""),
        ("session", bytes(257)),
        ("nonce", bytes(31)),
        ("nonce", bytes(33)),
        ("expires_at", -1),
        ("expires_at", 1 << 64),
        ("expires_at", True),
        ("suite", b"unsupported"),
        ("issuer_reference", b"invalid"),
        ("policy", Policy((3,), (Equality(4, 3),))),
        ("policy", Policy((3,), (Range(3, 0, 1),))),
        ("policy", Policy((4,), (Range(4, 4, 2),))),
        ("policy", Policy((3,), (Equality(3, True), Equality(3, True)))),
    ],
)
def test_context_domains_reject_without_repair(field, value):
    pp, statement, _ = auth_case()
    with pytest.raises(EncodingError):
        encode_context(pp, replace(statement.context, **{field: value}))


@pytest.mark.parametrize(
    "field,value",
    [
        ("epoch", -1),
        ("epoch", 1 << 64),
        ("epoch", True),
        ("root", bytes(47)),
        ("namespace", bytes(31)),
        ("namespace", bytes(32)),
        ("signature", bytes(3308)),
    ],
)
def test_state_domains(field, value):
    pp, statement, _ = auth_case()
    with pytest.raises(EncodingError):
        encode_state(pp, replace(statement.state, **{field: value}))


def test_full_uint64_epoch_expiry_and_identifier_boundaries():
    pp, statement, _ = auth_case()
    state = replace(statement.state, epoch=(1 << 64) - 1)
    assert decode_state(pp, encode_state(pp, state)) == state
    for expiry in (0, (1 << 64) - 1):
        context = replace(
            statement.context, audience=bytes(256), session=bytes(256), expires_at=expiry
        )
        assert decode_context(pp, encode_context(pp, context)) == context
    pp, statement, _ = enrol_case()
    for rid in (0, (1 << 20) - 1):
        candidate = replace(statement, revocation_identifier=rid)
        assert decode_enrol_statement(pp, encode_enrol_statement(pp, candidate)) == candidate


@pytest.mark.parametrize("kind", ["auth", "enrol", "context", "state", "reference"])
def test_public_framing_and_nested_byte_widths(kind):
    pp, auth, _ = auth_case()
    _, enrol, _ = enrol_case()
    encoder, decoder, value, tag = {
        "auth": (encode_auth_statement, decode_auth_statement, auth, "auth-statement"),
        "enrol": (encode_enrol_statement, decode_enrol_statement, enrol, "enrol-statement"),
        "context": (encode_context, decode_context, auth.context, "context"),
        "state": (encode_state, decode_state, auth.state, "rstate"),
        "reference": (encode_state_reference, decode_state_reference, auth.state.reference, "rref"),
    }[kind]
    raw = encoder(pp, value)
    for damaged in (raw[:-1], raw + b"\x00", b"\xff" * 4 + raw[4:], raw[:8] + b"!" + raw[9:]):
        with pytest.raises(EncodingError):
            decoder(pp, damaged)
    parts = decode_record(raw, tag)
    for i, part in enumerate(parts):
        if kind == "context" and i in (1, 2):
            changed = encode_record(tag, (*parts[:i], part + b"\x00", *parts[i + 1 :]))
            assert encoder(pp, decoder(pp, changed)) == changed != raw
            continue  # Audience/session are variable-length opaque identifiers.
        with pytest.raises(EncodingError):
            decoder(pp, encode_record(tag, (*parts[:i], part + b"\x00", *parts[i + 1 :])))


def test_repeated_metadata_parameters_mask_and_state_must_match():
    pp, statement, _ = auth_case()
    other = parameters("beta")
    candidates = [
        replace(statement, parameters=other),
        replace(statement, metadata=other.metadata),
        replace(statement, disclosed=(3,)),
        replace(statement, disclosed=[3, 4, 6]),
        replace(statement, disclosed=(7,)),
        replace(
            statement,
            context=replace(
                statement.context, state_reference=replace(statement.state.reference, epoch=8)
            ),
        ),
    ]
    for candidate in candidates:
        with pytest.raises(EncodingError):
            validate_auth_statement(pp, candidate)
    with pytest.raises(EncodingError):
        decode_auth_statement(other, encode_auth_statement(pp, statement))
    with pytest.raises(EncodingError):
        decode_instance_metadata(pp, bytes.fromhex(INSTANCES["beta"]["metadata"]))


def test_frozen_records_and_no_extra_hidden_public_fields():
    _, statement, witness = auth_case()
    with pytest.raises(FrozenInstanceError):
        witness.path = b""
    with pytest.raises(FrozenInstanceError):
        statement.disclosed = ()
    assert "holder_secret" not in repr(witness)
    assert [f.name for f in fields(AuthenticationStatement)] == [
        "parameters",
        "metadata",
        "context",
        "state",
        "disclosed",
        "disclosed_attributes",
    ]
    assert list(inspect.signature(decode_auth_witness).parameters) == ["schema", "encoded"]
