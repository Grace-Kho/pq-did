"""Structural fixtures only: the signature-shaped bytes are NOT authentic."""

import json
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path

import pytest

from pqdid.binding import decode_binding
from pqdid.codec import EncodingError, decode_record, encode_record
from pqdid.credentials import (
    CREDENTIAL_SIGNING_CONTEXT,
    Certificate,
    Credential,
    build_mcred,
    decode_certificate,
    decode_credential,
    encode_certificate,
    encode_credential,
    validate_certificate_structure,
    validate_credential_structure,
)
from pqdid.merkle import verify_non_revocation_path
from pqdid.parameters import (
    InstanceMetadata,
    PublicParameters,
    decode_instance_metadata,
    decode_parameters,
    encode_instance_metadata,
    encode_parameters,
    validate_metadata_structure,
    validate_parameters_structure,
)
from pqdid.schema import decode_schema

from .binding_merkle_cases import FIXTURE as BINDING_FIXTURE
from .binding_merkle_cases import domain, path, root
from .credentials_reference import build_fixture, record

FIXTURE = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "credentials_vectors.json").read_text()
)
ENC = {name: bytes.fromhex(value) for name, value in FIXTURE["encodings"].items()}
VARIANTS = {name: bytes.fromhex(value) for name, value in FIXTURE["mcred_variants"].items()}


def parameters(name="primary"):
    instance = domain(name)
    return PublicParameters(
        instance.suite,
        instance.issuer_reference,
        instance.namespace,
        ENC["issuer_public_key"],
        ENC["revocation_public_key"],
        instance.schema,
    )


@pytest.fixture
def pp():
    return parameters()


@pytest.fixture
def credential(pp):
    binding = decode_binding(
        pp.domain, bytes.fromhex(BINDING_FIXTURE["binding"]["binding_encoding_hex"])
    )
    return Credential(
        Certificate(binding, ENC["signature"]), binding.attributes, 42, b"", pp.metadata
    )


def message(pp, credential):
    validate_credential_structure(pp, credential)
    return build_mcred(
        pp, credential.metadata, credential.certificate.binding, credential.revocation_identifier
    )


def test_independent_fixture_provenance():
    assert FIXTURE == build_fixture()
    assert FIXTURE["synthetic_only"] and not FIXTURE["authentic_signature"]


def test_fixed_encodings_and_round_trips(pp, credential):
    assert encode_parameters(pp) == ENC["parameters"]
    assert decode_parameters(ENC["parameters"], expected=pp) == pp
    assert encode_instance_metadata(pp, pp.metadata) == ENC["metadata"]
    assert decode_instance_metadata(pp, ENC["metadata"]) == pp.metadata
    assert encode_certificate(pp, credential.certificate) == ENC["certificate"]
    assert decode_certificate(pp, ENC["certificate"]) == credential.certificate
    assert encode_credential(pp, credential) == ENC["credential"]
    assert decode_credential(pp, ENC["credential"]) == credential
    assert validate_parameters_structure(pp, expected=pp) is None
    assert validate_metadata_structure(pp, credential.metadata) is None
    assert validate_certificate_structure(pp, credential.certificate) is None
    assert validate_credential_structure(pp, credential) is None


def test_fixed_message_before_signing_and_after_parsing(pp, credential):
    assert build_mcred(pp, pp.metadata, credential.certificate.binding, 42) == ENC["mcred"]
    assert message(pp, decode_credential(pp, ENC["credential"])) == ENC["mcred"]
    assert decode_record(ENC["mcred"], "cred") == (
        b"PQ-DID-MITH-1",
        ENC["metadata"],
        bytes.fromhex(BINDING_FIXTURE["binding"]["binding_encoding_hex"]),
        b"\x00\x00\x00\x2a",
    )
    assert CREDENTIAL_SIGNING_CONTEXT == b"PQ-DID/credential/v1"
    assert CREDENTIAL_SIGNING_CONTEXT not in ENC["mcred"]


@pytest.mark.parametrize("kind", ["parameters", "metadata", "certificate", "credential"])
@pytest.mark.parametrize("damage", ["tag", "count", "length", "truncate", "trailing", "double"])
def test_bad_outer_framing(pp, kind, damage):
    raw = ENC[kind]
    tag_length = int.from_bytes(raw[:4], "big")
    offset = 4 + tag_length
    mutations = {
        "tag": raw[:4] + b"!" + raw[5:],
        "count": raw[:offset] + bytes(4) + raw[offset + 4 :],
        "length": raw[: offset + 4] + b"\xff" * 4 + raw[offset + 8 :],
        "truncate": raw[:-1],
        "trailing": raw + b"\x00",
        "double": record(raw),
    }
    decoders = {
        "parameters": lambda value: decode_parameters(value, expected=pp),
        "metadata": lambda value: decode_instance_metadata(pp, value),
        "certificate": lambda value: decode_certificate(pp, value),
        "credential": lambda value: decode_credential(pp, value),
    }
    with pytest.raises(EncodingError):
        decoders[kind](mutations[damage])


@pytest.mark.parametrize("key", ["issuer_public_key", "revocation_public_key"])
@pytest.mark.parametrize(
    "value", [b"", bytes(1951), bytes(1953), bytes(1312), "x", bytearray(1952), None]
)
def test_bad_key_representations(pp, key, value):
    with pytest.raises(EncodingError):
        replace(pp, **{key: value})


@pytest.mark.parametrize("value", [b"", b"PQ-DID-MITH-2", b"ML-DSA-44", "PQ-DID-MITH-1"])
def test_unsupported_suite(pp, value):
    with pytest.raises(EncodingError):
        replace(pp, suite=value)


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("size", [0, 257])
def test_invalid_issuer_key_identifiers(pp, index, size):
    reference_fields = list(decode_record(pp.issuer_reference, "iref"))
    reference_fields[index] = b"i" * size
    with pytest.raises(EncodingError):
        replace(pp, issuer_reference=encode_record("iref", reference_fields))


@pytest.mark.parametrize("size", [1, 256])
def test_identifier_boundaries(pp, size):
    ref = encode_record("iref", (b"i" * size, b"k" * size, ENC["schema"]))
    candidate = replace(pp, issuer_reference=ref)
    assert decode_parameters(encode_parameters(candidate), expected=candidate) == candidate


@pytest.mark.parametrize("value", [b"", bytes(31), bytes(33), bytearray(32), "x"])
def test_invalid_namespace(pp, value):
    with pytest.raises(EncodingError):
        replace(pp, namespace=value)
    with pytest.raises(EncodingError):
        InstanceMetadata(pp.issuer_reference, value)


def test_repeated_schema_and_nested_structure(pp):
    with pytest.raises(EncodingError):
        replace(pp, schema=domain("other_schema").schema)
    for index, replacement in [
        (1, pp.issuer_reference + b"\x00"),
        (5, ENC["schema"] + b"\x00"),
        (5, b""),
        (3, bytes(1951)),
        (4, bytes(1953)),
    ]:
        values = list(decode_record(ENC["parameters"], "parameters"))
        values[index] = replacement
        with pytest.raises(EncodingError):
            decode_parameters(encode_record("parameters", values))


@pytest.mark.parametrize("other", ["other_issuer", "other_key", "other_namespace", "other_schema"])
def test_external_parameter_and_metadata_agreement(pp, credential, other):
    different = parameters(other)
    assert decode_parameters(encode_parameters(different)) == different
    with pytest.raises(EncodingError):
        decode_parameters(encode_parameters(different), expected=pp)
    with pytest.raises(EncodingError):
        validate_parameters_structure(different, expected=pp)
    with pytest.raises(EncodingError):
        decode_instance_metadata(pp, encode_instance_metadata(different, different.metadata))
    with pytest.raises(EncodingError):
        encode_credential(different, credential)
    with pytest.raises(EncodingError):
        decode_credential(different, ENC["credential"])
    with pytest.raises(EncodingError):
        build_mcred(pp, different.metadata, credential.certificate.binding, 42)


@pytest.mark.parametrize("key", ["issuer_public_key", "revocation_public_key"])
def test_key_pin_cannot_be_substituted_but_is_not_added_to_message(pp, credential, key):
    different = replace(pp, **{key: bytes(1952)})
    with pytest.raises(EncodingError):
        decode_parameters(encode_parameters(different), expected=pp)
    # pp keys enter later cryptographic verification, not the literal Mcred tuple.
    assert message(different, credential) == ENC["mcred"]


@pytest.mark.parametrize("value", [b"", bytes(3308), bytes(3310), "x", bytearray(3309), None])
def test_signature_representation(pp, credential, value):
    with pytest.raises(EncodingError):
        replace(credential.certificate, signature=value)
    if type(value) is bytes:
        binding, _ = decode_record(ENC["certificate"], "certificate")
        with pytest.raises(EncodingError):
            decode_certificate(pp, encode_record("certificate", (binding, value)))


@pytest.mark.parametrize("value", [-1, 1 << 20, 1 << 32, True, 42.0, "42"])
def test_identifier_out_of_range(pp, credential, value):
    with pytest.raises(EncodingError):
        replace(credential, revocation_identifier=value)
    with pytest.raises(EncodingError):
        build_mcred(pp, pp.metadata, credential.certificate.binding, value)


@pytest.mark.parametrize("identifier", [0, (1 << 20) - 1])
def test_valid_identifier_boundaries(pp, credential, identifier):
    candidate = replace(credential, revocation_identifier=identifier)
    assert decode_credential(pp, encode_credential(pp, candidate)) == candidate


@pytest.mark.parametrize("identifier", [b"", bytes(3), bytes(5), b"\x00\x10\x00\x00", b"\xff" * 4])
def test_identifier_wire_width_and_range(pp, identifier):
    values = list(decode_record(ENC["credential"], "credential"))
    values[2] = identifier
    with pytest.raises(EncodingError):
        decode_credential(pp, encode_record("credential", values))


@pytest.mark.parametrize("value", [b"\x00", b"opening", None, "", bytearray()])
def test_required_empty_auxiliary(pp, credential, value):
    with pytest.raises(EncodingError):
        replace(credential, auxiliary=value)
    if type(value) is bytes:
        values = list(decode_record(ENC["credential"], "credential"))
        values[3] = value
        with pytest.raises(EncodingError):
            decode_credential(pp, encode_record("credential", values))


@pytest.mark.parametrize(
    "damage",
    [
        "short_y",
        "long_y",
        "short_attrs",
        "field_padding",
        "tail_padding",
        "bool",
        "nested_tag",
        "nested_count",
        "nested_trailing",
    ],
)
def test_malformed_binding_inside_certificate(pp, credential, damage):
    binding = credential.certificate.binding
    attributes = bytearray(binding.attributes)
    # Shorten the 56-byte version payload to expose a non-zero padding byte.
    if damage == "field_padding":
        attributes[173:175] = b"\x00\x37"
        attributes[230] = 1
    if damage == "tail_padding":
        attributes[-1] = 1
    if damage == "bool":
        attributes[233] = 2
    y = binding.holder_value
    if damage == "short_y":
        y = y[:-1]
    if damage == "long_y":
        y += b"\x00"
    attrs = bytes(attributes[:-1] if damage == "short_attrs" else attributes)
    encoded = record(b"binding", y, attrs)
    if damage == "nested_tag":
        encoded = record(b"holder", y, attrs)
    if damage == "nested_count":
        encoded = record(b"binding", y, attrs, b"")
    if damage == "nested_trailing":
        encoded += b"\x00"
    with pytest.raises(EncodingError):
        decode_certificate(pp, record(b"certificate", encoded, ENC["signature"]))


def test_attribute_splice_and_canonical_attribute_domain(pp, credential):
    _, _, encoded_binding, _ = decode_record(VARIANTS["attributes"], "cred")
    different = decode_binding(pp.domain, encoded_binding).attributes
    with pytest.raises(EncodingError):
        replace(credential, attributes=different)
    values = list(decode_record(ENC["credential"], "credential"))
    values[1] = different
    with pytest.raises(EncodingError):
        decode_credential(pp, encode_record("credential", values))
    # Equal copies are insufficient if BOTH contain malformed canonical padding.
    bad = credential.attributes[:-1] + b"\x01"
    cert = replace(
        credential.certificate, binding=replace(credential.certificate.binding, attributes=bad)
    )
    candidate = replace(credential, certificate=cert, attributes=bad)
    for action in [
        lambda: validate_credential_structure(pp, candidate),
        lambda: encode_credential(pp, candidate),
        lambda: build_mcred(pp, pp.metadata, cert.binding, 42),
    ]:
        with pytest.raises(EncodingError):
            action()


@pytest.mark.parametrize("name", list(VARIANTS))
def test_each_signed_field_matches_independent_changed_message(pp, credential, name):
    binding = credential.certificate.binding
    identifier = 42
    if name == "rid":
        identifier = 43
    elif name == "holder":
        binding = replace(
            binding, holder_value=bytes([binding.holder_value[0] ^ 1]) + binding.holder_value[1:]
        )
    elif name == "attributes":
        attrs = bytearray(binding.attributes)
        attrs[246:248] = b"GB"
        binding = replace(binding, attributes=bytes(attrs))
    else:
        pp = parameters(name)
    actual = build_mcred(pp, pp.metadata, binding, identifier)
    assert actual == VARIANTS[name]
    assert actual != ENC["mcred"]


def test_signature_is_outside_its_message(pp, credential):
    candidate = replace(
        credential, certificate=replace(credential.certificate, signature=bytes(3309))
    )
    assert encode_credential(pp, candidate) != ENC["credential"]
    assert message(pp, candidate) == ENC["mcred"]


def test_presentation_and_witness_reuse(pp, credential):
    # A real change between independent old/updated tree fixtures for unrevoked rid 43.
    candidate = replace(credential, revocation_identifier=43)
    before = encode_credential(pp, candidate)
    original_message = message(pp, candidate)
    old_path, new_path = path("old", 43), path("updated", 43)
    assert old_path != new_path
    assert verify_non_revocation_path(pp.domain, 43, old_path, root("old"))
    assert verify_non_revocation_path(pp.domain, 43, new_path, root("updated"))
    # Canonical context framing, not authenticated/approved presentation fixtures.
    state_reference = encode_record("rref", (pp.namespace, (10).to_bytes(8, "big"), root("old")))
    contexts = tuple(
        encode_record(
            "context",
            (
                pp.suite,
                audience,
                b"session",
                bytes(32),
                encode_record("policy", (bytes(2),)),
                pp.issuer_reference,
                state_reference,
                (2000000000).to_bytes(8, "big"),
            ),
        )
        for audience in (b"audience-A", b"audience-B")
    )
    assert contexts[0] != contexts[1]
    # Vary ctx alone, witness alone, then both. No claim these combinations authenticate.
    for context in contexts:
        for witness in (old_path, new_path):
            local_presentation_inputs = (candidate, context, witness)
            assert message(pp, local_presentation_inputs[0]) == original_message == VARIANTS["rid"]
            assert encode_credential(pp, local_presentation_inputs[0]) == before
    assert [field.name for field in fields(Credential)] == [
        "certificate",
        "attributes",
        "revocation_identifier",
        "auxiliary",
        "metadata",
    ]


def test_immutable_records_and_private_repr(pp, credential):
    for instance, field, value in [
        (pp, "suite", b"bad"),
        (pp.metadata, "namespace", bytes(32)),
        (credential.certificate, "signature", bytes(3309)),
        (credential, "revocation_identifier", 0),
    ]:
        with pytest.raises(FrozenInstanceError):
            setattr(instance, field, value)
    assert "attributes=" not in repr(credential)
    assert "signature=" not in repr(credential.certificate)


@pytest.mark.parametrize("value", [None, {}, (), b""])
def test_wrong_record_types(pp, credential, value):
    for action in [
        lambda: validate_parameters_structure(value),
        lambda: (
            validate_parameters_structure(pp, expected=value)
            if value is not None
            else encode_parameters(value)
        ),
        lambda: validate_metadata_structure(pp, value),
        lambda: validate_certificate_structure(pp, value),
        lambda: validate_credential_structure(pp, value),
        lambda: Certificate(value, ENC["signature"]),
        lambda: replace(credential, certificate=value),
        lambda: replace(credential, metadata=value),
        lambda: replace(pp, schema=value),
    ]:
        with pytest.raises(EncodingError):
            action()


def test_manifest_constants_are_preserved(pp):
    manifest = json.loads(
        (Path(__file__).resolve().parents[2] / "configs" / "suite.json").read_text()
    )
    confirmed = manifest["confirmed"]
    assert pp.suite.decode() == confirmed["suite"]["identifier_ascii"]
    assert confirmed["suite"]["lambda"] == 128
    assert confirmed["suite"]["circuit_profile"] == "BC-1"
    assert len(pp.issuer_public_key) == confirmed["signature"]["public_key_bytes"]
    assert len(ENC["signature"]) == confirmed["signature"]["signature_bytes"]
    assert (
        CREDENTIAL_SIGNING_CONTEXT.decode()
        == confirmed["signature"]["external_contexts_ascii"]["credential"]
    )
    assert pp.schema == decode_schema(ENC["schema"])
