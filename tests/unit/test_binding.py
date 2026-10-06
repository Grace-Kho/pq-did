"""R-020/R-023 consistency subset; all fixture secrets here are synthetic/public."""

from dataclasses import fields, replace

import pytest

from pqdid.binding import (
    BindingRepresentation,
    check_binding_consistency,
    create_binding,
    decode_binding,
    encode_binding,
    encode_holder_input,
    holder_binding_value,
)
from pqdid.codec import EncodingError, decode_record, encode_record
from pqdid.schema import decode_attributes, encode_attributes

from .binding_merkle_cases import DOMAINS, FIXTURE, domain

# Intentionally published synthetic test material, never a real holder secret.
SYNTHETIC_SECRET = bytes.fromhex(FIXTURE["binding"]["synthetic_public_test_secret_hex"])
ATTRIBUTES = bytes.fromhex(FIXTURE["binding"]["encoded_attributes_hex"])
BINDING_BYTES = bytes.fromhex(FIXTURE["binding"]["binding_encoding_hex"])


@pytest.mark.parametrize("name", DOMAINS)
def test_fixed_holder_inputs_and_digests(name):
    instance = domain(name)
    assert encode_holder_input(instance, SYNTHETIC_SECRET) == bytes.fromhex(
        DOMAINS[name]["holder_input_hex"]
    )
    assert holder_binding_value(instance, SYNTHETIC_SECRET) == bytes.fromhex(
        DOMAINS[name]["holder_value_hex"]
    )
    fields = decode_record(encode_holder_input(instance, SYNTHETIC_SECRET), "holder")
    assert fields == (
        instance.suite,
        bytes.fromhex(DOMAINS[name]["metadata_hex"]),
        SYNTHETIC_SECRET,
    )


def test_fixed_complete_binding_and_attribute_encoding(attributes):
    instance = domain()
    assert encode_attributes(instance.schema, attributes) == ATTRIBUTES
    binding = create_binding(instance, SYNTHETIC_SECRET, ATTRIBUTES)
    assert binding.holder_value == bytes.fromhex(DOMAINS["primary"]["holder_value_hex"])
    assert len(binding.holder_value) == 48
    assert binding.attributes == ATTRIBUTES
    assert encode_binding(instance, binding) == BINDING_BYTES
    assert decode_binding(instance, BINDING_BYTES) == binding
    assert check_binding_consistency(instance, binding, SYNTHETIC_SECRET, ATTRIBUTES)
    assert len(BINDING_BYTES) == 1095  # Tagged pair, not the 48-byte Y.


def test_wrong_secret_and_altered_attributes():
    instance = domain()
    binding = decode_binding(instance, BINDING_BYTES)
    assert not check_binding_consistency(instance, binding, b"\xff" * 32, ATTRIBUTES)
    values = list(decode_attributes(instance.schema, ATTRIBUTES))
    values[2] = False
    altered = encode_attributes(instance.schema, values)
    assert not check_binding_consistency(instance, binding, SYNTHETIC_SECRET, altered)
    changed_binding = create_binding(instance, SYNTHETIC_SECRET, altered)
    assert changed_binding.holder_value == binding.holder_value  # Y does not contain m.
    assert changed_binding != binding
    assert not check_binding_consistency(instance, changed_binding, SYNTHETIC_SECRET, ATTRIBUTES)
    # Anyone with these private inputs can make a different consistent B. This
    # is not evidence that an issuer certified the changed attributes.
    assert check_binding_consistency(instance, changed_binding, SYNTHETIC_SECRET, altered)


def test_altered_binding_bytes():
    instance = domain()
    holder, attributes = decode_record(BINDING_BYTES, "binding")
    altered_holder = bytes([holder[0] ^ 1]) + holder[1:]
    encoded = encode_record("binding", (altered_holder, attributes))
    assert not check_binding_consistency(
        instance, decode_binding(instance, encoded), SYNTHETIC_SECRET, ATTRIBUTES
    )


@pytest.mark.parametrize("name", [name for name in DOMAINS if name != "primary"])
def test_wrong_instance_does_not_open_binding(name):
    instance = domain(name)
    binding = decode_binding(instance, BINDING_BYTES)
    # Parsing B is not proof of which instance it belongs to; check its opening.
    assert not check_binding_consistency(instance, binding, SYNTHETIC_SECRET, ATTRIBUTES)


@pytest.mark.parametrize("secret", [b"", bytes(31), bytes(33), bytearray(32), "x" * 32, 32, None])
def test_invalid_holder_secret(secret):
    instance = domain()
    binding = decode_binding(instance, BINDING_BYTES)
    for operation in [
        lambda: encode_holder_input(instance, secret),
        lambda: holder_binding_value(instance, secret),
        lambda: create_binding(instance, secret, ATTRIBUTES),
        lambda: check_binding_consistency(instance, binding, secret, ATTRIBUTES),
    ]:
        with pytest.raises(EncodingError):
            operation()


@pytest.mark.parametrize("length", [0, 47, 49])
def test_invalid_binding_hash_length(length):
    with pytest.raises(EncodingError):
        BindingRepresentation(bytes(length), ATTRIBUTES)
    with pytest.raises(EncodingError):
        decode_binding(domain(), encode_record("binding", (bytes(length), ATTRIBUTES)))


@pytest.mark.parametrize("encoded", [b"", bytes(1023), bytes(1025), bytearray(1024), "x" * 1024])
def test_invalid_binding_attribute_representation(encoded):
    instance = domain()
    with pytest.raises(EncodingError):
        create_binding(instance, SYNTHETIC_SECRET, encoded)
    with pytest.raises(EncodingError):
        check_binding_consistency(
            instance, decode_binding(instance, BINDING_BYTES), SYNTHETIC_SECRET, encoded
        )


def test_reject_noncanonical_attributes_inside_binding():
    instance = domain()
    binding = decode_binding(instance, BINDING_BYTES)
    # Non-zero tail padding; and invalid Boolean at its own field position.
    boolean_offset = 2 + 171 + 2 + 56
    mutations = [
        ATTRIBUTES[:-1] + b"\1",
        ATTRIBUTES[: boolean_offset + 2] + b"\2" + ATTRIBUTES[boolean_offset + 3 :],
    ]
    for attributes in mutations:
        invalid = replace(binding, attributes=attributes)
        with pytest.raises(EncodingError):
            encode_binding(instance, invalid)
        with pytest.raises(EncodingError):
            decode_binding(instance, encode_record("binding", (binding.holder_value, attributes)))
        with pytest.raises(EncodingError):
            create_binding(instance, SYNTHETIC_SECRET, attributes)
        with pytest.raises(EncodingError):
            check_binding_consistency(instance, binding, SYNTHETIC_SECRET, attributes)


def test_reject_binding_tag_count_truncation_and_trailing_bytes():
    instance = domain()
    invalid = [
        BINDING_BYTES[:-1],
        BINDING_BYTES + b"\0",
        b"",
        encode_record("certificate", (bytes(48), ATTRIBUTES)),
    ]
    # binding tag has 7 bytes: count follows its 4-byte LP plus those 7 bytes.
    invalid.append(BINDING_BYTES[:11] + b"\0\0\0\3" + BINDING_BYTES[15:])
    for encoded in invalid:
        with pytest.raises(EncodingError):
            decode_binding(instance, encoded)
    with pytest.raises(EncodingError):
        encode_binding(instance, BINDING_BYTES)
    with pytest.raises(EncodingError):
        create_binding(None, SYNTHETIC_SECRET, ATTRIBUTES)


def test_private_input_handling_does_not_print_or_store_secret(capsys):
    instance = domain()
    binding = create_binding(instance, SYNTHETIC_SECRET, ATTRIBUTES)
    assert check_binding_consistency(instance, binding, SYNTHETIC_SECRET, ATTRIBUTES)
    assert {f.name for f in fields(binding)} == {"holder_value", "attributes"}
    assert "did:pqdid:" not in repr(binding)
    with pytest.raises(EncodingError) as failure:
        holder_binding_value(instance, b"synthetic-sensitive-invalid-input")
    assert "synthetic-sensitive" not in str(failure.value)
    assert capsys.readouterr() == ("", "")
