"""R-001/R-005 hash-domain subset; validation does not authorise an issuer."""

import pytest

from pqdid.codec import EncodingError, decode_record, encode_record
from pqdid.hash_domain import HashDomain, encode_metadata
from pqdid.schema import encode_schema

from .binding_merkle_cases import DOMAINS, domain


@pytest.mark.parametrize("name", DOMAINS)
def test_fixed_metadata_and_schema(name):
    instance = domain(name)
    assert encode_metadata(instance) == bytes.fromhex(DOMAINS[name]["metadata_hex"])
    assert encode_schema(instance.schema) == decode_record(instance.issuer_reference, "iref")[2]


@pytest.mark.parametrize("suite", [b"PQ-DID-MITH-2", b"pq-did-mith-1", b"", "PQ-DID-MITH-1", None])
def test_reject_wrong_suite(suite):
    instance = domain()
    with pytest.raises(EncodingError):
        HashDomain(suite, instance.issuer_reference, instance.namespace)


@pytest.mark.parametrize("namespace", [b"", bytes(31), bytes(33), bytearray(32), "x" * 32])
def test_reject_namespace_domain(namespace):
    instance = domain()
    with pytest.raises(EncodingError):
        HashDomain(instance.suite, instance.issuer_reference, namespace)


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("length", [0, 1, 256, 257])
def test_issuer_key_identifier_bounds(index, length):
    instance = domain()
    fields = list(decode_record(instance.issuer_reference, "iref"))
    fields[index] = b"x" * length
    encoded = encode_record("iref", fields)
    if length in (1, 256):
        assert HashDomain(instance.suite, encoded, instance.namespace).issuer_reference == encoded
    else:
        with pytest.raises(EncodingError):
            HashDomain(instance.suite, encoded, instance.namespace)


def test_reject_malformed_reference_and_schema():
    instance = domain()
    issuer, key, schema = decode_record(instance.issuer_reference, "iref")
    bad = [
        instance.issuer_reference[:-1],
        instance.issuer_reference + b"\0",
        encode_record("meta", (issuer, key)),
        encode_record("iref", (issuer, key, schema + b"\0")),
        encode_record("iref", (issuer, key, b"")),
        encode_record("iref", (issuer, key, encode_record("schema", (b"\2",) * 5))),
    ]
    for encoded in bad:
        with pytest.raises(EncodingError):
            HashDomain(instance.suite, encoded, instance.namespace)
    with pytest.raises(EncodingError):
        encode_metadata(None)
