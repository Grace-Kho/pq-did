"""Independent VII-A.1/.5 framing; no production imports or real signatures.

Reuses the earlier fixed synthetic B/metadata bytes. All NEW expected encodings
are assembled with struct and literal fields, independently of pqdid codecs.
Run with --output NEW_FILE; existing fixtures cannot be overwritten.
"""

import argparse
import hashlib
import json
import struct
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def record(tag: bytes, *fields: bytes) -> bytes:
    return (
        struct.pack(">I", len(tag))
        + tag
        + struct.pack(">I", len(fields))
        + b"".join(struct.pack(">I", len(value)) + value for value in fields)
    )


def build_fixture() -> dict:
    earlier = json.loads((FIXTURES / "binding_merkle_vectors.json").read_text())
    binding_fixture = earlier["binding"]
    domains = {item["name"]: item for item in earlier["domains"]}
    primary = domains["primary"]
    suite = b"PQ-DID-MITH-1"
    reference = bytes.fromhex(primary["issuer_reference_hex"])
    namespace = bytes.fromhex(primary["namespace_hex"])
    metadata = bytes.fromhex(primary["metadata_hex"])
    holder = bytes.fromhex(primary["holder_value_hex"])
    attributes = bytes.fromhex(binding_fixture["encoded_attributes_hex"])
    binding = bytes.fromhex(binding_fixture["binding_encoding_hex"])
    descriptors = [
        record(
            b"field",
            f["name"].encode("ascii"),
            bytes([f["type"]]),
            struct.pack(">H", f["capacity"]),
        )
        for f in binding_fixture["schema_fields"]
    ]
    schema = record(b"schema", b"\x06", b"\x01", b"\x02", *descriptors)
    # Public deterministic patterns; neither key provenance nor signature validity is claimed.
    issuer_key = bytes(i % 256 for i in range(1952))
    revocation_key = bytes((i + 17) % 256 for i in range(1952))
    signature = bytes((i * 7 + 3) % 256 for i in range(3309))
    rid = b"\x00\x00\x00\x2a"
    parameters = record(
        b"parameters", suite, reference, namespace, issuer_key, revocation_key, schema
    )
    certificate = record(b"certificate", binding, signature)
    credential = record(b"credential", certificate, attributes, rid, b"", metadata)
    mcred = record(b"cred", suite, metadata, binding, rid)
    # Independently assemble signed-field variants, including coherent namespace/schema changes.
    variants = {}
    variants["rid"] = record(b"cred", suite, metadata, binding, b"\x00\x00\x00\x2b")
    other_holder = bytes([holder[0] ^ 1]) + holder[1:]
    variants["holder"] = record(
        b"cred", suite, metadata, record(b"binding", other_holder, attributes), rid
    )
    other_attributes = bytearray(attributes)
    # countryOfResidence payload: after DID(173), version(58), bool(3), uint64(10), length(2).
    other_attributes[246:248] = b"GB"
    variants["attributes"] = record(
        b"cred", suite, metadata, record(b"binding", holder, bytes(other_attributes)), rid
    )
    for name, item in domains.items():
        if name != "primary":
            variants[name] = record(
                b"cred", suite, bytes.fromhex(item["metadata_hex"]), binding, rid
            )
    values = {
        "schema": schema,
        "issuer_public_key": issuer_key,
        "revocation_public_key": revocation_key,
        "signature": signature,
        "parameters": parameters,
        "metadata": metadata,
        "certificate": certificate,
        "credential": credential,
        "mcred": mcred,
    }
    return {
        "record_format": "pqdid-synthetic-credential-structure-v1",
        "synthetic_only": True,
        "authentic_signature": False,
        "manuscript_sha256": earlier["manuscript_sha256"],
        "source": "VII opening and A.1, p. 14; VII-A.5, p. 15",
        "provenance": "Manual struct framing; earlier fixed B/metadata; no pqdid imports",
        "prior_fixture_sha256": hashlib.sha256(
            (FIXTURES / "binding_merkle_vectors.json").read_bytes()
        ).hexdigest(),
        "revocation_identifier": 42,
        "encodings": {name: value.hex() for name, value in values.items()},
        "lengths": {name: len(value) for name, value in values.items()},
        "mcred_variants": {name: value.hex() for name, value in variants.items()},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.output.open("x") as output:
        json.dump(build_fixture(), output, indent=2)
        output.write("\n")
