"""Generate NEW ordinary-native fixtures, never a bounded signer or verifier.

Only public data and labelled synthetic holder openings are saved. Fresh native
signing secrets stay in memory; no retry/filter based on the bounded verifier.
Existing fixtures cannot be overwritten. No imports of pqdid.bounded_mldsa.
"""

import argparse
import hashlib
import json
from pathlib import Path

from pqdid.backend import LIBRARY, load_backend
from pqdid.binding import create_binding
from pqdid.credentials import (
    CREDENTIAL_SIGNING_CONTEXT,
    Certificate,
    Credential,
    build_mcred,
    encode_credential,
)
from pqdid.parameters import PublicParameters, encode_parameters
from pqdid.schema import decode_schema

ROOT = Path(__file__).resolve().parents[2]


def generate() -> dict:
    native = load_backend()
    earlier_path = ROOT / "tests/fixtures/credentials_vectors.json"
    earlier = json.loads(earlier_path.read_text())
    binding_path = ROOT / "tests/fixtures/binding_merkle_vectors.json"
    binding = json.loads(binding_path.read_text())
    domains = {item["name"]: item for item in binding["domains"]}
    vectors = []
    credentials = []
    with (
        native.Signature("ML-DSA-65") as verifier,
        native.Signature("ML-DSA-65") as issuer,
        native.Signature("ML-DSA-65") as other_issuer,
        native.Signature("ML-DSA-65") as manager,
    ):
        issuer_key = issuer.generate_keypair()
        other_key = other_issuer.generate_keypair()
        manager_key = manager.generate_keypair()

        def sign_case(name, message, context, signer=issuer, key=issuer_key):
            signature = signer.sign_with_ctx_str(message, context)
            assert verifier.verify_with_ctx_str(message, signature, context, key)
            vectors.append(
                {
                    "name": name,
                    "public_key": key.hex(),
                    "message": message.hex(),
                    "signature": signature.hex(),
                    "context": context.hex(),
                    "valid": True,
                }
            )
            return signature

        cases = [(b"", b""), (b"binary\x00message\xff", CREDENTIAL_SIGNING_CONTEXT)]
        cases += [
            (bytes(i % 256 for i in range(size)), b"binary\x00context\xff")
            for size in (135, 136, 137, 167, 168, 169)
        ]
        cases += [(bytes(range(256)) * 8, bytes(range(255)))]
        for index, (message, context) in enumerate(cases):
            sign_case(f"native-{index}", message, context)

        for index, name in enumerate(("alpha-42", "alpha-43", "beta-42")):
            other = index == 2
            item = domains["other_issuer" if other else "primary"]
            parameters = PublicParameters(
                item["suite_ascii"].encode("ascii"),
                bytes.fromhex(item["issuer_reference_hex"]),
                bytes.fromhex(item["namespace_hex"]),
                other_key if other else issuer_key,
                manager_key,
                decode_schema(bytes.fromhex(earlier["encodings"]["schema"])),
            )
            # Deliberately public synthetic test openings, not real holder secrets.
            holder_secret = bytes((i + index) % 256 for i in range(32))
            attributes = bytearray.fromhex(binding["binding"]["encoded_attributes_hex"])
            if index == 1:
                attributes[246:248] = b"GB"
            attributes = bytes(attributes)
            representation = create_binding(parameters.domain, holder_secret, attributes)
            rid = 43 if index == 1 else 42
            message = build_mcred(parameters, parameters.metadata, representation, rid)
            signature = sign_case(
                name,
                message,
                CREDENTIAL_SIGNING_CONTEXT,
                other_issuer if other else issuer,
                parameters.issuer_public_key,
            )
            credential = Credential(
                Certificate(representation, signature), attributes, rid, b"", parameters.metadata
            )
            credentials.append(
                {
                    "name": name,
                    "parameters": encode_parameters(parameters).hex(),
                    "credential": encode_credential(parameters, credential).hex(),
                    "synthetic_public_holder_secret": holder_secret.hex(),
                }
            )
    return {
        "record_format": "pqdid-ordinary-native-mldsa65-fixtures-v1",
        "provenance": {
            "generator": "tests/reference/generate_mldsa65_fixtures.py",
            "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "source": "ordinary liboqs ML-DSA-65 signer and external-context verifier",
            "native_dependencies": json.loads((ROOT / "native/dependencies.json").read_text()),
            "installed_library_sha256": hashlib.sha256(LIBRARY.read_bytes()).hexdigest(),
            "earlier_credentials_fixture_sha256": hashlib.sha256(
                earlier_path.read_bytes()
            ).hexdigest(),
            "bounded_signing": False,
            "bounded_verifier_used_to_generate_or_filter": False,
            "standard_validation_vectors": False,
            "secret_signing_keys_saved": False,
        },
        "vectors": vectors,
        "credentials": credentials,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    # Reserve the destination before key generation; reject any existing fixture.
    with args.output.open("x") as output:
        json.dump(generate(), output, indent=2)
        output.write("\n")
