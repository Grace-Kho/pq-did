"""Ordinary native Mcred interoperability ONLY, not manuscript-bounded verification."""

import json
from dataclasses import replace
from pathlib import Path

from pqdid.backend import load_backend
from pqdid.credentials import (
    CREDENTIAL_SIGNING_CONTEXT,
    build_mcred,
    decode_credential,
    encode_credential,
)
from pqdid.parameters import decode_parameters


def test_uncapped_native_credential_message_and_external_context():
    fixture = json.loads(
        (Path(__file__).resolve().parents[1] / "fixtures" / "credentials_vectors.json").read_text()
    )
    encoded = {key: bytes.fromhex(value) for key, value in fixture["encodings"].items()}
    # Synthetic revocation key is unused by this credential-signature interoperability check.
    pp = decode_parameters(encoded["parameters"])
    candidate = decode_credential(pp, encoded["credential"])
    oqs = load_backend()
    with oqs.Signature("ML-DSA-65") as signer:
        pp = replace(pp, issuer_public_key=signer.generate_keypair())
        body = build_mcred(pp, candidate.metadata, candidate.certificate.binding, 42)
        signature = signer.sign_with_ctx_str(body, CREDENTIAL_SIGNING_CONTEXT)
    candidate = replace(candidate, certificate=replace(candidate.certificate, signature=signature))
    parsed = decode_credential(pp, encode_credential(pp, candidate))
    verification_body = build_mcred(
        pp, parsed.metadata, parsed.certificate.binding, parsed.revocation_identifier
    )
    assert verification_body == body == encoded["mcred"]
    with oqs.Signature("ML-DSA-65") as verifier:
        assert verifier.verify_with_ctx_str(
            body, signature, CREDENTIAL_SIGNING_CONTEXT, pp.issuer_public_key
        )
        for altered_body, context in [
            (body + b"!", CREDENTIAL_SIGNING_CONTEXT),
            (
                build_mcred(pp, parsed.metadata, parsed.certificate.binding, 43),
                CREDENTIAL_SIGNING_CONTEXT,
            ),
            (body, b"PQ-DID/cred/v1"),
            (body, b"PQ-DID/state/v1"),
            (body, b""),
            (CREDENTIAL_SIGNING_CONTEXT + body, b""),
        ]:
            assert not verifier.verify_with_ctx_str(
                altered_body, signature, context, pp.issuer_public_key
            )
        changed_signature = bytes([signature[0] ^ 1]) + signature[1:]
        assert not verifier.verify_with_ctx_str(
            body, changed_signature, CREDENTIAL_SIGNING_CONTEXT, pp.issuer_public_key
        )
