"""Bounded Python verifier versus the pinned ordinary native oracle.

Native signing/verification is uncapped. These are interoperability tests, not
bounded signing or library/circuit equivalence claims.
"""

import hashlib
import json
from pathlib import Path

import pytest

from pqdid.backend import load_backend
from pqdid.bounded_mldsa import _Status, _verify_diagnostic, bounded_verify_mldsa65

FIXTURE = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "mldsa65_native_vectors.json").read_text()
)


@pytest.fixture(scope="module")
def native():
    return load_backend()


@pytest.mark.parametrize("item", FIXTURE["vectors"], ids=lambda item: item["name"])
def test_frozen_signatures_and_mutations_agree_with_uncapped_oracle(native, item):
    key, message, signature, context = (
        bytes.fromhex(item[field]) for field in ("public_key", "message", "signature", "context")
    )
    key_rho = bytes([key[0] ^ 1]) + key[1:]
    key_t1 = key[:32] + bytes([key[32] ^ 1]) + key[33:]
    altered_signature = bytes([signature[0] ^ 1]) + signature[1:]
    malformed_hint = signature[:3303] + b"\x38" + signature[3304:]
    cases = [
        (key, message, signature, context, True),
        (key_rho, message, signature, context, False),
        (key_t1, message, signature, context, False),
        (key, message + b"!", signature, context, False),
        (key, message, altered_signature, context, False),
        (key, message, malformed_hint, context, False),
        (key, message, signature[:-1], context, False),
        (key, message, signature, b"wrong role", False),
    ]
    with native.Signature("ML-DSA-65") as verifier:
        for pk, msg, sig, ctx, expected in cases:
            status = _verify_diagnostic(pk, msg, sig, context=ctx).status
            assert status is not _Status.EXHAUSTED  # These fixed cases all complete within bounds.
            assert (status is _Status.VALID) == expected
            assert verifier.verify_with_ctx_str(msg, sig, ctx, pk) == expected


@pytest.mark.parametrize(
    "context", [b"", b"PQ-DID/credential/v1", b"binary\x00context\xff", bytes(range(255))]
)
def test_fresh_uncapped_signer_and_bounded_verifier(native, context):
    message = bytes(range(256)) * 4
    with native.Signature("ML-DSA-65") as signer:
        key = signer.generate_keypair()
        signature = signer.sign_with_ctx_str(message, context)
    assert bounded_verify_mldsa65(key, message, signature, context=context)
    assert not bounded_verify_mldsa65(key, message, signature, context=b"x" * 256)


@pytest.mark.parametrize("bits,rate", [(128, 168), (256, 136)])
def test_reference_shake_against_independent_python_extension(bits, rate):
    # The installed liboqs hides its SHAKE symbols. Cross-check the two independent
    # SHAKE implementations already available in the preserved Python environment.
    import _sha3

    operation = getattr(_sha3, f"shake_{bits}")
    reference = getattr(hashlib, f"shake_{bits}")
    assert type(reference()).__module__ == "_hashlib"
    assert type(operation()).__module__ == "_sha3"
    for length in (0, rate - 1, rate, rate + 1, 2 * rate + 1):
        message = bytes(i % 256 for i in range(length))
        for output_length in (rate - 1, rate, rate + 1, 1026):
            assert operation(message).digest(output_length) == reference(message).digest(
                output_length
            )
