"""Real native ML-DSA-65 operations, with ephemeral keys held only in memory."""

import pytest

from pqdid.backend import LIBRARY, load_backend

MESSAGE = b"PQ-DID environment smoke\x00message"
CONTEXT = b"pqdid/environment-smoke/v1"


@pytest.fixture(scope="module")
def oqs():
    return load_backend()


def test_local_native_backend_and_sizes(oqs):
    assert LIBRARY.is_file()
    assert oqs.oqs_version() == oqs.oqs_python_version() == "0.16.0"
    assert oqs.get_enabled_sig_mechanisms() == ("ML-DSA-65",)
    with oqs.Signature("ML-DSA-65") as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(MESSAGE)
        assert signer.details["length_public_key"] == len(public_key) == 1952
        assert signer.details["length_secret_key"] == 4032  # Expanded, not seed form.
        assert signer.details["length_signature"] == len(signature) == 3309
    with oqs.Signature("ML-DSA-65") as verifier:
        assert verifier.verify(MESSAGE, signature, public_key)


def test_reject_altered_message_and_signature(oqs):
    with oqs.Signature("ML-DSA-65") as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(MESSAGE)
    altered_signature = bytes([signature[0] ^ 1]) + signature[1:]
    with oqs.Signature("ML-DSA-65") as verifier:
        assert verifier.verify(MESSAGE, signature, public_key)
        assert not verifier.verify(MESSAGE + b"!", signature, public_key)
        assert not verifier.verify(MESSAGE, altered_signature, public_key)
        assert not verifier.verify(MESSAGE, signature[:-1], public_key)


@pytest.mark.parametrize(
    "context",
    [b"", CONTEXT, b"binary\x00context\xff", bytes(range(255))],
    ids=["empty", "external", "binary", "255-byte-limit"],
)
def test_external_context_round_trip_and_substitution(oqs, context):
    with oqs.Signature("ML-DSA-65") as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign_with_ctx_str(MESSAGE, context)
    wrong_context = b"wrong" if context != b"wrong" else b"different"
    with oqs.Signature("ML-DSA-65") as verifier:
        assert verifier.verify_with_ctx_str(MESSAGE, signature, context, public_key)
        assert not verifier.verify_with_ctx_str(MESSAGE, signature, wrong_context, public_key)
        assert not verifier.verify_with_ctx_str(MESSAGE + b"!", signature, context, public_key)
        if context:
            assert not verifier.verify(MESSAGE, signature, public_key)


def test_context_is_not_message_concatenation(oqs):
    with oqs.Signature("ML-DSA-65") as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign_with_ctx_str(b"def", b"abc")
        prefixed_signature = signer.sign(b"abcdef")
    with oqs.Signature("ML-DSA-65") as verifier:
        assert verifier.verify_with_ctx_str(b"def", signature, b"abc", public_key)
        assert not verifier.verify_with_ctx_str(b"cdef", signature, b"ab", public_key)
        assert not verifier.verify_with_ctx_str(b"def", prefixed_signature, b"abc", public_key)


def test_reject_256_byte_context(oqs):
    with oqs.Signature("ML-DSA-65") as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign_with_ctx_str(MESSAGE, CONTEXT)
        with pytest.raises(RuntimeError, match="Can not sign message with context"):
            signer.sign_with_ctx_str(MESSAGE, b"x" * 256)
    with oqs.Signature("ML-DSA-65") as verifier:
        assert not verifier.verify_with_ctx_str(MESSAGE, signature, b"x" * 256, public_key)
