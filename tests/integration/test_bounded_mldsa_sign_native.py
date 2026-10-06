"""Synthetic deterministic differential inputs; native signing is NOT capped.

The already installed portable C internal entry points accept seed/rnd explicitly.
No native randombytes callback is changed. These are differential checks, not NIST
validation/KAT certification. Only seed/rnd labelled synthetic and output digests
are retained; private expanded keys and intermediate values are not logged.
"""

import ctypes
import hashlib
import json
import os
from pathlib import Path

import pytest

from pqdid import bounded_mldsa as v
from pqdid import bounded_mldsa_sign as s
from pqdid.backend import load_backend

SYNTHETIC_SEED = bytes(range(32))
SYNTHETIC_RANDOMNESS = bytes(range(32, 64))
SYNTHETIC_MESSAGE = b"synthetic bounded ML-DSA differential\x00\xff" + bytes(range(256))
_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def native():
    binding = load_backend()
    library = binding.native()
    # common.h removes the optional integration-context argument in this build.
    keygen = library.PQCP_MLDSA_NATIVE_MLDSA65_C_keypair_internal
    keygen.argtypes = [ctypes.c_void_p] * 3
    keygen.restype = ctypes.c_int
    sign = library.PQCP_MLDSA_NATIVE_MLDSA65_C_signature_internal
    sign.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    sign.restype = ctypes.c_int
    return binding, keygen, sign


def native_pair(keygen, seed):
    pk, sk = ctypes.create_string_buffer(1952), ctypes.create_string_buffer(4032)
    assert keygen(pk, sk, seed) == 0
    return pk.raw, sk.raw


def native_signature(sign, sk, message, context, rnd):
    signature, length = ctypes.create_string_buffer(3309), ctypes.c_size_t()
    prefix = bytes((0, len(context))) + context
    assert (
        sign(
            signature,
            ctypes.byref(length),
            message,
            len(message),
            prefix,
            len(prefix),
            rnd,
            sk,
            0,
        )
        == 0
    )
    assert length.value == 3309
    return signature.raw


def record(name, value):
    if os.environ.get("PQDID_PILOT_RUN") not in {"interop", "interop-final"}:
        return
    path = (
        _ROOT
        / "docs/data/s2_bounded_mldsa_keygen_sign_1"
        / (
            "differential-evidence-final.json"
            if os.environ["PQDID_PILOT_RUN"] == "interop-final"
            else "differential-evidence.json"
        )
    )
    rows = json.loads(path.read_text()) if path.exists() else {}
    assert name not in rows
    rows[name] = {"material": "PUBLIC SYNTHETIC TEST INPUTS ONLY", **value}
    path.write_text(json.dumps(rows, indent=2) + "\n")


@pytest.mark.parametrize("seed", [SYNTHETIC_SEED, bytes([255]) * 32])
def test_keygen_exact_portable_native_encoding(native, seed):
    pair = s.reference_keygen_mldsa65(seed)
    pk, sk = native_pair(native[1], seed)
    assert (len(pair.public_key), len(pair.secret_key)) == (1952, 4032)
    assert pair.public_key == pk
    assert pair.secret_key == sk
    assert s.reference_public_key_mldsa65(sk, expected_public_key=pk) == pk
    record(
        "keygen-" + seed.hex(),
        {
            "seed": seed.hex(),
            "public_key_sha256": hashlib.sha256(pk).hexdigest(),
            "expanded_secret_key_sha256": hashlib.sha256(sk).hexdigest(),
            "exact_equal": True,
        },
    )


@pytest.mark.parametrize(
    "context",
    [
        b"",
        b"binary\x00context\xff",
        bytes(range(255)),
        b"PQ-DID/credential/v1",
        b"PQ-DID/state/v1",
        b"PQ-DID/update/v1",
    ],
)
def test_identical_randomness_message_context_and_mutations(native, context):
    pair = s.reference_keygen_mldsa65(SYNTHETIC_SEED)
    pk, sk = native_pair(native[1], SYNTHETIC_SEED)
    expected = native_signature(native[2], sk, SYNTHETIC_MESSAGE, context, SYNTHETIC_RANDOMNESS)
    actual = s.reference_sign_mldsa65(
        pair.secret_key, SYNTHETIC_MESSAGE, context=context, randomness=SYNTHETIC_RANDOMNESS
    )
    assert actual == expected
    with native[0].Signature("ML-DSA-65") as verifier:
        cases = [
            (pk, SYNTHETIC_MESSAGE, actual, context, True),
            (pk, SYNTHETIC_MESSAGE + b"!", actual, context, False),
            (pk, SYNTHETIC_MESSAGE, actual, b"wrong role", False),
            (pk, SYNTHETIC_MESSAGE, bytes([actual[0] ^ 1]) + actual[1:], context, False),
            (bytes([pk[0] ^ 1]) + pk[1:], SYNTHETIC_MESSAGE, actual, context, False),
            (pk, bytes((0, len(context))) + context + SYNTHETIC_MESSAGE, actual, context, False),
        ]
        for key, message, signature, ctx, accepted in cases:
            assert v.bounded_verify_mldsa65(key, message, signature, context=ctx) is accepted
            assert verifier.verify_with_ctx_str(message, signature, ctx, key) is accepted
    record(
        "signature-" + context.hex(),
        {
            "seed": SYNTHETIC_SEED.hex(),
            "randomness": SYNTHETIC_RANDOMNESS.hex(),
            "message": SYNTHETIC_MESSAGE.hex(),
            "context": context.hex(),
            "signature_sha256": hashlib.sha256(actual).hexdigest(),
            "exact_equal": True,
            "bounded_and_native_verifier_comparisons": 6,
            "native_mode": "portable C internal, externalmu=0, 00||len(ctx)||ctx prefix",
        },
    )


def test_ordinary_native_generated_expanded_key_import_and_sign(native):
    with native[0].Signature("ML-DSA-65") as signer:
        pk = signer.generate_keypair()
        sk = signer.export_secret_key()
        assert s.reference_public_key_mldsa65(sk, expected_public_key=pk) == pk
        signature = s.reference_sign_mldsa65(
            sk,
            b"synthetic fresh-key test",
            context=b"PQ-DID/control/v1",
            randomness=SYNTHETIC_RANDOMNESS,
        )
        assert signer.verify_with_ctx_str(
            b"synthetic fresh-key test", signature, b"PQ-DID/control/v1", pk
        )
    # Ordinary native entropy is untouched; no byte-for-byte comparison claimed here.
