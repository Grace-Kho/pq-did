"""Complete local CredValid with real ordinary-native signatures, no proof claim."""

import inspect
from dataclasses import replace

import pytest

from pqdid import bounded_mldsa as mldsa
from pqdid.binding import check_binding_consistency, create_binding
from pqdid.codec import encode_record
from pqdid.credentials import (
    CREDENTIAL_SIGNING_CONTEXT,
    build_mcred,
    cred_valid,
    decode_credential,
    encode_credential,
    validate_credential_structure,
)
from pqdid.parameters import decode_parameters

from .mldsa_cases import load_cases
from .sampler_streams import CountingReader, ball_stream, ntt_stream

CASES = load_cases()


def credential_case(name="alpha-42"):
    item = next(item for item in CASES["credentials"] if item["name"] == name)
    parameters = decode_parameters(bytes.fromhex(item["parameters"]))
    credential = decode_credential(parameters, bytes.fromhex(item["credential"]))
    secret = bytes.fromhex(item["synthetic_public_holder_secret"])
    return parameters, credential, secret


@pytest.mark.parametrize("name", ["alpha-42", "alpha-43", "beta-42"])
def test_correct_signed_credential_for_expected_instance(name):
    parameters, credential, secret = credential_case(name)
    assert validate_credential_structure(parameters, credential) is None
    assert cred_valid(parameters, credential, secret) is True
    assert cred_valid(
        parameters, decode_credential(parameters, encode_credential(parameters, credential)), secret
    )


@pytest.mark.parametrize("damage", ["changed", "synthetic", "zeros"])
def test_structurally_valid_invalid_signature_fails(damage):
    pp, credential, secret = credential_case()
    signature = credential.certificate.signature
    if damage == "changed":
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    elif damage == "synthetic":
        signature = bytes((i * 7 + 3) % 256 for i in range(3309))
    else:
        signature = bytes(3309)
    candidate = replace(
        credential, certificate=replace(credential.certificate, signature=signature)
    )
    assert validate_credential_structure(pp, candidate) is None
    assert cred_valid(pp, candidate, secret) is False


@pytest.mark.parametrize("field", ["attributes", "holder", "rid", "namespace", "issuer_reference"])
def test_changed_certified_field_with_valid_opening_fails_original_signature(field):
    pp, credential, secret = credential_case()
    if field == "attributes":
        attributes = bytearray(credential.attributes)
        attributes[246:248] = b"GB"
        binding = replace(credential.certificate.binding, attributes=bytes(attributes))
        credential = replace(
            credential,
            certificate=replace(credential.certificate, binding=binding),
            attributes=bytes(attributes),
        )
    elif field == "rid":
        credential = replace(credential, revocation_identifier=43)
    else:
        if field == "holder":
            secret = bytes(reversed(secret))
        elif field == "namespace":
            pp = replace(pp, namespace=bytes(32))
        else:
            # Change only the issuer/key reference instance; retain its canonical schema.
            other_pp, _, _ = credential_case("beta-42")
            pp = replace(pp, issuer_reference=other_pp.issuer_reference)
        binding = create_binding(pp.domain, secret, credential.attributes)
        credential = replace(
            credential,
            metadata=pp.metadata,
            certificate=replace(credential.certificate, binding=binding),
        )
    assert validate_credential_structure(pp, credential) is None
    assert check_binding_consistency(
        pp.domain, credential.certificate.binding, secret, credential.attributes
    )
    assert cred_valid(pp, credential, secret) is False


@pytest.mark.parametrize("name", ["alpha-43", "beta-42"])
@pytest.mark.parametrize("part", ["signature", "binding", "certificate", "rid"])
def test_cross_credential_splices_reject(name, part):
    pp, credential, secret = credential_case()
    _, other, other_secret = credential_case(name)
    if part == "signature":
        candidate = replace(
            credential,
            certificate=replace(credential.certificate, signature=other.certificate.signature),
        )
    elif part == "binding":
        candidate = replace(
            credential,
            certificate=replace(credential.certificate, binding=other.certificate.binding),
            attributes=other.attributes,
        )
        secret = other_secret
    elif part == "certificate":
        candidate = replace(credential, certificate=other.certificate, attributes=other.attributes)
        secret = other_secret
    else:
        # A different value, even when the other instance happens to reuse numeric rid 42.
        candidate = replace(credential, revocation_identifier=43)
    assert cred_valid(pp, candidate, secret) is False


def test_other_expected_key_or_instance_fails():
    pp, credential, secret = credential_case()
    other_pp, _, _ = credential_case("beta-42")
    assert cred_valid(other_pp, credential, secret) is False
    assert (
        cred_valid(replace(pp, issuer_public_key=other_pp.issuer_public_key), credential, secret)
        is False
    )
    assert cred_valid(replace(pp, namespace=bytes(32)), credential, secret) is False


@pytest.mark.parametrize("secret", [bytes(32), b"", bytes(31), bytes(33), bytearray(32), None])
def test_wrong_or_malformed_holder_opening_fails(secret):
    pp, credential, _ = credential_case()
    assert cred_valid(pp, credential, secret) is False


@pytest.mark.parametrize("value", [None, {}, b"", ()])
def test_structural_failures_are_not_valid_credentials(value):
    pp, credential, secret = credential_case()
    assert cred_valid(value, credential, secret) is False
    assert cred_valid(pp, value, secret) is False


@pytest.mark.parametrize(
    "sampler,bits,data,budget",
    [("RejNTTPoly", 128, ntt_stream(87), 1026), ("SampleInBall", 256, ball_stream(200), 256)],
)
def test_actual_sampler_exhaustion_reaches_cred_valid(monkeypatch, sampler, bits, data, budget):
    pp, credential, secret = credential_case()
    real_reader = mldsa._shake_reader
    streams = []

    def reader(kind, seed):
        if kind == bits:
            stream = CountingReader(data)
            streams.append(stream)
            return stream
        return real_reader(kind, seed)

    monkeypatch.setattr(mldsa, "_shake_reader", reader)
    message = build_mcred(
        pp, credential.metadata, credential.certificate.binding, credential.revocation_identifier
    )
    diagnostic = mldsa._verify_diagnostic(
        pp.issuer_public_key,
        message,
        credential.certificate.signature,
        context=CREDENTIAL_SIGNING_CONTEXT,
    )
    assert (diagnostic.status, diagnostic.sampler) == (mldsa._Status.EXHAUSTED, sampler)
    assert cred_valid(pp, credential, secret) is False
    assert len(streams) == 2  # Exactly one exhausted sampler per call; no retry/fallback.
    assert all(stream.consumed == budget for stream in streams)


def test_runtime_failure_cannot_become_credential_acceptance(monkeypatch):
    def failure(*args):
        raise MemoryError("test resource failure")

    monkeypatch.setattr(mldsa, "_shake_reader", failure)
    pp, credential, secret = credential_case()
    with pytest.raises(MemoryError):
        cred_valid(pp, credential, secret)


def test_forged_auxiliary_is_rejected_by_full_structure_check():
    # Wire-level non-empty rho rejects before a typed object exists (existing codec).
    pp, credential, secret = credential_case()
    # Simulate bypass of a constructor to test the complete predicate's explicit check.
    object.__setattr__(credential, "auxiliary", b"forbidden")
    assert cred_valid(pp, credential, secret) is False


def test_no_skip_verification_or_presentation_context_argument():
    assert list(inspect.signature(cred_valid).parameters) == [
        "expected_parameters",
        "credential",
        "holder_secret",
    ]


def test_metadata_reference_cannot_silently_replace_schema():
    pp, credential, secret = credential_case()
    other_pp, _, _ = credential_case("beta-42")
    inconsistent = encode_record("iref", (b"different issuer", b"key", b"bad schema"))
    # Metadata is rechecked against validated pp even for a constructor-bypassing object.
    object.__setattr__(credential.metadata, "issuer_reference", inconsistent)
    assert cred_valid(pp, credential, secret) is False
    assert cred_valid(other_pp, credential, secret) is False
