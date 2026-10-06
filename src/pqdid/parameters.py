"""Structural public parameters and instance metadata (VII-A.1, p. 14).

The sole suite fixes lambda=128, ML-DSA-65 and BC-1. Key bytes here are
length-checked representations, not validated keys or trusted instance registration.
No wire format is invented for the local (pp, cfgD, trust) configuration.
"""

from dataclasses import dataclass

from pqdid.codec import EncodingError, decode_record, encode_record, require_bytes
from pqdid.hash_domain import SUITE, HashDomain, encode_metadata
from pqdid.schema import Schema, decode_schema, encode_schema

PUBLIC_KEY_BYTES = 1952


@dataclass(frozen=True)
class InstanceMetadata:
    issuer_reference: bytes
    namespace: bytes

    def __post_init__(self) -> None:
        HashDomain(SUITE, self.issuer_reference, self.namespace)


@dataclass(frozen=True)
class PublicParameters:
    suite: bytes
    issuer_reference: bytes
    namespace: bytes
    issuer_public_key: bytes
    revocation_public_key: bytes
    schema: Schema

    def __post_init__(self) -> None:
        validate_parameters_structure(self)

    @property
    def domain(self) -> HashDomain:
        return HashDomain(self.suite, self.issuer_reference, self.namespace)

    @property
    def metadata(self) -> InstanceMetadata:
        return InstanceMetadata(self.issuer_reference, self.namespace)


def validate_parameters_structure(
    parameters: PublicParameters, *, expected: PublicParameters | None = None
) -> None:
    """Check the complete pp representation; optionally match externally pinned pp.

    Success returns None, never a cryptographic verification result. This does not
    check bounded key expansion, key generation/ownership or trust authorisation.
    """
    if type(parameters) is not PublicParameters:
        raise EncodingError("expected public parameters")
    domain = parameters.domain
    if encode_schema(parameters.schema) != encode_schema(domain.schema):
        raise EncodingError("repeated schema disagrees with issuer reference")
    for key in (parameters.issuer_public_key, parameters.revocation_public_key):
        if len(require_bytes(key)) != PUBLIC_KEY_BYTES:
            raise EncodingError("ML-DSA-65 public key must contain exactly 1952 bytes")
    if expected is not None:
        validate_parameters_structure(expected)
        if parameters != expected:
            raise EncodingError("parameters disagree with expected instance")


def validate_metadata_structure(
    expected_parameters: PublicParameters, metadata: InstanceMetadata
) -> None:
    validate_parameters_structure(expected_parameters)
    if type(metadata) is not InstanceMetadata:
        raise EncodingError("expected instance metadata")
    if metadata != expected_parameters.metadata:
        raise EncodingError("metadata disagrees with expected instance")


def encode_parameters(parameters: PublicParameters) -> bytes:
    validate_parameters_structure(parameters)
    return encode_record(
        "parameters",
        (
            parameters.suite,
            parameters.issuer_reference,
            parameters.namespace,
            parameters.issuer_public_key,
            parameters.revocation_public_key,
            encode_schema(parameters.schema),
        ),
    )


def decode_parameters(
    encoded: bytes, *, expected: PublicParameters | None = None
) -> PublicParameters:
    """Parse canonical pp and check structure; expected must come from the caller."""
    suite, reference, namespace, issuer_key, revocation_key, schema = decode_record(
        encoded, "parameters"
    )
    parameters = PublicParameters(
        suite, reference, namespace, issuer_key, revocation_key, decode_schema(schema)
    )
    validate_parameters_structure(parameters, expected=expected)
    return parameters


def encode_instance_metadata(
    expected_parameters: PublicParameters, metadata: InstanceMetadata
) -> bytes:
    validate_metadata_structure(expected_parameters, metadata)
    return encode_metadata(expected_parameters.domain)


def decode_instance_metadata(
    expected_parameters: PublicParameters, encoded: bytes
) -> InstanceMetadata:
    reference, namespace = decode_record(encoded, "meta")
    metadata = InstanceMetadata(reference, namespace)
    validate_metadata_structure(expected_parameters, metadata)
    return metadata
