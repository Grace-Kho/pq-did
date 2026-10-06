"""Private certificate/credential structures and exact Mcred (VII-A.5, p. 15).

Codecs/structural validators do not establish authenticity. cred_valid separately
checks the local holder opening and bounded credential signature. It is not a
remote proof of knowledge, issuer-authorisation service or complete relation.
"""

from dataclasses import dataclass

from pqdid.binding import (
    BindingRepresentation,
    check_binding_consistency,
    decode_binding,
    encode_binding,
)
from pqdid.bounded_mldsa import bounded_verify_mldsa65
from pqdid.codec import (
    EncodingError,
    decode_record,
    decode_uint,
    encode_record,
    encode_uint,
    require_bytes,
    require_uint,
)
from pqdid.merkle import TREE_DEPTH
from pqdid.parameters import (
    InstanceMetadata,
    PublicParameters,
    decode_instance_metadata,
    encode_instance_metadata,
    validate_metadata_structure,
    validate_parameters_structure,
)
from pqdid.schema import ATTRIBUTE_VECTOR_BYTES, decode_attributes

SIGNATURE_BYTES = 3309
CREDENTIAL_SIGNING_CONTEXT = b"PQ-DID/credential/v1"


@dataclass(frozen=True, repr=False)
class Certificate:
    binding: BindingRepresentation
    signature: bytes

    def __post_init__(self) -> None:
        if type(self.binding) is not BindingRepresentation:
            raise EncodingError("expected binding representation")
        if len(require_bytes(self.signature)) != SIGNATURE_BYTES:
            raise EncodingError("ML-DSA-65 signature must contain exactly 3309 bytes")


@dataclass(frozen=True, repr=False)
class Credential:
    certificate: Certificate
    attributes: bytes
    revocation_identifier: int
    auxiliary: bytes
    metadata: InstanceMetadata

    def __post_init__(self) -> None:
        if type(self.certificate) is not Certificate:
            raise EncodingError("expected certificate")
        if type(self.metadata) is not InstanceMetadata:
            raise EncodingError("expected instance metadata")
        if len(require_bytes(self.attributes)) != ATTRIBUTE_VECTOR_BYTES:
            raise EncodingError("attribute vector must contain exactly 1024 bytes")
        require_uint(self.revocation_identifier, TREE_DEPTH)
        if require_bytes(self.auxiliary) != b"":
            raise EncodingError("credential auxiliary field must be empty")
        if self.attributes != self.certificate.binding.attributes:
            raise EncodingError("credential attributes disagree with binding")


def validate_certificate_structure(
    expected_parameters: PublicParameters, certificate: Certificate
) -> None:
    """Validate framing domains, not the signature's mathematical validity."""
    validate_parameters_structure(expected_parameters)
    if type(certificate) is not Certificate:
        raise EncodingError("expected certificate")
    encode_binding(expected_parameters.domain, certificate.binding)
    if len(require_bytes(certificate.signature)) != SIGNATURE_BYTES:
        raise EncodingError("ML-DSA-65 signature must contain exactly 3309 bytes")


def validate_credential_structure(
    expected_parameters: PublicParameters, credential: Credential
) -> None:
    """Check repeated fields and canonical domains; success is not CredValid."""
    if type(credential) is not Credential:
        raise EncodingError("expected credential")
    validate_metadata_structure(expected_parameters, credential.metadata)
    validate_certificate_structure(expected_parameters, credential.certificate)
    decode_attributes(expected_parameters.schema, credential.attributes)
    require_uint(credential.revocation_identifier, TREE_DEPTH)
    if require_bytes(credential.auxiliary) != b"":
        raise EncodingError("credential auxiliary field must be empty")
    if credential.attributes != credential.certificate.binding.attributes:
        raise EncodingError("credential attributes disagree with binding")


def encode_certificate(expected_parameters: PublicParameters, certificate: Certificate) -> bytes:
    validate_certificate_structure(expected_parameters, certificate)
    return encode_record(
        "certificate",
        (encode_binding(expected_parameters.domain, certificate.binding), certificate.signature),
    )


def decode_certificate(expected_parameters: PublicParameters, encoded: bytes) -> Certificate:
    validate_parameters_structure(expected_parameters)
    binding, signature = decode_record(encoded, "certificate")
    certificate = Certificate(decode_binding(expected_parameters.domain, binding), signature)
    validate_certificate_structure(expected_parameters, certificate)
    return certificate


def encode_credential(expected_parameters: PublicParameters, credential: Credential) -> bytes:
    validate_credential_structure(expected_parameters, credential)
    return encode_record(
        "credential",
        (
            encode_certificate(expected_parameters, credential.certificate),
            credential.attributes,
            encode_uint(credential.revocation_identifier, 4),
            credential.auxiliary,
            encode_instance_metadata(expected_parameters, credential.metadata),
        ),
    )


def decode_credential(expected_parameters: PublicParameters, encoded: bytes) -> Credential:
    certificate, attributes, identifier, auxiliary, metadata = decode_record(encoded, "credential")
    credential = Credential(
        decode_certificate(expected_parameters, certificate),
        attributes,
        decode_uint(identifier, 4),
        auxiliary,
        decode_instance_metadata(expected_parameters, metadata),
    )
    validate_credential_structure(expected_parameters, credential)
    return credential


def build_mcred(
    expected_parameters: PublicParameters,
    metadata: InstanceMetadata,
    binding: BindingRepresentation,
    revocation_identifier: int,
) -> bytes:
    """The sole Mcred constructor, shared by future signing and verification.

    Exactly enc_cred(suite, E(mu), E(B), [rid]4); no digest, context prefix,
    signature, presentation context or witness. The external signing context is
    CREDENTIAL_SIGNING_CONTEXT. This works before a signature exists. Callers
    handling an existing credential must also validate its complete structure.
    """
    validate_metadata_structure(expected_parameters, metadata)
    require_uint(revocation_identifier, TREE_DEPTH)
    return encode_record(
        "cred",
        (
            expected_parameters.suite,
            encode_instance_metadata(expected_parameters, metadata),
            encode_binding(expected_parameters.domain, binding),
            encode_uint(revocation_identifier, 4),
        ),
    )


def cred_valid(
    expected_parameters: PublicParameters, credential: Credential, holder_secret: bytes
) -> bool:
    """Complete local CredValid of V-A/B and VII-A.5, using the same B/m/rid.

    Structural errors, a wrong opening, an invalid signature and bounded sampler
    exhaustion return False. Runtime/resource failures propagate and never cause
    acceptance or an uncapped fallback. Expected pp must come from trusted caller
    configuration; this function does not authorise an issuer or register an instance.

    This private local predicate receives xH. It is not a proof of knowledge, a
    presentation-verifier API, non-revocation/freshness checking or the full Rauth.
    """
    try:
        validate_credential_structure(expected_parameters, credential)
        if not check_binding_consistency(
            expected_parameters.domain,
            credential.certificate.binding,
            holder_secret,
            credential.attributes,
        ):
            return False
        message = build_mcred(
            expected_parameters,
            credential.metadata,
            credential.certificate.binding,
            credential.revocation_identifier,
        )
    except EncodingError:
        return False
    return bounded_verify_mldsa65(
        expected_parameters.issuer_public_key,
        message,
        credential.certificate.signature,
        context=CREDENTIAL_SIGNING_CONTEXT,
    )
