"""Executable local reference predicates, V-B/C and VII-A.5/.6.

These functions inspect holder-local witnesses. They are not presentation/proof
verifiers and must never be exposed as remote witness-receiving services.
"""

from pqdid.binding import check_binding_consistency, create_binding
from pqdid.codec import EncodingError
from pqdid.credentials import Certificate, Credential, cred_valid
from pqdid.merkle import verify_non_revocation_path
from pqdid.parameters import PublicParameters
from pqdid.public_checks import pub_ok, public_policy_ok
from pqdid.schema import project_attributes
from pqdid.statements import (
    AuthenticationStatement,
    EnrolmentStatement,
    validate_auth_statement,
    validate_enrol_statement,
)
from pqdid.witnesses import (
    AuthenticationWitness,
    EnrolmentWitness,
    encode_enrol_witness,
    validate_auth_witness,
)


def enrol(
    expected_parameters: PublicParameters, statement: EnrolmentStatement, witness: EnrolmentWitness
) -> bool:
    """Enrolment's BindOpen reference relation; public/session checks are separate."""
    try:
        validate_enrol_statement(expected_parameters, statement)
        secret = encode_enrol_witness(witness)
        return check_binding_consistency(
            expected_parameters.domain, statement.binding, secret, statement.approved_attributes
        )
    except EncodingError:
        return False


def auth_private(
    expected_parameters: PublicParameters,
    statement: AuthenticationStatement,
    witness: AuthenticationWitness,
) -> bool:
    """Private circuit target only; use auth for the complete reference relation.

    Reconstruct exactly one credential from the five witness fields. CredValid
    retains its opening check and calls the sole build_mcred. The same attributes
    and rid are used for signature, zero-leaf path and projection.
    """
    try:
        validate_auth_statement(expected_parameters, statement)
        validate_auth_witness(expected_parameters.schema, witness)
        binding = create_binding(
            expected_parameters.domain, witness.holder_secret, witness.attributes
        )
        credential = Credential(
            Certificate(binding, witness.signature),
            witness.attributes,
            witness.revocation_identifier,
            b"",
            statement.metadata,
        )
        if not cred_valid(expected_parameters, credential, witness.holder_secret):
            return False
        if not verify_non_revocation_path(
            expected_parameters.domain,
            witness.revocation_identifier,
            witness.path,
            statement.state.root,
        ):
            return False
        return (
            project_attributes(expected_parameters.schema, witness.attributes, statement.disclosed)
            == statement.disclosed_attributes
        )
    except EncodingError:
        return False


def auth(
    expected_parameters: PublicParameters,
    statement: AuthenticationStatement,
    witness: AuthenticationWitness,
) -> bool:
    """Complete Rauth = PubOK AND private conjunction AND Ppub.

    Malformed/invalid/exhausted operations reject. Unexpected runtime/resource
    failures propagate without acceptance. No clock, freshness, nonce consumption,
    trust decision, optional check, proof or uncapped fallback exists here.
    """
    return (
        pub_ok(expected_parameters, statement)
        and auth_private(expected_parameters, statement, witness)
        and public_policy_ok(expected_parameters, statement)
    )
