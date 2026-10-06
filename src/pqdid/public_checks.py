"""Stateless public checks, V-B and VII-A.1/.5/.7; no lifecycle acceptance.

No function takes a private witness. Signatures authenticate a supplied state, not
its freshness. Request/controller authentication and proof checking remain separate.
"""

from pqdid.bounded_mldsa import bounded_verify_mldsa65
from pqdid.codec import EncodingError
from pqdid.parameters import PublicParameters
from pqdid.policy import evaluate_policy
from pqdid.schema import decode_attributes
from pqdid.statements import (
    AuthenticationStatement,
    EnrolmentStatement,
    RevocationState,
    build_state_message,
    validate_auth_statement,
    validate_enrol_statement,
)

STATE_SIGNING_CONTEXT = b"PQ-DID/state/v1"


def state_auth(expected_parameters: PublicParameters, state: RevocationState) -> bool:
    try:
        message = build_state_message(expected_parameters, state)
    except EncodingError:
        return False
    return bounded_verify_mldsa65(
        expected_parameters.revocation_public_key,
        message,
        state.signature,
        context=STATE_SIGNING_CONTEXT,
    )


def pub_ok(expected_parameters: PublicParameters, statement: AuthenticationStatement) -> bool:
    """PubOK including bounded StateAuth; does not evaluate Ppub or a proof."""
    try:
        validate_auth_statement(expected_parameters, statement)
    except EncodingError:
        return False
    return state_auth(expected_parameters, statement.state)


def public_policy_ok(
    expected_parameters: PublicParameters, statement: AuthenticationStatement
) -> bool:
    """Ppub on disclosed values only. Full acceptance also requires PubOK/private checks."""
    try:
        validate_auth_statement(expected_parameters, statement)
        return evaluate_policy(
            expected_parameters.schema, statement.context.policy, statement.disclosed_attributes
        )
    except EncodingError:
        return False


def enrol_public_ok(
    expected_parameters: PublicParameters, statement: EnrolmentStatement, approved_attributes: bytes
) -> bool:
    """Stateless surrounding enrolment checks against the issuer's approved vector.

    Does not check controller authorisation, holder approval, pending nonce,
    allocation, proof or fresh issuance reads; it is not an issuance API.
    """
    try:
        validate_enrol_statement(expected_parameters, statement)
        decode_attributes(expected_parameters.schema, approved_attributes)
        if not statement.approved_attributes == statement.binding.attributes == approved_attributes:
            return False
    except EncodingError:
        return False
    return state_auth(expected_parameters, statement.state)
