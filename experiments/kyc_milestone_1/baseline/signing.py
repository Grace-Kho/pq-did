"""Fixed-role local signers, fresh entropy, real bounded ML-DSA; no raw endpoint."""

import secrets
from dataclasses import dataclass, field

from pqdid import bounded_mldsa_sign as core
from pqdid.bounded_mldsa import bounded_verify_mldsa65
from pqdid.parameters import encode_parameters

from .records import credential_body, enrol_body, presentation_body, request_body, require

CONTEXTS = {
    "credential": b"PQ-DID-REF/credential/v1",
    "enrol": b"PQ-DID-REF/enrol/v1",
    "request": b"PQ-DID-REF/request/v1",
    "presentation": b"PQ-DID-REF/presentation/v1",
}


@dataclass(frozen=True, repr=False)
class Key:
    public: bytes
    secret: bytes = field(repr=False)

    @classmethod
    def generate(cls):
        pair = core.bounded_keygen_mldsa65()
        return cls(pair.public_key, pair.secret_key)


class Signer:
    def __init__(self, pp, role, key, expected_public, authorise):
        require(role in {"issuer", "holder", "verifier"}, "signing-role")
        require(type(key) is Key and key.public == expected_public, "signing-identity")
        core.reference_public_key_mldsa65(key.secret, expected_public_key=expected_public)
        self.pp, self.role, self._key, self._allow = pp, role, key, authorise

    def _sign(self, operation, message):
        roles = {
            "credential": "issuer",
            "enrol": "holder",
            "request": "verifier",
            "presentation": "holder",
        }
        require(self.role == roles[operation] and self._allow() is True, "signing-authority")
        try:
            random = secrets.token_bytes(32)
        except OSError:
            raise core.BoundedMLDSAError(core.Failure.ENTROPY_FAILURE) from None
        if type(random) is not bytes or len(random) != 32:
            raise core.BoundedMLDSAError(core.Failure.ENTROPY_FAILURE)
        signature = core.reference_sign_mldsa65(
            self._key.secret, message, context=CONTEXTS[operation], randomness=random
        )
        require(self._allow() is True, "signing-authority-changed")
        return signature

    def sign_credential(self, holder_key, attributes, identifier):
        return self._sign(
            "credential", credential_body(self.pp, holder_key, attributes, identifier)
        )

    def sign_enrolment(self, session, nonce, holder_key, attributes, identifier):
        require(holder_key == self._key.public, "enrolment-key")
        return self._sign(
            "enrol", enrol_body(self.pp, session, nonce, holder_key, attributes, identifier)
        )

    def sign_request(self, context, state):
        return self._sign("request", request_body(self.pp, context, state))

    def sign_presentation(self, request, credential, path):
        require(credential.holder_public_key == self._key.public, "presentation-key")
        return self._sign("presentation", presentation_body(self.pp, request, credential, path))

    @property
    def instance(self):
        return encode_parameters(self.pp)


def verify(operation, key, message, signature):
    return bounded_verify_mldsa65(key, message, signature, context=CONTEXTS[operation])
