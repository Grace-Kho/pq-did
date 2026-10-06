"""Synthetic issuance harness: native test signing and public-only controlled verdicts.

Local witness evaluation occurs in prepare(), never in the issuer or proof adapter.
These tokens are not proofs/receipts; ordinary native keygen/signing is not bounded
production signing. Existing vectors and their private test inputs are read unchanged.
"""

from dataclasses import replace

from pqdid.backend import load_backend
from pqdid.binding import create_binding
from pqdid.issuance import (
    CONTROL_CONTEXT,
    DEFAULT_ISSUE_LIMITS,
    ControllerResolution,
    EnrolmentSubmission,
    IssueRequest,
    IssueStatus,
    ReferenceIssuer,
)
from pqdid.relations import enrol
from pqdid.schema import decode_attributes
from pqdid.statements import encode_enrol_statement
from pqdid.verifier_state import ProofVerdict
from pqdid.witnesses import EnrolmentWitness

from .revocation_state_cases import RecordingSigner, RevocationAuthority
from .verifier_state_cases import NativeTestSigner, TestNonces, valid_resolution


class IssuanceAuthority(RevocationAuthority):
    def __init__(self):
        super().__init__()
        self.controller = NativeTestSigner(load_backend())

    def close(self):
        self.controller.close()
        super().close()


class Resolver:
    def __init__(self, authority, request):
        self.value = ControllerResolution(
            request.did,
            valid_resolution(request.did, request.version),
            authority.controller.public_key,
        )
        self.calls = []
        self.hook = lambda: None

    def current(self, pp, did):
        self.calls.append((pp, did))
        self.hook()
        return self.value


class Authorisation:
    def __init__(self, attributes):
        self.attributes = attributes
        self.calls = []
        self.hook = lambda: None

    def approve(self, pp, request, controller):
        self.calls.append((pp, request, controller))
        self.hook()
        return self.attributes if request.evidence == b"TEST-ONLY-APPROVED-EVIDENCE" else None


class ControlledEnrolmentVerifier:
    def __init__(self, pp):
        self.pp, self.approved, self.calls = pp, set(), []
        self.hook = lambda: None
        self.override = None

    def verify(self, statement, proof):
        self.calls.append((statement, proof))
        self.hook()
        if self.override is not None:
            return self.override
        return (
            ProofVerdict.VALID
            if (encode_enrol_statement(self.pp, statement), proof) in self.approved
            else ProofVerdict.INVALID
        )


class IssuanceHarness:
    def __init__(
        self, authority, *, allocated_count=42, limits=DEFAULT_ISSUE_LIMITS, **issuer_options
    ):
        self.authority, self.pp = authority, authority.pp
        self.manager, self.manager_signer, _ = authority.manager_model(
            empty=True, allocated_count=allocated_count
        )
        witness = authority.witnesses[42]
        self.secret, self.attributes = witness.holder_secret, witness.attributes
        values = decode_attributes(self.pp.schema, self.attributes)
        self.request = IssueRequest(
            b"session-A",
            values[self.pp.schema.did_index - 1],
            values[self.pp.schema.version_index - 1],
            self.attributes,
            b"TEST-ONLY-APPROVED-EVIDENCE",
            self.attributes,
        )
        self.resolver, self.authorisation = (
            Resolver(authority, self.request),
            Authorisation(self.attributes),
        )
        self.proofs = ControlledEnrolmentVerifier(self.pp)
        self.signer = RecordingSigner(authority.issuer)
        options = dict(
            resolver=self.resolver,
            authorisation=self.authorisation,
            manager=self.manager,
            signer=self.signer,
            proof_verifier=self.proofs,
            nonces=TestNonces(),
            limits=limits,
        )
        options.update(issuer_options)
        self.issuer = ReferenceIssuer(self.pp, **options)

    def begin(self, session=None):
        request = self.request if session is None else replace(self.request, session=session)
        return self.issuer.begin(request, self.manager.snapshot().state)

    def prepare(self, challenge, *, secret=None, binding=None):
        secret = self.secret if secret is None else secret
        binding = (
            create_binding(self.pp.domain, secret, self.attributes) if binding is None else binding
        )
        statement = challenge.statement(binding)
        token = b"TEST-ONLY-LOCAL-ENROLMENT-RESULT"
        if enrol(self.pp, statement, EnrolmentWitness(secret)):
            self.proofs.approved.add((encode_enrol_statement(self.pp, statement), token))
        signature = self.authority.controller.sign(
            encode_enrol_statement(self.pp, statement), CONTROL_CONTEXT
        )
        return EnrolmentSubmission(statement, token, signature)

    def pending(self):
        result = self.begin()
        assert result.status is IssueStatus.PENDING
        return result.challenge, self.prepare(result.challenge)

    def issue(self):
        challenge, submission = self.pending()
        result = self.issuer.finish(self.request.session, submission)
        assert result.status is IssueStatus.CERTIFIED
        return challenge, submission, result.issued
