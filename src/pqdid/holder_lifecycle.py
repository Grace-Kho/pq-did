"""Holder-local reference integration; no persistent wallet or proof generation.

Start only from the existing issuance acceptance procedure. Immutable credential and
witness/state snapshots change by one assignment, after the complete bounded batch.
Private presentation inputs are for a local relation/prover, never a remote verifier.
"""

from dataclasses import dataclass
from threading import Lock

from pqdid.bounded_manager import BoundedDurableManager
from pqdid.bounded_mldsa import bounded_verify_mldsa65
from pqdid.codec import EncodingError
from pqdid.credentials import Credential, cred_valid
from pqdid.expiry import is_unexpired
from pqdid.issuance import HolderAcceptance, IssuedCredential
from pqdid.parameters import validate_parameters_structure
from pqdid.public_checks import pub_ok, public_policy_ok
from pqdid.revocation_state import HistoryResult, ManagerStatus
from pqdid.schema import project_attributes
from pqdid.statements import AuthenticationStatement, RevocationState, encode_context
from pqdid.verifier_state import REQUEST_CONTEXT, AuthenticationRequest
from pqdid.witness_updates import (
    DEFAULT_UPDATE_LIMITS,
    AuthenticationUpdateResult,
    UpdateStatus,
    update_authentication_witness,
)
from pqdid.witnesses import AuthenticationWitness


@dataclass(frozen=True, repr=False)
class HolderSnapshot:
    credential: Credential
    witness: AuthenticationWitness
    state: RevocationState


@dataclass(frozen=True, repr=False)
class LocalPresentationInputs:
    statement: AuthenticationStatement
    witness: AuthenticationWitness


@dataclass(frozen=True, repr=False)
class AdvanceResult:
    history: HistoryResult
    update: AuthenticationUpdateResult | None = None


def _require(condition):
    if not condition:
        raise EncodingError("holder lifecycle input or state mismatch")


class ReferenceHolderLifecycle:
    """One accepted credential, unchanged across explicitly requested update calls.

    REVOKED and failures retain the old snapshot and return no replacement, per the
    existing contract. A retained old-root witness is not current eligibility.
    The lock and pointer assignment give in-memory atomicity, not crash durability.
    """

    def __init__(self, parameters, accepted: HolderAcceptance, holder_secret: bytes):
        _require(type(accepted) is HolderAcceptance)
        validate_parameters_structure(parameters, expected=accepted._parameters)
        issued = accepted.snapshot()
        _require(type(issued) is IssuedCredential)
        credential, checkpoint = issued.credential, issued.checkpoint
        _require(checkpoint.identifier == credential.revocation_identifier)
        _require(cred_valid(parameters, credential, holder_secret))
        witness = AuthenticationWitness(
            holder_secret,
            credential.attributes,
            credential.revocation_identifier,
            credential.certificate.signature,
            checkpoint.path,
        )
        initial = update_authentication_witness(
            parameters,
            witness,
            checkpoint.state,
            checkpoint.state,
            (),
        )
        _require(initial.status is UpdateStatus.UPDATED)
        self.parameters = parameters
        self._value = HolderSnapshot(credential, initial.witness, initial.state)
        self._lock = Lock()

    def snapshot(self):
        with self._lock:
            return self._value

    def _apply(self, target, records, limits):
        current = self._value
        result = update_authentication_witness(
            self.parameters,
            current.witness,
            current.state,
            target,
            records,
            limits=limits,
        )
        if result.status is UpdateStatus.UPDATED:
            # Construct the whole immutable replacement before the single commit point.
            self._value = HolderSnapshot(current.credential, result.witness, result.state)
        return result

    def apply(self, target, records, *, limits=DEFAULT_UPDATE_LIMITS):
        """Apply exactly this finite batch; no skips, auto-retry or resynchronisation."""
        with self._lock:
            return self._apply(target, records, limits)

    def advance(self, manager, target_epoch, *, limits=DEFAULT_UPDATE_LIMITS):
        """One public namespace/epoch page, one atomic local result; caller continues.

        Only namespace and epochs leave the holder. The manager already limits pages
        to <=16 records/178592 bytes. An incomplete page is not a completed catch-up;
        each successful page's exact endpoint must precede the next explicit call.
        """
        _require(type(manager) is BoundedDurableManager)
        validate_parameters_structure(manager.parameters, expected=self.parameters)
        with self._lock:
            history = manager.updates(
                self.parameters.namespace,
                self._value.state.epoch,
                target_epoch,
                limits=limits,
            )
            if history.status is not ManagerStatus.PAGE:
                return AdvanceResult(history)
            page = history.page
            _require(page.starting_state.reference == self._value.state.reference)
            return AdvanceResult(history, self._apply(page.endpoint_state, page.records, limits))

    def prepare(self, request, *, audience, session, request_public_key, approved_policy, now):
        """Authenticate a holder-approved request, return LOCAL inputs without a proof.

        Audience/key/session/policy/time are trusted application inputs. There is no
        automatic policy approval or clock choice, hidden DID read, or holder key in X.
        A coherent snapshot is taken once; later revocation remains a verifier read.
        """
        with self._lock:
            current = self._value
        _require(type(request) is AuthenticationRequest)
        context = request.context
        _require(context.audience == audience and context.session == session)
        _require(context.policy == approved_policy and is_unexpired(context.expires_at, now=now))
        _require(request.state.reference == current.state.reference)
        _require(
            bounded_verify_mldsa65(
                request_public_key,
                encode_context(self.parameters, context),
                request.signature,
                context=REQUEST_CONTEXT,
            )
        )
        disclosed = context.policy.disclosed
        statement = AuthenticationStatement(
            self.parameters,
            self.parameters.metadata,
            context,
            request.state,
            disclosed,
            project_attributes(self.parameters.schema, current.credential.attributes, disclosed),
        )
        _require(
            pub_ok(self.parameters, statement) and public_policy_ok(self.parameters, statement)
        )
        return LocalPresentationInputs(statement, current.witness)
