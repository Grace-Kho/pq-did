"""Persistent synthetic holder; all baseline certified fields are disclosed."""

from pathlib import Path

from pqdid.expiry import is_unexpired
from pqdid.merkle import verify_non_revocation_path
from pqdid.persistence.codec import decode, encode
from pqdid.policy import evaluate_policy
from pqdid.public_checks import state_auth
from pqdid.revocation_state import ManagerStatus
from pqdid.schema import project_attributes
from pqdid.statements import decode_state, encode_state
from pqdid.witness_updates import UpdateStatus, WitnessCheckpoint, update_witness

from .records import (
    BaselinePresentation,
    certified_expiry,
    decode_credential,
    encode_credential,
    encode_request,
    presentation_body,
    require,
)
from .signing import Key, Signer, verify
from .storage import directory, read_key, read_private, write_key, write_private


class Holder:
    def __init__(self, pp, path, clock, request_keys, approved_policy):
        self.pp, self.path, self.clock = pp, directory(path), clock
        self.request_keys, self.approved_policy = dict(request_keys), approved_policy
        self._key = read_key(self.path / "holder.key")
        self.signer = Signer(pp, "holder", self._key, self._key.public, lambda: True)
        self.credential = self.checkpoint = None
        data = decode(read_private(self.path / "wallet.bin"))
        if data:
            require(type(data) is tuple and len(data) == 4, "wallet-shape")
            credential = decode_credential(pp, data[0])
            checkpoint = WitnessCheckpoint(data[1], data[2], decode_state(pp, data[3]))
            self._validate(credential, checkpoint)
            self.credential, self.checkpoint = credential, checkpoint

    @classmethod
    def create(cls, pp, path, clock, request_keys, approved_policy, *, key=None):
        path = directory(Path(path), create=True)
        write_key(path / "holder.key", Key.generate() if key is None else key)
        write_private(path / "wallet.bin", encode(()), fresh=True)
        return cls(pp, path, clock, request_keys, approved_policy)

    @property
    def public_key(self):
        return self._key.public

    def _validate(self, credential, checkpoint):
        encoded = encode_credential(self.pp, credential)
        require(decode_credential(self.pp, encoded) == credential, "credential-canonical")
        require(credential.holder_public_key == self.public_key, "holder-key")
        require(
            verify("credential", self.pp.issuer_public_key, credential.body, credential.signature),
            "issuer-signature",
        )
        require(checkpoint.identifier == credential.identifier, "holder-rid")
        require(state_auth(self.pp, checkpoint.state), "holder-state")
        require(
            verify_non_revocation_path(
                self.pp.domain, checkpoint.identifier, checkpoint.path, checkpoint.state.root
            ),
            "holder-path",
        )

    def _commit(self, credential, checkpoint):
        payload = encode(
            (
                encode_credential(self.pp, credential),
                checkpoint.identifier,
                checkpoint.path,
                encode_state(self.pp, checkpoint.state),
            )
        )
        write_private(self.path / "wallet.bin", payload)
        self.credential, self.checkpoint = credential, checkpoint

    def enrol(self, challenge):
        require(challenge.holder_key == self.public_key, "enrol-key")
        return self.signer.sign_enrolment(
            challenge.session,
            challenge.nonce,
            challenge.holder_key,
            challenge.attributes,
            challenge.identifier,
        )

    def accept_credential(self, delivery, approved_attributes):
        require(delivery.credential.attributes == approved_attributes, "unapproved-credential")
        self._validate(delivery.credential, delivery.checkpoint)
        self._commit(delivery.credential, delivery.checkpoint)

    def apply(self, target, records):
        require(self.credential is not None, "holder-no-credential")
        result = update_witness(self.pp, self.checkpoint, target, records)
        if result.status is UpdateStatus.UPDATED:
            self._commit(self.credential, result.checkpoint)
        return result

    def synchronise(self, manager, target_epoch):
        require(self.checkpoint is not None, "holder-no-credential")
        page = manager.updates(self.pp.namespace, self.checkpoint.state.epoch, target_epoch)
        self.last_history = page  # Already obtained public response, for size accounting only.
        require(page.status is ManagerStatus.PAGE, "history-unavailable")
        require(
            page.page.starting_state.reference == self.checkpoint.state.reference, "history-start"
        )
        require(page.page.complete, "history-incomplete")
        return self.apply(page.page.endpoint_state, page.page.records)

    def present(self, request):
        encode_request(self.pp, request)
        context = request.context
        require(context.audience in self.request_keys, "unapproved-audience")
        require(context.policy == self.approved_policy, "unapproved-policy")
        require(is_unexpired(context.expires_at, now=self.clock.now()), "expired")
        require(
            verify("request", self.request_keys[context.audience], request.body, request.signature),
            "request-signature",
        )
        require(state_auth(self.pp, request.state), "request-state")
        require(
            self.checkpoint is not None
            and request.state.reference == self.checkpoint.state.reference,
            "holder-state-mismatch",
        )
        certified_expiry(self.pp, self.credential.attributes, context)
        require(
            evaluate_policy(
                self.pp.schema,
                context.policy,
                project_attributes(
                    self.pp.schema, self.credential.attributes, context.policy.disclosed
                ),
            ),
            "policy",
        )
        body = presentation_body(self.pp, request, self.credential, self.checkpoint.path)
        signature = self.signer.sign_presentation(request, self.credential, self.checkpoint.path)
        return BaselinePresentation(body, signature, request, self.credential, self.checkpoint.path)
