"""Test-only ephemeral issuer/manager signing and independently built expectations.

Original relation vectors are read unchanged. Only synthetic credential signatures
are re-created for the ephemeral issuer; original messages/attributes/secrets stay
fixed. These ordinary native helpers do not establish bounded production signing.
"""

from dataclasses import replace

from pqdid.backend import load_backend
from pqdid.revocation_state import (
    DEFAULT_MANAGER_LIMITS,
    ReferenceRevocationManager,
    RevocationRequest,
    SigningResult,
    SigningStatus,
)

from .binding_merkle_reference import SparseReferenceTree, record
from .relation_cases import CREDENTIALS, INSTANCES, auth_case
from .verifier_state_cases import NativeTestSigner
from .witness_update_cases import UpdateAuthority, ref_bytes


class RecordingSigner:
    def __init__(self, native_signer):
        self.native_signer = native_signer
        self.calls = []
        self.hook = None

    def sign(self, message, context):
        self.calls.append((message, context))
        if self.hook is not None:
            replacement = self.hook(message, context)
            if replacement is not None:
                return replacement
        return SigningResult(SigningStatus.SIGNED, self.native_signer.sign(message, context))


class RevocationAuthority(UpdateAuthority):
    __test__ = False

    def __init__(self):
        super().__init__()
        self.issuer = NativeTestSigner(load_backend())
        self.pp = replace(self.pp, issuer_public_key=self.issuer.public_key)
        self.witnesses = {}
        for rid in (42, 43):
            _, _, witness = auth_case(f"alpha-{rid}-old-002c")
            self.witnesses[rid] = replace(
                witness,
                signature=self.issuer.sign(
                    bytes.fromhex(CREDENTIALS[f"alpha-{rid}"]["message"]), b"PQ-DID/credential/v1"
                ),
            )
        self.witness = self.witnesses[42]

    def request(
        self,
        state,
        identifier=42,
        nonce=b"R" * 32,
        *,
        context=b"PQ-DID/revreq/v1",
        metadata=None,
        signer=None,
    ):
        message = record(
            "revreq",
            self.pp.suite,
            self.metadata if metadata is None else metadata,
            identifier.to_bytes(4, "big"),
            ref_bytes(state),
            nonce,
        )
        signature = (self.issuer if signer is None else signer).sign(message, context)
        return RevocationRequest(identifier, state.reference, nonce, signature)

    def manager_model(
        self,
        *,
        empty=False,
        allocated_count=2**20,
        epoch=None,
        consumed_nonces=frozenset(),
        limits=DEFAULT_MANAGER_LIMITS,
        signer=None,
        revoked=None,
    ):
        revoked = frozenset(
            ([] if empty else INSTANCES["alpha"]["states"]["old"]["revoked"])
            if revoked is None
            else revoked
        )
        epoch = (0 if empty else 7) if epoch is None else epoch
        tree = SparseReferenceTree(self.pp.suite, self.metadata, list(revoked))
        state = self.signed_state(tree.root, epoch)
        adapter = RecordingSigner(self.manager) if signer is None else signer
        model = ReferenceRevocationManager(
            self.pp,
            state=state,
            allocated_count=allocated_count,
            revoked=revoked,
            consumed_nonces=consumed_nonces,
            limits=limits,
            signer=adapter,
        )
        return model, adapter, tree

    def close(self):
        self.issuer.close()
        super().close()
