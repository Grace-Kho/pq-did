"""Synthetic integration inputs; retained credential plus fresh bounded manager key."""

from dataclasses import replace

from experiments.kyc_milestone_1.baseline.scenario import _OwnerGate
from experiments.kyc_milestone_1.baseline.signing import Key
from pqdid.credentials import decode_credential
from pqdid.issuance import HolderAcceptance, IssuedCredential, IssueStatus
from pqdid.parameters import encode_instance_metadata
from pqdid.recovery_records import Role
from pqdid.revocation_state import SigningStatus
from pqdid.signing_adapters import ManagerSigningAdapter, TrustedSigningKey
from pqdid.statements import RevocationState
from pqdid.witness_updates import PublicUpdate, WitnessCheckpoint, encode_update
from tests.unit.binding_merkle_reference import SparseReferenceTree
from tests.unit.relation_cases import CREDENTIALS, INSTANCES, enrol_case


class WalletFixture:
    def __init__(self):
        pp, statement, witness = enrol_case()
        pair = Key.generate()
        self.pp = replace(pp, revocation_public_key=pair.public)
        key = TrustedSigningKey(self.pp, b"M" * 32, Role.MANAGER, b"M", pair.public, pair.secret)
        signer = ManagerSigningAdapter(key, authorisation=_OwnerGate(key))
        revoked = INSTANCES["alpha"]["states"]["old"]["revoked"]
        meta = encode_instance_metadata(self.pp, self.pp.metadata)
        trees = [
            SparseReferenceTree(pp.suite, meta, list(revoked)),
            SparseReferenceTree(pp.suite, meta, [*revoked, 43]),
        ]
        self.states = []
        for i, tree in enumerate(trees):
            blank = RevocationState(pp.namespace, 7 + i, tree.root, bytes(3309))
            result = signer.state(self.pp, blank)
            assert result.status is SigningStatus.SIGNED
            self.states.append(replace(blank, signature=result.signature))
        update = PublicUpdate(*self.states, 43, trees[0].path(43), bytes(3309))
        result = signer.update(self.pp, update)
        assert result.status is SigningStatus.SIGNED
        self.records = (encode_update(self.pp, replace(update, signature=result.signature)),)
        self.secret = witness.holder_secret
        self.credential = decode_credential(
            self.pp, bytes.fromhex(CREDENTIALS["alpha-42"]["encoded"])
        )
        statement = replace(statement, parameters=self.pp, state=self.states[0])
        self.accepted = HolderAcceptance(
            self.pp, self.secret, self.credential.attributes, statement
        )
        issued = IssuedCredential(
            self.credential, WitnessCheckpoint(42, trees[0].path(42), self.states[0])
        )
        assert self.accepted.accept(issued).status is IssueStatus.ACCEPTED
        self.expected_path = trees[1].path(42)
