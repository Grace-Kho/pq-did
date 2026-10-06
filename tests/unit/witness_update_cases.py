"""Independent sparse-tree/update-message construction; test-only native signing.

No production update algorithm or encoder derives the expected roots/paths/bytes.
Ephemeral service keys come from the existing labelled lifecycle fixture helper.
"""

from dataclasses import dataclass

from pqdid.statements import RevocationState

from .binding_merkle_reference import SparseReferenceTree, record
from .relation_cases import INSTANCES
from .verifier_state_cases import TestAuthority


def state_bytes(state):
    return record(
        "rstate", state.namespace, state.epoch.to_bytes(8, "big"), state.root, state.signature
    )


def ref_bytes(state):
    return record("rref", state.namespace, state.epoch.to_bytes(8, "big"), state.root)


@dataclass(frozen=True)
class History:
    trees: tuple
    states: tuple
    records: tuple[bytes, ...]


class UpdateAuthority(TestAuthority):
    __test__ = False

    def signed_state(self, root, epoch, namespace=None):
        signature = self.manager.sign(
            record("state", self.pp.suite, self.metadata, epoch.to_bytes(8, "big"), root),
            b"PQ-DID/state/v1",
        )
        return RevocationState(
            self.pp.namespace if namespace is None else namespace, epoch, root, signature
        )

    def public_update(
        self,
        old,
        new,
        identifier,
        path,
        *,
        context=b"PQ-DID/update/v1",
        metadata=None,
        sign_transport=False,
    ):
        message = record(
            "update",
            self.pp.suite,
            self.metadata if metadata is None else metadata,
            ref_bytes(old),
            ref_bytes(new),
            identifier.to_bytes(4, "big"),
            path,
        )
        if sign_transport:
            message = record(
                "rupdate",
                state_bytes(old),
                state_bytes(new),
                identifier.to_bytes(4, "big"),
                path,
                bytes(3309),
            )
        signature = self.manager.sign(message, context)
        return record(
            "rupdate",
            state_bytes(old),
            state_bytes(new),
            identifier.to_bytes(4, "big"),
            path,
            signature,
        )

    def history(self, additions, *, empty=False, initial=None, epoch=None):
        revoked = [] if empty else list(INSTANCES["alpha"]["states"]["old"]["revoked"])
        if initial is not None:
            revoked = list(initial)
        epoch = (0 if empty else 7) if epoch is None else epoch
        trees = [SparseReferenceTree(self.pp.suite, self.metadata, revoked)]
        states = [self.signed_state(trees[0].root, epoch)]
        records = []
        for identifier in additions:
            next_tree = SparseReferenceTree(self.pp.suite, self.metadata, [*revoked, identifier])
            next_state = self.signed_state(next_tree.root, states[-1].epoch + 1)
            records.append(
                self.public_update(states[-1], next_state, identifier, trees[-1].path(identifier))
            )
            trees.append(next_tree)
            states.append(next_state)
            revoked.append(identifier)
        return History(tuple(trees), tuple(states), tuple(records))
