"""Bounded in-memory manager reference (IV-B, VII-A.8); not a production service.

Trusted bootstrap imports permanent allocation/nonce state, not a new allocation
protocol. Signing is an explicit fail-closed dependency. Immutable snapshots and
a local compare-and-swap commit provide no persistence or distributed guarantee.
"""

from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from enum import Enum
from threading import BoundedSemaphore, Lock
from types import MappingProxyType
from typing import Protocol

from pqdid import bounded_mldsa
from pqdid.codec import (
    EncodingError,
    encode_record,
    encode_uint,
    pack_sibling_path,
    require_bytes,
    require_uint,
)
from pqdid.credentials import SIGNATURE_BYTES
from pqdid.merkle import TREE_DEPTH, default_subtree_roots, leaf_hash, node_hash, path_root
from pqdid.parameters import (
    PublicParameters,
    encode_instance_metadata,
    validate_parameters_structure,
)
from pqdid.public_checks import STATE_SIGNING_CONTEXT
from pqdid.statements import (
    RevocationState,
    StateReference,
    build_state_message,
    encode_state_reference,
    validate_state_reference,
    validate_state_structure,
)
from pqdid.verifier_state import CURRENT_CONTEXT, CurrentStateReply, build_current_message
from pqdid.witness_updates import (
    DEFAULT_UPDATE_LIMITS,
    UPDATE_RECORD_BYTES,
    UPDATE_SIGNING_CONTEXT,
    PublicUpdate,
    UpdateLimits,
    build_update_message,
    decode_update,
    encode_update,
)

REVOCATION_REQUEST_CONTEXT = b"PQ-DID/revreq/v1"
MAX_HISTORY = 32
MAX_REVOKED = 64
MAX_NONCES = 64
MAX_INFLIGHT = 2


class SigningStatus(Enum):
    SIGNED = "signed"
    UNSUPPORTED = "unsupported"
    EXHAUSTED = "exhausted"
    FAILED = "failed"


@dataclass(frozen=True)
class SigningResult:
    status: SigningStatus
    signature: bytes | None = None


class ManagerSigner(Protocol):
    def sign(self, message: bytes, context: bytes) -> SigningResult:
        """Exact pure ML-DSA role signing; production internals must be bounded."""
        ...


class UnsupportedManagerSigner:
    def sign(self, message: bytes, context: bytes) -> SigningResult:
        return SigningResult(SigningStatus.UNSUPPORTED)


class ManagerStatus(Enum):
    COMMITTED = "committed"
    CURRENT = "authenticated-ordered-current"
    PAGE = "public-update-page"
    INVALID_INPUT = "invalid-input"
    UNAUTHORISED = "invalid-issuer-authorisation"
    UNALLOCATED = "unallocated-identifier"
    ALREADY_REVOKED = "already-revoked"
    REPLAY = "consumed-request-nonce"
    CONFLICT = "obsolete-starting-state"
    BUSY = "local-concurrency-admission"
    RESOURCE_EXHAUSTED = "resource-exhausted"
    SIGNING_UNSUPPORTED = "signing-unsupported"
    SIGNING_FAILED = "signing-failed"
    INVALID_ARTEFACT = "invalid-completed-artefact"
    UNAVAILABLE = "history-unavailable-or-inconsistent"
    FAILURE = "processing-failure"


class ManagerError(Exception):
    """Fixed status only, without request/private data or partial published output."""

    def __init__(self, status: ManagerStatus):
        super().__init__(status.value)
        self.status = status


@dataclass(frozen=True)
class ManagerLimits:
    history: int = MAX_HISTORY
    revoked: int = MAX_REVOKED
    nonces: int = MAX_NONCES

    def __post_init__(self):
        for value, ceiling in (
            (self.history, MAX_HISTORY),
            (self.revoked, MAX_REVOKED),
            (self.nonces, MAX_NONCES),
        ):
            if type(value) is not int or not 0 <= value <= ceiling:
                raise EncodingError("unsupported manager storage allowance")


DEFAULT_MANAGER_LIMITS = ManagerLimits()


@dataclass(frozen=True, repr=False)
class RevocationRequest:
    """Local typed arguments rid/ref plus the specified req=(nonce,signature)."""

    identifier: int
    reference: StateReference
    nonce: bytes
    signature: bytes


@dataclass(frozen=True)
class RevocationResult:
    status: ManagerStatus
    state: RevocationState | None = None
    record: bytes | None = None


@dataclass(frozen=True)
class CurrentResult:
    status: ManagerStatus
    reply: CurrentStateReply | None = None


@dataclass(frozen=True)
class UpdatePage:
    starting_state: RevocationState
    endpoint_state: RevocationState
    records: tuple[bytes, ...]
    requested_epoch: int

    @property
    def next_epoch(self) -> int:
        return self.endpoint_state.epoch

    @property
    def complete(self) -> bool:
        return self.next_epoch == self.requested_epoch


@dataclass(frozen=True)
class HistoryResult:
    status: ManagerStatus
    page: UpdatePage | None = None


def _nonce(value: bytes) -> bytes:
    if len(require_bytes(value)) != 32:
        raise EncodingError("nonce must contain 32 immutable bytes")
    return value


def build_revocation_request_message(pp: PublicParameters, request: RevocationRequest) -> bytes:
    """R-030 MR, not a new request wire format; signature remains outside MR."""
    validate_parameters_structure(pp)
    if type(request) is not RevocationRequest:
        raise EncodingError("expected revocation request")
    require_uint(request.identifier, TREE_DEPTH)
    validate_state_reference(pp, request.reference)
    _nonce(request.nonce)
    if len(require_bytes(request.signature)) != SIGNATURE_BYTES:
        raise EncodingError("incorrect request signature width")
    return encode_record(
        "revreq",
        (
            pp.suite,
            encode_instance_metadata(pp, pp.metadata),
            encode_uint(request.identifier, 4),
            encode_state_reference(pp, request.reference),
            request.nonce,
        ),
    )


def _verify(key: bytes, message: bytes, signature: bytes, context: bytes, failure: ManagerStatus):
    # Same bounded core used by StateAuth/holder updates; retain exhaustion separately.
    result = bounded_mldsa._verify_diagnostic(key, message, signature, context=context)
    if result.status is bounded_mldsa._Status.EXHAUSTED:
        raise ManagerError(ManagerStatus.RESOURCE_EXHAUSTED)
    if result.status is not bounded_mldsa._Status.VALID:
        raise ManagerError(failure)


@dataclass(frozen=True, repr=False)
class _Tree:
    defaults: tuple[bytes, ...]
    layers: tuple[Mapping[int, bytes], ...]

    @property
    def root(self):
        return self.layers[TREE_DEPTH].get(0, self.defaults[TREE_DEPTH])

    def path(self, identifier: int) -> bytes:
        return pack_sibling_path(
            tuple(
                self.layers[j].get((identifier >> j) ^ 1, self.defaults[j])
                for j in range(TREE_DEPTH)
            )
        )

    def revoke(self, pp: PublicParameters, identifier: int):
        """Copy the bounded sparse maps; old maps remain immutable and unaliased."""
        layers = [dict(layer) for layer in self.layers]
        value = leaf_hash(pp.domain, 1)
        layers[0][identifier] = value
        for j in range(TREE_DEPTH):
            index = identifier >> j
            sibling = layers[j].get(index ^ 1, self.defaults[j])
            left, right = (sibling, value) if index & 1 else (value, sibling)
            value = node_hash(pp.domain, j + 1, left, right)
            layers[j + 1][index >> 1] = value
        return _Tree(self.defaults, tuple(MappingProxyType(layer) for layer in layers))

    @classmethod
    def build(cls, pp: PublicParameters, revoked: frozenset[int]):
        tree = cls(
            default_subtree_roots(pp.domain),
            tuple(MappingProxyType({}) for _ in range(TREE_DEPTH + 1)),
        )
        for identifier in sorted(revoked):
            tree = tree.revoke(pp, identifier)
        return tree


@dataclass(frozen=True, repr=False)
class ManagerSnapshot:
    """Manager-local inspection only, NOT the public state/update interface."""

    state: RevocationState
    base_state: RevocationState
    allocated_count: int
    revoked: frozenset[int]
    consumed_nonces: frozenset[bytes]
    history: tuple[bytes, ...]
    tree: _Tree


class ReferenceRevocationManager:
    def __init__(
        self,
        parameters: PublicParameters,
        *,
        state: RevocationState,
        allocated_count: int,
        revoked: frozenset[int],
        consumed_nonces: frozenset[bytes],
        signer: ManagerSigner | None = None,
        limits: ManagerLimits = DEFAULT_MANAGER_LIMITS,
    ):
        """Import a trusted local checkpoint. No allocation, signing or history eviction.

        Registration is the permanent prefix [0,allocated_count), including aborted
        issuance. The caller must supply the complete retained consumed-nonce set.
        Earlier update records are unavailable here, not claimed to be reconstructed.
        """
        validate_parameters_structure(parameters)
        validate_state_structure(parameters, state)
        if type(limits) is not ManagerLimits:
            raise EncodingError("expected manager limits")
        limits.__post_init__()
        if type(allocated_count) is not int or not 0 <= allocated_count <= 1 << TREE_DEPTH:
            raise EncodingError("invalid permanent allocation counter")
        if type(revoked) is not frozenset or type(consumed_nonces) is not frozenset:
            raise EncodingError("immutable bootstrap sets required")
        if len(revoked) > limits.revoked or len(consumed_nonces) > limits.nonces:
            raise ManagerError(ManagerStatus.RESOURCE_EXHAUSTED)
        for identifier in revoked:
            require_uint(identifier, TREE_DEPTH)
            if identifier >= allocated_count:
                raise EncodingError("revoked identifier was not allocated")
        for nonce in consumed_nonces:
            _nonce(nonce)
        _verify(
            parameters.revocation_public_key,
            build_state_message(parameters, state),
            state.signature,
            STATE_SIGNING_CONTEXT,
            ManagerStatus.INVALID_ARTEFACT,
        )
        tree = _Tree.build(parameters, revoked)
        if tree.root != state.root:
            raise ManagerError(ManagerStatus.INVALID_ARTEFACT)
        self._parameters, self._limits = parameters, limits
        self._signer = signer if signer is not None else UnsupportedManagerSigner()
        self._lock, self._operations = Lock(), BoundedSemaphore(MAX_INFLIGHT)
        self._snapshot = ManagerSnapshot(
            state, state, allocated_count, revoked, consumed_nonces, (), tree
        )

    @property
    def parameters(self):
        return self._parameters

    @contextmanager
    def _operation(self):
        if not self._operations.acquire(blocking=False):
            raise ManagerError(ManagerStatus.BUSY)
        try:
            yield
        finally:
            self._operations.release()

    @contextmanager
    def _locked(self):
        if not self._lock.acquire(blocking=False):
            raise ManagerError(ManagerStatus.BUSY)
        try:
            yield
        finally:
            self._lock.release()

    def snapshot(self) -> ManagerSnapshot:
        """Local administrative inspection; no mutable alias or holder query."""
        with self._locked():
            return self._snapshot

    def _sign(self, message: bytes, context: bytes) -> bytes:
        try:
            result = self._signer.sign(message, context)
        except MemoryError:
            raise
        except Exception:
            raise ManagerError(ManagerStatus.SIGNING_FAILED) from None
        if type(result) is not SigningResult:
            raise ManagerError(ManagerStatus.SIGNING_FAILED)
        if result.status is SigningStatus.EXHAUSTED:
            raise ManagerError(ManagerStatus.RESOURCE_EXHAUSTED)
        if result.status is SigningStatus.UNSUPPORTED:
            raise ManagerError(ManagerStatus.SIGNING_UNSUPPORTED)
        if result.status is not SigningStatus.SIGNED:
            raise ManagerError(ManagerStatus.SIGNING_FAILED)
        if type(result.signature) is not bytes or len(result.signature) != SIGNATURE_BYTES:
            raise ManagerError(ManagerStatus.INVALID_ARTEFACT)
        _verify(
            self.parameters.revocation_public_key,
            message,
            result.signature,
            context,
            ManagerStatus.INVALID_ARTEFACT,
        )
        return result.signature

    def revoke(self, request: RevocationRequest) -> RevocationResult:
        try:
            with self._operation():
                return self._revoke(request)
        except ManagerError as error:
            return RevocationResult(error.status)
        except EncodingError:
            return RevocationResult(ManagerStatus.INVALID_INPUT)
        except MemoryError:
            return RevocationResult(ManagerStatus.RESOURCE_EXHAUSTED)
        except Exception:
            return RevocationResult(ManagerStatus.FAILURE)

    def _revoke(self, request: RevocationRequest) -> RevocationResult:
        pp = self.parameters
        message = build_revocation_request_message(pp, request)
        old = self.snapshot()
        if request.reference != old.state.reference:
            raise ManagerError(ManagerStatus.CONFLICT)
        if request.identifier >= old.allocated_count:
            raise ManagerError(ManagerStatus.UNALLOCATED)
        if request.nonce in old.consumed_nonces:
            raise ManagerError(ManagerStatus.REPLAY)
        if request.identifier in old.revoked:
            raise ManagerError(ManagerStatus.ALREADY_REVOKED)
        if (
            old.state.epoch == (1 << 64) - 1
            or len(old.history) >= self._limits.history
            or len(old.revoked) >= self._limits.revoked
            or len(old.consumed_nonces) >= self._limits.nonces
        ):
            raise ManagerError(ManagerStatus.RESOURCE_EXHAUSTED)
        _verify(
            pp.issuer_public_key,
            message,
            request.signature,
            REVOCATION_REQUEST_CONTEXT,
            ManagerStatus.UNAUTHORISED,
        )

        path = old.tree.path(request.identifier)
        tree = old.tree.revoke(pp, request.identifier)
        if (
            path_root(pp.domain, request.identifier, 0, path) != old.state.root
            or path_root(pp.domain, request.identifier, 1, path) != tree.root
        ):
            raise ManagerError(ManagerStatus.INVALID_ARTEFACT)
        state = RevocationState(
            pp.namespace, old.state.epoch + 1, tree.root, bytes(SIGNATURE_BYTES)
        )
        state = replace(
            state, signature=self._sign(build_state_message(pp, state), STATE_SIGNING_CONTEXT)
        )
        update = PublicUpdate(old.state, state, request.identifier, path, bytes(SIGNATURE_BYTES))
        update = replace(
            update, signature=self._sign(build_update_message(pp, update), UPDATE_SIGNING_CONTEXT)
        )
        encoded = encode_update(pp, update)
        try:
            decoded = decode_update(pp, encoded)
        except EncodingError:
            raise ManagerError(ManagerStatus.INVALID_ARTEFACT) from None
        if decoded != update:
            raise ManagerError(ManagerStatus.INVALID_ARTEFACT)
        candidate = ManagerSnapshot(
            state,
            old.base_state,
            old.allocated_count,
            old.revoked | {request.identifier},
            old.consumed_nonces | {request.nonce},
            (*old.history, encoded),
            tree,
        )
        result = RevocationResult(ManagerStatus.COMMITTED, state, encoded)
        # All allocation, signing and validation precede the sole effective commit.
        with self._locked():
            if self._snapshot is not old:
                raise ManagerError(ManagerStatus.CONFLICT)
            self._snapshot = candidate
        return result

    def read_current(self, nonce: bytes) -> CurrentResult:
        try:
            with self._operation():
                _nonce(nonce)
                old = self.snapshot()
                message = build_current_message(self.parameters, nonce, old.state)
                signature = self._sign(message, CURRENT_CONTEXT)
                result = CurrentResult(
                    ManagerStatus.CURRENT, CurrentStateReply(nonce, old.state, signature)
                )
                with self._locked():
                    if self._snapshot is not old:
                        raise ManagerError(ManagerStatus.CONFLICT)
                    # Ordered read linearises here; later updates cannot undo it.
                    return result
        except ManagerError as error:
            return CurrentResult(error.status)
        except EncodingError:
            return CurrentResult(ManagerStatus.INVALID_INPUT)
        except MemoryError:
            return CurrentResult(ManagerStatus.RESOURCE_EXHAUSTED)
        except Exception:
            return CurrentResult(ManagerStatus.FAILURE)

    def updates(
        self,
        namespace: bytes,
        after_epoch: int,
        target_epoch: int,
        *,
        limits: UpdateLimits = DEFAULT_UPDATE_LIMITS,
    ) -> HistoryResult:
        """Public namespace/version retrieval only; exact target, explicit continuation."""
        try:
            with self._operation():
                if require_bytes(namespace) != self.parameters.namespace:
                    raise EncodingError("wrong namespace")
                require_uint(after_epoch, 64)
                require_uint(target_epoch, 64)
                if after_epoch > target_epoch or type(limits) is not UpdateLimits:
                    raise EncodingError("invalid public range or limits")
                limits.__post_init__()
                snapshot = self.snapshot()
                if (
                    not snapshot.base_state.epoch
                    <= after_epoch
                    <= target_epoch
                    <= snapshot.state.epoch
                ):
                    raise ManagerError(ManagerStatus.UNAVAILABLE)
                # Scan at most 32 immutable records. Detect a gap instead of omitting it.
                states = [snapshot.base_state]
                if len(snapshot.history) != snapshot.state.epoch - snapshot.base_state.epoch:
                    raise ManagerError(ManagerStatus.UNAVAILABLE)
                for encoded in snapshot.history:
                    try:
                        update = decode_update(self.parameters, encoded)
                    except EncodingError:
                        raise ManagerError(ManagerStatus.UNAVAILABLE) from None
                    if (
                        update.old_state.reference != states[-1].reference
                        or update.new_state.epoch != states[-1].epoch + 1
                    ):
                        raise ManagerError(ManagerStatus.UNAVAILABLE)
                    states.append(update.new_state)
                if states[-1] != snapshot.state:
                    raise ManagerError(ManagerStatus.UNAVAILABLE)
                count = min(
                    target_epoch - after_epoch,
                    limits.records,
                    limits.encoded_bytes // UPDATE_RECORD_BYTES,
                )
                if not count and target_epoch != after_epoch:
                    raise ManagerError(ManagerStatus.RESOURCE_EXHAUSTED)
                start = after_epoch - snapshot.base_state.epoch
                end = start + count
                return HistoryResult(
                    ManagerStatus.PAGE,
                    UpdatePage(
                        states[start],
                        states[end],
                        snapshot.history[start:end],
                        target_epoch,
                    ),
                )
        except ManagerError as error:
            return HistoryResult(error.status)
        except EncodingError:
            return HistoryResult(ManagerStatus.INVALID_INPUT)
        except MemoryError:
            return HistoryResult(ManagerStatus.RESOURCE_EXHAUSTED)
        except Exception:
            return HistoryResult(ManagerStatus.FAILURE)

    # Existing verifier provider interface: configured instance trust only.
    # DID registry support is absent and fails closed.
    def instance(self, expected: PublicParameters) -> PublicParameters | None:
        return self.parameters if expected == self.parameters else None

    def current(self, expected: PublicParameters, nonce: bytes) -> CurrentStateReply | None:
        if expected != self.parameters:
            return None
        result = self.read_current(nonce)
        if result.status is ManagerStatus.RESOURCE_EXHAUSTED:
            raise MemoryError("bounded current-state resource failure")
        return result.reply

    def resolve_did(self, did: bytes, version: bytes):
        return None
