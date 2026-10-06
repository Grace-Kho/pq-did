"""Bounded holder-local UpdateWit reference (IV-C, VII-A.8), not wallet storage.

Public update records never contain the holder's secret/path. Expected parameters
and the certified identifier must come from the holder's trusted credential state.
No retrieval, signature fallback, retry, publication or freshness claim is made.
"""

from dataclasses import dataclass, replace
from enum import Enum

from pqdid import bounded_mldsa
from pqdid.codec import (
    PATH_BYTES,
    EncodingError,
    decode_record,
    decode_uint,
    encode_record,
    encode_uint,
    pack_sibling_path,
    require_bytes,
    require_uint,
    unpack_sibling_path,
)
from pqdid.credentials import SIGNATURE_BYTES
from pqdid.merkle import TREE_DEPTH, leaf_hash, node_hash, path_root
from pqdid.parameters import (
    PublicParameters,
    encode_instance_metadata,
    validate_parameters_structure,
)
from pqdid.public_checks import STATE_SIGNING_CONTEXT
from pqdid.statements import (
    RevocationState,
    build_state_message,
    decode_state,
    encode_state,
    encode_state_reference,
    validate_state_structure,
)
from pqdid.witnesses import AuthenticationWitness, validate_auth_witness

UPDATE_SIGNING_CONTEXT = b"PQ-DID/update/v1"
STATE_BYTES = 3427
UPDATE_RECORD_BYTES = 11162
MAX_UPDATE_RECORDS = 16
MAX_UPDATE_BYTES = MAX_UPDATE_RECORDS * UPDATE_RECORD_BYTES


@dataclass(frozen=True)
class PublicUpdate:
    old_state: RevocationState
    new_state: RevocationState
    revoked_identifier: int
    old_path: bytes
    signature: bytes


@dataclass(frozen=True, repr=False)
class WitnessCheckpoint:
    """Local private path/id paired with authenticated state; not a freshness token."""

    identifier: int
    path: bytes
    state: RevocationState


@dataclass(frozen=True)
class UpdateLimits:
    """Lowerable local admission limits, not cryptographic suite parameters."""

    records: int = MAX_UPDATE_RECORDS
    encoded_bytes: int = MAX_UPDATE_BYTES

    def __post_init__(self):
        if type(self.records) is not int or not 0 <= self.records <= MAX_UPDATE_RECORDS:
            raise EncodingError("unsupported update record allowance")
        if type(self.encoded_bytes) is not int or not 0 <= self.encoded_bytes <= MAX_UPDATE_BYTES:
            raise EncodingError("unsupported update byte allowance")


DEFAULT_UPDATE_LIMITS = UpdateLimits()


class UpdateStatus(Enum):
    UPDATED = "updated-at-target-state"
    REVOKED = "authenticated-revocation"
    INVALID_INPUT = "invalid-input"
    INVALID_HISTORY = "missing-or-inconsistent-history"
    RESOURCE_EXHAUSTED = "resource-exhausted"
    PROCESSING_FAILED = "processing-failed"


class UpdateReason(Enum):
    NONE = "none"
    ENCODING = "encoding-or-domain"
    STARTING_WITNESS = "invalid-starting-witness"
    HISTORY = "sequence-or-endpoints"
    AUTHENTICATION = "invalid-state-or-update-signature"
    TRANSITION = "invalid-zero-to-one-transition"
    RESULT_WITNESS = "invalid-resulting-witness"
    ADMISSION = "record-or-byte-allowance"
    SAMPLER = "bounded-signature-sampler-exhausted"
    MEMORY = "allocation-failure"
    RUNTIME = "unexpected-processing-failure"


@dataclass(frozen=True, repr=False)
class UpdateResult:
    status: UpdateStatus
    checkpoint: WitnessCheckpoint | None = None
    reason: UpdateReason = UpdateReason.NONE


@dataclass(frozen=True, repr=False)
class AuthenticationUpdateResult:
    status: UpdateStatus
    witness: AuthenticationWitness | None = None
    state: RevocationState | None = None
    reason: UpdateReason = UpdateReason.NONE


def _validate_update(pp: PublicParameters, update: PublicUpdate) -> None:
    if type(update) is not PublicUpdate:
        raise EncodingError("expected public update")
    validate_state_structure(pp, update.old_state)
    validate_state_structure(pp, update.new_state)
    require_uint(update.revoked_identifier, TREE_DEPTH)
    unpack_sibling_path(update.old_path)
    if len(require_bytes(update.signature)) != SIGNATURE_BYTES:
        raise EncodingError("incorrect update signature width")


def encode_update(pp: PublicParameters, update: PublicUpdate) -> bytes:
    """SPEC-001 transport: five fields; a single raw 960-byte path payload."""
    _validate_update(pp, update)
    return encode_record(
        "rupdate",
        (
            encode_state(pp, update.old_state),
            encode_state(pp, update.new_state),
            encode_uint(update.revoked_identifier, 4),
            update.old_path,
            update.signature,
        ),
    )


def decode_update(pp: PublicParameters, encoded: bytes) -> PublicUpdate:
    """Reject total and nested widths before decoding states or costly crypto."""
    if len(require_bytes(encoded)) != UPDATE_RECORD_BYTES:
        raise EncodingError("incorrect rupdate byte length")
    old, new, identifier, path, signature = decode_record(encoded, "rupdate")
    if (len(old), len(new), len(identifier), len(path), len(signature)) != (
        STATE_BYTES,
        STATE_BYTES,
        4,
        PATH_BYTES,
        SIGNATURE_BYTES,
    ):
        raise EncodingError("incorrect rupdate field widths")
    update = PublicUpdate(
        decode_state(pp, old), decode_state(pp, new), decode_uint(identifier, 4), path, signature
    )
    _validate_update(pp, update)
    return update


def build_update_message(pp: PublicParameters, update: PublicUpdate) -> bytes:
    """Exact six-field Mu; sign refs and public old path, never rupdate transport."""
    _validate_update(pp, update)
    return encode_record(
        "update",
        (
            pp.suite,
            encode_instance_metadata(pp, pp.metadata),
            encode_state_reference(pp, update.old_state.reference),
            encode_state_reference(pp, update.new_state.reference),
            encode_uint(update.revoked_identifier, 4),
            update.old_path,
        ),
    )


class _Failure(Exception):
    def __init__(self, status: UpdateStatus, reason: UpdateReason):
        super().__init__(reason.value)
        self.status, self.reason = status, reason


def _authenticate(pp: PublicParameters, message: bytes, signature: bytes, context: bytes) -> None:
    # The existing public Boolean verifier deliberately merges INVALID/EXHAUSTED.
    # Reuse its *same* bounded implementation once, retaining the internal status.
    result = bounded_mldsa._verify_diagnostic(
        pp.revocation_public_key, message, signature, context=context
    )
    if result.status is bounded_mldsa._Status.EXHAUSTED:
        raise _Failure(UpdateStatus.RESOURCE_EXHAUSTED, UpdateReason.SAMPLER)
    if result.status is not bounded_mldsa._Status.VALID:
        raise _Failure(UpdateStatus.INVALID_INPUT, UpdateReason.AUTHENTICATION)


def _state_auth(pp: PublicParameters, state: RevocationState) -> None:
    _authenticate(pp, build_state_message(pp, state), state.signature, STATE_SIGNING_CONTEXT)


def _ancestors(pp: PublicParameters, identifier: int, path: bytes) -> tuple[bytes, ...]:
    values = [leaf_hash(pp.domain, 1)]
    for j, sibling in enumerate(unpack_sibling_path(path)):
        left, right = (sibling, values[-1]) if (identifier >> j) & 1 else (values[-1], sibling)
        values.append(node_hash(pp.domain, j + 1, left, right))
    return tuple(values)


def update_witness(
    expected_parameters: PublicParameters,
    starting: WitnessCheckpoint,
    target: RevocationState,
    records: tuple[bytes, ...],
    *,
    limits: UpdateLimits = DEFAULT_UPDATE_LIMITS,
) -> UpdateResult:
    """Validate the complete batch; return a new checkpoint or no replacement.

    Equal references identify a logical state; every transported state signature
    is still verified, even if its bytes differ from another signature for that
    reference. Empty history is valid only for the same authenticated reference.
    No partial checkpoint is exposed, including when a later record fails.
    """
    try:
        if type(limits) is not UpdateLimits:
            raise EncodingError("expected update limits")
        limits.__post_init__()
        if type(records) is not tuple:
            raise EncodingError("immutable finite record tuple required")
        if len(records) > limits.records:
            return UpdateResult(UpdateStatus.RESOURCE_EXHAUSTED, reason=UpdateReason.ADMISSION)
        total = 0
        for encoded in records:
            total += len(require_bytes(encoded))
            if total > limits.encoded_bytes:
                return UpdateResult(UpdateStatus.RESOURCE_EXHAUSTED, reason=UpdateReason.ADMISSION)
            if len(encoded) != UPDATE_RECORD_BYTES:
                raise EncodingError("incorrect public update length")
        validate_parameters_structure(expected_parameters)
        pp = expected_parameters
        if type(starting) is not WitnessCheckpoint:
            raise EncodingError("expected private witness checkpoint")
        require_uint(starting.identifier, TREE_DEPTH)
        unpack_sibling_path(starting.path)
        validate_state_structure(pp, starting.state)
        validate_state_structure(pp, target)
        if target.epoch - starting.state.epoch != len(records):
            return UpdateResult(UpdateStatus.INVALID_HISTORY, reason=UpdateReason.HISTORY)
        updates = tuple(decode_update(pp, encoded) for encoded in records)
        previous = starting.state.reference
        for update in updates:
            if (
                update.old_state.reference != previous
                or update.new_state.epoch != previous.epoch + 1
            ):
                return UpdateResult(UpdateStatus.INVALID_HISTORY, reason=UpdateReason.HISTORY)
            previous = update.new_state.reference
        if previous != target.reference:
            return UpdateResult(UpdateStatus.INVALID_HISTORY, reason=UpdateReason.HISTORY)

        _state_auth(pp, starting.state)
        _state_auth(pp, target)
        if path_root(pp.domain, starting.identifier, 0, starting.path) != starting.state.root:
            return UpdateResult(UpdateStatus.INVALID_INPUT, reason=UpdateReason.STARTING_WITNESS)
        changed_ancestors = []
        for update in updates:
            _state_auth(pp, update.old_state)
            _state_auth(pp, update.new_state)
            _authenticate(
                pp, build_update_message(pp, update), update.signature, UPDATE_SIGNING_CONTEXT
            )
            ancestors = _ancestors(pp, update.revoked_identifier, update.old_path)
            if (
                path_root(pp.domain, update.revoked_identifier, 0, update.old_path)
                != update.old_state.root
                or ancestors[-1] != update.new_state.root
            ):
                return UpdateResult(UpdateStatus.INVALID_HISTORY, reason=UpdateReason.TRANSITION)
            changed_ancestors.append(ancestors)

        # Only after the complete public chain is valid may a private result be returned.
        siblings = unpack_sibling_path(starting.path)
        for update, ancestors in zip(updates, changed_ancestors, strict=True):
            if starting.identifier == update.revoked_identifier:
                return UpdateResult(UpdateStatus.REVOKED)
            siblings = tuple(
                ancestors[j]
                if ((starting.identifier >> j) ^ 1) == (update.revoked_identifier >> j)
                else siblings[j]
                for j in range(TREE_DEPTH)
            )
            candidate = pack_sibling_path(siblings)
            if path_root(pp.domain, starting.identifier, 0, candidate) != update.new_state.root:
                return UpdateResult(
                    UpdateStatus.INVALID_HISTORY, reason=UpdateReason.RESULT_WITNESS
                )
        checkpoint = WitnessCheckpoint(starting.identifier, pack_sibling_path(siblings), target)
        return UpdateResult(UpdateStatus.UPDATED, checkpoint)
    except _Failure as failure:
        return UpdateResult(failure.status, reason=failure.reason)
    except EncodingError:
        return UpdateResult(UpdateStatus.INVALID_INPUT, reason=UpdateReason.ENCODING)
    except MemoryError:
        return UpdateResult(UpdateStatus.RESOURCE_EXHAUSTED, reason=UpdateReason.MEMORY)
    except Exception:
        return UpdateResult(UpdateStatus.PROCESSING_FAILED, reason=UpdateReason.RUNTIME)


def update_authentication_witness(
    expected_parameters: PublicParameters,
    witness: AuthenticationWitness,
    starting_state: RevocationState,
    target_state: RevocationState,
    records: tuple[bytes, ...],
    *,
    limits: UpdateLimits = DEFAULT_UPDATE_LIMITS,
) -> AuthenticationUpdateResult:
    """Local immutable convenience wrapper: only path/state can change.

    This does not establish CredValid: use a previously validated holder-local
    credential/witness, and keep full authentication checks at presentation time.
    """
    try:
        validate_parameters_structure(expected_parameters)
        validate_auth_witness(expected_parameters.schema, witness)
        result = update_witness(
            expected_parameters,
            WitnessCheckpoint(witness.revocation_identifier, witness.path, starting_state),
            target_state,
            records,
            limits=limits,
        )
        if result.status is not UpdateStatus.UPDATED:
            return AuthenticationUpdateResult(result.status, reason=result.reason)
        return AuthenticationUpdateResult(
            result.status, replace(witness, path=result.checkpoint.path), result.checkpoint.state
        )
    except EncodingError:
        return AuthenticationUpdateResult(UpdateStatus.INVALID_INPUT, reason=UpdateReason.ENCODING)
    except MemoryError:
        return AuthenticationUpdateResult(
            UpdateStatus.RESOURCE_EXHAUSTED, reason=UpdateReason.MEMORY
        )
    except Exception:
        return AuthenticationUpdateResult(
            UpdateStatus.PROCESSING_FAILED, reason=UpdateReason.RUNTIME
        )
