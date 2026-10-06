"""Bounded DID method reference (IV-B, VII-A.1–4), not a network service.

Trusted configuration pins the whole issuer instance and registry. Controller and
registry signatures are verified by the existing bounded ML-DSA reference. Signers
default to unsupported. No key generation, holder secret, proof or cache is here.
"""

import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from threading import BoundedSemaphore, Lock
from typing import Protocol

from pqdid import bounded_mldsa
from pqdid.codec import EncodingError, decode_record, decode_uint, encode_record, require_bytes
from pqdid.issuance import ControllerResolution
from pqdid.parameters import PublicParameters, validate_parameters_structure
from pqdid.revocation_state import (
    MAX_HISTORY,
    MAX_INFLIGHT,
    MAX_NONCES,
    ManagerSigner,
    SigningResult,
    SigningStatus,
    UnsupportedManagerSigner,
)
from pqdid.verifier_state import (
    CurrentStateReply,
    NonceSource,
    ResolvedDID,
    SystemNonces,
    TrustedPublicProvider,
)

RECORD_CONTEXT = b"PQ-DID/did-record/v1"
READ_CONTEXT = b"PQ-DID/did-read/v1"
MAX_RECORD_BYTES = 8192
MAX_READ_BYTES = MAX_HISTORY * (MAX_RECORD_BYTES + 4) + 1024
ZERO_DIGEST = bytes(48)
_DID = re.compile(rb"did:pqdid:[0-9a-f]{64}:[0-9a-f]{96}")


class DIDStatus(Enum):
    ACTIVE = "authenticated-active-endpoint"
    DEACTIVATED = "authenticated-inactive-endpoint"
    UNKNOWN = "authenticated-absence"
    COMMITTED = "committed"
    CONFIRMED = "confirmed-publication"
    CONFLICT = "different-current-predecessor"
    INVALID = "invalid-input"
    UNAUTHORISED = "invalid-controller-signature"
    MISMATCH = "different-trusted-instance-or-registry"
    INCONSISTENT = "invalid-registry-response"
    UNAVAILABLE = "unavailable-dependency"
    UNSUPPORTED = "unsupported-operation-or-signer"
    EXHAUSTED = "resource-exhausted"
    BUSY = "local-concurrency-admission"


class DIDError(Exception):
    def __init__(self, status: DIDStatus):
        super().__init__(status.value)  # No input/credential/key material in errors.
        self.status = status


def _fixed(value, length):
    if len(require_bytes(value)) != length:
        raise EncodingError("incorrect DID field length")
    return value


def _version(value):
    _fixed(value, 56)
    if int.from_bytes(value[:8], "big") >= 1 << 16:
        raise EncodingError("DID index outside method domain")
    return value


def _key(public_key):
    _fixed(public_key, 1952)
    # Reuse the existing FIPS decoder and ALL 30 bounded matrix expansions.
    # No native fallback or new public-key validity predicate is introduced.
    rho, _ = bounded_mldsa._decode_public_key(public_key)
    try:
        bounded_mldsa._expand_a(rho)
    except bounded_mldsa._SamplerExhausted as error:
        raise DIDError(DIDStatus.EXHAUSTED) from error


def _verify(public_key, message, signature, context, invalid):
    result = bounded_mldsa._verify_diagnostic(public_key, message, signature, context=context)
    if result.status is bounded_mldsa._Status.EXHAUSTED:
        raise DIDError(DIDStatus.EXHAUSTED)
    if result.status is not bounded_mldsa._Status.VALID:
        raise DIDError(invalid)


def _sign(signer, key, message, context):
    result = signer.sign(message, context)
    if type(result) is not SigningResult:
        raise DIDError(DIDStatus.UNAVAILABLE)
    if result.status is SigningStatus.UNSUPPORTED:
        raise DIDError(DIDStatus.UNSUPPORTED)
    if result.status is SigningStatus.EXHAUSTED:
        raise DIDError(DIDStatus.EXHAUSTED)
    if result.status is not SigningStatus.SIGNED:
        raise DIDError(DIDStatus.UNAVAILABLE)
    _verify(key, message, result.signature, context, DIDStatus.UNAUTHORISED)
    return result.signature


def _failure(error):
    if isinstance(error, DIDError):
        return error.status
    if isinstance(error, MemoryError):
        return DIDStatus.EXHAUSTED
    if isinstance(error, EncodingError):
        return DIDStatus.INVALID
    return DIDStatus.UNAVAILABLE


@dataclass(frozen=True)
class DIDLimits:
    """Lower local admissions; method index space remains 0..65535."""

    records: int = MAX_HISTORY  # Total retained records across ALL DIDs, never evict.
    reads: int = MAX_NONCES  # Lifetime resolver nonce history, never evict.
    nonce_draws: int = 8

    def __post_init__(self):
        for value, bound in (
            (self.records, MAX_HISTORY),
            (self.reads, MAX_NONCES),
            (self.nonce_draws, 100),
        ):
            if type(value) is not int or not 1 <= value <= bound:
                raise EncodingError("unsupported DID admission limit")


DEFAULT_DID_LIMITS = DIDLimits()


@dataclass(frozen=True, repr=False)
class DIDConfiguration:
    parameters: PublicParameters
    registry_id: bytes
    registry_public_key: bytes

    def __post_init__(self):
        validate_parameters_structure(self.parameters)
        _fixed(self.registry_id, 32)
        _key(self.registry_public_key)


def validate_did(config: DIDConfiguration, did: bytes):
    require_bytes(did)
    if len(did) > 171:
        raise EncodingError("DID input exceeds method length")
    if did.startswith(b"did:") and not did.startswith(b"did:pqdid:"):
        raise DIDError(DIDStatus.UNSUPPORTED)
    if _DID.fullmatch(did) is None:
        raise EncodingError("non-canonical DID")
    if did[10:74] != config.registry_id.hex().encode("ascii"):
        raise DIDError(DIDStatus.MISMATCH)


def make_did(config: DIDConfiguration, public_key: bytes, salt: bytes) -> bytes:
    """Derive an identifier from supplied validated key/salt; does not generate keys."""
    _key(public_key)
    _fixed(salt, 32)
    digest = (
        hashlib.sha3_384(
            encode_record("did-id", (config.parameters.suite, config.registry_id, public_key, salt))
        )
        .hexdigest()
        .encode("ascii")
    )
    return b"did:pqdid:" + config.registry_id.hex().encode("ascii") + b":" + digest


@dataclass(frozen=True, repr=False)
class DIDBody:
    registry_id: bytes
    did: bytes
    index: int
    predecessor: bytes
    controller_key: bytes
    active: int
    salt: bytes

    def __post_init__(self):
        _fixed(self.registry_id, 32)
        if _DID.fullmatch(_fixed(self.did, 171)) is None:
            raise EncodingError("non-canonical DID")
        if type(self.index) is not int or not 0 <= self.index < 1 << 16:
            raise EncodingError("invalid DID record index")
        _fixed(self.predecessor, 48)
        _fixed(self.controller_key, 1952)
        if type(self.active) is not int or self.active not in (0, 1):
            raise EncodingError("invalid DID activity flag")
        _fixed(self.salt, 32)


def encode_body(body: DIDBody) -> bytes:
    if type(body) is not DIDBody:
        raise EncodingError("expected DID body")
    body.__post_init__()
    return encode_record(
        "did-body",
        (
            body.registry_id,
            body.did,
            body.index.to_bytes(8, "big"),
            body.predecessor,
            body.controller_key,
            bytes((body.active,)),
            body.salt,
        ),
    )


@dataclass(frozen=True, repr=False)
class DIDRecord:
    body: DIDBody
    signature: bytes

    def __post_init__(self):
        encode_body(self.body)
        _fixed(self.signature, 3309)

    @property
    def version(self) -> bytes:
        return (
            self.body.index.to_bytes(8, "big") + hashlib.sha3_384(encode_did_record(self)).digest()
        )


def encode_did_record(record: DIDRecord) -> bytes:
    if type(record) is not DIDRecord:
        raise EncodingError("expected DID record")
    return encode_record("did-record", (encode_body(record.body), _fixed(record.signature, 3309)))


def decode_did_record(encoded: bytes) -> DIDRecord:
    if len(require_bytes(encoded)) > MAX_RECORD_BYTES:
        raise DIDError(DIDStatus.EXHAUSTED)
    body, signature = decode_record(encoded, "did-record")
    gamma, did, index, predecessor, key, active, salt = decode_record(body, "did-body")
    return DIDRecord(
        DIDBody(gamma, did, decode_uint(index, 8), predecessor, key, decode_uint(active, 1), salt),
        signature,
    )


def _transition(config, record, previous):
    body = record.body
    validate_did(config, body.did)
    if body.registry_id != config.registry_id:
        raise DIDError(DIDStatus.MISMATCH)
    _key(body.controller_key)
    if previous is None:
        if (
            body.index != 0
            or body.predecessor != ZERO_DIGEST
            or body.active != 1
            or make_did(config, body.controller_key, body.salt) != body.did
        ):
            raise DIDError(DIDStatus.INCONSISTENT)
        signing_key = body.controller_key
    else:
        old = previous.body
        if (
            old.active != 1
            or body.index != old.index + 1
            or body.did != old.did
            or body.salt != old.salt
            or body.predecessor != previous.version[8:]
            or (body.active == 0 and body.controller_key != old.controller_key)
        ):
            raise DIDError(DIDStatus.INCONSISTENT)
        signing_key = old.controller_key
    _verify(
        signing_key, encode_body(body), record.signature, RECORD_CONTEXT, DIDStatus.UNAUTHORISED
    )


def _selector(selector):
    require_bytes(selector)
    if selector == b"\x00":
        return None
    if len(selector) == 57 and selector[:1] == b"\x01":
        return _version(selector[1:])
    raise DIDError(DIDStatus.UNSUPPORTED)


@dataclass(frozen=True, repr=False)
class RegistryReply:
    message: bytes
    signature: bytes


class RegistryTransport(Protocol):
    def read(self, did: bytes, selector: bytes, nonce: bytes) -> RegistryReply:
        """Trusted ordered read; remote adapters must preserve that service contract."""
        ...

    def append(self, encoded: bytes, expected: bytes | None) -> DIDStatus: ...


class ReferenceDIDRegistry:
    """Atomic in-process append and ordered reads, retaining every committed record.

    A read linearises at the locked snapshot, before signing. Concurrent writes may
    finish before delivery; signatures alone cannot establish service ordering.
    """

    def __init__(
        self,
        config: DIDConfiguration,
        *,
        signer: ManagerSigner | None = None,
        limits: DIDLimits = DEFAULT_DID_LIMITS,
    ):
        if type(config) is not DIDConfiguration or type(limits) is not DIDLimits:
            raise EncodingError("expected trusted DID configuration/limits")
        self.config, self.limits = config, limits
        self.signer = signer if signer is not None else UnsupportedManagerSigner()
        self._histories: dict[bytes, tuple[DIDRecord, ...]] = {}
        self._lock, self._slots = Lock(), BoundedSemaphore(MAX_INFLIGHT)

    def snapshot(self) -> tuple[tuple[bytes, tuple[DIDRecord, ...]], ...]:
        with self._lock:
            return tuple(sorted(self._histories.items()))

    def append(self, encoded: bytes, expected: bytes | None) -> DIDStatus:
        if not self._slots.acquire(blocking=False):
            return DIDStatus.BUSY
        try:
            if expected is not None:
                _version(expected)
            record = decode_did_record(encoded)
            did = record.body.did
            with self._lock:
                before = self._histories.get(did, ())
            previous = before[-1] if before else None
            if expected != (previous.version if previous else None):
                return DIDStatus.CONFLICT
            _transition(self.config, record, previous)
            after = (*before, record)
            with self._lock:
                if self._histories.get(did, ()) != before:
                    return DIDStatus.CONFLICT
                if sum(map(len, self._histories.values())) >= self.limits.records:
                    return DIDStatus.EXHAUSTED
                # Copy before assignment: allocation failure cannot partly change state.
                histories = {**self._histories, did: after}
                self._histories = histories
            return DIDStatus.COMMITTED
        except Exception as error:
            return _failure(error)
        finally:
            self._slots.release()

    def read(self, did: bytes, selector: bytes, nonce: bytes) -> RegistryReply:
        if not self._slots.acquire(blocking=False):
            raise DIDError(DIDStatus.BUSY)
        try:
            validate_did(self.config, did)
            version = _selector(selector)
            _fixed(nonce, 32)
            with self._lock:
                chain = self._histories.get(did, ())
                if version is not None:
                    index = int.from_bytes(version[:8], "big")
                    chain = (
                        chain[: index + 1]
                        if index < len(chain) and chain[index].version == version
                        else ()
                    )
            message = encode_record(
                "did-read",
                (
                    self.config.registry_id,
                    did,
                    selector,
                    nonce,
                    bytes((0 if chain else 1,)),
                    encode_record("did-chain", tuple(encode_did_record(r) for r in chain)),
                ),
            )
            signature = _sign(self.signer, self.config.registry_public_key, message, READ_CONTEXT)
            return RegistryReply(message, signature)
        except Exception as error:
            raise DIDError(_failure(error)) from error
        finally:
            self._slots.release()


@dataclass(frozen=True, repr=False)
class DIDResolution:
    status: DIDStatus
    chain: tuple[DIDRecord, ...] = ()
    document: ResolvedDID | None = None


class ReferenceDIDResolver:
    def __init__(
        self,
        config: DIDConfiguration,
        transport: RegistryTransport,
        *,
        nonces: NonceSource | None = None,
        limits: DIDLimits = DEFAULT_DID_LIMITS,
    ):
        if type(config) is not DIDConfiguration or type(limits) is not DIDLimits:
            raise EncodingError("expected trusted DID configuration/limits")
        self.config, self.transport, self.limits = config, transport, limits
        self.nonces = nonces if nonces is not None else SystemNonces()
        self._used: set[bytes] = set()
        self._lock, self._slots = Lock(), BoundedSemaphore(MAX_INFLIGHT)

    def _nonce(self):
        with self._lock:
            if len(self._used) >= self.limits.reads:
                raise DIDError(DIDStatus.EXHAUSTED)
            for _ in range(self.limits.nonce_draws):
                nonce = _fixed(self.nonces.nonce(), 32)
                if nonce not in self._used:
                    self._used.add(nonce)  # Retired even on transport failure.
                    return nonce
        raise DIDError(DIDStatus.EXHAUSTED)

    def _check_reply(self, did, selector, nonce, reply):
        if type(reply) is not RegistryReply:
            raise DIDError(DIDStatus.INCONSISTENT)
        if len(require_bytes(reply.message)) > MAX_READ_BYTES:
            raise DIDError(DIDStatus.EXHAUSTED)
        _verify(
            self.config.registry_public_key,
            reply.message,
            reply.signature,
            READ_CONTEXT,
            DIDStatus.INCONSISTENT,
        )
        gamma, identity, selection, challenge, status, encoded_chain = decode_record(
            reply.message, "did-read"
        )
        if (gamma, identity, selection, challenge) != (
            self.config.registry_id,
            did,
            selector,
            nonce,
        ) or status not in (b"\x00", b"\x01"):
            raise DIDError(DIDStatus.INCONSISTENT)
        # Preflight count BEFORE generic framing allocates a variable field tuple.
        prefix = (9).to_bytes(4, "big") + b"did-chain"
        if not encoded_chain.startswith(prefix) or len(encoded_chain) < 17:
            raise EncodingError("invalid chain framing")
        count = int.from_bytes(encoded_chain[13:17], "big")
        if count > self.limits.records:
            raise DIDError(DIDStatus.EXHAUSTED)
        encoded = decode_record(encoded_chain, "did-chain", expected_count=count)
        if (status == b"\x01") != (count == 0):
            raise DIDError(DIDStatus.INCONSISTENT)
        chain = tuple(decode_did_record(value) for value in encoded)
        previous = None
        for record in chain:
            if record.body.did != did:
                raise DIDError(DIDStatus.INCONSISTENT)
            _transition(self.config, record, previous)
            previous = record
        if not chain:
            return DIDResolution(DIDStatus.UNKNOWN)
        requested = _selector(selector)
        if requested is not None and chain[-1].version != requested:
            raise DIDError(DIDStatus.INCONSISTENT)
        if chain[-1].body.active == 0:
            return DIDResolution(DIDStatus.DEACTIVATED, chain)
        doc = ResolvedDID(b'{"id":"' + did + b'"}', chain[-1].version, "application/did+json", True)
        return DIDResolution(DIDStatus.ACTIVE, chain, doc)

    def resolve(
        self, expected: PublicParameters, did: bytes, selector: bytes = b"\x00"
    ) -> DIDResolution:
        if not self._slots.acquire(blocking=False):
            return DIDResolution(DIDStatus.BUSY)
        try:
            validate_parameters_structure(expected)
            if expected != self.config.parameters:
                return DIDResolution(DIDStatus.MISMATCH)
            validate_did(self.config, did)
            _selector(selector)
            nonce = self._nonce()
            reply = self.transport.read(did, selector, nonce)
            try:
                return self._check_reply(did, selector, nonce, reply)
            except EncodingError:
                return DIDResolution(DIDStatus.INCONSISTENT)
        except Exception as error:
            return DIDResolution(_failure(error))
        finally:
            self._slots.release()


@dataclass(frozen=True, repr=False)
class ControllerSnapshot:
    did: bytes
    public_key: bytes
    version: bytes | None
    pending: DIDRecord | None


class ReferenceDIDController:
    """Holder-local publication/recovery using supplied independent controller keys.

    At most one pending record and two potentially active signer handles. Retain
    pending bytes/handles across reply loss. Explicit recover() may resend the SAME
    bytes once; no timers, automatic retry loop, persistence or key generation.
    """

    def __init__(
        self,
        resolver: ReferenceDIDResolver,
        public_key: bytes,
        salt: bytes,
        *,
        signer: ManagerSigner | None = None,
    ):
        self.resolver, self.salt = resolver, _fixed(salt, 32)
        did = make_did(resolver.config, public_key, salt)
        self._state = ControllerSnapshot(did, public_key, None, None)
        self._signer = signer if signer is not None else UnsupportedManagerSigner()
        self._pending_signer: ManagerSigner | None = None
        self._operation, self._lock = Lock(), Lock()

    def snapshot(self):
        with self._lock:
            return self._state

    def _read(self):
        return self.resolver.resolve(self.resolver.config.parameters, self._state.did)

    def _finish_pending(self, answer):
        state = self._state
        pending = state.pending
        if answer.status not in {DIDStatus.ACTIVE, DIDStatus.DEACTIVATED, DIDStatus.UNKNOWN}:
            return answer.status
        index = pending.body.index
        if index < len(answer.chain) and answer.chain[index] == pending:
            new = ControllerSnapshot(state.did, pending.body.controller_key, pending.version, None)
            with self._lock:
                self._state, self._signer = new, self._pending_signer
                self._pending_signer = None
            return DIDStatus.CONFIRMED
        current = answer.chain[-1].version if answer.chain else None
        if current != state.version:
            with self._lock:
                self._state = ControllerSnapshot(state.did, state.public_key, state.version, None)
                self._pending_signer = None
            return DIDStatus.CONFLICT
        return None

    def _submit(self):
        state = self._state
        # Even an exception may follow a commit. Preserve pending until authenticated
        # confirmation; a failed reply cannot undo the registry's committed state.
        try:
            submitted = self.resolver.transport.append(
                encode_did_record(state.pending), state.version
            )
        except Exception as error:
            return _failure(error)
        confirmed = self._finish_pending(self._read())
        if confirmed is not None:
            return confirmed
        # A transport acknowledgement never establishes publication success.
        failures = {
            DIDStatus.CONFLICT,
            DIDStatus.INVALID,
            DIDStatus.UNAUTHORISED,
            DIDStatus.MISMATCH,
            DIDStatus.INCONSISTENT,
            DIDStatus.UNAVAILABLE,
            DIDStatus.UNSUPPORTED,
            DIDStatus.EXHAUSTED,
            DIDStatus.BUSY,
        }
        return (
            submitted
            if type(submitted) is DIDStatus and submitted in failures
            else DIDStatus.UNAVAILABLE
        )

    def recover(self) -> DIDStatus:
        if not self._operation.acquire(blocking=False):
            return DIDStatus.BUSY
        try:
            if self._state.pending is None:
                return DIDStatus.INVALID
            outcome = self._finish_pending(self._read())
            return outcome if outcome is not None else self._submit()
        except Exception as error:
            return _failure(error)
        finally:
            self._operation.release()

    def publish(
        self,
        metadata: tuple[int, int] = (1, 0),
        *,
        new_public_key: bytes | None = None,
        new_signer: ManagerSigner | None = None,
    ) -> DIDStatus:
        if not self._operation.acquire(blocking=False):
            return DIDStatus.BUSY
        try:
            if (
                type(metadata) is not tuple
                or len(metadata) != 2
                or any(type(v) is not int for v in metadata)
                or metadata not in ((1, 0), (1, 1), (0, 0))
            ):
                return DIDStatus.UNSUPPORTED
            state = self._state
            if state.pending is not None:
                return DIDStatus.CONFLICT  # Caller must explicitly resolve pending first.
            rotating = metadata[1] == 1
            if not rotating and (new_public_key is not None or new_signer is not None):
                return DIDStatus.INVALID
            if rotating and (new_public_key is None or new_signer is None):
                return DIDStatus.UNSUPPORTED
            answer = self._read()
            if answer.status not in {DIDStatus.ACTIVE, DIDStatus.UNKNOWN}:
                return answer.status
            previous = answer.chain[-1] if answer.chain else None
            if state.version is None:
                if previous is not None:
                    return DIDStatus.CONFLICT
                if metadata != (1, 0):
                    return DIDStatus.UNSUPPORTED
            elif (
                previous is None
                or previous.version != state.version
                or previous.body.controller_key != state.public_key
            ):
                return DIDStatus.CONFLICT
            key = new_public_key if rotating else state.public_key
            _key(key)
            body = DIDBody(
                self.resolver.config.registry_id,
                state.did,
                previous.body.index + 1 if previous else 0,
                previous.version[8:] if previous else ZERO_DIGEST,
                key,
                metadata[0],
                self.salt,
            )
            signature = _sign(self._signer, state.public_key, encode_body(body), RECORD_CONTEXT)
            record = DIDRecord(body, signature)
            _transition(self.resolver.config, record, previous)
            pending = ControllerSnapshot(state.did, state.public_key, state.version, record)
            with self._lock:
                self._state = pending
                self._pending_signer = new_signer if rotating else self._signer
            return self._submit()
        except Exception as error:
            return _failure(error)
        finally:
            self._operation.release()


def _adapter_result(answer):
    if answer.status is DIDStatus.EXHAUSTED:
        raise MemoryError("DID reference resource exhausted")
    return answer.status is DIDStatus.ACTIVE


class IssuanceDIDAdapter:
    def __init__(self, resolver: ReferenceDIDResolver):
        self.resolver = resolver

    def current(self, parameters: PublicParameters, did: bytes) -> ControllerResolution | None:
        answer = self.resolver.resolve(parameters, did)
        if not _adapter_result(answer):
            return None
        return ControllerResolution(did, answer.document, answer.chain[-1].body.controller_key)


class DIDLifecycleProvider:
    """Pin pp independently of DID data; delegate current revocation state unchanged.

    resolve_did is historical, called only by the verifier's existing opt-in check
    of BOTH disclosed certified did/vD. instance/current never resolve a holder DID.
    """

    def __init__(self, resolver: ReferenceDIDResolver, authority: TrustedPublicProvider):
        self.resolver, self.authority = resolver, authority

    def instance(self, expected: PublicParameters) -> PublicParameters | None:
        try:
            validate_parameters_structure(expected, expected=self.resolver.config.parameters)
            actual = self.authority.instance(expected)
            validate_parameters_structure(actual, expected=expected)
        except EncodingError:
            return None
        return expected

    def current(self, expected: PublicParameters, nonce: bytes) -> CurrentStateReply | None:
        return (
            self.authority.current(expected, nonce) if self.instance(expected) is not None else None
        )

    def resolve_did(self, did: bytes, version: bytes) -> ResolvedDID | None:
        try:
            _version(version)
        except EncodingError:
            return None
        answer = self.resolver.resolve(self.resolver.config.parameters, did, b"\x01" + version)
        return answer.document if _adapter_result(answer) else None
