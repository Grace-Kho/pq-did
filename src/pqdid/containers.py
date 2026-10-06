"""Bounded project-local research containers, never authentication or a VC cryptosuite.

Typed conversion is unverified input for existing lifecycle checks. Trusted constructor
arguments select receiver/instance/context; no transport field selects a key or role.
Example inspection returns a different wrapper and never a proof/acceptance object.
No I/O, signing, proof verification, service state, retry or timestamp conversion.
"""

import base64
import binascii
import json
import re
from dataclasses import dataclass

from pqdid.codec import EncodingError
from pqdid.credentials import decode_credential, encode_credential
from pqdid.issuance import EnrolmentChallenge, IssuedCredential, IssueRequest
from pqdid.parameters import decode_parameters, encode_parameters, validate_parameters_structure
from pqdid.revocation_state import ManagerStatus, UpdatePage
from pqdid.schema import decode_attributes, decode_disclosed_attributes
from pqdid.statements import (
    decode_auth_statement,
    decode_context,
    decode_enrol_statement,
    decode_state,
    encode_auth_statement,
    encode_context,
    encode_enrol_statement,
    encode_state,
)
from pqdid.verifier_state import AuthenticationRequest, CurrentStateReply, Decision
from pqdid.witness_updates import WitnessCheckpoint, decode_update, encode_update
from pqdid.witnesses import decode_auth_witness, encode_auth_witness

PROFILE = "pqdid-application-container-1"
EXAMPLE_PROFILE = "pqdid-application-container-draft-1"
ORDINARY_BYTES = 65536
HISTORY_BYTES = 524288
_FIELDS = {
    "instance": ("parameters",),
    "issuance-request": ("session", "did", "version", "attributes", "holderApproval", "evidence"),
    "enrolment-challenge": ("parameters", "approvedAttributes", "identifier", "nonce", "state"),
    "enrolment-submission": ("statement", "proof", "controllerSignature"),
    "issuance-delivery": ("credential", "identifier", "path", "state"),
    "private-holder": ("credential", "authenticationWitness", "state"),
    "presentation-request": ("context", "state", "requestSignature", "sessionExpiresAtSeconds"),
    "presentation-submission": ("statement", "proof", "disclosedClaims"),
    "revocation-state": ("state", "currentNonce", "currentSignature"),
    "updates-request": ("namespace", "afterEpoch", "targetEpoch"),
    "updates-response": (
        "status",
        "startingState",
        "endpointState",
        "records",
        "requestedEpoch",
        "nextEpoch",
        "complete",
    ),
    "did-resolution": (
        "did",
        "selector",
        "document",
        "version",
        "contentType",
        "registryReply",
        "registrySignature",
    ),
    "verification-result": ("decision", "accepted", "challengeConsumed", "businessAction"),
}
_EXPOSURE = dict(
    zip(
        _FIELDS,
        (
            "public-trusted-configuration",
            "private-issuer-holder-channel",
            "private-issuer-holder-channel",
            "private-issuer-holder-channel",
            "private-original-recipient",
            "private-holder-only",
            "public-request",
            "public-disclosed",
            "public-authenticated-state",
            "public-namespace-epochs",
            "public-authenticated-history",
            "public-method-result",
            "private-verifier-application-channel",
        ),
        strict=True,
    )
)
_ROUTES = {
    "holder": frozenset(
        {
            "instance",
            "private-holder",
            "issuance-delivery",
            "enrolment-challenge",
            "presentation-request",
            "revocation-state",
            "updates-response",
        }
    ),
    "issuer": frozenset(
        {
            "instance",
            "issuance-request",
            "enrolment-submission",
            "revocation-state",
            "did-resolution",
        }
    ),
    "verifier": frozenset(
        {"instance", "presentation-submission", "revocation-state", "did-resolution"}
    ),
    "revocation": frozenset({"updates-request"}),
    "application": frozenset({"verification-result"}),
}


class ContainerError(ValueError):
    """Fixed code only: no input bytes, JSON exception text or private state."""


class UnsupportedContainer(ContainerError):
    pass


def _require(condition, code="invalid-container"):
    if not condition:
        raise ContainerError(code)


def _keys(obj, names):
    _require(type(obj) is dict and obj.keys() == set(names), "fields")


def _uint(value, bits=64):
    # Decimal strings are the specified transport type, not generic coercion.
    _require(
        type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is not None, "integer"
    )
    result = int(value)
    _require(result < 1 << bits, "integer-range")
    return result


def _b64(value, maximum, *, exact=None, minimum=0):
    _require(type(value) is str, "binary")
    _require(len(value) <= (maximum * 8 + 5) // 6, "binary-limit")
    _require(re.fullmatch(r"[A-Za-z0-9_-]*", value) is not None, "binary")
    try:
        result = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except binascii.Error:
        raise ContainerError("binary") from None
    _require(
        minimum <= len(result) <= maximum and (exact is None or len(result) == exact),
        "binary-width",
    )
    _require(_encode64(result) == value, "binary-canonical")
    return result


def _encode64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _scan(data):
    """Lexical resource preflight, not a replacement JSON grammar validator.

    Stack depth and separator/member counts are bounded before json.loads allocates
    collections. String token allocation is still bounded only by the document cap.
    Escaped delimiters are ignored; malformed grammar is subsequently rejected.
    """
    stack, total, quoted, escaped = [], 0, False, False
    for char in data:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
            continue
        if char in (9, 10, 13, 32):
            continue
        if char in (125, 93):
            _require(stack and stack[-1][0] == char, "json")
            _, commas, content = stack.pop()
            count = commas + 1 if content else 0
            total += count
            _require(count <= 32 and total <= 512, "collection-limit")
            continue
        if stack:
            stack[-1][2] = True
        if char == 34:
            quoted = True
        elif char in (123, 91):
            _require(len(stack) < 8, "depth-limit")
            stack.append([125 if char == 123 else 93, 0, False])
        elif char == 44:
            _require(stack, "json")
            stack[-1][1] += 1
            _require(stack[-1][1] < 32, "collection-limit")
    _require(not quoted and not stack, "json")


def _object(pairs):
    result = {}
    for key, value in pairs:
        _require(len(key.encode("utf-8")) <= 64, "key-limit")
        _require(key not in result, "duplicate-key")
        result[key] = value
    return result


def _number(_value):
    raise ContainerError("json-number")


def _json(data, kind):
    _require(type(data) is bytes, "input-type")
    limit = HISTORY_BYTES if kind in {"updates-response", "did-resolution"} else ORDINARY_BYTES
    _require(len(data) <= limit, "document-limit")
    _scan(data)
    try:
        result = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_object,
            parse_int=_number,
            parse_float=_number,
            parse_constant=_number,
        )

        # Reject escaped lone surrogates in values as well as object keys.
        def strings(value):
            if type(value) is str:
                value.encode("utf-8")
            elif type(value) is dict:
                for item in value.values():
                    strings(item)
            elif type(value) is list:
                for item in value:
                    strings(item)

        strings(result)
        return result
    except UnicodeError, json.JSONDecodeError, RecursionError:
        raise ContainerError("json") from None


@dataclass(frozen=True, repr=False)
class ConvertedInput:
    """Structurally validated only; never a verification or release result."""

    kind: str
    value: object


@dataclass(frozen=True, repr=False)
class ExamplePreview:
    """Non-operational fixture inspection; never a Presentation or proof object."""

    kind: str
    value: object


@dataclass(frozen=True, repr=False)
class PrivateHolderInput:
    credential: object
    witness: object
    state: object


@dataclass(frozen=True)
class UpdateQuery:
    namespace: bytes
    after_epoch: int
    target_epoch: int

    def __post_init__(self):
        _require(type(self.namespace) is bytes and len(self.namespace) == 32)
        _require(type(self.after_epoch) is int and type(self.target_epoch) is int)
        _require(0 <= self.after_epoch <= self.target_epoch < 1 << 64)


@dataclass(frozen=True, repr=False)
class ContainerAdapter:
    """Configure from trusted local routing, never from the parsed body/metadata.

    No key/role/context selection is performed from containers. Context is supplied
    independently per request/statement. The class owns no mutable lifecycle state.
    """

    parameters: object
    receiver: str

    def __post_init__(self):
        validate_parameters_structure(self.parameters)
        _require(type(self.receiver) is str and self.receiver in _ROUTES, "receiver")

    def parse(self, data, *, kind, context=None, nonce=None, query=None, starting=None):
        return self._read(data, kind, False, context, nonce, query, starting)

    def inspect_example(self, data, *, kind, context=None, query=None, starting=None):
        """Explicit synthetic-only reader, not an allow-synthetic configuration flag."""
        return self._read(data, kind, True, context, None, query, starting)

    def _read(self, data, kind, example, context, nonce, query, starting):
        _require(type(kind) is str and kind in _ROUTES[self.receiver], "route")
        root = _json(data, kind)
        _keys(root, ("profile", "kind", "synthetic", "exposure", "evidenceStatus", "body"))
        _require(
            type(root["synthetic"]) is bool and root["synthetic"] is example, "synthetic-boundary"
        )
        _require(root["profile"] == (EXAMPLE_PROFILE if example else PROFILE), "version")
        _require(root["kind"] == kind and root["exposure"] == _EXPOSURE[kind], "type")
        label = root["evidenceStatus"]
        _require(type(label) is str and len(label.encode("utf-8")) <= 256, "metadata")
        if not example:
            _require(label == "unverified-input", "metadata")
        body = root["body"]
        _keys(body, _FIELDS[kind])
        try:
            value = self._convert(kind, body, example, context, nonce, query, starting)
        except EncodingError, TypeError, OverflowError:
            raise ContainerError("canonical-input") from None
        return (ExamplePreview if example else ConvertedInput)(kind, value)

    def _canonical(self, text, decoder, encoder, maximum=ORDINARY_BYTES, exact=None):
        raw = _b64(text, maximum, exact=exact)
        value = decoder(self.parameters, raw)
        _require(encoder(self.parameters, value) == raw, "canonical-input")
        return value

    def _state(self, text):
        return self._canonical(text, decode_state, encode_state, 3427, 3427)

    def _parameters(self, text):
        raw = _b64(text, ORDINARY_BYTES)
        value = decode_parameters(raw, expected=self.parameters)
        _require(encode_parameters(value) == raw, "canonical-input")
        return value

    def _context(self, value, expected):
        _require(expected is not None, "expected-context-required")
        _require(
            encode_context(self.parameters, value) == encode_context(self.parameters, expected),
            "context-binding",
        )

    def _convert(self, kind, body, example, context, nonce, query, starting):
        pp = self.parameters
        if kind == "instance":
            return self._parameters(body["parameters"])
        if kind == "issuance-request":
            attrs = _b64(body["attributes"], 1024, exact=1024)
            approved = _b64(body["holderApproval"], 1024, exact=1024)
            values = decode_attributes(pp.schema, attrs)
            did, version = _b64(body["did"], 171, exact=171), _b64(body["version"], 56, exact=56)
            _require(
                re.fullmatch(rb"did:pqdid:[0-9a-f]{64}:[0-9a-f]{96}", did)
                and int.from_bytes(version[:8], "big") < 1 << 16,
                "did",
            )
            _require(
                attrs == approved
                and values[pp.schema.did_index - 1] == did
                and values[pp.schema.version_index - 1] == version,
                "attribute-binding",
            )
            return IssueRequest(
                _b64(body["session"], 256, minimum=1),
                did,
                version,
                attrs,
                _b64(body["evidence"], 65536),
                approved,
            )
        if kind == "enrolment-challenge":
            params = self._parameters(body["parameters"])
            attrs = _b64(body["approvedAttributes"], 1024, exact=1024)
            decode_attributes(pp.schema, attrs)
            return EnrolmentChallenge(
                params,
                attrs,
                _uint(body["identifier"], 20),
                _b64(body["nonce"], 32, exact=32),
                self._state(body["state"]),
            )
        if kind in {"issuance-delivery", "private-holder"}:
            credential = self._canonical(body["credential"], decode_credential, encode_credential)
            state = self._state(body["state"])
            if kind == "issuance-delivery":
                identifier = _uint(body["identifier"], 20)
                _require(identifier == credential.revocation_identifier, "identifier-binding")
                return IssuedCredential(
                    credential,
                    WitnessCheckpoint(identifier, _b64(body["path"], 960, exact=960), state),
                )
            raw = _b64(body["authenticationWitness"], 5329, exact=5329)
            witness = decode_auth_witness(pp.schema, raw)
            _require(encode_auth_witness(pp.schema, witness) == raw, "canonical-input")
            _require(
                (witness.attributes, witness.revocation_identifier, witness.signature)
                == (
                    credential.attributes,
                    credential.revocation_identifier,
                    credential.certificate.signature,
                ),
                "private-binding",
            )
            return PrivateHolderInput(credential, witness, state)
        if kind == "presentation-request":
            ctx = self._canonical(body["context"], decode_context, encode_context)
            self._context(ctx, context)
            state = self._state(body["state"])
            _require(
                state.reference == ctx.state_reference
                and _uint(body["sessionExpiresAtSeconds"]) == ctx.expires_at,
                "context-binding",
            )
            if example and body["requestSignature"] is None:
                return (ctx, state)  # Deliberately not an AuthenticationRequest.
            return AuthenticationRequest(
                ctx, state, _b64(body["requestSignature"], 3309, exact=3309)
            )
        if kind in {"presentation-submission", "enrolment-submission"}:
            if kind == "presentation-submission":
                value = self._canonical(
                    body["statement"], decode_auth_statement, encode_auth_statement
                )
                self._context(value.context, context)
                _claims(pp, value, body["disclosedClaims"])
            else:
                value = self._canonical(
                    body["statement"], decode_enrol_statement, encode_enrol_statement
                )
                _require(value.binding.attributes == value.approved_attributes, "attribute-binding")
                if body["controllerSignature"] is not None:
                    _b64(body["controllerSignature"], 3309, exact=3309)
            if not example or body["proof"] is not None:
                raise UnsupportedContainer("proof-transport-unsupported")
            return value  # Statement preview only; no proof bytes or proof-verdict flag.
        if kind == "revocation-state":
            state = self._state(body["state"])
            if body["currentNonce"] is None and body["currentSignature"] is None:
                _require(nonce is None, "current-reply-required")
                return state  # Signed-state candidate only; no freshness assertion.
            actual = _b64(body["currentNonce"], 32, exact=32)
            _require(type(nonce) is bytes and len(nonce) == 32 and actual == nonce, "nonce-binding")
            return CurrentStateReply(
                actual, state, _b64(body["currentSignature"], 3309, exact=3309)
            )
        if kind == "updates-request":
            result = UpdateQuery(
                _b64(body["namespace"], 32, exact=32),
                _uint(body["afterEpoch"]),
                _uint(body["targetEpoch"]),
            )
            _require(result.namespace == pp.namespace, "instance-binding")
            return result
        if kind == "updates-response":
            _require(
                type(query) is UpdateQuery and query.namespace == pp.namespace,
                "expected-query-required",
            )
            start, end = self._state(body["startingState"]), self._state(body["endpointState"])
            _require(
                starting is not None and encode_state(pp, starting) == encode_state(pp, start),
                "starting-state-binding",
            )
            _require(body["status"] == ManagerStatus.PAGE.value, "history-status")
            _require(type(body["records"]) is list and len(body["records"]) <= 16, "history-limit")
            records, previous = [], start
            for text in body["records"]:
                raw = _b64(text, 11162, exact=11162)
                update = decode_update(pp, raw)
                _require(
                    encode_update(pp, update) == raw
                    and update.old_state == previous
                    and update.new_state.epoch == previous.epoch + 1,
                    "history-binding",
                )
                records.append(raw)
                previous = update.new_state
            _require(
                start.epoch == query.after_epoch
                and previous == end
                and start.epoch <= end.epoch <= query.target_epoch,
                "history-binding",
            )
            _require(
                _uint(body["requestedEpoch"]) == query.target_epoch
                and _uint(body["nextEpoch"]) == end.epoch
                and type(body["complete"]) is bool
                and body["complete"] == (end.epoch == query.target_epoch),
                "history-binding",
            )
            return UpdatePage(start, end, tuple(records), query.target_epoch)
        # No method-aware resolver or application outcome admission is selected here.
        if kind == "did-resolution":
            _require(
                type(body["did"]) is str
                and re.fullmatch(r"did:pqdid:[0-9a-f]{64}:[0-9a-f]{96}", body["did"]),
                "did",
            )
            version = _b64(body["version"], 56, exact=56)
            _require(_b64(body["selector"], 57) in (b"\0", b"\1" + version), "selector")
            document = _b64(body["document"], 180, exact=180)
            _require(
                document == b'{"id":"' + body["did"].encode() + b'"}'
                and body["contentType"] == "application/did+json",
                "did-document",
            )
            if (
                not example
                or body["registryReply"] is not None
                or body["registrySignature"] is not None
            ):
                raise UnsupportedContainer("did-method-adapter-unsupported")
            return (document, version)
        if kind == "verification-result":
            _require(
                type(body["decision"]) is str and body["decision"] in {x.value for x in Decision},
                "decision",
            )
            _require(
                type(body["accepted"]) is bool and type(body["challengeConsumed"]) is bool,
                "result-type",
            )
            if (
                not example
                or body["accepted"]
                or body["challengeConsumed"]
                or body["decision"] == Decision.ACCEPTED.value
                or body["businessAction"] != "not-authorised"
            ):
                raise UnsupportedContainer("outcome-admission-unsupported")
            return None  # No acceptance flag or service result object is returned.
        raise UnsupportedContainer("unsupported-kind")


def _claims(pp, statement, claims):
    _require(type(claims) is list and len(claims) == len(statement.disclosed), "claims")
    values = decode_disclosed_attributes(
        pp.schema, statement.disclosed, statement.disclosed_attributes
    )
    for claim, index in zip(claims, statement.disclosed, strict=True):
        _keys(claim, ("index", "name", "type", "value"))
        field = pp.schema.field(index)
        _require(
            _uint(claim["index"], 8) == index
            and claim["name"] == field.name
            and claim["type"] == ("bytes", "boolean", "uint64")[field.type_code],
            "claims",
        )
        value = claim["value"]
        if field.type_code == 0:
            value = _b64(value, field.capacity)
        elif field.type_code == 1:
            _require(type(value) is bool, "claim-type")
        else:
            value = _uint(value)
        _require(value == values[index], "claim-binding")
