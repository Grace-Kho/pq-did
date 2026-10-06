"""Approved experimental records; production tags and encodings remain unchanged."""

from dataclasses import dataclass

from pqdid.codec import EncodingError, encode_length_prefixed, encode_uint, require_uint
from pqdid.parameters import decode_parameters, encode_parameters, validate_parameters_structure
from pqdid.policy import Range
from pqdid.schema import decode_attributes
from pqdid.statements import decode_context, decode_state, encode_context, encode_state

PROFILE = b"pqdid-mldsa-reference-1"
CAP = 65536
ARITIES = {
    "credential-body": 4,
    "credential": 2,
    "enrol-body": 6,
    "request-body": 2,
    "request": 2,
    "presentation-body": 3,
    "presentation": 2,
}


def require(condition, reason="baseline-input"):
    if not condition:
        raise EncodingError(reason)


def octets(value, size=None, maximum=CAP):
    require(type(value) is bytes and len(value) <= maximum, "binary-type-or-limit")
    require(size is None or len(value) == size, "binary-width")
    return value


def frame(tag, fields):
    require(tag in ARITIES and type(fields) is tuple and len(fields) == ARITIES[tag], "arity")
    result = encode_length_prefixed(PROFILE + b"/" + tag.encode("ascii"))
    result += encode_uint(len(fields), 4)
    result += b"".join(encode_length_prefixed(octets(value)) for value in fields)
    return octets(result)


def unframe(data, tag):
    octets(data)
    require(tag in ARITIES, "tag")
    offset = 0

    def take(count):
        nonlocal offset
        require(offset + count <= len(data), "truncated-record")
        value = data[offset : offset + count]
        offset += count
        return value

    def field():
        return take(int.from_bytes(take(4), "big"))

    require(field() == PROFILE + b"/" + tag.encode("ascii"), "tag")
    require(int.from_bytes(take(4), "big") == ARITIES[tag], "arity")
    values = tuple(field() for _ in range(ARITIES[tag]))
    require(offset == len(data), "trailing-record")
    return values


def identity(pp, encoded):
    expected = decode_parameters(encoded)
    validate_parameters_structure(expected, expected=pp)
    require(encode_parameters(expected) == encoded, "canonical-parameters")


def certified_expiry(pp, attributes, context):
    """Keep the certified validity claim distinct from strict session expiry."""
    index = next(
        (i for i, value in enumerate(pp.schema.fields, 1) if value.name == "validUntil"), None
    )
    require(index is not None and index in context.policy.disclosed, "validity-policy")
    require(
        any(
            type(clause) is Range and clause.index == index and clause.lower >= context.expires_at
            for clause in context.policy.clauses
        ),
        "validity-policy-clause",
    )
    value = decode_attributes(pp.schema, attributes)[index - 1]
    require(type(value) is int and value >= context.expires_at, "certified-validity")


@dataclass(frozen=True)
class BaselineCredential:
    body: bytes
    signature: bytes
    holder_public_key: bytes
    attributes: bytes
    identifier: int


@dataclass(frozen=True)
class BaselineRequest:
    body: bytes
    signature: bytes
    context: object
    state: object


@dataclass(frozen=True)
class BaselinePresentation:
    body: bytes
    signature: bytes
    request: BaselineRequest
    credential: BaselineCredential
    path: bytes


def credential_body(pp, holder_public_key, attributes, identifier):
    validate_parameters_structure(pp)
    octets(holder_public_key, 1952)
    decode_attributes(pp.schema, attributes)
    require_uint(identifier, 20)
    return frame(
        "credential-body",
        (encode_parameters(pp), holder_public_key, attributes, encode_uint(identifier, 4)),
    )


def decode_credential(pp, encoded):
    body, signature = unframe(encoded, "credential")
    params, key, attributes, rid = unframe(body, "credential-body")
    identity(pp, params)
    octets(signature, 3309)
    identifier = int.from_bytes(octets(rid, 4), "big")
    require(credential_body(pp, key, attributes, identifier) == body, "canonical-credential")
    return BaselineCredential(body, signature, key, attributes, identifier)


def encode_credential(pp, value):
    require(type(value) is BaselineCredential)
    encoded = frame("credential", (value.body, octets(value.signature, 3309)))
    require(decode_credential(pp, encoded) == value, "conflicting-credential")
    return encoded


def enrol_body(pp, session, nonce, holder_key, attributes, identifier):
    octets(session, maximum=256)
    require(bool(session), "session")
    credential_body(pp, holder_key, attributes, identifier)
    return frame(
        "enrol-body",
        (
            encode_parameters(pp),
            session,
            octets(nonce, 32),
            holder_key,
            attributes,
            encode_uint(identifier, 4),
        ),
    )


def request_body(pp, context, state):
    require(context.state_reference == state.reference, "request-state")
    return frame("request-body", (encode_context(pp, context), encode_state(pp, state)))


def decode_request(pp, encoded):
    body, signature = unframe(encoded, "request")
    context, state = unframe(body, "request-body")
    value = BaselineRequest(
        body, octets(signature, 3309), decode_context(pp, context), decode_state(pp, state)
    )
    require(request_body(pp, value.context, value.state) == body, "canonical-request")
    return value


def encode_request(pp, value):
    require(type(value) is BaselineRequest)
    encoded = frame("request", (value.body, octets(value.signature, 3309)))
    require(decode_request(pp, encoded) == value, "conflicting-request")
    return encoded


def presentation_body(pp, request, credential, path):
    return frame(
        "presentation-body",
        (encode_request(pp, request), encode_credential(pp, credential), octets(path, 960)),
    )


def decode_presentation(pp, encoded):
    body, signature = unframe(encoded, "presentation")
    request, credential, path = unframe(body, "presentation-body")
    return BaselinePresentation(
        body,
        octets(signature, 3309),
        decode_request(pp, request),
        decode_credential(pp, credential),
        octets(path, 960),
    )


def encode_presentation(pp, value):
    require(type(value) is BaselinePresentation)
    require(
        presentation_body(pp, value.request, value.credential, value.path) == value.body,
        "conflicting-presentation",
    )
    return frame("presentation", (value.body, octets(value.signature, 3309)))
