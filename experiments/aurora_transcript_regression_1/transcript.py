"""EXP2 public-only reimplementation; no native patch, proof or accepted backend."""

import hashlib
from dataclasses import dataclass, fields, is_dataclass, replace
from functools import wraps

from pqdid.statements import AuthenticationStatement, encode_auth_statement

VARIANT = b"PQDID-AURORA-TRANSCRIPT-EXP2"
PROTO = b"PQDID-AURORA-AUTH"
ARITIES = {
    "profile": 4,
    "relation": 1,
    "statement": 5,
    "init": 1,
    "round": 3,
    "absorb": 4,
    "challenge": 7,
}
FRAME_CAP = 65536


class TranscriptError(ValueError):
    """Invalid transcript operation; never an authentication result."""


def require(ok, reason):
    if not ok:
        raise TranscriptError(reason)


def uint(n, width):
    require(type(n) is int and 0 <= n < 1 << (8 * width), "unsigned integer")
    return n.to_bytes(width, "big")


def frame(label, parts):
    require(type(label) is str and label in ARITIES, "label")
    require(type(parts) is tuple and len(parts) == ARITIES[label], "frame arity")
    tag = VARIANT + b"/" + label.encode("ascii")
    length = 2 + len(tag) + 4
    for part in parts:
        require(type(part) is bytes, "immutable frame part")
        length += 8 + len(part)
        require(length <= FRAME_CAP, "frame capacity")
    return (
        uint(len(tag), 2) + tag + uint(len(parts), 4) + b"".join(uint(len(p), 8) + p for p in parts)
    )


def digest(data):
    result = hashlib.blake2b(data, digest_size=64).digest()
    require(type(result) is bytes and len(result) == 64, "hash failure")
    return result


@dataclass(frozen=True)
class Round:
    roots: int
    messages: tuple[int, ...]
    challenges: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class Descriptor:
    variant: bytes
    parameters: bytes
    relation: bytes
    plan: tuple[Round, ...]


BASE = Descriptor(
    VARIANT,
    b"PUBLIC-HARNESS;F=2^192;rho=1/8;eta=1;pow=0;not-an-IOP",
    b"PUBLIC-TRANSCRIPT-HARNESS-NOT-AUTHENTICATION",
    (Round(2, (1, 1), ((1, 192), (2, 8), (2, 0))), Round(0, (0,), ((1, 192),)), Round(0, (), ())),
)
GROUPED = replace(BASE, plan=(replace(BASE.plan[0], messages=(2,)), *BASE.plan[1:]))


def encode_plan(trusted):
    require(trusted is BASE or trusted is GROUPED, "untrusted descriptor")
    require(trusted.variant == VARIANT, "variant")
    for part in (trusted.parameters, trusted.relation):
        require(type(part) is bytes and 0 < len(part) <= 4096, "descriptor bytes")
    require(type(trusted.plan) is tuple and 1 <= len(trusted.plan) <= 4, "round count")
    out = [uint(len(trusted.plan), 4)]
    for r, spec in enumerate(trusted.plan):
        require(type(spec) is Round, "round descriptor")
        require(type(spec.roots) is int and 0 <= spec.roots <= 4, "root count")
        require(type(spec.messages) is tuple and len(spec.messages) <= 4, "message count")
        out.extend((uint(r, 4), uint(spec.roots, 4), uint(len(spec.messages), 4)))
        for n in spec.messages:
            require(type(n) is int and 0 <= n <= 4, "field count")
            out.append(uint(n, 4))
        require(type(spec.challenges) is tuple and len(spec.challenges) <= 4, "challenge count")
        out.append(uint(len(spec.challenges), 4))
        for c, pair in enumerate(spec.challenges):
            require(type(pair) is tuple and len(pair) == 2, "challenge pair")
            kind, width = pair
            require(type(kind) is int and type(width) is int, "challenge integers")
            require(
                (kind == 1 and width == 192) or (kind == 2 and 0 <= width <= 63),
                "challenge mapping",
            )
            out.extend((uint(c, 4), uint(kind, 1), uint(width, 2)))
    return b"".join(out)


def bounded_public_object(value):
    """Capacity precheck, not scheme validation or a general deserialiser."""
    stack = [(value, 0)]
    nodes = byte_count = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        require(nodes <= 1024 and depth <= 16, "public object capacity")
        if type(item) is bytes:
            byte_count += len(item)
            require(byte_count <= 65536, "public byte capacity")
        elif type(item) is int:
            require(item.bit_length() <= 64, "public integer capacity")
        elif type(item) is bool:
            pass  # Boolean attribute values; uint() still rejects boolean counters.
        elif type(item) is str:
            require(item.isascii() and len(item) <= 64, "schema name capacity")
        elif type(item) is tuple:
            require(len(item) <= 64, "public collection capacity")
            stack.extend((part, depth + 1) for part in item)
        elif is_dataclass(item) and not isinstance(item, type):
            stack.extend((getattr(item, f.name), depth + 1) for f in fields(item))
        else:
            raise TranscriptError("public object type")


@dataclass(frozen=True)
class State:
    digest: bytes
    next_round: int = 0
    pending: int | None = None
    next_challenge: int = 0
    counter: int = 0


def atomic(method):
    @wraps(method)
    def call(self, *args):
        try:
            require(self.mode == "LIVE", "not live")
            return method(self, *args)
        except Exception:
            self.mode = "FAILED"
            raise

    return call


class Transcript:
    def __init__(self, trusted, expected_pp, typed_x, version):
        self.mode = "FAILED"
        require(type(version) is int and version == 2, "unsupported transcript version")
        plan = encode_plan(trusted)
        require(type(typed_x) is AuthenticationStatement, "typed public statement required")
        bounded_public_object(expected_pp)
        bounded_public_object(typed_x)
        encoded = encode_auth_statement(expected_pp, typed_x)
        require(0 < len(encoded) <= 32768, "statement capacity")
        pp = frame("profile", (uint(2, 2), PROTO, trusted.parameters, plan))
        rp = frame("relation", (trusted.relation,))
        pid, rid = digest(pp), digest(rp)
        self.xdom = frame("statement", (uint(2, 2), PROTO, pid, rid, encoded))
        init = frame("init", (self.xdom,))
        state = digest(init)
        self.trusted = trusted
        self.trace = (("profile", pp, pid), ("relation", rp, rid), ("init", init, state))
        self.records = ()
        self.outputs = ()
        self.state = State(state)
        self.mode = "LIVE"

    @classmethod
    def new(cls, trusted, expected_pp, typed_x, version):
        return cls(trusted, expected_pp, typed_x, version)

    def _round_record(self, r, roots, messages):
        spec = self.trusted.plan[r]
        require(type(roots) is tuple and len(roots) == spec.roots, "roots")
        require(type(messages) is tuple and len(messages) == len(spec.messages), "messages")
        for root in roots:
            require(type(root) is bytes and len(root) == 64, "root width")
        for message, n in zip(messages, spec.messages, strict=True):
            require(type(message) is bytes and len(message) == 24 * n, "message width")
        root_bytes = uint(len(roots), 4) + b"".join(roots)
        message_bytes = uint(len(messages), 4) + b"".join(
            uint(n, 4) + message for message, n in zip(messages, spec.messages, strict=True)
        )
        return frame("round", (uint(r, 4), root_bytes, message_bytes))

    def _challenges_done(self):
        s = self.state
        return s.pending is None or s.next_challenge == len(self.trusted.plan[s.pending].challenges)

    @atomic
    def commit_round(self, r, roots, messages):
        s = self.state
        require(type(r) is int and r == s.next_round < len(self.trusted.plan), "round order")
        require(self._challenges_done(), "outstanding challenges")
        record = self._round_record(r, roots, messages)
        preimage = frame("absorb", (s.digest, uint(r, 4), uint(s.counter, 8), record))
        value = digest(preimage)
        state = State(value, r + 1, r, 0, s.counter)
        trace = (*self.trace, (f"absorb-{r}", preimage, value))
        records = (*self.records, record)
        self.state, self.trace, self.records = state, trace, records

    @atomic
    def challenge(self, r, c):
        s = self.state
        require(type(r) is int and type(c) is int and r == s.pending, "challenge round")
        require(c == s.next_challenge < len(self.trusted.plan[r].challenges), "challenge order")
        require(s.counter < (1 << 64) - 1, "counter exhausted")
        kind, width = self.trusted.plan[r].challenges[c]
        preimage = frame(
            "challenge",
            (
                self.xdom,
                s.digest,
                uint(r, 4),
                uint(c, 4),
                uint(s.counter, 8),
                uint(kind, 1),
                uint(width, 2),
            ),
        )
        block = digest(preimage)
        value = block[:24] if kind == 1 else int.from_bytes(block, "little") % (1 << width)
        state = replace(s, next_challenge=c + 1, counter=s.counter + 1)
        trace = (*self.trace, (f"challenge-{r}-{c}", preimage, block))
        outputs = (*self.outputs, value)
        self.state, self.trace, self.outputs = state, trace, outputs
        return value

    @atomic
    def finish(self):
        require(
            self.state.next_round == len(self.trusted.plan) and self._challenges_done(),
            "incomplete transcript",
        )
        result = (self.state.digest, self.state.counter)
        self.mode = "FINISHED"
        return result

    @atomic
    def consume_record(self, record):
        require(type(record) is bytes and len(record) <= FRAME_CAP, "round frame capacity")
        reader = Reader(record)
        require(reader.take(reader.number(2)) == VARIANT + b"/round", "round label")
        require(reader.number(4) == 3, "round frame arity")
        parts = tuple(reader.take(reader.number(8)) for _ in range(3))
        reader.end()
        require(len(parts[0]) == 4, "round integer width")
        r = int.from_bytes(parts[0], "big")
        require(r == self.state.next_round < len(self.trusted.plan), "round order")
        spec = self.trusted.plan[r]
        roots_reader, messages_reader = Reader(parts[1]), Reader(parts[2])
        require(roots_reader.number(4) == spec.roots, "encoded root count")
        roots = tuple(roots_reader.take(64) for _ in range(spec.roots))
        roots_reader.end()
        require(messages_reader.number(4) == len(spec.messages), "encoded message count")
        messages = []
        for n in spec.messages:
            require(messages_reader.number(4) == n, "encoded field count")
            messages.append(messages_reader.take(24 * n))
        messages_reader.end()
        messages = tuple(messages)
        require(self._round_record(r, roots, messages) == record, "noncanonical round")
        self.commit_round(r, roots, messages)


class Reader:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, count):
        require(0 <= count <= len(self.data) - self.offset, "truncated input")
        value = self.data[self.offset : self.offset + count]
        self.offset += count
        return value

    def number(self, width):
        return int.from_bytes(self.take(width), "big")

    def end(self):
        require(self.offset == len(self.data), "trailing input")


def reconstruct(trusted, expected_pp, x, version, records):
    """Public diagnostics only. No roots, statements or proofs are authenticated."""
    transcript = Transcript.new(trusted, expected_pp, x, version)
    try:
        require(type(records) is tuple and len(records) == len(trusted.plan), "record count")
        for r, record in enumerate(records):
            transcript.consume_record(record)
            for c in range(len(trusted.plan[r].challenges)):
                transcript.challenge(r, c)
        result = transcript.finish()
        return transcript, result
    except Exception:
        transcript.mode = "FAILED"
        raise


def replay_public_rounds(trusted, expected_pp, x, version, records):
    return reconstruct(trusted, expected_pp, x, version, records)[1]
