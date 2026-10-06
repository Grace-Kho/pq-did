"""Independent direct-byte expansion of the sealed EXP2 expected trace recipe.

No candidate import, schedule helper, frame helper or typed-X encoder is used.
Only hashlib's primitive is shared. Inputs are public fixture E and fixed mutations.
"""

from hashlib import blake2b


def expected(encoded_statement, *, root=None, message=None, swap=False, grouped=False):
    prefix = b"PQDID-AURORA-TRANSCRIPT-EXP2/"
    trace = []

    def record(tag, components):
        name = prefix + tag
        out = bytearray(len(name).to_bytes(2, "big"))
        out.extend(name)
        out.extend(len(components).to_bytes(4, "big"))
        for component in components:
            out.extend(len(component).to_bytes(8, "big"))
            out.extend(component)
        return bytes(out)

    def hashed(label, preimage):
        value = blake2b(preimage, digest_size=64).digest()
        trace.append((label, preimage, value))
        return value

    def u32(n):
        return n.to_bytes(4, "big")

    # Literal three-round plan; no candidate descriptor or generic schedule traversal.
    plan = u32(3) + u32(0) + u32(2)
    plan += (u32(1) + u32(2)) if grouped else (u32(2) + u32(1) + u32(1))
    plan += u32(3) + u32(0) + b"\x01\x00\xc0"
    plan += u32(1) + b"\x02\x00\x08" + u32(2) + b"\x02\x00\x00"
    plan += u32(1) + u32(0) + u32(1) + u32(0) + u32(1) + u32(0) + b"\x01\x00\xc0"
    plan += u32(2) + u32(0) + u32(0) + u32(0)
    protocol = b"PQDID-AURORA-AUTH"
    pid = hashed(
        "profile",
        record(
            b"profile",
            (b"\x00\x02", protocol, b"PUBLIC-HARNESS;F=2^192;rho=1/8;eta=1;pow=0;not-an-IOP", plan),
        ),
    )
    rid = hashed(
        "relation", record(b"relation", (b"PUBLIC-TRANSCRIPT-HARNESS-NOT-AUTHENTICATION",))
    )
    xdom = record(b"statement", (b"\x00\x02", protocol, pid, rid, encoded_statement))
    initial = hashed("init", record(b"init", (xdom,)))
    a = bytes(64) if root is None else root
    v = b"\x02" * 24 if message is None else message
    w = b"\x03" * 24
    messages = (
        (u32(1) + u32(2) + v + w)
        if grouped
        else (u32(2) + u32(1) + (w if swap else v) + u32(1) + (v if swap else w))
    )
    rr0 = record(b"round", (u32(0), u32(2) + a + b"\x01" * 64, messages))
    s0 = hashed("absorb-0", record(b"absorb", (initial, u32(0), bytes(8), rr0)))
    b00 = hashed(
        "challenge-0-0",
        record(b"challenge", (xdom, s0, u32(0), u32(0), bytes(8), b"\x01", b"\x00\xc0")),
    )
    b01 = hashed(
        "challenge-0-1",
        record(
            b"challenge", (xdom, s0, u32(0), u32(1), (1).to_bytes(8, "big"), b"\x02", b"\x00\x08")
        ),
    )
    hashed(
        "challenge-0-2",
        record(
            b"challenge", (xdom, s0, u32(0), u32(2), (2).to_bytes(8, "big"), b"\x02", b"\x00\x00")
        ),
    )
    rr1 = record(b"round", (u32(1), u32(0), u32(1) + u32(0)))
    s1 = hashed("absorb-1", record(b"absorb", (s0, u32(1), (3).to_bytes(8, "big"), rr1)))
    b10 = hashed(
        "challenge-1-0",
        record(
            b"challenge", (xdom, s1, u32(1), u32(0), (3).to_bytes(8, "big"), b"\x01", b"\x00\xc0")
        ),
    )
    rr2 = record(b"round", (u32(2), u32(0), u32(0)))
    s2 = hashed("absorb-2", record(b"absorb", (s1, u32(2), (4).to_bytes(8, "big"), rr2)))
    return {
        "trace": tuple(trace),
        "records": (rr0, rr1, rr2),
        "outputs": (b00[:24], b01[0], 0, b10[:24]),
        "finish": (s2, 4),
    }


def length_repair_expected(state, digest):
    # Separate incremental primitive calls establish the complete 128-byte span.
    h = blake2b(digest_size=64)
    h.update(state)
    h.update(digest)
    return h.digest()
