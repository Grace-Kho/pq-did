"""Independent byte framing and stdlib hashes for synthetic pilot observations.

No production imports. Even malformed bytes have a deterministic prepared message;
their validity is checked separately. These are never accepted as signature proofs.
"""

import hashlib


def record(tag, fields):
    def lp(data):
        return len(data).to_bytes(4, "big") + data

    return lp(tag) + len(fields).to_bytes(4, "big") + b"".join(map(lp, fields))


def preparation_bytes(suite, metadata, key, raw):
    holder = record(b"holder", (suite, metadata, raw[:32]))
    value = hashlib.sha3_384(holder).digest()
    binding = record(b"binding", (value, raw[32:1056]))
    message = record(b"cred", (suite, metadata, binding, raw[1056:1060]))
    context = b"PQ-DID/credential/v1"
    formatted = bytes((0, len(context))) + context + message
    tr = hashlib.shake_256(key).digest(64)
    preimage = tr + formatted
    mu = hashlib.shake_256(preimage).digest(64)
    return holder, value, binding, message, formatted, tr, preimage, mu
