"""Independent public framing; conditional cryptographic negative reference check."""

import hashlib
import json
import sys
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from pqdid import credentials
from pqdid.parameters import decode_parameters

ROOT = Path(__file__).resolve().parents[1]


def unpack(data, tag):
    at = 0

    def word():
        nonlocal at
        assert at + 4 <= len(data)
        result = int.from_bytes(data[at : at + 4], "big")
        at += 4
        return result

    def field():
        nonlocal at
        size = word()
        assert at + size <= len(data)
        result = data[at : at + size]
        at += size
        return result

    assert field() == tag
    values = [field() for _ in range(word())]
    assert at == len(data)
    return values


def encode(tag, *fields):
    def lp(value):
        return len(value).to_bytes(4, "big") + value

    return lp(tag) + len(fields).to_bytes(4, "big") + b"".join(lp(f) for f in fields)


mode = sys.argv[1]
assert mode in ("public", "negative")
public = (ROOT / "fixtures/public/cred-alpha-42.bin").read_bytes()
profile, operation, rawpp, context, _payload = unpack(public, b"r0-statement")
assert profile == b"PQDID-R0S-DIAG1" and operation == b"cred-valid" and len(context) == 32
if mode == "public":
    expected = encode(b"r0-result", profile, operation, public)
    (ROOT / "fixtures/expected-public-journal.bin").write_bytes(expected)
    result = {
        "expected_acceptance": True,
        "validation": "reuse immutable six native tests and 35 comparisons; no native rerun",
        "public_journal_SHA256": hashlib.sha256(expected).hexdigest(),
        "public_journal_bytes": len(expected),
    }
else:
    first = json.loads((ROOT / "evidence/valid.result.json").read_text())
    assert (
        first["status"] == "completed" and first["accepted"] and first["journal_matches_expected"]
    )
    assert (ROOT / "fixtures/public/cred-rid-changed.bin").read_bytes() == public
    pp = decode_parameters(rawpp)
    valid, secret = unpack(
        (ROOT / "fixtures/private/cred-alpha-42.bin").read_bytes(), b"r0-credential-witness"
    )
    negative, same_secret = unpack(
        (ROOT / "fixtures/private/cred-rid-changed.bin").read_bytes(), b"r0-credential-witness"
    )
    original = credentials.decode_credential(pp, valid)
    changed = credentials.decode_credential(pp, negative)
    assert same_secret == secret
    assert original.revocation_identifier != changed.revocation_identifier
    assert replace(original, revocation_identifier=changed.revocation_identifier) == changed
    # A wrapper records only call count; the original bounded verifier computes
    # the result. No witness bytes or verifier arguments enter the evidence.
    with patch.object(
        credentials, "bounded_verify_mldsa65", wraps=credentials.bounded_verify_mldsa65
    ) as verify:
        accepted = credentials.cred_valid(pp, changed, secret)
        assert accepted is False and verify.call_count == 1
    result = {
        "fixture": "cred-rid-changed",
        "expected_acceptance": False,
        "structurally_valid": True,
        "mutation": "canonical revocation identifier changed; original signature retained",
        "cryptographic_verifier_called": True,
        "bounded_verifier_calls": 1,
        "native_reference": "unchanged pqdid.credentials.cred_valid and bounded_verify_mldsa65",
        "expected_successful_journal": None,
    }
(ROOT / f"evidence/{mode}-reference.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result))
