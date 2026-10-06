"""One synthetic parser/lifecycle boundary fixture per authorised B invocation."""

import hashlib
import struct

from pqdid.verifier_state import (
    Decision,
    InMemoryChallengeStore,
    Presentation,
    ReferenceVerifier,
    Registration,
    StoredChallenge,
)

from .fixtures import auth_case
from .proof_boundary import (
    InactiveProofAdapter,
    Opening,
    ParseSchedule,
    Round,
    decode_field,
    parse_envelope,
)


def public_fixture():
    statement = b"public synthetic statement for inactive wire parsing"
    pid = hashlib.sha512(b"unadmitted synthetic parameter descriptor").digest()
    rid = hashlib.sha512(b"unadmitted synthetic ordered matrices").digest()
    schedule = ParseSchedule(pid, rid, (Round(7, 1, 1),), (Opening(3, 1, 1),) * 2)
    # Exact independent fixed fixture; no encoder under test derives the payload.
    opening = bytes([0xFF]) * 24 + bytes([0xA5]) * 128 + bytes([0x5A]) * 64
    body = (
        struct.pack(">III", 7, 1, 1)
        + bytes([0x31]) * 64
        + bytes([0xFF]) * 24
        + struct.pack(">I", 2)
        + opening
        + opening
    )
    # Independently framed from the construction contract, not the parser helper.
    tag = b"PQDID-AURORA-AUTH-DRAFT1/statement"
    frame = len(tag).to_bytes(2, "big") + tag + b"\x00\x00\x00\x01"
    frame += len(statement).to_bytes(8, "big") + statement
    expected_tag = hashlib.blake2b(frame, digest_size=64).digest()
    raw = (
        b"PQDAUR01\x00\x01\x01\x00" + pid + rid + expected_tag + len(body).to_bytes(4, "big") + body
    )
    return statement, schedule, raw


def _lifecycle(case_id):
    pp, statement, _ = auth_case()

    class Clock:
        value = statement.context.expires_at - 1

        def now(self):
            return self.value

    class Provider:
        def instance(self, expected):
            assert expected == pp
            return pp

        def current(self, *_):
            raise AssertionError("unsupported/expired proof must not reach Current or consume")

    clock = Clock()
    store = InMemoryChallengeStore(statement.context.audience)
    stored = StoredChallenge(pp, statement.context, statement.state, False)
    assert store.register(stored, clock) is Registration.ADDED
    verifier = ReferenceVerifier(
        parameters=pp,
        audience=statement.context.audience,
        request_public_key=pp.issuer_public_key,
        clock=clock,
        store=store,
        provider=Provider(),
        proof_verifier=InactiveProofAdapter(pp),
    )
    if case_id == "B-12":
        clock.value = statement.context.expires_at
    presentation = Presentation(
        statement.disclosed, statement.disclosed_attributes, b"synthetic-proof-placeholder"
    )
    decision = verifier.verify(
        session=statement.context.session,
        context=statement.context,
        presentation=presentation,
    )
    expected = Decision.EXPIRED if case_id == "B-12" else Decision.UNSUPPORTED
    assert decision is expected and not decision.accepted
    assert store.pending(statement.context.nonce) == stored
    return {
        "case_id": case_id,
        "passed": True,
        "decision": decision.value,
        "challenge_pending_unchanged": True,
        "accepted": False,
        "fixture_registration": "synthetic preload of retained signed public fixture",
        "crash_durability_claimed": False,
        "replay_evidence": "unaffected existing reference store evidence reused; no replay rerun",
    }


def run_case(case_id, meter):
    number = int(case_id.removeprefix("B-"))
    if case_id != f"B-{number:02d}" or not 1 <= number <= 12:
        raise ValueError("unknown boundary case")
    if number >= 11:
        return _lifecycle(case_id)
    statement, schedule, raw = public_fixture()
    changed = bytearray(raw)
    if number == 2:
        changed[11] = 1  # forbidden profile flags; one concrete malformed case
    elif number == 3:
        changed[12] ^= 1
    elif number == 4:
        changed[76] ^= 1
    elif number == 5:
        changed[140] ^= 1
    elif number == 6:
        changed[204:208] = b"\xff" * 4
    elif number == 8:
        changed[-216] ^= 1  # conflicting value in the duplicate opening
    elif number == 9:
        changed[216:220] = (0).to_bytes(4, "big")  # required direct field count
    elif number == 10:
        changed.extend(b"unauthorised private or trailing data")
    try:
        if number == 7:
            decode_field(b"\x00" * 25)
            raise AssertionError("noncanonical field width accepted")
        parsed = parse_envelope(bytes(changed), schedule=schedule, encoded_statement=statement)
    except ValueError as error:
        assert number != 1, "canonical inactive envelope must parse"
        return {
            "case_id": case_id,
            "passed": True,
            "rejected": True,
            "reason": str(error),
            "accepted": False,
            "proof_generated": False,
            "field_note": "all 24-byte encodings canonical; wrong width rejected",
        }
    assert number == 1 and parsed == {
        "parsed": True,
        "verified": False,
        "direct_fields": 1,
        "opening_slots": 2,
        "bytes": len(raw),
    }
    return {"case_id": case_id, "passed": True, "parsed": parsed, "accepted": False}
