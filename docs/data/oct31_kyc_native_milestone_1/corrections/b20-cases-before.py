"""Forty-eight counted baseline cases. Run only through the milestone coordinator.

Faults below patch private test-worker symbols. Ordinary baseline APIs expose no
fault selectors. Transaction interruptions are simulated exceptions, not crashes.
"""

import argparse
import hashlib
import json
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from experiments.kyc_milestone_1.baseline import signing, storage, verifier
from experiments.kyc_milestone_1.baseline.records import (
    BaselinePresentation,
    credential_body,
    decode_credential,
    decode_presentation,
    decode_request,
    encode_credential,
    encode_presentation,
    frame,
    presentation_body,
    request_body,
)
from experiments.kyc_milestone_1.baseline.scenario import Scenario
from experiments.kyc_milestone_1.baseline.signing import Key, Signer, verify
from experiments.kyc_milestone_1.baseline.verifier import Verdict
from pqdid import bounded_mldsa as bounded_verify
from pqdid import bounded_mldsa_sign as core
from pqdid.codec import EncodingError
from pqdid.parameters import encode_parameters
from pqdid.policy import Equality
from pqdid.revocation_state import ManagerStatus
from pqdid.schema import decode_attributes, encode_attributes
from pqdid.witness_updates import UpdateStatus


def rejected(operation, error=Exception):
    try:
        operation()
    except error:
        return
    raise AssertionError("expected rejection was not observed")


def consumption(s):
    return tuple(s.verifiers[name].snapshot()["consumed"] for name in ("A", "B"))


def pending(s):
    challenge = s.issuer.begin(s.data.attributes, s.holder.public_key, b"holder")
    signature = s.holder.enrol(challenge)
    return challenge, signature


def signed_presentation(s, request, *, credential=None, path=None):
    credential = s.holder.credential if credential is None else credential
    path = s.holder.checkpoint.path if path is None else path
    body = presentation_body(s.pp, request, credential, path)
    signature = s.holder.signer.sign_presentation(request, credential, path)
    return BaselinePresentation(body, signature, request, credential, path)


def assert_unpublished(s, challenge, phase):
    assert s.issuer.journal.snapshot()[challenge.operation][0] == phase
    rejected(lambda: s.issuer.retrieve(challenge.operation, b"holder"), EncodingError)
    assert s.holder.credential is None
    assert s.manager.snapshot()[1].state.allocated_count == 1


def case(case_id, s):
    number = int(case_id[2:])
    notes = {}
    if number <= 12:
        s.issue()
        credential = s.holder.credential
        encoded = encode_credential(s.pp, credential)
        if number == 1:
            assert decode_credential(s.pp, encoded) == credential
            assert verify(
                "credential", s.pp.issuer_public_key, credential.body, credential.signature
            )
        elif number == 2:
            request = s.request()
            presentation = s.present(request)
            assert (
                decode_presentation(s.pp, encode_presentation(s.pp, presentation)) == presentation
            )
            assert s.verify(request, presentation) is Verdict.ACCEPTED
        elif number == 3:
            rejected(
                lambda: credential_body(
                    s.pp,
                    credential.holder_public_key[:-1],
                    credential.attributes,
                    credential.identifier,
                ),
                EncodingError,
            )
        elif number == 4:
            rejected(lambda: decode_credential(s.pp, encoded + b"x"), EncodingError)
        elif number == 5:
            rejected(
                lambda: decode_credential(
                    s.pp, frame("request", (credential.body, credential.signature))
                ),
                EncodingError,
            )
        elif number == 6:
            rejected(
                lambda: credential_body(
                    s.pp, credential.holder_public_key, credential.attributes, True
                ),
                EncodingError,
            )
        elif number == 7:
            foreign = replace(s.pp, namespace=bytes([s.pp.namespace[0] ^ 1]) + s.pp.namespace[1:])
            rejected(lambda: decode_credential(foreign, encoded), EncodingError)
        elif number == 8:
            foreign = replace(s.pp, issuer_public_key=s.keys[1].public)
            rejected(lambda: decode_credential(foreign, encoded), EncodingError)
        elif number == 9:
            body = credential_body(
                s.pp, s.keys[5].public, credential.attributes, credential.identifier
            )
            changed = decode_credential(s.pp, frame("credential", (body, credential.signature)))
            assert not verify("credential", s.pp.issuer_public_key, changed.body, changed.signature)
            rejected(
                lambda: s.holder.signer.sign_presentation(
                    s.request(), changed, s.holder.checkpoint.path
                ),
                EncodingError,
            )
        elif number == 10:
            values = list(decode_attributes(s.pp.schema, credential.attributes))
            values[s.data.validity_index - 1] += 1
            body = credential_body(
                s.pp,
                credential.holder_public_key,
                encode_attributes(s.pp.schema, tuple(values)),
                credential.identifier,
            )
            assert not verify("credential", s.pp.issuer_public_key, body, credential.signature)
        elif number == 11:
            rejected(
                lambda: credential_body(
                    s.pp, credential.holder_public_key, credential.attributes, 1 << 20
                ),
                EncodingError,
            )
        elif number == 12:
            presentation = encode_presentation(s.pp, s.present(s.request()))
            assert s.keys[4].secret not in encoded and s.keys[4].secret not in presentation
            assert s.holder.public_key in encoded
            assert "secret" not in repr(s.holder.signer)
        assert s.holder.credential == credential
    elif number in {13, 14, 15, 16}:
        if number == 13:
            rejected(
                lambda: s.holder.signer.sign_credential(s.holder.public_key, s.data.attributes, 0),
                EncodingError,
            )
        elif number == 14:
            rejected(
                lambda: s.holder.signer.sign_enrolment(
                    b"session",
                    bytes(32),
                    s.holder.public_key,
                    s.data.attributes,
                    0,
                    context=b"override",
                ),
                TypeError,
            )
        elif number == 15:
            rejected(
                lambda: Signer(
                    s.pp,
                    "holder",
                    Key(s.keys[4].public, s.keys[5].secret),
                    s.keys[4].public,
                    lambda: True,
                ),
                core.BoundedMLDSAError,
            )
        else:
            with patch.object(
                core.secrets, "token_bytes", side_effect=OSError("synthetic-entropy")
            ):
                rejected(Key.generate, core.BoundedMLDSAError)
        assert not s.issuer.journal.snapshot() and consumption(s) == (0, 0)
    elif number in {17, 18, 19, 20}:
        challenge, signature = pending(s)
        if number == 17:
            fault = patch.object(
                signing.secrets, "token_bytes", side_effect=OSError("synthetic-entropy")
            )
        elif number == 18:
            fault = patch.object(core, "_candidate", return_value=None)
        elif number == 19:
            fault = patch.object(
                core,
                "_checked_secret",
                side_effect=bounded_verify._SamplerExhausted("synthetic", 1026),
            )
        else:
            fault = patch.object(
                core.v,
                "_verify_diagnostic",
                return_value=SimpleNamespace(status=core.v._Status.INVALID),
            )
        with fault:
            rejected(
                lambda: s.issuer.complete(challenge.session, signature), core.BoundedMLDSAError
            )
        assert_unpublished(s, challenge, b"SIGNING")
    elif number in {21, 22, 23, 24, 25, 26, 27, 28}:
        if number == 21:

            def fail(point):
                if point == "reservation-before-commit":
                    raise RuntimeError("synthetic-reservation-commit-failure")

            with patch.object(storage, "_fault", side_effect=fail):
                rejected(
                    lambda: s.issuer.begin(s.data.attributes, s.holder.public_key, b"holder"),
                    RuntimeError,
                )
            assert s.manager.snapshot()[1].state.allocated_count == 1
            assert list(s.issuer.journal.snapshot().values())[0][0] == b"INTENT"
            assert s.holder.credential is None
        elif number == 23:
            values = list(decode_attributes(s.pp.schema, s.data.attributes))
            values[s.data.validity_index - 1] += 1
            rejected(
                lambda: s.issuer.begin(
                    encode_attributes(s.pp.schema, tuple(values)), s.holder.public_key, b"holder"
                ),
                EncodingError,
            )
            assert not s.issuer.journal.snapshot()
            assert s.manager.snapshot()[1].state.allocated_count == 0
        elif number in {27, 28}:
            challenge, signature = pending(s)
            operation = s.issuer.complete(challenge.session, signature)
            if number == 28:
                rejected(lambda: s.issuer.retrieve(operation, b"another-recipient"), EncodingError)
                assert s.issuer.journal.snapshot()[operation][0] == b"CERTIFIED"
            else:
                retained = encode_credential(
                    s.pp, s.issuer.retrieve(operation, b"holder").credential
                )
                # Deliberately unobserved first response; no OS-crash claim.
                s.reopen()
                with patch.object(
                    s.issuer.signer,
                    "sign_credential",
                    side_effect=AssertionError("redelivery-resigned"),
                ):
                    recovered = s.issuer.retrieve(operation, b"holder")
                assert encode_credential(s.pp, recovered.credential) == retained
                s.holder.accept_credential(recovered, s.data.attributes)
                notes["interruption"] = "response deliberately unobserved, not a process crash"
        else:
            challenge, signature = pending(s)
            if number == 22:
                rejected(lambda: s.issuer.complete(challenge.session, bytes(3309)), EncodingError)
                assert_unpublished(s, challenge, b"RESERVED")
            elif number in {24, 26}:
                phase = "claim" if number == 24 else "certification"

                def fail(point):
                    if point == phase + "-before-commit":
                        raise RuntimeError("synthetic-commit-failure")

                with patch.object(storage, "_fault", side_effect=fail):
                    rejected(lambda: s.issuer.complete(challenge.session, signature), RuntimeError)
                assert_unpublished(s, challenge, b"RESERVED" if number == 24 else b"SIGNING")
            else:
                original = core.reference_sign_mldsa65
                replacement = []

                def fence_after_signature(*args, **kwargs):
                    result = original(*args, **kwargs)
                    replacement.append(s.issuer.journal.fence())
                    return result

                with patch.object(
                    core, "reference_sign_mldsa65", side_effect=fence_after_signature
                ):
                    rejected(lambda: s.issuer.complete(challenge.session, signature), EncodingError)
                assert replacement[0].snapshot()[challenge.operation][0] == b"SIGNING"
                s.issuer.journal = replacement[0]  # Explicit independently returned new head.
                assert_unpublished(s, challenge, b"SIGNING")
    else:
        s.issue()
        if number in {29, 30}:
            audience = "A" if number == 29 else "B"
            request = s.request(audience)
            assert s.verify(request, s.present(request)) is Verdict.ACCEPTED
            assert consumption(s) == ((1, 0) if number == 29 else (0, 1))
        elif number in {31, 32, 33, 34, 35, 36, 37, 38, 39, 40}:
            request = s.request()
            presentation = s.present(request)
            if number in {31, 33}:
                ctx = (
                    replace(request.context, nonce=b"x" * 32)
                    if number == 31
                    else replace(request.context, session=b"changed")
                )
                changed = decode_request(
                    s.pp,
                    frame("request", (request_body(s.pp, ctx, request.state), request.signature)),
                )
                assert s.verifiers["A"].verify(changed, presentation) is Verdict.MISMATCH
                assert consumption(s) == (0, 0)
            elif number == 32:
                assert s.verifiers["B"].verify(request, presentation) is Verdict.MISMATCH
                assert consumption(s) == (0, 0)
            elif number == 34:
                first = next(c for c in request.context.policy.clauses if type(c) is Equality)
                bad = replace(
                    request.context.policy,
                    clauses=tuple(
                        replace(c, value=not c.value) if c is first else c
                        for c in request.context.policy.clauses
                    ),
                )
                other = s.verifiers["A"].request(bad, b"policy-failure", request.context.expires_at)
                assert (
                    s.verifiers["A"].verify(other, signed_presentation(s, other)) is Verdict.POLICY
                )
                assert consumption(s) == (0, 0)
            elif number in {35, 36}:

                def expire():
                    s.clock.offset += request.context.expires_at - s.clock.now()

                if number == 35:
                    expire()
                    assert s.verify(request, presentation) is Verdict.EXPIRED
                else:
                    original = verifier.current_state

                    def current_then_expire(*args):
                        result = original(*args)
                        expire()
                        return result

                    with patch.object(verifier, "current_state", side_effect=current_then_expire):
                        assert s.verify(request, presentation) is Verdict.EXPIRED
                assert consumption(s) == (0, 0)
            elif number in {37, 38}:
                assert s.verify(request, presentation) is Verdict.ACCEPTED
                if number == 38:
                    s.reopen()
                assert s.verify(request, presentation) is Verdict.REPLAY
                assert consumption(s) == (1, 0)
                other = s.request("B")
                assert s.verify(other, s.present(other)) is Verdict.ACCEPTED
            elif number == 39:
                public = s.holder.public_key
                credential = encode_credential(s.pp, s.holder.credential)
                s.reopen()
                assert s.holder.public_key == public
                assert encode_credential(s.pp, s.holder.credential) == credential
                assert s.verify(request, s.present(request)) is Verdict.ACCEPTED
            else:
                owner = s.verifiers["A"]
                permit, ticket = owner.store.acquire(b"admin", b"f" * 32, owner.ticket, b"writer")
                assert owner.verify(request, presentation) is Verdict.FAILURE
                s.verifier_permits["A"] = permit
                s.verifiers["A"] = verifier.BaselineVerifier(owner.store, permit, ticket, s.keys[2])
                assert consumption(s) == (0, 0)
        elif number in {41, 42, 43, 44, 45, 46, 47, 48}:
            if number in {41, 42, 43, 44}:
                other = s.add_holder() if number == 43 else None
                request = s.request()
                presentation = s.present(request)
                if number == 41:
                    assert (
                        verifier.current_state(s.pp, s.verifiers["A"].provider).reference
                        == request.state.reference
                    )
                    assert s.verify(request, presentation) is Verdict.ACCEPTED
                elif number == 42:
                    provider = s.verifiers["A"].provider
                    original = provider.current

                    def bad_current(*args):
                        return replace(original(*args), signature=bytes(3309))

                    with patch.object(provider, "current", side_effect=bad_current):
                        assert s.verify(request, presentation) is Verdict.FAILURE
                    assert consumption(s) == (0, 0)
                elif number == 43:
                    s.revoke(other.credential.identifier)
                    assert s.verify(request, presentation) is Verdict.STATE
                    assert consumption(s) == (0, 0)
                else:
                    path = bytes([presentation.path[0] ^ 1]) + presentation.path[1:]
                    assert (
                        s.verify(request, signed_presentation(s, request, path=path))
                        is Verdict.REVOKED
                    )
                    assert consumption(s) == (0, 0)
            elif number == 45:
                old = s.holder.checkpoint
                s.revoke(s.holder.credential.identifier)
                assert s.synchronise().status is UpdateStatus.REVOKED
                assert s.holder.checkpoint == old
                request = s.request()
                rejected(lambda: s.present(request), EncodingError)
                assert s.verify(request, signed_presentation(s, request)) is Verdict.REVOKED
                assert consumption(s) == (0, 0)
            elif number == 46:
                other = s.add_holder()
                previous = s.holder.checkpoint
                s.revoke(other.credential.identifier)
                assert s.synchronise().status is UpdateStatus.UPDATED
                assert (
                    s.holder.checkpoint.path != previous.path
                    and s.holder.checkpoint.state.epoch == 1
                )
                request = s.request()
                assert s.verify(request, s.present(request)) is Verdict.ACCEPTED
            elif number == 47:
                a, b = s.add_holder(), s.add_holder()
                s.revoke(a.credential.identifier)
                s.revoke(b.credential.identifier)
                page = s.manager.updates(s.pp.namespace, 0, 2)
                assert page.status is ManagerStatus.PAGE
                previous = s.holder.checkpoint
                result = s.holder.apply(page.page.endpoint_state, page.page.records[::-1])
                assert (
                    result.status is UpdateStatus.INVALID_HISTORY
                    and s.holder.checkpoint == previous
                )
            else:
                other = s.add_holder()
                s.revoke(other.credential.identifier)
                previous = s.holder.checkpoint
                rejected(lambda: s.holder.synchronise(s.manager, 2), EncodingError)
                assert s.holder.checkpoint == previous
                assert consumption(s) == (0, 0)
    return notes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", required=True)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    ids = args.cases.split(",")
    assert ids and len(set(ids)) == len(ids)
    assert all(name == f"B-{int(name[2:]):02d}" and 1 <= int(name[2:]) <= 48 for name in ids)
    args.root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.output.exists():
        raise FileExistsError("case output is append-only per unique attempt")
    material_start = time.monotonic_ns()
    material = Scenario.material()
    setup_ns = time.monotonic_ns() - material_start
    failed = False
    with args.output.open("x", encoding="utf-8") as stream:
        for case_id in ids:
            start = time.monotonic_ns()
            scenario = None
            row = {
                "case": case_id,
                "synthetic_only": True,
                "setup_material_ns": setup_ns,
                "fault_model": "in-process test injection where specified; no process crash",
            }
            try:
                scenario = Scenario.create(args.root / case_id, material=material)
                row.update(case(case_id, scenario))
                row["state"] = scenario.snapshot()
                row["outcome"] = "pass"
            except Exception as error:
                row["outcome"] = "fail"
                row["error_type"] = type(error).__name__
                row["error"] = str(error)[:500]
                failed = True
                if scenario is not None:
                    try:
                        row["state"] = scenario.snapshot()
                    except Exception as state_error:
                        row["state_unavailable"] = type(state_error).__name__
                import traceback

                traceback.print_exc()
            row["elapsed_ns"] = time.monotonic_ns() - start
            row["fixture_sha256"] = material.fixture_sha256
            row["instance_sha256"] = hashlib.sha256(encode_parameters(material.pp)).hexdigest()
            stream.write(json.dumps(row, sort_keys=True) + "\n")
            stream.flush()
            print(json.dumps({"case": case_id, "outcome": row["outcome"]}), flush=True)
            if failed:
                break
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
