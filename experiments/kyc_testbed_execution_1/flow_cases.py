"""Connected genuine-baseline checks; no synthetic proof adapter."""

from dataclasses import replace

from experiments.kyc_milestone_1.baseline.verifier import Verdict
from pqdid.did_state import DIDStatus, ReferenceDIDRegistry, encode_did_record
from pqdid.schema import decode_attributes
from pqdid.verifier_state import ProofVerdict, UnsupportedProofVerifier
from pqdid.witness_updates import UpdateStatus

from .wallet_cases import denied


def run(number, app, cache):
    s = app.scenario
    if number in (1, 2):
        name = "A" if number == 1 else "B"
        if number == 1:
            cache["delivery"] = app.issue()
        before = s.snapshot()
        request = s.request(name)
        presentation = s.present(request)
        assert s.verify(request, presentation) is Verdict.ACCEPTED
        cache[name] = (request, presentation)
        after = s.snapshot()
        assert after["verifiers"][name]["consumed"] == before["verifiers"][name]["consumed"] + 1
        other = "B" if name == "A" else "A"
        assert after["verifiers"][other] == before["verifiers"][other]
    elif number == 3:
        before = s.snapshot()
        assert s.verify(*cache["A"]) is Verdict.REPLAY
        assert s.snapshot() == before
    elif number == 4:
        before = s.snapshot()
        assert s.verifiers["B"].verify(*cache["A"]) is Verdict.MISMATCH
        assert s.snapshot() == before
    elif number == 5:
        before = s.snapshot()
        assert s.issuer.retrieve(s.last_operation, b"holder") == cache["delivery"]
        denied(lambda: s.issuer.retrieve(s.last_operation, b"other"))
        assert s.snapshot() == before
    elif number == 6:
        before = s.snapshot()
        s.reopen()
        assert s.issuer.retrieve(s.last_operation, b"holder") == cache["delivery"]
        assert s.snapshot() == before
    elif number == 7:
        answer = app.resolver.resolve(s.pp, app.did)
        assert answer.status is DIDStatus.ACTIVE
        values = decode_attributes(s.pp.schema, s.holder.credential.attributes)
        assert values[s.pp.schema.did_index - 1] == app.did
        assert values[s.pp.schema.version_index - 1] == answer.chain[-1].version
        assert answer.chain[-1].body.controller_key == s.holder.public_key
        cache["genesis"] = answer.chain[0]
    elif number == 8:
        assert app.rotate() is DIDStatus.CONFIRMED
        answer = app.resolver.resolve(s.pp, app.did)
        assert answer.status is DIDStatus.ACTIVE
        assert answer.chain[-1].body.controller_key == app.material.keys[5].public
        before = s.snapshot()
        denied(app.issue)  # Old certified intent is not silently rewritten on rotation.
        assert s.snapshot() == before
    elif number == 9:
        assert app.deactivate() is DIDStatus.CONFIRMED
        before = s.snapshot()
        denied(app.issue)
        assert s.snapshot() == before
    elif number == 10:
        registry = ReferenceDIDRegistry(app.resolver.config)
        wrong = replace(cache["genesis"], signature=bytes(3309))
        assert registry.append(encode_did_record(wrong), None) is DIDStatus.UNAUTHORISED
        assert registry.snapshot() == ()
    elif number == 11:
        s.add_holder()
        assert s.revoke_update().status is UpdateStatus.UPDATED
        old = s.holder.checkpoint
        s.revoke(s.holder.credential.identifier)
        assert s.synchronise().status is UpdateStatus.REVOKED
        assert s.holder.checkpoint == old
        cache["revoked"] = True
    elif number == 12:
        old = (s.holder.credential, s.holder.checkpoint)
        s.reopen()
        assert (s.holder.credential, s.holder.checkpoint) == old
    elif number == 13:
        request, presentation = cache["A"]
        s.clock.offset += 121
        # Existing consumed request remains a replay; a new expired request cannot be created.
        before = s.snapshot()
        denied(lambda: s.verifiers["A"].request(request.context.policy, b"expired", s.clock.now()))
        assert s.snapshot() == before
    elif number == 14:
        before = s.snapshot()
        assert UnsupportedProofVerifier().verify(None, b"fixture-proof") is ProofVerdict.UNSUPPORTED
        assert not s.capabilities()["prove_auth"] and not s.capabilities()["verify_auth_proof"]
        assert s.snapshot() == before
    else:
        raise AssertionError("unregistered flow case")
    return {
        "state": s.snapshot(),
        "proof_backend": "unavailable",
        "signatures": "genuine bounded ML-DSA-65",
    }
