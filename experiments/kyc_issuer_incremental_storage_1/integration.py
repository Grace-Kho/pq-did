"""Affected genuine ML-DSA application paths using the isolated v2 journal."""

from experiments.kyc_issuer_incremental_storage_1 import journal as v2
from experiments.kyc_issuer_incremental_storage_1.cases import rejected, reopen
from experiments.kyc_milestone_1.baseline.records import encode_credential
from experiments.kyc_milestone_1.baseline.verifier import Verdict
from experiments.kyc_testbed_execution_1.application import Application


def upgrade(app):
    s = app.scenario
    old = s.issuer.journal
    plan = v2.IssuerJournal.migration_plan(old.path, old.identity, old.ticket, old.generation)
    s.issuer = s._issuer(v2.IssuerJournal.migrate(plan))
    return plan


def run(number, path, cache):
    if not cache:
        app = Application.create(path)
        original = app.issue()
        old = app.scenario.issuer.journal
        rows = old.snapshot()
        plan = upgrade(app)
        assert app.scenario.issuer.journal.snapshot() == rows
        cache.update(
            app=app, delivery=original, migration=plan, operation=app.scenario.last_operation
        )
    s = cache["app"].scenario
    j = s.issuer.journal
    if number == 1:
        s.issuer = s._issuer(reopen(j))

        def unavailable(*_args):
            raise AssertionError("redelivery must not sign")

        s.issuer.signer.sign_credential = unavailable
        delivered = s.issuer.retrieve(cache["operation"], b"holder")
        assert encode_credential(s.pp, delivered.credential) == encode_credential(
            s.pp, cache["delivery"].credential
        )
        before = s.snapshot()
        rejected(lambda: s.issuer.retrieve(cache["operation"], b"wrong-recipient"))
        assert s.snapshot() == before
        s.issuer = s._issuer(reopen(s.issuer.journal))
    elif number in (2, 3):
        audience = "A" if number == 2 else "B"
        before = s.snapshot()
        request = s.request(audience)
        presentation = s.present(request)
        assert s.verify(request, presentation) is Verdict.ACCEPTED
        assert s.verify(request, presentation) is Verdict.REPLAY
        after = s.snapshot()
        other = "B" if audience == "A" else "A"
        assert after["verifiers"][other] == before["verifiers"][other]
        assert (
            after["verifiers"][audience]["consumed"]
            == before["verifiers"][audience]["consumed"] + 1
        )
    elif number in (4, 5):
        challenge = s.issuer.begin(s.data.attributes, s.holder.public_key, b"holder")
        signature = s.holder.enrol(challenge)
        point = "commit-" + ("before" if number == 4 else "after") + "-commit"

        def fault(where):
            if where == point and j.pending is not None and j.pending.phase == "certification":
                raise RuntimeError("simulated lost commit response")

        v2._fault = fault
        try:
            s.issuer.complete(challenge.session, signature)
        except RuntimeError:
            pass
        else:
            raise AssertionError("fault not reached")
        finally:
            v2._fault = lambda _: None
        assert j.pending is not None
        expected = j.pending.before if number == 4 else j.pending.after
        s.issuer = s._issuer(reopen(j, expected))
        if number == 4:
            rejected(lambda: s.issuer.retrieve(challenge.operation, b"holder"))
            assert s.issuer.journal.snapshot()[challenge.operation][0] == b"SIGNING"
        else:
            delivered = s.issuer.retrieve(challenge.operation, b"holder")
            raw = encode_credential(s.pp, delivered.credential)
            assert (
                raw == j.pending.data[-len(raw) :]
            )  # PQL1 final byte field retains exact credential bytes.
            s.issuer = s._issuer(reopen(s.issuer.journal))
            assert (
                encode_credential(
                    s.pp, s.issuer.retrieve(challenge.operation, b"holder").credential
                )
                == raw
            )
        assert s.manager.reservation(s.trusted[b"I"].service_id, challenge.operation) is not None
    elif number == 6:
        challenge = s.issuer.begin(s.data.attributes, s.holder.public_key, b"holder")
        signature = s.holder.enrol(challenge)

        def fail(*_args):
            raise RuntimeError("test-only signing exhaustion")

        s.issuer.signer.sign_credential = fail
        try:
            s.issuer.complete(challenge.session, signature)
        except RuntimeError:
            pass
        else:
            raise AssertionError("signing failure absent")
        assert j.snapshot()[challenge.operation][0] == b"SIGNING"
        rejected(lambda: s.issuer.retrieve(challenge.operation, b"holder"))
        rejected(lambda: s.issuer.complete(challenge.session, signature))
        assert s.manager.reservation(s.trusted[b"I"].service_id, challenge.operation) is not None
        s.issuer = s._issuer(reopen(j))
    elif number == 7:
        challenge = s.issuer.begin(s.data.attributes, s.holder.public_key, b"holder")
        signature = s.holder.enrol(challenge)
        original = s.issuer.signer.sign_credential
        replacement = []

        def fenced(*args):
            result = original(*args)
            replacement.append(j.fence())
            return result

        s.issuer.signer.sign_credential = fenced
        rejected(lambda: s.issuer.complete(challenge.session, signature))
        s.issuer = s._issuer(replacement[0])
        assert s.issuer.journal.snapshot()[challenge.operation][0] == b"SIGNING"
        rejected(lambda: s.issuer.retrieve(challenge.operation, b"holder"))
    elif number == 8:
        before = s.snapshot()
        old = s.last_enrolment
        rejected(lambda: s.issuer.complete(old.session, bytes(3309)))
        assert s.snapshot() == before
        assert s.issuer.retrieve(cache["operation"], b"holder") == cache["delivery"]
    else:
        raise AssertionError(number)
    return dict(
        case=number,
        state=s.snapshot(),
        schema=2,
        crypto="genuine bounded ML-DSA-65",
        private_proof="unavailable",
        migration_anchor=cache["migration"].before[2].hex(),
    )
