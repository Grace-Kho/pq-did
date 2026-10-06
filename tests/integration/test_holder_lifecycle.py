"""22 individually counted synthetic lifecycle cases; no proof/native/crash campaign."""

import copy
import json
import os
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest
from holder_lifecycle_cases import Rig, keys

from pqdid.codec import EncodingError
from pqdid.holder_lifecycle import ReferenceHolderLifecycle
from pqdid.merkle import verify_non_revocation_path
from pqdid.public_checks import state_auth
from pqdid.relations import auth
from pqdid.revocation_state import ManagerStatus
from pqdid.verifier_state import Decision
from pqdid.witness_updates import (
    MAX_UPDATE_BYTES,
    MAX_UPDATE_RECORDS,
    UpdateLimits,
    UpdateReason,
    UpdateStatus,
    decode_update,
    encode_update,
)

D = Path(__file__).resolve().parents[2] / "docs/data/s2_holder_witness_revocation_integration_1"
ROWS = []


@pytest.fixture(scope="module")
def material():
    return keys()


@pytest.fixture
def rig(material, request):
    with tempfile.TemporaryDirectory(prefix="holder-flow-") as directory:
        value = Rig(Path(directory), material)
        try:
            yield value
        finally:
            ROWS.append({"case": request.node.name, "after": value.summary(), **value.notes})
            (D / ("case-evidence-" + os.environ["PQDID_PILOT_RUN"] + ".json")).write_text(
                json.dumps(ROWS, indent=2) + "\n"
            )


def test_integrated_reference_scenario(rig, monkeypatch):
    rig.request(0)
    initial = rig.prepare(0)
    assert auth(rig.pp, initial.statement, initial.witness)
    assert state_auth(rig.pp, rig.initial.state)
    other = rig.issue_other()
    rig.revoke(other.credential.revocation_identifier)
    calls, updates = [], rig.manager.updates

    def public_page(namespace, start, target, **kwargs):
        calls.append((namespace, start, target))
        return updates(namespace, start, target, **kwargs)

    monkeypatch.setattr(rig.manager, "updates", public_page)
    outcome = rig.local.advance(rig.manager, 1)
    assert outcome.history.status is ManagerStatus.PAGE and outcome.history.page.complete
    assert outcome.update.status is UpdateStatus.UPDATED
    updated = rig.local.snapshot()
    assert (
        updated.credential is rig.initial.credential
        and updated.witness.path != rig.initial.witness.path
    )
    assert calls == [(rig.pp.namespace, 0, 1)]
    # Two separately labelled audience preparations/acceptances within the one scenario.
    rig.request(0)
    a = rig.prepare(0)
    assert rig.synthetic_verify(0, a) is Decision.ACCEPTED
    rig.request(1)
    b = rig.prepare(1)
    assert rig.synthetic_verify(1, b) is Decision.ACCEPTED
    assert a.statement.context.audience != b.statement.context.audience
    assert a.witness == b.witness
    rig.revoke(updated.credential.revocation_identifier)
    revoked = rig.local.advance(rig.manager, 2)
    assert revoked.update.status is UpdateStatus.REVOKED
    assert revoked.update.witness is None and revoked.update.state is None
    assert rig.local.snapshot() is updated
    request = rig.request(0)
    assert state_auth(rig.pp, request.state)
    assert not verify_non_revocation_path(
        rig.pp.domain,
        updated.witness.revocation_identifier,
        updated.witness.path,
        request.state.root,
    )
    before_calls = len(rig.proofs[0].calls)
    _, valid = rig.local_at_request(0)
    assert valid is False and len(rig.proofs[0].calls) == before_calls
    with pytest.raises(EncodingError):
        rig.prepare(0)
    rig.notes["scenario"] = {
        "A": "bounded issuance/state/update authentication; unrelated update succeeds, own REVOKED",
        "B": (
            "complete local auth valid initially/after unrelated update, false at own revoked root"
        ),
        "C": (
            "two test-only exact X/token acceptances at epoch1; "
            "no revoked synthetic verdict invoked"
        ),
        "holder_epoch_retained": 1,
        "manager_epoch": 2,
        "public_page_calls": len(calls),
    }


@pytest.mark.parametrize("kind", ["secret", "identifier", "path", "credential"])
def test_initial_binding_rejects(rig, kind):
    rig.request()
    inputs = rig.prepare()
    accepted = copy.copy(rig.holder)
    issued, secret, witness = rig.holder.snapshot(), rig.h.secret, inputs.witness
    if kind == "secret":
        secret = b"X" * 32
        witness = replace(witness, holder_secret=secret)
    elif kind == "identifier":
        issued = replace(issued, checkpoint=replace(issued.checkpoint, identifier=0))
        witness = replace(witness, revocation_identifier=0)
    elif kind == "path":
        path = bytes([witness.path[0] ^ 1]) + witness.path[1:]
        issued = replace(issued, checkpoint=replace(issued.checkpoint, path=path))
        witness = replace(witness, path=path)
    else:
        cert = replace(issued.credential.certificate, signature=bytes(3309))
        issued = replace(issued, credential=replace(issued.credential, certificate=cert))
        witness = replace(witness, signature=bytes(3309))
    accepted._accepted = issued  # Test-only corrupted hand-off, never a production interface.
    with pytest.raises(EncodingError):
        ReferenceHolderLifecycle(rig.pp, accepted, secret)
    assert auth(rig.pp, inputs.statement, witness) is False
    assert rig.local.snapshot() is rig.initial


@pytest.mark.parametrize("kind", ["audience", "signature", "policy", "state"])
def test_presentation_context_preparation(rig, kind):
    request = rig.request()
    args = {}
    if kind == "audience":
        args["audience"] = b"other"
    elif kind == "signature":
        request = replace(request, signature=bytes(3309))
    elif kind == "policy":
        args["approved_policy"] = replace(rig.policy, clauses=())
    else:
        rig.issue_other()
        rig.revoke(2)
        request = rig.request()
    with pytest.raises(EncodingError):
        rig.prepare(request=request, **args)
    assert rig.local.snapshot() is rig.initial


@pytest.mark.parametrize("kind", ["signature", "path", "state", "instance"])
def test_update_authentication_failure(rig, kind):
    rig.issue_other()
    rig.revoke(2)
    page = rig.history()
    update = decode_update(rig.pp, page.records[0])
    target = page.endpoint_state
    if kind == "signature":
        update = replace(update, signature=bytes(3309))
    elif kind == "path":
        update = replace(update, old_path=bytes([update.old_path[0] ^ 1]) + update.old_path[1:])
    elif kind == "state":
        update = replace(update, new_state=replace(target, signature=bytes(3309)))
    else:
        target = replace(target, namespace=bytes([target.namespace[0] ^ 1]) + target.namespace[1:])
    result = rig.local.apply(target, (encode_update(rig.pp, update),))
    assert result.status is UpdateStatus.INVALID_INPUT
    assert result.witness is None and result.state is None
    assert rig.local.snapshot() is rig.initial


@pytest.mark.parametrize("kind", ["missing", "reordered", "repeated", "stale"])
def test_update_history_failure(rig, kind):
    page = rig.two_updates()
    records, target = page.records, page.endpoint_state
    if kind == "missing":
        records = records[1:]
    elif kind == "reordered":
        records = records[::-1]
    elif kind == "repeated":
        records = (records[0], records[0])
    else:
        target = decode_update(rig.pp, records[0]).new_state
        assert rig.local.apply(target, records[:1]).status is UpdateStatus.UPDATED
        records = records[:1]
    before = rig.local.snapshot()
    result = rig.local.apply(target, records)
    assert result.status is UpdateStatus.INVALID_HISTORY
    assert result.witness is None and result.state is None and rig.local.snapshot() is before


@pytest.mark.parametrize("kind", ["records", "bytes"])
def test_update_limits_atomic(rig, kind):
    assert MAX_UPDATE_RECORDS == 16 and MAX_UPDATE_BYTES == 178592
    records = (b"x" * 11162,) * 17 if kind == "records" else (b"x" * 178593,)
    result = rig.local.apply(rig.initial.state, records)
    assert (
        result.status is UpdateStatus.RESOURCE_EXHAUSTED and result.reason is UpdateReason.ADMISSION
    )
    assert result.witness is None and result.state is None and rig.local.snapshot() is rig.initial


def test_update_explicit_continuation(rig):
    rig.two_updates()
    first = rig.local.advance(rig.manager, 2, limits=UpdateLimits(records=1))
    assert first.history.page.next_epoch == 1 and first.history.page.complete is False
    assert first.update.status is UpdateStatus.UPDATED
    retained = rig.local.snapshot()
    second = rig.local.advance(rig.manager, 2, limits=UpdateLimits(records=1))
    assert second.history.page.starting_state == retained.state and second.history.page.complete
    assert second.update.status is UpdateStatus.REVOKED and rig.local.snapshot() is retained
    rig.notes["continuation"] = (
        "Two explicit one-record pages; no auto-loop, epoch1 retained at REVOKED"
    )


def test_update_invalid_tail_suppresses_partial_revoked_result(rig):
    rig.issue_other()
    rig.revoke(1)
    rig.revoke(2)
    page = rig.history()
    last = decode_update(rig.pp, page.records[1])
    records = (page.records[0], encode_update(rig.pp, replace(last, signature=bytes(3309))))
    result = rig.local.apply(page.endpoint_state, records)
    assert result.status is UpdateStatus.INVALID_INPUT
    assert result.witness is None and result.state is None and rig.local.snapshot() is rig.initial


def test_update_stale_prepared_presentation_rejected(rig):
    rig.request()
    inputs = rig.prepare()
    assert auth(rig.pp, inputs.statement, inputs.witness)
    rig.issue_other()
    rig.revoke(2)
    assert auth(rig.pp, inputs.statement, inputs.witness)  # Historical relation, not freshness.
    assert rig.synthetic_verify(0, inputs) is Decision.STATE
    assert rig.verifiers[0].snapshot()[1].state.challenges[0].consumed is False
    assert rig.local.snapshot() is rig.initial
    rig.notes["freshness"] = (
        "Revocation before final manager read; old-valid local relation, STATE remotely"
    )
