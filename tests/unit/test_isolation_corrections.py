"""Focused temporary fixtures/models; never actual-identity isolation evidence."""

# ruff: noqa: E402

import contextlib
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/isolation_pilot_v2"))
import activation_guard
import control
import emergency_stop
import layout
import ledger
import provision
import shared_parent
import termination


def put(tmp_path, rows):
    path = tmp_path / "input.json"
    path.write_text(json.dumps(rows, indent=2))
    return path


def row(name="check", **extra):
    return {"name": name, "status": "pass", "seconds": 0.1, "exit_code": 0, "stop": None, **extra}


def test_legitimate_historical_ledger_and_unchanged_ipc_ceiling():
    path = layout.EVIDENCE / "run-ledger.json"
    assert path.stat().st_size == 155989
    rows = ledger.read_ledger(path)
    assert len(rows) == 21 and sum(r["status"] == "failed" for r in rows) == 5
    assert sum(r["seconds"] for r in rows) == pytest.approx(35.44347673098673)
    with pytest.raises(layout.PilotError, match="input-size"):
        layout.read_json(path)
    assert layout.LIMIT == 65536


def test_ledger_remaining_results_fit(tmp_path):
    source = layout.EVIDENCE / "run-ledger.json"
    additions = [row("future-" + str(i), diagnostic="x" * 12000) for i in range(26)]
    path = put(tmp_path, ledger.read_ledger(source) + additions)
    assert path.stat().st_size < 1048576
    assert len(ledger.read_ledger(path)) == 47
    assert ledger.capacity(paths=(source,), remaining=26)["projected_bytes"] <= 1048576


def test_ledger_oversized_rejected_before_read(tmp_path, monkeypatch):
    path = put(tmp_path, [row()])
    real_fstat = os.fstat

    def oversized(fd):
        info = real_fstat(fd)
        return SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink, st_size=1048577)

    monkeypatch.setattr(os, "fstat", oversized)
    with pytest.raises(layout.PilotError, match="input-size"):
        ledger.read_ledger(path)


def test_ledger_malformed_truncated_duplicate_json(tmp_path):
    path = tmp_path / "input.json"
    for data in (b'[{"name":', b"[{}", b'[{"name":"a","name":"b"}]', b"[] trailing", b"\xff"):
        path.write_bytes(data)
        with pytest.raises((layout.PilotError, ValueError)):
            ledger.read_ledger(path)


def test_ledger_structure_count_and_record_bound(tmp_path):
    for invalid in (
        {"name": "not-a-list"},
        [row(str(i)) for i in range(129)],
        [row(diagnostic="x" * 16384)],
        [row(), row()],
    ):
        with pytest.raises(layout.PilotError):
            ledger.read_ledger(put(tmp_path, invalid))


def test_ledger_invalid_times_and_false_success(tmp_path):
    for invalid in (
        row(seconds=-1),
        row(seconds=float("nan")),
        row(seconds=float("inf")),
        row(seconds=True),
        row(seconds=61),
        row(exit_code=1),
        row(stop="memory-limit"),
    ):
        with pytest.raises(layout.PilotError):
            ledger.read_ledger(put(tmp_path, [invalid]))


def test_ledger_incomplete_is_explicit_and_charged(tmp_path):
    path = put(tmp_path, [{"name": "running", "status": "launched"}])
    with pytest.raises(layout.PilotError, match="ledger-incomplete"):
        ledger.read_ledger(path)
    assert ledger.elapsed(paths=(path,), allow_incomplete=True) == 65


def test_admission_failure_precedes_privileged_mutation(tmp_path, monkeypatch):
    monkeypatch.setattr(activation_guard, "OUT", tmp_path / "absent")

    def fail():
        raise layout.PilotError("ledger-malformed")

    monkeypatch.setattr(activation_guard, "capacity", fail)
    with pytest.raises(layout.PilotError, match="ledger-malformed"):
        activation_guard.admission("provision", None)
    assert not (tmp_path / "absent").exists()


@pytest.fixture
def parent_model(tmp_path, monkeypatch):
    target = tmp_path / "sysusers.d"
    monkeypatch.setattr(shared_parent, "PARENT", target)
    # Retain real filesystem mode/type/symlink checks. Model only root ownership;
    # no actual chown to root or host path mutation is performed by these tests.
    real = layout.protected

    def model(path, **kwargs):
        kwargs.update(uid=os.getuid(), gid=os.getgid(), ancestors=False)
        return real(path, **kwargs)

    monkeypatch.setattr(shared_parent, "protected", model)
    changes = []
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: changes.append((uid, gid)))
    return target, changes


def test_absent_shared_parent_created_and_recordable(parent_model):
    target, changes = parent_model
    assert shared_parent.ensure_parent() is True
    assert stat.S_IMODE(target.stat().st_mode) == 0o755 and changes == [(0, 0)]


def test_existing_parent_preserves_metadata_and_contents(parent_model, monkeypatch):
    target, changes = parent_model
    target.mkdir(mode=0o750)
    (target / "unrelated.conf").write_text("retain")
    before = target.stat()

    def forbidden(*args):
        raise AssertionError("existing directory chmod")

    monkeypatch.setattr(os, "fchmod", forbidden)
    assert shared_parent.ensure_parent() is False
    after = target.stat()
    assert (before.st_ino, before.st_mode, before.st_uid, before.st_gid) == (
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
    )
    assert (target / "unrelated.conf").read_text() == "retain" and changes == []


def test_unsafe_shared_parent_variants_refused(parent_model):
    target, changes = parent_model
    target.write_text("unexpected file")
    with pytest.raises(layout.PilotError):
        shared_parent.ensure_parent()
    target.unlink()
    target.symlink_to(target.parent)
    with pytest.raises(layout.PilotError):
        shared_parent.ensure_parent()
    target.unlink()
    target.mkdir(mode=0o777)
    target.chmod(0o777)
    with pytest.raises(layout.PilotError):
        shared_parent.ensure_parent()
    target.rmdir()
    target.parent.chmod(0o777)
    try:
        with pytest.raises(layout.PilotError):
            shared_parent.ensure_parent()
    finally:
        target.parent.chmod(0o700)
    assert changes == []


def response(unit="pqiso-owner@m.service", **extra):
    record = {
        "Id": unit,
        "LoadState": "not-found",
        "ActiveState": "inactive",
        "SubState": "dead",
        "Job": "",
        "MainPID": "0",
        "ControlPID": "0",
        "ControlGroup": "",
    }
    if unit == "pqiso.slice":
        record.pop("MainPID")
        record.pop("ControlPID")
    record.update(extra)
    return record


def wire(record):
    return ("\n".join(k + "=" + v for k, v in record.items()) + "\n").encode()


def test_documented_not_found_and_inactive_interface(monkeypatch):
    unit = "pqiso-owner@m.service"
    rows = termination.parse_query(wire(response()), (unit,))
    monkeypatch.setattr(termination, "populated", lambda name: False)
    assert termination.complete(rows)
    record = response("pqiso.slice", LoadState="loaded")
    assert termination.complete(termination.parse_query(wire(record), ("pqiso.slice",)))


def test_systemd_query_transport_failures_are_unknown(monkeypatch):
    for result in (
        SimpleNamespace(returncode=1, stdout=wire(response()), stderr=b""),
        SimpleNamespace(returncode=0, stdout=b"", stderr=b"Failed to connect to bus"),
    ):
        monkeypatch.setattr(subprocess, "run", lambda *a, _result=result, **k: _result)
        with pytest.raises(layout.PilotError):
            termination.query(("pqiso-owner@m.service",), time.monotonic() + 5)
    for error in (subprocess.TimeoutExpired("systemctl", 1), OSError("bus")):

        def fail(*a, _error=error, **k):
            raise _error

        monkeypatch.setattr(subprocess, "run", fail)
        with pytest.raises(layout.PilotError, match="shutdown-transport-unknown"):
            termination.query(("pqiso-owner@m.service",), time.monotonic() + 5)


def test_query_missing_malformed_and_out_of_scope_properties():
    good = wire(response())
    for data in (
        b"",
        good.replace(b"MainPID=0\n", b""),
        good + b"Id=pqiso-owner@m.service\n",
        wire(response(ControlGroup="/system.slice/ssh.service")),
        wire(response(Id="ssh.service")),
        wire(response(MainPID="unknown")),
        good + b"Extra=unexpected\n",
        b"\xff",
    ):
        with pytest.raises(layout.PilotError):
            termination.parse_query(data, ("pqiso-owner@m.service",))


def test_zero_main_pid_does_not_hide_descendants(tmp_path, monkeypatch):
    monkeypatch.setattr(termination, "CGROOT", tmp_path)
    (tmp_path / "cgroup.controllers").write_text("memory pids")
    cg = tmp_path / "pqiso.slice/pqiso-owner@m.service"
    cg.mkdir(parents=True)
    events = cg / "cgroup.events"
    events.write_text("populated 1\nfrozen 0\n")
    rows = {"pqiso-owner@m.service": response()}
    assert not termination.complete(rows)
    events.write_text("populated 0\nfrozen 0\n")
    assert termination.complete(rows)
    events.write_text("frozen 0\n")
    with pytest.raises(layout.PilotError):
        termination.complete(rows)


def test_partial_provision_emergency_covers_fixed_units_and_inhibits(monkeypatch):
    seen = []
    monkeypatch.setattr(emergency_stop, "root_required", lambda: None)
    monkeypatch.setattr(emergency_stop, "inhibit", lambda: seen.append("inhibit"))

    @contextlib.contextmanager
    def gate(**kwargs):
        seen.append("gate")
        yield

    monkeypatch.setattr(emergency_stop, "gate", gate)

    def terminate(**kwargs):
        seen.append(kwargs)
        return {"complete": True}

    monkeypatch.setattr(emergency_stop, "terminate", terminate)
    assert emergency_stop.stop()["complete"]
    assert seen[:2] == ["inhibit", "gate"]
    assert seen[2]["emergency"] is True
    assert "pqiso-guard-provision.service" in seen[2]["units"]
    assert "pqiso.slice" in seen[2]["units"] and "ssh.service" not in seen[2]["units"]
    assert all(
        "pqiso-guard-" + case.lower() + ".service" in seen[2]["units"]
        for case in termination.CASE_IDS
    )
    assert len(termination.CASE_IDS) == 22


def test_incomplete_termination_cannot_succeed(monkeypatch):
    unit = "pqiso-owner@m.service"
    rows = {
        unit: response(LoadState="loaded", ActiveState="active", SubState="running", MainPID="123")
    }
    monkeypatch.setattr(termination, "query", lambda units, deadline: rows)
    monkeypatch.setattr(termination, "command", lambda *a: b"")
    monkeypatch.setattr(termination, "populated", lambda name: True)
    with pytest.raises(layout.PilotError, match="shutdown-incomplete"):
        termination.terminate(units=(unit,), deadline=time.monotonic() - 1)


def test_rollback_refuses_unknown_shutdown_before_removal(tmp_path, monkeypatch):
    config = tmp_path / "config"
    config.mkdir()
    file = config / "creation.json"
    file.write_text(json.dumps({"created_files": {}}))
    marker = config / "ACTIVATION-AUTHORISED"
    marker.write_text("retain")
    monkeypatch.setattr(provision, "CONFIG", config)
    monkeypatch.setattr(provision, "root_required", lambda: None)
    monkeypatch.setattr(provision, "protected", lambda *a, **k: None)

    def fail(**kwargs):
        raise layout.PilotError("shutdown-transport-unknown")

    monkeypatch.setattr(control, "shutdown", fail)
    with pytest.raises(layout.PilotError, match="shutdown-transport-unknown"):
        provision.rollback()
    assert marker.read_text() == "retain" and json.loads(file.read_text()) == {"created_files": {}}


def test_partial_rollback_retains_shared_parent_and_history(tmp_path, monkeypatch):
    config = tmp_path / "config"
    config.mkdir()
    ledger_path = config / "creation.json"
    ledger_path.write_text(
        json.dumps(
            {
                "created_files": {},
                "shared_sysusers_parent": {"created_by_pilot": True, "retain": True},
            }
        )
    )
    marker = config / "ACTIVATION-AUTHORISED"
    marker.write_text("marker")
    parent = tmp_path / "sysusers.d"
    parent.mkdir()
    (parent / "unrelated.conf").write_text("keep")
    store = tmp_path / "authority.sqlite3"
    store.write_bytes(b"retained-history")
    monkeypatch.setattr(provision, "CONFIG", config)
    monkeypatch.setattr(provision, "root_required", lambda: None)
    monkeypatch.setattr(provision, "protected", lambda *a, **k: None)
    calls = []
    monkeypatch.setattr(
        control, "shutdown", lambda **kwargs: calls.append(kwargs) or {"complete": True}
    )
    monkeypatch.setattr(provision, "run", lambda *args: calls.append(args))
    monkeypatch.setattr(
        layout, "atomic_json", lambda path, value: path.write_text(json.dumps(value))
    )
    provision.rollback()
    assert calls[0] == {"final": True} and calls[-1] == ("/usr/bin/systemctl", "daemon-reload")
    assert not marker.exists() and store.read_bytes() == b"retained-history"
    assert (parent / "unrelated.conf").read_text() == "keep"
    assert json.loads(ledger_path.read_text())["shared_sysusers_parent"]["retain"] is True


def test_inhibitor_prevents_launch_even_with_installed_runtime(monkeypatch):
    monkeypatch.setattr(termination, "inhibited", lambda: True)
    # Exercise the actual locked branch using a modelled root-owned lock descriptor.
    monkeypatch.setattr(termination, "protected", lambda *a, **k: None)
    monkeypatch.setattr(os, "open", lambda *a, **k: 42)
    monkeypatch.setattr(os, "close", lambda fd: None)
    monkeypatch.setattr(
        os,
        "fstat",
        lambda fd: SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=1),
    )
    monkeypatch.setattr(termination.fcntl, "flock", lambda *a: None)
    with pytest.raises(layout.PilotError, match="launch-inhibited"):
        with termination.gate(launching=True):
            raise AssertionError("launch proceeded")


def test_sealed_admission_inputs_correction_closure(tmp_path, monkeypatch):
    proposal = tmp_path / "proposal"
    proposal.mkdir()
    source = tmp_path / "code.py"
    source.write_text("reviewed")
    control_input = tmp_path / "ledger.json"
    control_input.write_text("[]")
    seal = {
        "version": 2,
        "sha256": {"code.py": layout.digest(source)},
        "control_inputs_sha256": {"ledger.json": layout.digest(control_input)},
    }
    (proposal / "source-manifest.json").write_text(json.dumps(seal))
    monkeypatch.setattr(provision, "PROJECT", tmp_path)
    monkeypatch.setattr(provision, "PROPOSAL", proposal)
    monkeypatch.setattr(provision, "source_files", lambda: [source])
    assert provision.verify_authorisation() == seal
    control_input.write_text("[changed]")
    with pytest.raises(layout.PilotError, match="sealed-input-changed"):
        provision.verify_authorisation()


def test_guard_worker_failure_stops_and_remains_failed_correction_closure(tmp_path, monkeypatch):
    monkeypatch.setattr(activation_guard, "OUT", tmp_path)
    (tmp_path / "provision.worker.json").write_text(
        json.dumps({"after": {"memory.peak": "1"}, "resource_guard_passed": False})
    )
    process = SimpleNamespace(poll=lambda: 1, wait=lambda **kwargs: 1)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(activation_guard, "gate", lambda **kwargs: contextlib.nullcontext())
    monkeypatch.setattr(activation_guard, "write_new", lambda path, value: path.write_bytes(value))
    stops = []
    monkeypatch.setattr(
        emergency_stop, "stop_recorded", lambda **kwargs: stops.append(kwargs) or {"complete": True}
    )
    assert activation_guard.monitored("provision", None, "provision", 42) == 1
    report = json.loads((tmp_path / "provision.guard.json").read_text())
    assert not report["passed"] and report["stop"] == "worker-failure" and len(stops) == 1
    assert report["shutdown"]["complete"] is True


def test_false_shutdown_result_blocks_rollback_correction_closure(tmp_path, monkeypatch):
    (tmp_path / "creation.json").write_text(json.dumps({"created_files": {}}))
    marker = tmp_path / "ACTIVATION-AUTHORISED"
    marker.write_text("retain")
    monkeypatch.setattr(provision, "CONFIG", tmp_path)
    monkeypatch.setattr(provision, "root_required", lambda: None)
    monkeypatch.setattr(provision, "protected", lambda *a, **k: None)
    monkeypatch.setattr(control, "shutdown", lambda **kwargs: {"complete": False})
    with pytest.raises(layout.PilotError, match="rollback-shutdown-incomplete"):
        provision.rollback()
    assert marker.read_text() == "retain"


def test_emergency_reporting_failure_is_not_success_correction_closure(monkeypatch):
    calls = []
    monkeypatch.setattr(
        emergency_stop, "stop", lambda *a: calls.append("stop-attempted") or {"complete": True}
    )

    def broken_record():
        raise layout.PilotError("stop-record-framing")

    monkeypatch.setattr(emergency_stop, "recorded_seconds", broken_record)
    result = emergency_stop.stop_recorded()
    assert calls == ["stop-attempted"] and result["complete"] is False
    assert result["report_failure"] == "PilotError"
