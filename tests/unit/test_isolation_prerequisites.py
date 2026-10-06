"""Unprivileged models/temporary fixtures; these do not establish OS isolation."""

import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from pqdid.persistence.codec import Unavailable
from pqdid.persistence.endpoint_policy import EndpointPolicy
from pqdid.persistence.owner_ipc import OwnerClient, endpoint_path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/isolation_pilot"))
from layout import PilotError, expected_groups, read_json, write_new  # noqa: E402


def model(
    monkeypatch,
    *,
    parent_mode=0o2750,
    socket_mode=0o660,
    uid=101,
    gid=201,
    ancestor_mode=0o755,
    acl=False,
):
    path = Path("/run/pqiso/m/owner.sock")
    monkeypatch.setattr(Path, "resolve", lambda self: self)
    monkeypatch.setattr(Path, "is_symlink", lambda self: False)

    def info(self):
        if self == path:
            return SimpleNamespace(
                st_mode=stat.S_IFSOCK | socket_mode, st_uid=uid, st_gid=gid, st_nlink=1
            )
        if self == path.parent:
            return SimpleNamespace(st_mode=stat.S_IFDIR | parent_mode, st_uid=101, st_gid=201)
        return SimpleNamespace(st_mode=stat.S_IFDIR | ancestor_mode, st_uid=0, st_gid=0)

    monkeypatch.setattr(Path, "lstat", info)
    monkeypatch.setattr(
        os, "listxattr", lambda *a, **kw: ["system.posix_acl_access"] if acl else []
    )
    return path


def test_explicit_cross_uid_endpoint_model(monkeypatch):
    path = model(monkeypatch)
    policy = EndpointPolicy(101, 102, 201)
    assert endpoint_path(path, exists=True, policy=policy) == path


@pytest.mark.parametrize(
    "fault", ["parent-mode", "socket-mode", "uid", "gid", "ancestor-write", "acl"]
)
def test_model_unsafe_endpoint_refused(monkeypatch, fault):
    kwargs = {
        "parent-mode": {"parent_mode": 0o2770},
        "socket-mode": {"socket_mode": 0o666},
        "uid": {"uid": 103},
        "gid": {"gid": 202},
        "ancestor-write": {"ancestor_mode": 0o777},
        "acl": {"acl": True},
    }[fault]
    path = model(monkeypatch, **kwargs)
    with pytest.raises(Unavailable):
        EndpointPolicy(101, 102, 201).validate(path, exists=True)


def test_policy_cannot_mismatch_kernel_peer_expectation():
    with pytest.raises(Unavailable):
        OwnerClient(
            "/run/pqiso/m/owner.sock",
            b"s" * 32,
            b"t" * 32,
            owner_uid=101,
            owner_gid=103,
            endpoint_policy=EndpointPolicy(101, 102, 201),
        )


def test_binding_requires_primary_and_transport_groups(monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 101)
    monkeypatch.setattr(os, "getgid", lambda: 102)
    monkeypatch.setattr(os, "getgroups", lambda: [201])
    policy = EndpointPolicy(101, 102, 201)
    policy.bind_identity()
    monkeypatch.setattr(os, "getgroups", lambda: [])
    with pytest.raises(Unavailable):
        policy.bind_identity()


def test_relative_symlink_and_long_endpoints_fail(tmp_path):
    policy = EndpointPolicy(101, 102, 201)
    with pytest.raises(Unavailable):
        policy.validate("relative", exists=False)
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "other")
    with pytest.raises(Unavailable):
        policy.validate(link, exists=False)
    with pytest.raises(Unavailable):
        policy.validate("/" + "x" * 108, exists=False)


def test_exclusive_bounded_files(tmp_path):
    path = tmp_path / "file"
    write_new(path, b"original", uid=os.getuid(), gid=os.getgid())
    with pytest.raises(FileExistsError):
        write_new(path, b"replacement")
    assert path.read_bytes() == b"original"
    with pytest.raises(PilotError):
        write_new(tmp_path / "large", b"x" * (1048576 + 1))


@pytest.mark.parametrize("value", [b'{"a": 1, "a": 2}', b'{"a":', b"x" * 65537])
def test_manifest_duplicate_truncation_and_size_fail(tmp_path, value):
    path = tmp_path / "fixture.json"
    path.write_bytes(value)
    with pytest.raises((PilotError, ValueError)):
        read_json(path)


def test_symlink_configuration_fails(tmp_path):
    target = tmp_path / "target"
    target.write_text("{}")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError):
        read_json(link)


def test_role_groups_separate():
    assert expected_groups("pqiso-w-va") == ("pqiso-ipc-va",)
    assert expected_groups("pqiso-w-vb") == ("pqiso-ipc-vb",)
    assert expected_groups("pqiso-denied") == ()
    assert expected_groups("pqiso-o-i") == ("pqiso-ipc-i", "pqiso-ipc-m")
    with pytest.raises(PilotError):
        expected_groups("root")


def test_imports_and_dry_run_do_not_mutate(monkeypatch):
    import pilotctl

    def forbidden(*args, **kwargs):
        raise AssertionError("dry-run mutation")

    monkeypatch.setattr(os, "chown", forbidden)
    monkeypatch.setattr(os, "chmod", forbidden)
    monkeypatch.setattr(os, "mkdir", forbidden)
    monkeypatch.setattr(pilotctl, "collision_report", lambda: [])
    result = pilotctl.proposal()
    assert len(result["accounts"]) == 13
    assert result["mutating"] is False and result["activation_authorised"] is False
    assert result["actual_identity_tests_executed"] == 0


def test_existing_resources_are_not_adopted(monkeypatch):
    import provision

    monkeypatch.setattr(provision, "root_required", lambda: None)
    monkeypatch.setattr(provision, "collision_report", lambda: ["account:pqiso-w-m"])
    with pytest.raises(PilotError, match="existing-pilot-resource"):
        provision.provision()


def test_mutation_requires_guard(monkeypatch):
    import pilotctl

    monkeypatch.setattr(sys, "argv", ["pilotctl.py", "provision"])
    monkeypatch.setattr(pilotctl, "root_required", lambda: None)
    monkeypatch.delenv("PQISO_GUARDED_ACTION", raising=False)
    with pytest.raises(PilotError, match="guarded-action-required"):
        pilotctl.main()


def test_release_mapping_is_fixed():
    from layout import PROJECT, RELEASE
    from provision import destination

    assert destination(PROJECT / "src/pqdid/schema.py") == RELEASE / "src/pqdid/schema.py"
    assert (
        destination(PROJECT / "scripts/isolation_pilot/client_entry.py")
        == RELEASE / "client_entry.py"
    )
    with pytest.raises(ValueError):
        destination(Path("/etc/passwd"))


@pytest.fixture
def configured(tmp_path, monkeypatch):
    """Modelled NSS/chown in a temporary tree; never evidence of actual UID isolation."""
    import grp
    import shutil

    import configure
    from layout import ACCOUNTS, IPC_GROUPS

    config, state = tmp_path / "config", tmp_path / "state"
    config.mkdir()
    state.mkdir()
    shutil.copytree(
        ROOT / "docs/data/s2_authority_isolation_pilot_1/activation-inputs", state / "inputs"
    )
    for name in ("owners", "clients", "credentials"):
        (config / name).mkdir()
    (state / "clients").mkdir()
    ids = {
        account: {"uid": 10000 + index, "gid": 11000 + index, "groups": [11000 + index]}
        for index, account in enumerate(ACCOUNTS)
    }
    for role in ("m", "i", "va", "vb"):
        (config / "owners" / role).mkdir()
    monkeypatch.setattr(configure, "CONFIG", config)
    monkeypatch.setattr(configure, "STATE", state)
    monkeypatch.setattr(configure, "identities", lambda: ids)
    monkeypatch.setattr(configure, "root_required", lambda: None)
    monkeypatch.setattr(os, "chown", lambda *args: None)
    monkeypatch.setattr(
        grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=12000 + IPC_GROUPS.index(name))
    )
    original = write_new
    monkeypatch.setattr(
        configure,
        "write_new",
        lambda path, data, **kwargs: original(
            path, data, uid=os.getuid(), gid=os.getgid(), mode=kwargs.get("mode", 0o600)
        ),
    )
    configure.main()
    return config, state, ids


def test_model_configuration_complete(configured):
    config, _, ids = configured
    assert len(list((config / "owners").glob("*/policy.json"))) == 4
    assert len(list((config / "clients").glob("*/policy.json"))) == 13
    assert len(list((config / "credentials").iterdir())) == 17
    for name, identity in ids.items():
        assert read_json(config / "clients" / name / "policy.json")["identity"] == identity


def test_model_capability_and_uid_both_required(configured, monkeypatch):
    import runtime

    config, state, ids = configured
    monkeypatch.setattr(runtime, "CONFIG", config)
    monkeypatch.setattr(runtime, "STATE", state)
    cfg = read_json(config / "owners/m/policy.json")
    bundle = read_json(config / "credentials/owner-m.bin")
    owner = runtime.make_owner(cfg, bundle, "primary")
    secret = bytes.fromhex(bundle["tokens"]["m:writer"])
    identity = ids["pqiso-w-m"]
    assert (
        owner._policy.authenticate(
            secret, owner._policy.scope, (123, identity["uid"], identity["gid"])
        ).name
        == b"writer"
    )
    with pytest.raises(Unavailable):
        owner._policy.authenticate(
            secret, owner._policy.scope, (123, ids["pqiso-admin"]["uid"], identity["gid"])
        )


def test_model_issuer_bridge_read_only(configured):
    config, _, _ = configured
    cfg = read_json(config / "owners/m/policy.json")
    bridge = next(g for g in cfg["grants"] if g["name"] == "issuer-bridge")
    assert bridge["permissions"] == ["allocation-count", "reservation"]
    assert bridge["account"] == "pqiso-o-i"
    issuer = read_json(config / "owners/i/policy.json")
    assert issuer["manager"]["scope"] == cfg["scope"]
    assert "store" not in issuer["manager"]


def test_model_recipient_tokens_and_bindings_are_distinct(configured):
    config, _, _ = configured
    cfg = read_json(config / "owners/i/policy.json")
    recipients = [g for g in cfg["grants"] if g["recipient"]]
    assert len(recipients) == 2 and recipients[0]["recipient"] != recipients[1]["recipient"]
    assert all(g["permissions"] == ["retrieve"] for g in recipients)
    a = read_json(config / "credentials/client-pqiso-rec-a.bin")["tokens"]
    b = read_json(config / "credentials/client-pqiso-rec-b.bin")["tokens"]
    assert set(a) == {"i:recipient-a"} and set(b) == {"i:recipient-b"}
    assert set(a.values()).isdisjoint(b.values())


def test_model_verifier_scope_separation(configured):
    config, _, _ = configured
    a = read_json(config / "owners/va/policy.json")
    b = read_json(config / "owners/vb/policy.json")
    assert a["scope"] != b["scope"] and a["service"]["audience"] != b["service"]["audience"]
    assert a["store"] != b["store"]
    assert not any(g["recipient"] for cfg in (a, b) for g in cfg["grants"])


def test_rollback_rejects_out_of_scope_record(tmp_path, monkeypatch):
    import control
    import provision

    sentinel = tmp_path / "unrelated"
    sentinel.write_text("unchanged")
    (tmp_path / "creation.json").write_text(json.dumps({"created_files": {str(sentinel): "bad"}}))
    monkeypatch.setattr(provision, "CONFIG", tmp_path)
    monkeypatch.setattr(provision, "root_required", lambda: None)
    monkeypatch.setattr(provision, "protected", lambda *args, **kwargs: None)
    monkeypatch.setattr(control, "shutdown", lambda: None)
    with pytest.raises(PilotError, match="rollback-scope"):
        provision.rollback()
    assert sentinel.read_text() == "unchanged"


def test_no_protected_file_helpers_follow_hardlinks(tmp_path):
    path = tmp_path / "a"
    path.write_text("{}")
    os.link(path, tmp_path / "b")
    with pytest.raises(PilotError, match="private-file-type"):
        read_json(path)


def test_actual_cases_remain_pending_and_have_driver_branches():
    import ast

    tree = ast.parse((ROOT / "scripts/isolation_pilot/cases.py").read_text())
    constants = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    plan = read_json(ROOT / "docs/proposals/s2_authority_isolation_plan_1/acceptance.json")
    assert len(plan["cases"]) == 22
    prefixes = {"ISO-ROLE-", "ISO-CROSS-", "ISO-MISCONFIG-", "ISO-RESTART-"}
    for row in plan["cases"]:
        assert row["id"] in constants or any(
            row["id"].startswith(p) and p in constants for p in prefixes
        )
    assert plan["executed"] is False
