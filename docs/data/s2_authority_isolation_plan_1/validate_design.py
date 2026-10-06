"""Non-privileged static consistency checks; never activate a unit or impersonate a user."""

import ast
import configparser
import json
import os
import subprocess
import tempfile
from pathlib import Path

BASE = Path(__file__).resolve().parent
P = BASE.parents[2]
PROPOSAL = P / "docs/proposals/s2_authority_isolation_plan_1"
RUN = os.environ.get("PQDID_PILOT_RUN", "static")


def read(name):
    path = PROPOSAL / name
    assert path.stat().st_size < 65536
    return json.loads(path.read_text())


def main():
    data = read("principals.json")
    accounts, roles = data["accounts"], data["roles"]
    assert data["proposal_only"] and data["activate"] is False
    assert len(accounts) == 13 and set(roles) == {"m", "i", "va", "vb"}
    assert len({r["store"] for r in roles.values()}) == 4
    assert len({r["socket"] for r in roles.values()}) == 4
    assert len({r["owner_account"] for r in roles.values()}) == 4
    membership = set()
    for name, account in accounts.items():
        assert account["primary_group"] == name
        assert account["privileged_host_groups"] == []
        membership.update((name, group) for group in account["ipc_groups"])
    for short, role in roles.items():
        owner = role["owner_account"]
        assert owner != "pqiso-w-" + short and role["deployment_enabled"] is False
        assert role["socket_parent_mode"] == "2750" and role["socket_mode"] == "0660"
        assert len(role["socket"].encode()) <= 107
        assert role["grant_limit"] == 8 and len(role["grants"]) <= 8
        for grant in role["grants"]:
            assert grant["account"] in accounts and grant["account"] != owner
            assert (grant["account"], "pqiso-ipc-" + short) in membership
            for key in ("peer_uid", "peer_primary_gid", "capability_ref"):
                assert grant[key].startswith("@") and grant[key].endswith("@")
            if grant["principal"].startswith("recipient"):
                assert grant["permissions"] == ["retrieve"] and short == "i"
                assert grant["recipient"].startswith("@IMMUTABLE_RECIPIENT_")
            if grant["principal"] == "admin":
                assert set(grant["permissions"]) == {"status", "admit", "replace"}
            if grant["principal"] == "observer":
                assert grant["permissions"] == ["status"]
    for short in ("va", "vb"):
        for kind in ("o", "w"):
            assert accounts[f"pqiso-{kind}-{short}"]["ipc_groups"] == [f"pqiso-ipc-{short}"]
    assert accounts["pqiso-denied"]["ipc_groups"] == []
    sysusers = (PROPOSAL / "accounts.sysusers.conf.in").read_text().splitlines()
    assert {line.split()[1] for line in sysusers if line.startswith("u ")} == set(accounts)
    assert {(s[1], s[2]) for line in sysusers if (s := line.split()) and s[0] == "m"} == membership
    directories = {}
    for line in (PROPOSAL / "directories.tmpfiles.conf.in").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        kind, path, mode, user, group, age = line.split()
        assert kind == "d" and age == "-" and path not in directories
        assert not int(mode, 8) & 0o022
        directories[path] = (mode, user, group)
    for short, role in roles.items():
        assert directories[str(Path(role["store"]).parent)] == (
            "0700",
            role["owner_account"],
            role["owner_account"],
        )
        assert directories[str(Path(role["socket"]).parent)] == (
            "2750",
            role["owner_account"],
            "pqiso-ipc-" + short,
        )
    credentials = read("credentials.json.in")
    assert credentials["proposal_only"] and credentials["live_secrets"] is False
    layout = read("runtime-layout.json")
    assert not layout["installed"] and not layout["old_venv_copied"]
    assert not layout["downloads_or_dependency_upgrades"]
    assert layout["base_interpreter"] == "/usr/bin/python3.14"
    assert layout["pth"]["exact_content"] == "/opt/pqiso/r1/src\n"
    accept = read("acceptance.json")
    assert accept["selected_case_count"] == len(accept["cases"]) == 22
    assert len({c["id"] for c in accept["cases"]}) == 22
    assert accept["actual_kernel_identities_required"] and not accept["executed"]
    assert accept["case_instance_budget"] == 32 and not accept["mock_UIDs_sufficient"]
    config = json.loads((BASE / "config.json").read_text())
    assert accept["memory_bytes_aggregate"] == config["memory_bytes"] == 268435456
    for key in (
        "swap_bytes",
        "command_seconds",
        "child_seconds",
        "aggregate_seconds",
        "workers",
        "controlled_children",
        "cpu_threads",
        "temporary_bytes",
        "output_bytes",
        "automatic_retries",
    ):
        assert accept[key] == config[key]
    assert accept["case_instance_budget"] <= config["synthetic_case_limit"]
    facts = json.loads((BASE / "environment-facts.json").read_text())
    host = json.loads((BASE / "host-metadata.json").read_text())
    assert host["uid"] == facts["uid"] == 1000 and host["paths"][0]["uid"] == 0
    assert not host["host_changes"] and not facts["private_store_or_credential_contents_read"]
    assert all(value is None for value in facts["proposed_account_collisions"].values())
    # Keep original remapped observation and its explicit interpretation correction together.
    assert (BASE / "inspection-view-note.json").is_file()
    assert facts["sqlite_version"] == "3.46.1"
    records = []
    with tempfile.TemporaryDirectory(prefix="unit-static-") as temporary:
        root = Path(temporary)
        paths = []
        for name in (
            "pqiso.slice",
            "pqiso-owner@.service",
            "pqiso-client@.service",
            "pqiso-replacement-m.service",
        ):
            text = (PROPOSAL / (name + ".in")).read_text()
            parser = configparser.ConfigParser(interpolation=None, strict=False)
            parser.read_string(text)
            assert "Install" not in parser
            if name.endswith(".service"):
                service = parser["Service"]
                for key, expected in {
                    "Slice": "pqiso.slice",
                    "CPUAffinity": "0 1",
                    "Delegate": "no",
                    "ProtectControlGroups": "yes",
                    "Restart": "no",
                    "UMask": "0077",
                    "NoNewPrivileges": "yes",
                    "ProtectHome": "yes",
                    "PrivateNetwork": "yes",
                    "RestrictAddressFamilies": "AF_UNIX",
                    "ProtectSystem": "strict",
                    "FileDescriptorStoreMax": "0",
                }.items():
                    assert service[key] == expected
                assert service["CapabilityBoundingSet"] == service["AmbientCapabilities"] == ""
                assert service["ExecStart"].startswith("/usr/bin/env -i ")
                assert " -I -B " in service["ExecStart"]
                assert "preflight.py" in service["ExecStartPre"]
                assert parser["Unit"]["ConditionPathExists"] == "/etc/pqiso/ACTIVATION-AUTHORISED"
            else:
                assert parser["Slice"]["MemoryMax"] == "268435456"
                assert parser["Slice"]["MemorySwapMax"] == "0"
                assert parser["Slice"]["AllowedCPUs"] == "0-1"
            path = root / name
            path.write_text(text)
            paths.append(str(path))
        args = ["systemd-analyze", "verify", "--man=no", *paths]
        process = subprocess.run(args, capture_output=True, text=True, timeout=10, check=False)
        assert len(process.stdout) + len(process.stderr) < 32768
        records.append(
            {
                "command": args,
                "exit_code": process.returncode,
                "stdout": process.stdout,
                "stderr": process.stderr,
                "units_started": 0,
                "files_installed": 0,
            }
        )
        (BASE / (RUN + "-unit-syntax.json")).write_text(json.dumps(records, indent=2) + "\n")
        assert process.returncode == 0, process.stderr
    for path in BASE.glob("*.py"):
        ast.parse(path.read_text(), filename=str(path))
    result = {
        "package": config["package"],
        "passed": True,
        "static_only": True,
        "proposed_accounts": 13,
        "owner_scopes": 4,
        "case_plan_count": 22,
        "actual_identity_cases_executed": 0,
        "functional_tests_run": 0,
        "units_installed_or_started": 0,
        "host_changes": False,
        "checks": [
            "identity/group/permission matrix",
            "exact store/endpoint ownership",
            "no live secrets or resolved identity placeholders",
            "runtime assembly plan",
            "unchanged resource envelope",
            "installed systemd unit syntax parser",
            "actual host vs remapped guard interpretation",
            "evidence Python AST",
        ],
        "unit_parser_scope": "Static syntax only; missing launchers and deployment remain blockers",
    }
    (BASE / (RUN + "-validation.json")).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
