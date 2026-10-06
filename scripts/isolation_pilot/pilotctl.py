"""Reviewable fixed-scope pilot CLI. Dry-run/static never perform host mutations."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from layout import (
    ACCOUNTS,
    IPC_GROUPS,
    PROJECT,
    PROPOSAL,
    RELEASE,
    check,
    collision_report,
    expected_groups,
    root_required,
)


def proposal():
    return {
        "package": "S2-AUTHORITY-ISOLATION-PILOT-1",
        "mutating": False,
        "activation_authorised": False,
        "actual_identity_tests_executed": 0,
        "accounts": [
            {
                "name": a,
                "uid": "fresh NSS allocation; pin after creation",
                "primary_group": a,
                "home": "/nonexistent",
                "shell": "/usr/sbin/nologin",
                "supplementary_groups": expected_groups(a),
            }
            for a in ACCOUNTS
        ],
        "transport_groups": IPC_GROUPS,
        "collisions": collision_report(),
        "ownership_modes": (PROPOSAL / "directories.tmpfiles.conf.in").read_text(),
        "launch_files": {p.name: p.read_text() for p in sorted(PROPOSAL.glob("*.service.in"))},
        "aggregate_slice": (PROPOSAL / "pqiso.slice.in").read_text(),
        "configuration_modes": {
            "owner_client_policies": "root:private-primary 0640",
            "credential_vault": "root:root 0700",
            "bundles": "root:root 0400",
            "runtime_directories": "root:root 0755",
            "runtime_files": "root:root 0644",
            "database": "owner:private-primary 0600",
            "socket": "owner:transport 0660",
        },
        "release": str(RELEASE),
        "fresh_venv": True,
        "existing_venv_relocated": False,
        "identity_view": "current namespace only; root activation repeats host NSS/path checks",
        "no_existing_project_chown_or_chmod": True,
    }


def static():
    import ast

    from provision import source_files

    files = list((PROJECT / "scripts/isolation_pilot").glob("*.py"))
    for path in files:
        ast.parse(path.read_text(), filename=str(path))
    check(len(ACCOUNTS) == 13 and len(IPC_GROUPS) == 4, "principal-count")
    check(not collision_report(), "collision")
    with tempfile.TemporaryDirectory(prefix="pqiso-static-") as tmp:
        paths = []
        for path in sorted(PROPOSAL.glob("*.service.in")):
            # Preserve every security/identity directive. Substitute only unavailable
            # executable/working-directory paths for parser validation, never install.
            text = path.read_text()
            lines = [
                line
                if not line.startswith(("ExecStart=", "ExecStartPre=", "WorkingDirectory="))
                else "ExecStart=/usr/bin/true"
                if line.startswith("ExecStart=")
                else "ExecStartPre=/usr/bin/true"
                if line.startswith("ExecStartPre=")
                else "WorkingDirectory=/"
                for line in text.splitlines()
            ]
            target = Path(tmp) / path.name.removesuffix(".in")
            target.write_text("\n".join(lines) + "\n")
            paths.append(str(target))
        target = Path(tmp) / "pqiso.slice"
        target.write_bytes((PROPOSAL / "pqiso.slice.in").read_bytes())
        paths.append(str(target))
        result = subprocess.run(
            ["/usr/bin/systemd-analyze", "verify", "--man=no", *paths],
            capture_output=True,
            timeout=10,
        )
        check(len(result.stdout) + len(result.stderr) < 32768, "static-output-limit")
        print(json.dumps({"parser_exit": result.returncode, "stderr": result.stderr.decode()}))
        check(result.returncode == 0 and not result.stderr, "systemd-static-validation")
    return {
        "passed": True,
        "kind": "static-only",
        "actual_identity_tests_executed": 0,
        "accounts_created": 0,
        "units_installed_or_started": 0,
        "python_files": len(files),
        "release_source_files": len(source_files()),
        "parser_substitutions": "ExecStart/ExecStartPre=/usr/bin/true; WorkingDirectory=/ only",
        "unsubstituted_templates_retained": True,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=(
            "dry-run",
            "static",
            "provision",
            "verify",
            "shutdown",
            "rollback",
            "case",
            "launch",
        ),
    )
    parser.add_argument("name", nargs="?")
    args = parser.parse_args()
    if args.action in {"dry-run", "static"}:
        value = proposal() if args.action == "dry-run" else static()
        print(json.dumps(value, indent=2))
        return
    root_required()
    # Mutating commands must be inside the resource-guard worker, not a direct sudo invocation.
    check(os.environ.get("PQISO_GUARDED_ACTION") == args.action, "guarded-action-required")
    if args.action == "provision":
        from provision import provision

        provision()
    elif args.action == "rollback":
        from provision import rollback

        rollback()
    else:
        from runtime import release_check

        release_check()
        sys.path.insert(0, str(RELEASE / "src"))
        sys.path.insert(0, str(RELEASE / ".venv/lib/python3.14/site-packages"))
        from control import shutdown, start, verify

        if args.action == "verify":
            print(json.dumps(verify()))
        elif args.action == "shutdown":
            shutdown()
        elif args.action == "launch":
            verify()
            start(args.name)
        else:
            from cases import run_case

            run_case(args.name)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(
            json.dumps(
                {
                    "passed": False,
                    "error_type": type(error).__name__,
                    "reason": str(error)
                    if type(error).__name__ == "PilotError"
                    else "bounded-operation-failed",
                }
            )
        )
        raise SystemExit(1) from None
