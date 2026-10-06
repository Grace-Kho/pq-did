"""Invoke existing preservation helpers with the authorised inventory delta."""

import json
import resource
import subprocess
import sys
import types
from pathlib import Path

F = Path(__file__).resolve().parent
C = F.parent / "continuation-1"
B = F.parent.parent
P = B.parents[2]
ADMISSION = json.loads((F / "admission.json").read_text())
m = types.ModuleType("existing_continuation")
m.__file__ = str(C / "run.py")
source = (C / "run.py").read_text()
old = '"charged + 5 <= 374 and package_charge + 5 <= 40"'
assert source.count(old) == 1
# The user allows the existing reserve to be consumed for all completion work.
source = source.replace(old, '"charged <= 374 and package_charge <= 40"')
exec(compile(source, m.__file__, "exec"), m.__dict__)
g, r, h = m.g, m.r, m.h
read, digest = m.read, m.digest
original_scope = m.scope
original_hydrated = r.hydrated_runs
original_read = m.original_read
m.OPENING = ADMISSION["opening_combined_seconds"]
m.BOOKKEEPING = ADMISSION["bookkeeping_charge_seconds"]
g.CONFIG.update(
    operator_charge_seconds=m.OPENING + m.BOOKKEEPING,
    original_package_charged_seconds=m.OPENING,
    opening_remaining_implementation_seconds=ADMISSION["opening_implementation_seconds"],
    repair_seconds_remaining_at_start=40 - m.OPENING,
    cleanup_and_evidence_reserve_seconds=0,
    accounting="Prior charges plus five bookkeeping seconds and new guard durations; "
    "completion reserve consumed within the same cap, not added to it.",
)
g.CONFIG["command_reservations_seconds"]["static"] = 1
g.COMMANDS = {
    name: [str(P / ".venv/bin/python"), "-I", "-B", str(F / "run.py"), "work", name]
    for name in ("static", "prepare", "full-audit")
}
h.W = r.R = h.runner.R = g.D = g.BASE = F
g.__file__ = str(F / "run.py")
g.FILES = [str(F / "run.py")]
NAMES = {
    "run.py",
    "admission.json",
    "inventory-reconciliation.json",
    "prefixes.json",
    "config.json",
    "checked-inputs.json",
    "run.lock",
    "run-ledger.json",
    "static.json",
    "static.log",
    "static.service.json",
    "preparation.json",
    "prepare.json",
    "prepare.log",
    "prepare.service.json",
    "full-audit.json",
    "full-audit.log",
    "full-audit.service.json",
    "phases.json",
    "validation.json",
    "result.json",
    "STOP.json",
    "validation-closure.json",
    "manifest.json",
}


def helper_read(path):
    if path == F / "checked-inputs.json":
        return read(C / "checked-inputs.json")
    return read(path)


h.read = helper_read


def scope():
    value = original_scope()
    target = ADMISSION["corrected_entry"]
    assert digest(P / target) == ADMISSION["historical_sha256"]
    assert target not in value["original_permitted_documentation"]
    assert target not in value["supplementary_allowed_docs"]
    value["required_names"] = sorted(set(value["required_names"]) | {target})
    assert value["frozen_package_inputs"][target] == ADMISSION["historical_sha256"]
    value["optional_names"] = sorted(
        set(value["optional_names"]) | {str((F / name).relative_to(P)) for name in NAMES}
    )
    pins = read(C / "manifest.json")["sha256"]
    for name, expected in pins.items():
        if name not in r.DOCS:
            assert value["frozen_package_inputs"].get(name, expected) == expected
            value["frozen_package_inputs"][name] = expected
    value["frozen_package_inputs"][str((C / "manifest.json").relative_to(P))] = ADMISSION[
        "source_manifest_sha256"
    ]
    value["frozen_package_inputs"].update(read(F / "checked-inputs.json")["files"])
    value["new_python_files"] = sorted(
        set(value["new_python_files"]) | {str((F / "run.py").relative_to(P))}
    )
    return value


h.scope = r.load_scope = scope


def hydrated_runs():
    reused = next(row for row in read(C / "run-ledger.json") if row["name"] == "checks")
    reused["service"] = read(C / reused["service_record"])
    return [reused, *original_hydrated()]


def routed_read(path):
    value = original_read(path)
    if path == B / "config.json":
        # Reused successful checks are already included in the opening charge.
        value["operator_charge_seconds"] -= next(
            row["seconds"] for row in read(C / "run-ledger.json") if row["name"] == "checks"
        )
    return value


r.hydrated_runs = hydrated_runs
r.read = routed_read


def static():
    for args in (("format",), ("check",), ("format", "--check")):
        subprocess.run(
            [str(P / ".venv/bin/ruff"), *args, "--no-cache", str(F / "run.py")],
            check=True,
            timeout=0.4,
        )
    r.audit.write_report(
        F / "checked-inputs.json",
        {
            "files": {
                str((F / name).relative_to(P)): digest(F / name)
                for name in (
                    "run.py",
                    "admission.json",
                    "inventory-reconciliation.json",
                    "prefixes.json",
                    "config.json",
                )
            }
        },
    )


def full_audit():
    import hashlib

    assert (
        hashlib.sha256(json.dumps(scope(), sort_keys=True).encode()).hexdigest()
        == (read(F / "preparation.json")["scope_sha256"])
    )
    r.full_audit()


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    if sys.argv[1] == "--worker":
        raise SystemExit(g.worker(sys.argv[2]))
    if sys.argv[1] == "work":
        {"static": static, "prepare": h.prepare, "full-audit": full_audit}[sys.argv[2]]()
    else:
        config = F / "config.json"
        if not config.exists():
            config.write_text(json.dumps(g.CONFIG, indent=2) + "\n")
        assert read(config) == g.CONFIG
        raise SystemExit(g.main(sys.argv[1]))
