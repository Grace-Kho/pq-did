"""Approved component dispatcher reusing the existing cgroup and stop guard."""

import json
import resource
import sys
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[3]
X = P / "experiments/binius_embedding_correspondence_1"
OLD = P / "docs/data/s3_aurora_transcript_correction_contract_1/run_checks.py"


def load(path):
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


g = types.ModuleType("component_guard")
g.__file__ = str(OLD)
source = OLD.read_text()
for before, after in (
    ('unit = "pqdid-auroracontract-" + name', 'unit = "pqdid-biniusembed-" + name.lower()'),
    ("size(BASE)", "package_size()"),
    (
        'if (D / "STOP.json").exists():',
        'if (D / "STOP.json").exists() and not formatting_resume():',
    ),
    (
        'CONFIG["prior_output_bytes"] + package_size() >= CONFIG["output_bytes"]',
        '(CONFIG["prior_output_bytes"] + package_size() >= CONFIG["output_bytes"] '
        'or package_size() >= CONFIG["new_evidence_subcap_bytes"])',
    ),
    ("> 300:", '> CONFIG["package_seconds"]:'),
    (
        '"PrivateNetwork=yes",',
        '"PrivateNetwork=no" if name == "acquire" else "PrivateNetwork=yes",',
    ),
    (
        'assert len(Path("/proc/net/route").read_text().splitlines()) == 1',
        'assert name == "acquire" or len(Path("/proc/net/route").read_text().splitlines()) == 1',
    ),
    (
        '"network": "private-no-routes",',
        '"network": "approved-exact-source-fetch" if name == "acquire" else "private-no-routes",',
    ),
    (
        'reserve = CONFIG["cleanup_and_evidence_reserve_seconds"]',
        'reserve = 0 if CONFIG["command_phases"][name] == "completion" '
        'else CONFIG["cleanup_and_evidence_reserve_seconds"]',
    ),
):
    assert before in source, before
    source = source.replace(before, after)
exec(compile(source, str(OLD), "exec"), g.__dict__)
g.BASE = g.D = R
g.P = P
g.__file__ = str(R / "run.py")
g.CONFIG = json.loads((R / "config.json").read_text())
g.FILES = [str(R), str(X)]
safety = load(
    P / "docs/data/s3_aurora_native_transcript_pilot_1/output-guard-repair-1/monitor_safety.py"
)


def package_size():
    total = g.size(R) + g.size(X)
    for name, prefix in json.loads((R / "prefixes.json").read_text()).items():
        total += (P / name).stat().st_size - prefix["bytes"]
    return total


def write(name, value):
    (R / name).write_text(json.dumps(value, separators=(",", ":")) + "\n")


g.package_size = package_size
g.write = write
g.COMMANDS = {
    name: [str(P / ".venv/bin/python"), "-I", "-B", str(R / "run.py"), "work", name]
    for name in g.CONFIG["command_reservations_seconds"]
}


def main(name):
    if (R / "representation-blocker.json").exists() and name.startswith("EC-"):
        raise SystemExit("representation admission blocked; no cases authorised past this stop")
    config = g.CONFIG
    rows = (
        json.loads((R / "run-ledger.json").read_text()) if (R / "run-ledger.json").exists() else []
    )
    phase = config["command_phases"][name]
    spent = config["operator_by_phase"][phase] + sum(
        row.get("seconds", row["limit_seconds"])
        for row in rows
        if config["command_phases"][row["name"]] == phase
    )
    assert (
        spent + config["command_reservations_seconds"][name] <= config["phase_caps_seconds"][phase]
    )
    assert package_size() + (262144 if phase != "completion" else 32768) <= 1048576
    return safety.protect(g.main, g, name)


def formatting_resume():
    import hashlib

    record = json.loads((R / "completion-corrections.json").read_text())
    expected_stops = {"STOP.json", "STOP-prepare.json", "STOP-quality-3.json"}
    assert {p.name for p in R.glob("STOP*.json")} == expected_stops
    for filename, expected in record["sha256"].items():
        assert hashlib.sha256((R / filename).read_bytes()).hexdigest() == expected
    assert "E501 Line too long" in (R / "quality.log").read_text()
    assert "refusing to overwrite an existing report" in (R / "prepare.log").read_text()
    fatal = json.loads((R / "quality-3.fatal.json").read_text())
    assert fatal["original_error"]["type"] == "AssertionError"
    assert "assert not list(R.glob" in fatal["traceback"]
    assert fatal["original_resource_record"] is None and fatal["contained"] and fatal["reaped"]
    rows = json.loads((R / "run-ledger.json").read_text())
    assert {row["name"] for row in rows if row["status"] == "failed"} == {
        "quality",
        "prepare",
        "quality-3",
    }
    return True


g.formatting_resume = formatting_resume


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    if sys.argv[1] == "--worker":
        raise SystemExit(g.worker(sys.argv[2]))
    if sys.argv[1] == "work":
        name = sys.argv[2]
        if name in {"preflight", "acquire"}:
            load(R / "admission.py").run(name)
        elif name.startswith("EC-"):
            sys.path.insert(0, str(X))
            load(X / "cases.py").run(name, R)
        else:
            load(R / "checks.py").run(name)
    elif sys.argv[1] == "cases":
        for i in range(1, 26):
            code = main(f"EC-{i:02}")
            if code:
                raise SystemExit(code)
    else:
        name = sys.argv[2] if sys.argv[1] == "case" else sys.argv[1]
        raise SystemExit(main(name))
