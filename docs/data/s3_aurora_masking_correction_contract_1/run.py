"""Reuse the bounded analysis guard; documentation/static commands only."""

import hashlib
import json
import resource
import sys
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[2]
REPORT = P / "docs/stage3_aurora_masking_correction_contract.md"
OLD = P / "docs/data/s3_aurora_transcript_correction_contract_1/run_checks.py"
NATIVE = P / "docs/data/s3_aurora_native_transcript_pilot_1/output-guard-repair-1"


def load(path):
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


g = types.ModuleType("analysis_guard")
g.__file__ = str(OLD)
source = OLD.read_text()
for before, after in (
    ('unit = "pqdid-auroracontract-" + name', 'unit = "pqdid-auroramaskingcontract-" + name'),
    ("size(BASE)", "package_size()"),
    (
        'CONFIG["prior_output_bytes"] + package_size() >= CONFIG["output_bytes"]',
        '(CONFIG["prior_output_bytes"] + package_size() >= CONFIG["output_bytes"] '
        'or package_size() >= CONFIG["new_evidence_subcap_bytes"])',
    ),
):
    assert before in source
    source = source.replace(before, after)
# Retain the diagnosed documentation-only lint stop; a different failure still stops.
source = source.replace(
    'if (D / "STOP.json").exists():',
    'if (D / "STOP.json").exists() and not acknowledged_format_stop(name):',
)
exec(compile(source, str(OLD), "exec"), g.__dict__)
g.BASE = g.D = R
g.__file__ = str(R / "run.py")
g.CONFIG = json.loads((R / "config.json").read_text())
g.FILES = [str(R)]
safety = load(NATIVE / "monitor_safety.py")


def package_size():
    total = g.size(R)
    if REPORT.exists():
        total += REPORT.stat().st_size
    for name, prefix in json.loads((R / "prefixes.json").read_text()).items():
        total += (P / name).stat().st_size - prefix["bytes"]
    return total


def acknowledged_format_stop(name):
    correction = json.loads((R / "format-correction.json").read_text())
    stop = R / "STOP.json"
    return (
        name in {"quality-2", "prepare", "full-audit"}
        and hashlib.sha256(stop.read_bytes()).hexdigest() == correction["retained_stop_sha256"]
        and hashlib.sha256((R / "quality.log").read_bytes()).hexdigest()
        == correction["retained_diagnostic_sha256"]
    )


g.acknowledged_format_stop = acknowledged_format_stop
g.package_size = package_size
g.COMMANDS = {
    name: [str(P / ".venv/bin/python"), "-I", "-B", str(R / "run.py"), "work", name]
    for name in g.CONFIG["command_reservations_seconds"]
}


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    if sys.argv[1] == "--worker":
        raise SystemExit(g.worker(sys.argv[2]))
    if sys.argv[1] == "work":
        load(R / "checks.py").run(sys.argv[2])
    else:
        raise SystemExit(safety.protect(g.main, g, sys.argv[1]))
