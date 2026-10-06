"""Reuse the established resource guard for documentation/preservation only."""

import json
import resource
import sys
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[2]
OLD = P / "docs/data/s3_aurora_transcript_correction_contract_1/run_checks.py"
REPORT = P / "docs/stage3_binius_committed_view_correspondence.md"


def load(path):
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


g = types.ModuleType("committed_view_guard")
g.__file__ = str(OLD)
source = OLD.read_text()
for before, after in (
    ('unit = "pqdid-auroracontract-" + name', 'unit = "pqdid-biniusview-" + name'),
    ("size(BASE)", "package_size()"),
    (
        'reserve = CONFIG["cleanup_and_evidence_reserve_seconds"]',
        'reserve = 0 if CONFIG["command_phases"][name] == "completion" '
        'else CONFIG["cleanup_and_evidence_reserve_seconds"]',
    ),
    (
        'CONFIG["prior_output_bytes"] + package_size() >= CONFIG["output_bytes"]',
        '(CONFIG["prior_output_bytes"] + package_size() >= CONFIG["output_bytes"] '
        'or package_size() >= CONFIG["new_evidence_subcap_bytes"])',
    ),
):
    assert before in source, before
    source = source.replace(before, after)
exec(compile(source, str(OLD), "exec"), g.__dict__)
g.BASE = g.D = R
g.P = P
g.__file__ = str(R / "run.py")
g.CONFIG = json.loads((R / "config.json").read_text())
g.FILES = [str(R)]
safety = load(
    P / "docs/data/s3_aurora_native_transcript_pilot_1/output-guard-repair-1/monitor_safety.py"
)


def package_size():
    total = g.size(R) + (REPORT.stat().st_size if REPORT.exists() else 0)
    for name, prefix in json.loads((R / "prefixes.json").read_text()).items():
        total += (P / name).stat().st_size - prefix["bytes"]
    return total


g.package_size = package_size
g.COMMANDS = {
    name: [str(P / ".venv/bin/python"), "-I", "-B", str(R / "run.py"), "work", name]
    for name in g.CONFIG["command_reservations_seconds"]
}


def main(name):
    opening = json.loads((R / "opening.json").read_text())
    assert g.CONFIG["package_seconds"] <= opening["outside_KYC_remaining_seconds"]
    assert package_size() + 98304 < 1048576
    assert opening["storage_opening"]["shared_headroom_bytes"] - 1048576 >= 2097152
    return safety.protect(g.main, g, name)


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    if sys.argv[1] == "--worker":
        raise SystemExit(g.worker(sys.argv[2]))
    if sys.argv[1] == "work":
        load(R / "checks.py").run(sys.argv[2])
    else:
        raise SystemExit(main(sys.argv[1]))
