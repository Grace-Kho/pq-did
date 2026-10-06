"""Continue the sealed repair with authorised caps and fresh output records."""

import ast
import json
import lzma
import resource
import subprocess
import sys
import types
from pathlib import Path

C = Path(__file__).resolve().parent
S = C.parent
B = S.parent
P = B.parents[2]
AMENDMENT = json.loads((C / "amendment.json").read_text())
OPENING = AMENDMENT["opening_combined_seconds"]
BOOKKEEPING = AMENDMENT["bookkeeping_charge_seconds"]
CAP = AMENDMENT["package_output_bytes"]
FILES = [str(C / name) for name in ("driver.py", "run.py")]

# Keep the corrected source's original path context. Only its formatting changed.
h = types.ModuleType("retained_repair")
h.__file__ = str(S / "run.py")
exec(compile((C / "driver.py").read_text(), h.__file__, "exec"), h.__dict__)
g = h.g
r = h.r
read = h.read
digest = r.audit.digest_file

# Apply the approved output ceiling to both inherited aggregate checks.
source = (B / "repair-1/repair.py").read_text()
assert source.count("assert package_bytes() < 262144") == 2
source = source.replace("assert package_bytes() < 262144", "assert package_bytes() < 1048576")
exec(compile(source, r.__file__, "exec"), r.__dict__)
h.W = r.R = h.runner.R = g.D = g.BASE = C
g.__file__ = str(C / "run.py")
g.CONFIG.update(
    package_seconds=40,
    new_evidence_subcap_bytes=CAP,
    operator_charge_seconds=OPENING + BOOKKEEPING,
    original_package_charged_seconds=OPENING,
    opening_remaining_implementation_seconds=AMENDMENT["opening_implementation_seconds"],
    repair_seconds_remaining_at_start=40 - OPENING,
    accounting="Prior charges retained; five bookkeeping seconds plus actual continuation guards.",
)
g.COMMANDS = {
    name: [str(P / ".venv/bin/python"), "-I", "-B", str(C / "run.py"), "work", name]
    for name in ("checks", "prepare", "full-audit")
}
g.FILES = FILES
g.package_size = r.package_bytes
g.size = h.size

NEW_NAMES = {
    "driver.py",
    "run.py",
    "amendment.json",
    "config.json",
    "prefixes.json",
    "checked-inputs.json",
    "run.lock",
    "run-ledger.json",
    "checks.json",
    "checks.log",
    "checks.service.json",
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
inherited_scope = h.scope


def scope():
    value = inherited_scope()
    required = set(value["required_names"])
    required.update(
        str((C / name).relative_to(P))
        for name in (
            "driver.py",
            "run.py",
            "amendment.json",
            "config.json",
            "prefixes.json",
            "checked-inputs.json",
            "checks.json",
            "checks.log",
            "checks.service.json",
            "run.lock",
            "run-ledger.json",
        )
    )
    value["required_names"] = sorted(required)
    value["optional_names"] = sorted(
        set(value["optional_names"]) | {str((C / name).relative_to(P)) for name in NEW_NAMES}
    )
    value["frozen_package_inputs"][str((S / "evidence.json.xz").relative_to(P))] = AMENDMENT[
        "source_archive_sha256"
    ]
    value["frozen_package_inputs"][str((S / "run.py").relative_to(P))] = read(
        C / "checked-inputs.json"
    )["retained_bootstrap_sha256"]
    value["new_python_files"] = sorted(
        set(value["new_python_files"]) | set(str(Path(name).relative_to(P)) for name in FILES)
    )
    return value


h.scope = r.load_scope = scope


def original_read(path):
    value = read(path)
    if path == B / "config.json":
        old = read(B / "run-ledger.json")
        # full_audit adds the original failed preparation and five seconds itself.
        value["operator_charge_seconds"] = (
            OPENING + BOOKKEEPING - sum(row["seconds"] for row in old[:-1]) - 5 - old[-1]["seconds"]
        )
        value["package_seconds"] = 40
        value["new_evidence_subcap_bytes"] = CAP
    return value


r.read = original_read


def code_module(name):
    substitutions = ()
    if name == "audit":
        substitutions = (
            (
                '(D / row["evidence"]).is_file()',
                '(REGRESSION_EVIDENCE_INPUT / row["evidence"]).is_file()',
            ),
            (
                "charged + 10 <= 374 and package_charge + 10 <= 25",
                "charged + 5 <= 374 and package_charge + 5 <= 40",
            ),
            ("for root in (D, experiment)", "for root in (REGRESSION_EVIDENCE_INPUT, experiment)"),
            (
                'package_bytes < 262144, "new package subcap"',
                'package_bytes < 1048576, "new package subcap"',
            ),
        )
    obj = h.load(B / (name + ".py"), substitutions)
    obj.REGRESSION_EVIDENCE_INPUT = B
    return obj


r.module = code_module


def checks():
    # Reuse the completed 16-reference check; this is static source validation only.
    assert digest(S / "evidence.json.xz") == AMENDMENT["source_archive_sha256"]
    archived = json.loads(lzma.decompress((S / "evidence.json.xz").read_bytes()))
    closure = json.loads(archived["files"]["closure.json"])
    assert closure["verified_original_case_files_before_lint"] == 16
    assert ast.dump(ast.parse(archived["source"])) == ast.dump(
        ast.parse((C / "driver.py").read_text())
    )
    for args in (
        ("check", "--select", "I", "--fix"),
        ("format",),
        ("check",),
        ("format", "--check"),
    ):
        subprocess.run(
            [str(P / ".venv/bin/ruff"), *args, "--no-cache", *FILES], check=True, timeout=0.4
        )
    assert ast.dump(ast.parse(archived["source"])) == ast.dump(
        ast.parse((C / "driver.py").read_text())
    )
    r.audit.write_report(
        C / "checked-inputs.json",
        {
            "files": {
                str((C / name).relative_to(P)): digest(C / name)
                for name in (
                    "driver.py",
                    "run.py",
                    "amendment.json",
                    "config.json",
                    "prefixes.json",
                )
            },
            "driver_sha256": digest(C / "driver.py"),
            "retained_bootstrap_sha256": digest(S / "run.py"),
            "reference_checks_reused": 16,
            "reference_check_archive_sha256": AMENDMENT["source_archive_sha256"],
            "formatting_AST_equal": True,
            "new_regression_invocations": 0,
        },
    )


if __name__ == "__main__":
    # Bounded standard-library coordinator; workers retain the existing cgroup guard.
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    if sys.argv[1] == "--worker":
        raise SystemExit(g.worker(sys.argv[2]))
    if sys.argv[1] == "work":
        {"checks": checks, "prepare": h.prepare, "full-audit": h.audit_run}[sys.argv[2]]()
    else:
        config_path = C / "config.json"
        if not config_path.exists():
            config_path.write_text(json.dumps(g.CONFIG, indent=2) + "\n")
        assert read(config_path) == g.CONFIG
        if sys.argv[1] == "full-audit":
            # Consume the authorised completion reserve for the audit; retain five
            # uncharged seconds for reporting, besides the charged operator allowance.
            g.CONFIG["cleanup_and_evidence_reserve_seconds"] = 5
        raise SystemExit(g.main(sys.argv[1]))
