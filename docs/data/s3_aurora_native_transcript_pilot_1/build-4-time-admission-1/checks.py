"""Record a stale preflight seal and complete preservation; no native launch."""

import hashlib
import json
import subprocess
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[3]
OLD = R.parent / "build-4-resumption-1"
DOCS = tuple(json.loads((R / "prefixes.json").read_text()))


def load(path):
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


prior = load(OLD / "checks.py")
guard = load(R / "run.py")
audit, read, digest, policy = prior.audit, prior.read, prior.digest, prior.policy
PYTHON = ("run.py", "checks.py")
NAMES = {
    *PYTHON,
    "config.json",
    "prefixes.json",
    "opening-ledger.json",
    "admission-result.json",
    "native-case-outcomes.json",
    "checked-inputs.json",
    "preparation.json",
    "validation.json",
    "phases.json",
    "result.json",
    "validation-closure.json",
    "manifest.json",
    "run-ledger.json",
    "run.lock",
    "STOP.json",
    "STOP-prepare.json",
    "STOP-full-audit.json",
    *{
        n + suffix
        for n in ("quality", "prepare", "full-audit")
        for suffix in (".json", ".log", ".service.json")
    },
}


def scope():
    value = prior.scope()
    seal = OLD / "manifest.json"
    assert digest(seal) == "ca5484293953e9d24cc45116324cac51c264de94fa43e03803c159b616a03840"
    required = set(value["required_names"]) | set(read(seal)["sha256"])
    required.add(str(seal.relative_to(P)))
    for name, expected in read(seal)["sha256"].items():
        if name not in DOCS:
            assert value["frozen_package_inputs"].get(name, expected) == expected
            value["frozen_package_inputs"][name] = expected
    value["frozen_package_inputs"][str(seal.relative_to(P))] = digest(seal)
    for name, prefix in read(R / "prefixes.json").items():
        if name in value["frozen_package_inputs"]:
            assert value["frozen_package_inputs"].pop(name) == prefix["sha256"]
        value["append_only_documentation"][name] = prefix
    for name, expected in read(R / "checked-inputs.json")["sha256"].items():
        assert value["frozen_package_inputs"].get(name, expected) == expected
        value["frozen_package_inputs"][name] = expected
        required.add(name)
    value["required_names"] = sorted(required)
    value["optional_names"] = sorted(
        set(value["optional_names"]) | {str((R / n).relative_to(P)) for n in NAMES}
    )
    value["new_python_files"] += [str((R / n).relative_to(P)) for n in PYTHON]
    return value


def quality():
    # Only the new completion entry points need static checks; old lint is reused.
    files = [str(R / n) for n in PYTHON]
    for args in (("format",), ("check",), ("format", "--check")):
        subprocess.run(
            [str(P / ".venv/bin/ruff"), *args, "--no-cache", *files],
            check=True,
            timeout=0.5,
        )
    seal = OLD / "manifest.json"
    assert digest(seal) == read(R / "opening-ledger.json")["prior_manifest_sha256"]
    for manifest in ("manifest.json", "checked-inputs.json"):
        for name, expected in read(OLD / manifest)["sha256"].items():
            assert digest(P / name) == expected, name
    stale = R.parent / "build-4-admission-1"
    latest = read(seal)["sha256"]
    prefixes = read(OLD / "prefixes.json")
    rows = []
    for manifest in ("manifest.json", "checked-inputs.json"):
        for name, expected in read(stale / manifest)["sha256"].items():
            actual = digest(P / name)
            if actual != expected:
                assert name in DOCS and latest[name] == actual
                prefix = prefixes[name]
                assert prefix["sha256"] == expected
                with (P / name).open("rb") as stream:
                    assert hashlib.sha256(stream.read(prefix["bytes"])).hexdigest() == expected
                rows.append(
                    {
                        "path": name,
                        "expected_by_preflight": expected,
                        "current_sha256": actual,
                        "latest_seal_matches": True,
                        "historical_prefix_preserved": True,
                    }
                )
    assert {row["path"] for row in rows} == set(DOCS)
    assert not any((prior.A / "guarded-build-v1").iterdir())
    assert guard.artifact_limits() is None
    audit.write_report(
        R / "admission-result.json",
        {
            "status": "blocked-before-preflight",
            "reason": "Preflight compares authorised append-only reports to old full hashes",
            "preflight_source": str((OLD / "work.py").relative_to(P)),
            "preflight_source_sha256": digest(OLD / "work.py"),
            "launcher_source_sha256": digest(OLD / "run.py"),
            "mismatches": rows,
            "new_preflight_attempts": 0,
            "new_builds": 0,
            "guard_policy_changed": False,
            "original_launcher_and_work_unchanged": True,
            "required_correction": "Verify historic prefixes and latest sealed appendices",
            "formatting_only_correction": False,
            "time_amendment_recorded_total": 120,
        },
    )
    names = [f"SEM-{n:02d}" for n in range(1, 9)] + [f"TR-{n:02d}" for n in range(1, 17)]
    audit.write_report(
        R / "native-case-outcomes.json",
        {
            "cases": [{"id": n, "status": "not-run"} for n in names],
            "new_invocations": 0,
            "cumulative_invocations": 411,
            "ceiling": 438,
        },
    )


def prepare():
    assert read(R / "quality.json")["status"] == "pass"
    present = {p.name for p in R.iterdir() if p.is_file()}
    assert present <= NAMES, sorted(present - NAMES)
    frozen = present - {
        "run-ledger.json",
        "run.lock",
        "prepare.json",
        "prepare.log",
        "prepare.service.json",
    }
    audit.write_report(
        R / "checked-inputs.json",
        {"sha256": {str((R / n).relative_to(P)): digest(R / n) for n in sorted(frozen)}},
    )
    value = scope()
    result = audit.inventory_check(
        P,
        value["additional_name_inventory_roots"],
        set(value["required_names"]),
        optional_names=set(value["optional_names"]),
    )
    assert result["passed"], result
    audit.write_report(
        R / "preparation.json",
        {
            "inventory": result,
            "scope_sha256": hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
        },
    )


def current_checks(original):
    rows = read(R / "run-ledger.json")
    assert [r["name"] for r in rows] == ["quality", "prepare", "full-audit"]
    for row in rows[:-1]:
        policy.validate_record(row, "resumption/" + row["name"])
    assert rows[-1]["status"] == "launched"
    config = read(R / "config.json")
    charge = 5 + sum(r.get("seconds", r["limit_seconds"]) for r in rows)
    assert charge <= config["package_seconds"]
    assert charge <= read(R / "opening-ledger.json")["parent_remaining"]
    assert read(R / "native-case-outcomes.json")["new_invocations"] == 0
    return config["prior_implementation_charged_seconds"] + charge


def full_audit():
    bindings = dict(prior.__dict__)
    bindings.update(R=R, scope=scope, current_checks=current_checks, guard=guard)
    types.FunctionType(prior.full_audit.__code__, bindings)()


def run(name):
    {"quality": quality, "prepare": prepare, "full-audit": full_audit}[name]()
