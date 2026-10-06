"""One complete preservation audit; invoked only inside the inherited cgroup guard."""

import ast
import json
import re
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import unquote, urlsplit

BASE = Path(__file__).resolve().parent
D = BASE
TESTS = BASE
P = BASE.parents[2]
OLD = P / "docs/data/s2_revoke_state_1"
sys.path.insert(0, str(P))
from scripts import preservation_audit as audit  # noqa: E402


def require(condition, reason):
    if not condition:
        raise audit.AuditError(reason)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def small_json(path):
    require(path.stat().st_size < 1024 * 1024, "JSON read exceeds bounded admission")
    with path.open() as stream:
        return json.load(stream, object_pairs_hook=unique_object)


class Measurements:
    def __init__(self):
        self.started = time.monotonic()
        self.cg = Path("/sys/fs/cgroup") / next(
            line[3:]
            for line in Path("/proc/self/cgroup").read_text().splitlines()
            if line.startswith("0::")
        ).lstrip("/")
        self.rows = []
        self.highest = {"current": 0}

    def snapshot(self):
        return {
            "current": int((self.cg / "memory.current").read_text()),
            "peak": int((self.cg / "memory.peak").read_text()),
            "stat": {
                k: int(v)
                for k, v in (
                    line.split() for line in (self.cg / "memory.stat").read_text().splitlines()
                )
            },
            "events": (self.cg / "memory.events").read_text().strip(),
        }

    def progress(self, _offset):
        current = int((self.cg / "memory.current").read_text())
        if current > self.highest["current"]:
            self.highest = self.snapshot()

    def phase(self, name):
        require(len(self.rows) < 20, "phase instrumentation bound")
        self.rows.append(
            {"phase": name, "seconds": time.monotonic() - self.started, **self.snapshot()}
        )
        with (D / "phases.json").open("w") as stream:
            json.dump(
                {"phases": self.rows, "highest_sampled_current": self.highest}, stream, indent=2
            )
            stream.write("\n")


def tests(directory, name, expected):
    suites = ET.parse(directory / (name + ".xml")).getroot().findall("testsuite")
    count = sum(int(suite.attrib["tests"]) for suite in suites)
    require(count == expected, "unexpected test count")
    require(
        all(
            int(suite.attrib[key]) == 0
            for suite in suites
            for key in ["failures", "errors", "skipped"]
        ),
        "unsuccessful test evidence",
    )
    return count


def check_runs(directory, names):
    runs = small_json(directory / "run-ledger.json")
    selected = [run for run in runs if run["name"] in names]
    require(
        len(selected) == len(names) and {run["name"] for run in selected} == names,
        "incomplete validation commands",
    )
    for run in selected:
        require(
            run["status"] == "pass" and run["exit_code"] == 0 and run["stop"] is None,
            "failed prior command",
        )
        require(
            run["seconds"] < 60 and run["sampled_tree_RSS_peak"] <= 268435456,
            "prior resource measurement outside envelope",
        )
        service = run["service"]
        require(
            service["before"]["memory.max"] == "268435456"
            and service["before"]["memory.swap.max"] == "0"
            and service["before"]["cpu.max"] == "200000 100000"
            and len(service["allowed_cpus"]) <= 2,
            "changed prior resource controls",
        )
        events = dict(line.split() for line in service["after"]["memory.events"].splitlines())
        require(
            all(int(events[key]) == 0 for key in ["max", "oom", "oom_kill"]), "prior memory event"
        )
    seconds = sum(run["seconds"] for run in selected)
    require(seconds < 300, "prior aggregate wall time")
    return seconds


def main(measure):
    scope = small_json(BASE / "scope.json")
    config = small_json(BASE / "config.json")
    for key, value in small_json(P / "docs/data/s2_revoke_audit_1/config.json").items():
        if key not in {"package", "diagnostic_read_bytes", "diagnostic_early_stop_bytes"}:
            require(config[key] == value, "changed resource/proof limit: " + key)
    ledger = small_json(BASE / "run-ledger.json")
    require(sum(r["name"] == "full-audit" for r in ledger) == 1, "one complete audit")
    measure.phase("start")
    for name, expected in scope["baseline_identities"].items():
        require(
            audit.digest_file(P / name, progress=measure.progress) == expected,
            "original baseline identity changed",
        )
    measure.phase("original-baseline-identities-complete")
    permitted = set(scope["original_permitted_documentation"])
    primary = audit.compare(
        P,
        audit.iter_manifest(OLD / "preservation-before.json"),
        expected_count=8759,
        permitted=permitted,
        progress=measure.progress,
    )
    require(
        primary.passed and set(primary.allowed_changed) == permitted,
        "primary comparison: " + json.dumps(primary.report()),
    )
    measure.phase("original-8759-content-complete")
    later = {}
    for name, count in scope["supplementary_manifests"].items():
        rows = small_json(P / name)["sha256"]
        require(len(rows) == count, "historical seal count")
        later.update(rows)
    supplement = audit.compare(
        P,
        ((name, value) for name, value in later.items() if name not in primary.names),
        expected_count=scope["supplementary_count"],
        permitted=set(),
        progress=measure.progress,
    )
    require(supplement.passed, "supplement comparison: " + json.dumps(supplement.report()))
    require(not primary.names & supplement.names, "duplicate comparison partition")
    known = primary.names | supplement.names | scope["baseline_identities"].keys()
    require(len(known) == scope["known_manifest_union_names"], "missing partition")
    prefix = scope["historical_manager_report_prefix"]
    require(
        audit.digest_file(P / prefix["path"], prefix_bytes=prefix["bytes"]) == prefix["sha256"],
        "original manager failure report changed",
    )
    require(
        audit.digest_file(P / "docs/manuscript/PQ_DID__Implementation.pdf")
        == "d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca",
        "manuscript",
    )
    attempts = P / "experiments/r0_credvalid_po17_1/evidence/cumulative_attempt_ledger.json"
    require(
        audit.digest_file(attempts)
        == "fc64f7efbd2f20cd23fec24d828f36f1460afb0b73a76ea256d0716f309d75c5",
        "proof ledger",
    )
    require(
        small_json(attempts)["attempts_used"] == 2 and small_json(attempts)["remaining"] == 1,
        "proof budget",
    )
    measure.phase("historical-supplements-and-protected-ledger-complete")
    good = {r["name"] for r in ledger if r["status"] == "pass"}
    require(
        {"environment", "inspection", "static-accepted", "quality-final", "format"} <= good,
        "planning checks missing",
    )
    check_runs(BASE, good)
    require(all(r["status"] in {"pass", "launched"} for r in ledger), "failed command")
    preceding_seconds = sum(r.get("seconds", 0) for r in ledger)
    require(preceding_seconds < 300, "aggregate limit")
    static = small_json(BASE / "static-accepted-validation.json")
    require(
        static["passed"] and static["actual_identity_cases_executed"] == 0,
        "planning validation scope",
    )
    require(
        static["functional_tests_run"] == 0 and static["units_installed_or_started"] == 0,
        "no activation or functional execution",
    )
    require(
        small_json(P / "docs/data/s2_authority_owner_boundary_1/result.json")["passed"],
        "prior owner audit",
    )
    require(
        small_json(P / "docs/data/s2_durable_authority_pilot_1/result.json")["passed"],
        "prior durable audit",
    )
    prior = small_json(P / "docs/data/s2_authority_owner_boundary_1/validation.json")
    require(
        prior["unique_passed_focused_cases"] == 28
        and prior["unchanged_lifecycle_regressions"] == 28,
        "reused functional evidence",
    )
    require(
        small_json(P / "docs/data/s2_revoke_audit_1/final_checks/result.json")["passed"],
        "corrected auditor",
    )
    require(small_json(OLD / "final-audit.json")["exit_code"] == 125, "old ceiling failure")
    measure.phase("static-checks-original-functional-and-failure-evidence-complete")
    for name in scope["new_python_files"]:
        ast.parse((P / name).read_text(), filename=name)
    json_count = 0
    for path in BASE.rglob("*.json"):
        small_json(path)
        json_count += 1
    links = 0
    optional = {P / n for n in scope["new_optional_evidence_files"]}
    for name in [*sorted(permitted), *scope["new_markdown_files"]]:
        path = P / name
        contents = path.read_text()
        require(
            contents.count("```") % 2 == 0
            and all(line.rstrip() == line for line in contents.splitlines()),
            "Markdown formatting",
        )
        for target in re.findall(r"\[[^\]\n]*\]\(([^)\s]+)\)", contents):
            parsed = urlsplit(target.strip("<>"))
            if parsed.scheme or not parsed.path:
                continue
            destination = (path.parent / unquote(parsed.path)).resolve()
            require(destination.exists() or destination in optional, "broken link: " + target)
            links += 1
    roots = scope["additional_name_inventory_roots"]
    required = {name for name in known if name.split("/")[0] in roots}
    required.update(scope["pre_existing_inventory_only_names"])
    required.update(scope["new_required_files"])
    inventory = audit.inventory_check(
        P, roots, required, optional_names=set(scope["new_optional_evidence_files"])
    )
    require(inventory["passed"], "inventory: " + json.dumps(inventory))
    require(not any((BASE / "tmp").iterdir()), "temporary stores retained")
    package_bytes = sum(p.stat().st_size for p in BASE.rglob("*") if p.is_file())
    require(package_bytes < config["output_bytes"], "package output cap")
    measure.phase("syntax-documents-inventory-and-storage-complete")
    report = {
        "package": config["package"],
        "passed": True,
        "comparison_complete": True,
        "resource_guard_status": "pending-outer-worker-finalisation",
        "acceptance_rule": "Require result.json AND completed clean full-audit.json",
        **primary.report(),
        "supplementary_comparison": supplement.report(),
        "content_partition_union": len(primary.names | supplement.names),
        "content_partition_overlap": 0,
        "identity_inclusive_unique_paths": len(known),
        "baseline_identities": scope["baseline_identities"],
        "name_inventory": inventory,
        "all_pre_existing_source_files_unchanged": True,
        "manuscript_historical_evidence_and_ledger_preserved": True,
        "functional_tests_run": 0,
        "actual_identity_tests_run": 0,
        "reused_owner_boundary_focused_cases": 28,
        "reused_lifecycle_regressions": 28,
        "reused_durable_focused_cases": 38,
        "reused_durable_SIGKILL_cases": 18,
        "static_validation_passed": True,
        "deployment_activated": False,
        "local_links_checked": links,
        "JSON_files_parsed": json_count,
        "preceding_checks_seconds": preceding_seconds,
        "package_bytes_before_report": package_bytes,
        "temporary_storage_bytes_at_completion": 0,
        "new_proofs": 0,
        "new_zkvm_executions": 0,
        "proof_attempts_used": 2,
        "proof_attempts_unused": 1,
        "CPU_proving_paused": True,
        "production_restart_approved": False,
        "scope": ("Uninstalled isolation plan; actual identities and protection not yet tested"),
    }
    audit.write_report(D / "validation.json", report)
    require(small_json(D / "validation.json") == report, "report readback")
    measure.phase("report-written-and-readback-complete")
    print(
        json.dumps(
            {
                "content_passed": True,
                "outer_guard_pending": True,
                "historical_paths": len(known),
                "inventory": inventory,
                "actual_identity_tests_run": 0,
            }
        )
    )


if __name__ == "__main__":
    measurements = Measurements()
    try:
        main(measurements)
    except Exception as error:
        measurements.phase("incomplete-audit-failure")
        if not (D / "validation.json").exists():
            audit.write_report(
                D / "validation.json",
                {
                    "package": "S2-AUTHORITY-ISOLATION-PLAN-1",
                    "passed": False,
                    "comparison_complete": False,
                    "failure_type": type(error).__name__,
                    "failure": str(error)[:3000],
                },
            )
        raise
