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
D = BASE / "final_checks"
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
    old_config = small_json(OLD / "config.json")
    for key, value in old_config.items():
        if key != "package" and not key.startswith(("expected_", "max_")):
            require(config[key] == value, "resource/proof configuration changed: " + key)
    require(not (D / "STOP.json").exists(), "STOP prohibits further checks")
    runs = small_json(D / "run-ledger.json")
    require(
        sum(run["name"] == "full-audit" for run in runs) == 1, "exactly one full audit admitted"
    )
    measure.phase("start")
    for name, expected in scope["baseline_identities"].items():
        require(
            audit.digest_file(P / name, progress=measure.progress) == expected,
            "historical baseline identity mismatch",
        )
    measure.phase("baseline-identities-complete")
    permitted = set(scope["original_permitted_changes"])
    primary = audit.compare(
        P,
        audit.iter_manifest(OLD / "preservation-before.json"),
        expected_count=scope["primary_count"],
        permitted=permitted,
        progress=measure.progress,
    )
    require(
        primary.passed and set(primary.allowed_changed) == permitted,
        "original protected comparison failed: " + json.dumps(primary.report()),
    )
    measure.phase("original-8759-content-comparisons-complete")
    historical = small_json(OLD / "manifest.json")["sha256"]
    overlap = primary.names & historical.keys()
    require(
        len(historical) == scope["historical_final_manifest_count"]
        and len(overlap) == scope["historical_overlap_count"]
        and overlap == permitted,
        "historical supplementary partition overlap mismatch",
    )
    append = scope["new_permitted_existing_change"]
    supplementary = audit.compare(
        P,
        ((name, digest) for name, digest in historical.items() if name not in primary.names),
        expected_count=scope["supplementary_count"],
        permitted={append["path"]},
        progress=measure.progress,
    )
    require(
        supplementary.passed and supplementary.allowed_changed == [append["path"]],
        "historical final evidence comparison failed",
    )
    require(
        audit.digest_file(P / append["path"], prefix_bytes=append["original_bytes"])
        == append["original_sha256"]
        == historical[append["path"]],
        "historical manager report was not preserved as an exact prefix",
    )
    require(not (primary.names & supplementary.names), "duplicate comparison partition")
    measure.phase("supplementary-30-content-and-append-prefix-complete")
    manuscript = "docs/manuscript/PQ_DID__Implementation.pdf"
    require(
        audit.digest_file(P / manuscript, progress=measure.progress)
        == "d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca",
        "manuscript identity",
    )
    ledger_path = P / "experiments/r0_credvalid_po17_1/evidence/cumulative_attempt_ledger.json"
    ledger_digest = audit.digest_file(ledger_path)
    require(
        ledger_digest == "fc64f7efbd2f20cd23fec24d828f36f1460afb0b73a76ea256d0716f309d75c5",
        "proof ledger identity",
    )
    ledger = small_json(ledger_path)
    require(ledger["attempts_used"] == 2 and ledger["remaining"] == 1, "proof attempt ledger")
    counts = {"focused": tests(OLD, "focused", 73), "regression": tests(OLD, "regression", 25)}
    focused = tests(BASE, "focused", 44)
    require(focused <= config["synthetic_case_limit"], "fixture count limit")
    old_seconds = check_runs(OLD, {"focused", "regression", "quality", "format"})
    new_seconds = check_runs(BASE, {"diagnostic", "focused"})
    new_seconds += check_runs(D, {"quality", "format"})
    old_failure = small_json(OLD / "final-audit.json")
    require(
        old_failure["exit_code"] == 125 and (OLD / "STOP.json").exists(),
        "historical ceiling failure no longer recorded",
    )
    measure.phase("identities-and-reused-validation-complete")
    scripts = [
        "scripts/preservation_audit.py",
        "tests/unit/test_preservation_audit.py",
        *[
            str(BASE.relative_to(P) / name)
            for name in ["diagnose.py", "full_audit.py", "run_checks.py"]
        ],
        "src/pqdid/revocation_state.py",
        "tests/unit/revocation_state_cases.py",
        "tests/unit/test_revocation_state.py",
        str(OLD.relative_to(P) / "audit.py"),
        str(OLD.relative_to(P) / "run_checks.py"),
    ]
    for name in scripts:
        ast.parse((P / name).read_text(), filename=name)
    json_count = 0
    for directory in [OLD, BASE]:
        for path in directory.rglob("*.json"):
            if path == OLD / "preservation-before.json":
                continue  # Already parsed through final EOF during the complete comparison.
            small_json(path)
            json_count += 1
    json_count += 1
    links = 0
    pending = {P / name for name in scope["new_optional_evidence_files"]}
    for name in [*sorted(permitted), append["path"], "docs/stage2_revocation_audit.md"]:
        path = P / name
        content = path.read_text()
        require(
            content.count("```") % 2 == 0
            and all(line.rstrip() == line for line in content.splitlines()),
            "Markdown formatting",
        )
        for target in re.findall(r"\[[^\]\n]*\]\(([^)\s]+)\)", content):
            parsed = urlsplit(target.strip("<>"))
            if parsed.scheme or not parsed.path:
                continue
            destination = (path.parent / unquote(parsed.path)).resolve()
            require(destination.exists() or destination in pending, "broken link: " + target)
            links += 1
    measure.phase("syntax-json-and-document-checks-complete")
    roots = scope["additional_name_inventory_roots"]
    known = primary.names | supplementary.names | {str(OLD.relative_to(P) / "manifest.json")}
    required_names = {name for name in known if name.split("/")[0] in roots}
    required_names.update(scope["pre_existing_inventory_only_names"])
    required_names.update(scope["new_required_files"])
    inventory = audit.inventory_check(
        P, roots, required_names, optional_names=set(scope["new_optional_evidence_files"])
    )
    require(inventory["passed"], "name inventory mismatch: " + json.dumps(inventory))
    package_bytes = sum(path.stat().st_size for path in BASE.rglob("*") if path.is_file())
    require(package_bytes < config["output_bytes"], "package output budget")
    require(not any((D / "tmp").iterdir()), "temporary fixtures were not removed")
    measure.phase("complete-name-inventory-and-output-checks-complete")
    report = {
        "package": config["package"],
        "passed": True,
        "comparison_complete": True,
        "resource_guard_status": "pending-outer-worker-finalisation",
        "acceptance_rule": "result.json must also confirm full-audit.json guard success",
        **primary.report(),
        "supplementary_comparison": supplementary.report(),
        "partition_union_count": len(primary.names | supplementary.names),
        "partition_overlap_count": 0,
        "historical_manifest_overlap_removed": len(overlap),
        "baseline_identities": scope["baseline_identities"],
        "historical_final_manifest_identity_checked_separately": True,
        "manager_report_original_prefix_preserved": True,
        "name_inventory": inventory,
        "test_counts": counts,
        "tests_total": sum(counts.values()),
        "new_audit_fixture_tests": focused,
        "failures": 0,
        "skips": 0,
        "manuscript_identity_matches": True,
        "original_source_encodings_vectors_dependencies_preserved": True,
        "historical_evidence_and_ledgers_preserved": True,
        "proof_attempt_ledger_sha256": ledger_digest,
        "proof_attempts_used": 2,
        "unused": 1,
        "new_proofs": 0,
        "new_zkvm_executions": 0,
        "dependencies_installed": 0,
        "proof_parameters_changed": False,
        "CPU_proving_paused": True,
        "local_markdown_link_paths_checked": links,
        "JSON_files_parsed": json_count,
        "package_bytes_before_report": package_bytes,
        "temporary_storage_bytes_at_completion": 0,
        "initial_four_check_wall_seconds": new_seconds,
        "reused_manager_check_wall_seconds": old_seconds,
        "final_lint_and_format": [
            small_json(D / (name + ".json")) for name in ["quality", "format"]
        ],
        "validation_reused": ["Manager 73 focused and 25 scoped regressions; source unchanged"],
        "scope": "Preservation only; no protocol, cryptographic or proof claim",
    }
    audit.write_report(D / "validation.json", report)
    require(small_json(D / "validation.json") == report, "report readback incomplete")
    measure.phase("report-written-and-readback-complete")
    print(
        json.dumps(
            {
                "content_passed": True,
                "resource_guard_pending": True,
                "primary_files": len(primary.names),
                "supplementary_files": len(supplementary.names),
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
                    "package": "S2-REVOKE-AUDIT-1",
                    "passed": False,
                    "comparison_complete": False,
                    "failure_type": type(error).__name__,
                    "failure": str(error)[:3000],
                },
            )
        raise
