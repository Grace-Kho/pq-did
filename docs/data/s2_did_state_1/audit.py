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
    previous = P / "docs/data/s2_revoke_audit_1"
    for key, value in small_json(previous / "config.json").items():
        if key not in {"package", "diagnostic_read_bytes", "diagnostic_early_stop_bytes"}:
            require(config[key] == value, "changed resource/proof control: " + key)
    require(not (D / "STOP.json").exists(), "STOP prohibits more validation")
    ledger = small_json(D / "run-ledger.json")
    require(
        sum(run["name"] == "full-audit" for run in ledger) == 1, "one full preservation audit only"
    )
    measure.phase("start")
    for name, expected in scope["baseline_identities"].items():
        require(
            audit.digest_file(P / name, progress=measure.progress) == expected,
            "historical manifest identity mismatch",
        )
    measure.phase("original-baseline-identities-complete")
    permitted_docs = set(scope["original_permitted_documentation"])
    primary = audit.compare(
        P,
        audit.iter_manifest(OLD / "preservation-before.json"),
        expected_count=scope["primary_count"],
        permitted=permitted_docs,
        progress=measure.progress,
    )
    require(
        primary.passed and set(primary.allowed_changed) == permitted_docs,
        "original content comparison failed: " + json.dumps(primary.report()),
    )
    measure.phase("original-8759-content-complete")
    manager = small_json(OLD / "manifest.json")["sha256"]
    corrected = small_json(previous / "manifest.json")["sha256"]
    require(
        len(manager) == scope["manager_manifest_count"]
        and len(corrected) == scope["correction_manifest_count"],
        "historical counts",
    )
    # Small supplementary maps only. The latest historic seal fixes the exact
    # already-authorised report append; neither original baseline is regenerated.
    issuance = small_json(P / "docs/data/s2_issue_enrol_1/manifest.json")["sha256"]
    require(len(issuance) == scope["issuance_manifest_count"], "issuance seal count")
    later = {**manager, **corrected, **issuance}
    supplemental = audit.compare(
        P,
        ((name, digest) for name, digest in later.items() if name not in primary.names),
        expected_count=scope["supplementary_count"],
        permitted=set(scope["new_permitted_existing_code"]),
        progress=measure.progress,
    )
    require(
        supplemental.passed
        and set(supplemental.allowed_changed) == set(scope["new_permitted_existing_code"]),
        "supplemental content comparison failed: " + json.dumps(supplemental.report()),
    )
    require(not primary.names & supplemental.names, "duplicated coverage partition")
    known = primary.names | supplemental.names | scope["baseline_identities"].keys()
    require(len(known) == scope["known_manifest_union_names"], "incomplete historical coverage")
    prefix = scope["historical_manager_report_prefix"]
    require(
        audit.digest_file(P / prefix["path"], prefix_bytes=prefix["bytes"]) == prefix["sha256"],
        "original manager report prefix changed",
    )
    measure.phase("historical-supplements-and-exact-change-boundaries-complete")
    require(
        audit.digest_file(
            P / "docs/manuscript/PQ_DID__Implementation.pdf", progress=measure.progress
        )
        == "d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca",
        "manuscript identity mismatch",
    )
    attempts = P / "experiments/r0_credvalid_po17_1/evidence/cumulative_attempt_ledger.json"
    require(
        audit.digest_file(attempts)
        == "fc64f7efbd2f20cd23fec24d828f36f1460afb0b73a76ea256d0716f309d75c5",
        "proof ledger changed",
    )
    proof_ledger = small_json(attempts)
    require(
        proof_ledger["attempts_used"] == 2 and proof_ledger["remaining"] == 1,
        "proof attempts changed",
    )
    counts = {
        "focused": tests(TESTS, "focused", config["expected_focused_cases"]),
        "regression": tests(TESTS, "regression", config["expected_regression_cases"]),
    }
    require(sum(counts.values()) <= config["synthetic_case_limit"], "case admission exceeded")
    preceding_seconds = check_runs(TESTS, {"focused", "regression"})
    preceding_seconds += check_runs(D, {"quality", "format"})
    require(preceding_seconds < 300, "aggregate allowance")
    require(
        small_json(P / "docs/data/s2_issue_enrol_1/release_checks/result.json")["passed"] is True,
        "issuance package evidence no longer passed",
    )
    require(
        small_json(previous / "final_checks/result.json")["passed"] is True,
        "corrected auditor evidence no longer passed",
    )
    require(
        small_json(OLD / "final-audit.json")["exit_code"] == 125,
        "original resource failure no longer preserved",
    )
    measure.phase("tests-resource-records-and-proof-ledger-complete")
    scripts = [
        "src/pqdid/did_state.py",
        "tests/unit/did_state_cases.py",
        "tests/unit/test_did_state.py",
        str(BASE.relative_to(P) / "run_checks.py"),
        str(BASE.relative_to(P) / "audit.py"),
    ]
    for name in scripts:
        ast.parse((P / name).read_text(), filename=name)
    json_count = 0
    for path in BASE.rglob("*.json"):
        small_json(path)
        json_count += 1
    pending = {P / name for name in scope["new_optional_evidence_files"]}
    links = 0
    for name in [*sorted(permitted_docs), "docs/stage2_did_state.md"]:
        path = P / name
        text = path.read_text()
        require(
            text.count("```") % 2 == 0 and all(line.rstrip() == line for line in text.splitlines()),
            "Markdown formatting",
        )
        for target in re.findall(r"\[[^\]\n]*\]\(([^)\s]+)\)", text):
            parsed = urlsplit(target.strip("<>"))
            if parsed.scheme or not parsed.path:
                continue
            destination = (path.parent / unquote(parsed.path)).resolve()
            require(destination.exists() or destination in pending, "broken link: " + target)
            links += 1
    roots = scope["additional_name_inventory_roots"]
    required_names = {name for name in known if name.split("/")[0] in roots}
    required_names.update(scope["pre_existing_inventory_only_names"])
    required_names.update(scope["new_required_files"])
    inventory = audit.inventory_check(
        P, roots, required_names, optional_names=set(scope["new_optional_evidence_files"])
    )
    require(inventory["passed"], "name inventory mismatch: " + json.dumps(inventory))
    require(
        not any((D / "tmp").iterdir()) and not any((BASE / "tmp").iterdir()),
        "temporary storage not cleaned",
    )
    package_bytes = sum(path.stat().st_size for path in BASE.rglob("*") if path.is_file())
    require(package_bytes < config["output_bytes"], "package output allowance")
    measure.phase("syntax-json-documents-inventory-and-storage-complete")
    report = {
        "package": config["package"],
        "passed": True,
        "comparison_complete": True,
        "resource_guard_status": "pending-outer-worker-finalisation",
        "acceptance_rule": "Require result.json AND completed clean full-audit.json",
        **primary.report(),
        "supplementary_comparison": supplemental.report(),
        "content_partition_union": len(primary.names | supplemental.names),
        "content_partition_overlap": 0,
        "identity_inclusive_unique_paths": len(known),
        "baseline_identities": scope["baseline_identities"],
        "all_pre_existing_source_files_unchanged": True,
        "manager_original_report_prefix_and_latest_report_digest_preserved": True,
        "test_counts": counts,
        "tests_total": sum(counts.values()),
        "failures": 0,
        "skips": 0,
        "prior_package_failures_preserved": True,
        "original_content_preserved_except_authorised_changes": True,
        "manuscript_identity_matches": True,
        "historical_evidence_and_ledgers_preserved": True,
        "name_inventory": inventory,
        "local_markdown_link_paths_checked": links,
        "JSON_files_parsed": json_count,
        "new_proofs": 0,
        "new_zkvm_executions": 0,
        "proof_attempts_used": 2,
        "proof_attempts_unused": 1,
        "CPU_proving_paused": True,
        "dependencies_installed": 0,
        "proof_parameters_changed": False,
        "package_bytes_before_report": package_bytes,
        "temporary_storage_bytes_at_completion": 0,
        "preceding_final_checks_seconds": preceding_seconds,
        "final_lint_and_format": [
            small_json(D / (name + ".json")) for name in ["quality", "format"]
        ],
        "reused": [
            "Corrected streaming/cache-bounded audit implementation and 44 fixture tests",
            "Existing vectors and prior full cryptographic/circuit/experimental evidence",
        ],
        "scope": (
            "DID registry/resolver/controller reference lifecycle; "
            "no proof, ZK or production-service claim"
        ),
    }
    audit.write_report(D / "validation.json", report)
    require(small_json(D / "validation.json") == report, "incomplete report readback")
    measure.phase("report-written-and-readback-complete")
    print(
        json.dumps(
            {
                "content_passed": True,
                "resource_guard_pending": True,
                "primary": len(primary.names),
                "supplementary": len(supplemental.names),
                "tests": counts,
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
                    "package": "S2-DID-STATE-1",
                    "passed": False,
                    "comparison_complete": False,
                    "failure_type": type(error).__name__,
                    "failure": str(error)[:3000],
                },
            )
        raise
