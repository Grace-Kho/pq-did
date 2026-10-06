"""One corrected complete preservation audit using the unchanged streaming engine."""

# ruff: noqa: E402

import ast
import importlib.util
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import unquote, urlsplit

D = Path(__file__).resolve().parent
E = D.parent
P = E.parents[2]
sys.path.insert(0, str(P))
sys.path.insert(0, str(P / "scripts/isolation_pilot_v2"))
from layout import PROPOSAL, digest, read_json
from ledger import elapsed

from scripts import preservation_audit as audit

spec = importlib.util.spec_from_file_location("prior_audit_helpers", E / "audit.py")
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
prior.D = D
require = prior.require
small = prior.small_json


def main(measure):
    scope = small(D / "scope.json")
    config = small(D / "config.json")
    old_config = small(E / "config.json")
    for key, value in old_config.items():
        require(
            config[key] == (124 if key == "synthetic_case_limit" else value),
            "unexpected resource change: " + key,
        )
    require(config["additional_focused_invocations"] == 24, "test amendment")
    measure.phase("start")
    for name, value in scope["baseline_identities"].items():
        require(
            audit.digest_file(P / name, progress=measure.progress) == value,
            "baseline identity changed: " + name,
        )
    measure.phase("original-baseline-identities-complete")
    primary = audit.compare(
        P,
        audit.iter_manifest(P / "docs/data/s2_revoke_state_1/preservation-before.json"),
        expected_count=8759,
        permitted=set(scope["original_permitted_documentation"]),
        progress=measure.progress,
    )
    require(primary.passed, "primary content comparison")
    measure.phase("original-8759-content-complete")
    latest = {}
    for name, count in scope["supplementary_manifests"].items():
        rows = small(P / name)["sha256"]
        require(len(rows) == count, "historical seal count")
        latest.update(rows)
    supplement = audit.compare(
        P,
        ((n, h) for n, h in latest.items() if n not in primary.names),
        expected_count=scope["supplementary_count"],
        permitted=set(scope["supplementary_allowed_docs"]),
        progress=measure.progress,
    )
    require(supplement.passed, "supplement content comparison: " + json.dumps(supplement.report()))
    require(not primary.names & supplement.names, "overlapping content partitions")
    known = primary.names | supplement.names | set(scope["baseline_identities"])
    require(len(known) == scope["known_manifest_union_names"], "missing coverage")
    for name, prefix in scope["append_only_documentation"].items():
        require(
            audit.digest_file(P / name, prefix_bytes=prefix["bytes"]) == prefix["sha256"],
            "prior report prefix altered",
        )
    require(
        digest(P / "docs/proposals/s2_authority_isolation_pilot_1/source-manifest.json")
        == "7fd9f0e1bcedf7ed7756b4f25bdde6458e06650cdece62841100c0f636e09086",
        "old authorisation seal",
    )
    candidate = read_json(PROPOSAL / "candidate-manifest.json", 262144)
    for name, value in {**candidate["sha256"], **candidate["control_inputs_sha256"]}.items():
        require(digest(P / name) == value, "candidate input changed: " + name)
    require(
        digest(P / "docs/manuscript/PQ_DID__Implementation.pdf")
        == "d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca",
        "manuscript",
    )
    proof_path = P / "experiments/r0_credvalid_po17_1/evidence/cumulative_attempt_ledger.json"
    require(
        digest(proof_path) == "fc64f7efbd2f20cd23fec24d828f36f1460afb0b73a76ea256d0716f309d75c5",
        "proof ledger",
    )
    require(
        small(proof_path)["attempts_used"] == 2 and small(proof_path)["remaining"] == 1,
        "proof count",
    )
    require(small(E / "result.json")["passed"], "previous complete preservation result")
    measure.phase("supplements-prefixes-candidate-and-proof-ledger-complete")
    invocations = [
        json.loads(line) for line in (D / "test-invocations.jsonl").read_text().splitlines()
    ]
    count = 0
    for name, expected in [("focused", 20), ("focused-closure", 4)]:
        suites = ET.parse(D / (name + ".xml")).getroot().findall("testsuite")
        require(sum(int(s.attrib["tests"]) for s in suites) == expected, "focused count")
        require(
            all(int(s.attrib[k]) == 0 for s in suites for k in ("failures", "errors", "skipped")),
            "focused outcome",
        )
        count += expected
    require(
        len(invocations) == count == 24 and 76 + count + 22 <= 124,
        "cumulative invocation amendment",
    )
    prior.check_runs(
        D,
        {
            "v2-lint-closure",
            "v2-format",
            "v2-focused",
            "v2-focused-closure",
            "v2-static",
            "v2-cleanup",
        },
    )
    runs = small(D / "run-ledger.json")
    require(sum(r["name"] == "v2-audit" for r in runs) == 1, "one corrected complete audit")
    corrections = {small(path)["failure"] for path in D.glob("correction*.json")}
    for run in runs:
        if run["status"] == "failed":
            require(
                run["name"] in corrections and run["exit_code"] == 1 and run["stop"] is None,
                "unreviewed failure",
            )
            events = dict(
                line.split() for line in run["service"]["after"]["memory.events"].splitlines()
            )
            require(
                all(int(events[k]) == 0 for k in ("max", "oom", "oom_kill")), "resource failure"
            )
    charged = elapsed(allow_incomplete=True)
    require(charged + 10 <= 300, "cumulative time envelope")
    measure.phase("focused-validation-accounting-and-original-failures-complete")
    for name in scope["new_python_files"]:
        ast.parse((P / name).read_text(), filename=name)
    optional = set(scope["new_optional_evidence_files"])
    links = 0
    for name in [*scope["original_permitted_documentation"], *scope["new_markdown_files"]]:
        path = P / name
        text = path.read_text()
        require(
            text.count("```") % 2 == 0 and all(line.rstrip() == line for line in text.splitlines()),
            "Markdown format",
        )
        for target in re.findall(r"\[[^\]\n]*\]\(([^)\s]+)\)", text):
            parsed = urlsplit(target.strip("<>"))
            if parsed.scheme or not parsed.path:
                continue
            dest = (path.parent / unquote(parsed.path)).resolve()
            require(dest.exists() or str(dest.relative_to(P)) in optional, "broken link: " + target)
            links += 1
    roots = scope["additional_name_inventory_roots"]
    required = {name for name in known if name.split("/")[0] in roots}
    required.update(scope["pre_existing_inventory_only_names"])
    required.update(scope["new_required_files"])
    inventory = audit.inventory_check(P, roots, required, optional_names=optional)
    require(inventory["passed"], "inventory: " + json.dumps(inventory))
    require(not any((D / "tmp").iterdir()), "temporary fixtures retained")
    package_bytes = sum(p.stat().st_size for p in E.rglob("*") if p.is_file())
    require(package_bytes < 10485760, "package output ceiling")
    measure.phase("inventory-links-syntax-storage-complete")
    report = {
        "package": "S2-AUTHORITY-ISOLATION-PILOT-1",
        "version": 2,
        "passed": True,
        "comparison_complete": True,
        "resource_guard_status": "pending-outer-finalisation",
        **primary.report(),
        "supplementary_comparison": supplement.report(),
        "content_partition_union": len(primary.names | supplement.names),
        "content_partition_overlap": 0,
        "identity_inclusive_unique_paths": len(known),
        "name_inventory": inventory,
        "candidate_sha256": digest(PROPOSAL / "candidate-manifest.json"),
        "focused_invocations": count,
        "historical_invocations": 76,
        "cumulative_invocations": 76 + count,
        "pending_identity_cases": 22,
        "actual_identity_tests_run": 0,
        "charged_seconds_including_inflight_audit_reservation": charged,
        "only_existing_changes": [
            *scope["original_permitted_documentation"],
            *scope["supplementary_allowed_docs"],
        ],
        "local_links_checked": links,
        "package_bytes_before_report": package_bytes,
        "temporary_storage_bytes": 0,
        "proofs": 0,
        "zkvm_executions": 0,
        "proof_attempts_used": 2,
        "proof_attempts_unused": 1,
        "activation": False,
    }
    audit.write_report(D / "validation.json", report)
    require(small(D / "validation.json") == report, "report readback")
    measure.phase("report-written-and-readback-complete")
    print(
        json.dumps(
            {
                "content_passed": True,
                "outer_guard_pending": True,
                "historical_paths": len(known),
                "inventory": inventory,
            }
        )
    )


if __name__ == "__main__":
    measure = prior.Measurements()
    try:
        main(measure)
    except Exception as error:
        measure.phase("incomplete-audit-failure")
        audit.write_report(
            D / "validation.json",
            {
                "passed": False,
                "comparison_complete": False,
                "failure_type": type(error).__name__,
                "failure": str(error)[:3000],
            },
        )
        raise
