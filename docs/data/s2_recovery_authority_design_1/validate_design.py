"""Static documentation/data consistency only; no store, service or crash experiment."""

import ast
import json
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

BASE = Path(__file__).resolve().parent
P = BASE.parents[2]


def read(name):
    path = BASE / name
    assert path.stat().st_size < 1024 * 1024
    return json.loads(path.read_text())


def main():
    design = read("design.json")
    environment = read("sqlite-environment.json")
    host = read("filesystem-package-facts.json")
    sources = read("sources.json")
    config = read("config.json")
    scope = read("scope.json")
    assert design["status"] == "design-only" and not design["implemented"]
    roles = {r["role"] for r in design["roles"]}
    assert roles == {
        "manager",
        "issuer",
        "verifier",
        "registry",
        "resolver",
        "controller",
        "holder",
    }
    assert len(design["roles"]) == 7
    assert all(
        r["authoriser"] and r["durable_facts"] and r["private_scope"] and r["unavailable"]
        for r in design["roles"]
    )
    assert {f["id"] for f in design["failure_model"]} == {f"F{i:02}" for i in range(1, 9)}
    assert {t["id"] for t in design["future_tests"]} == {f"T{i:02}" for i in range(1, 17)}
    assert len(design["future_tests"]) == 16
    assert all(t["run_in_design_package"] is False for t in design["future_tests"])
    assert environment["sqlite_version"] == sources["installed_version"] == "3.46.1"
    assert environment["sqlite_version_info"] == [3, 46, 1]
    assert host["package_version"] == "3.46.1-9ubuntu0.3"
    assert host["wal_backport_established"] is False
    assert sources["distribution_fix_verified"] is False
    assert sources["wal_fix"]["first_fixed_mainline"] == "3.51.3"
    assert sources["wal_fix"]["listed_backports"] == ["3.44.6", "3.50.7"]
    assert environment["persistent_databases_created"] == 0
    assert environment["persistent_databases_opened"] == 0
    assert environment["settings_changed"] is False
    assert environment["hardware_flush_and_VHD_durability_verified"] is False
    assert host["filesystems"][0]["fstype"] == "ext4"
    assert len(sources["sources"]) == 8
    assert all(
        urlsplit(row["url"]).hostname in {"www.sqlite.org", "docs.python.org"}
        for row in sources["sources"]
    )
    selected = design["recommended_sqlite"]
    assert selected["journal_mode"] == "DELETE" and selected["synchronous"] == "EXTRA"
    assert selected["wal_selected"] is False and selected["automatic_retries"] == 0
    assert design["fencing"]["per_commit"] and design["fencing"]["per_publication"]
    assert design["fencing"]["counter_max"] == (1 << 63) - 1
    assert design["atomicity"]["cross_role_transaction"] is False
    assert design["issuer_reconciliation"]["reservation_rebind"] is False
    assert design["other_roles_live_admission_in_pilot"] is False
    assert design["next_package"] == "S2-DURABLE-AUTHORITY-PILOT-1"
    for key in [
        "new_functional_tests",
        "process_crash_tests_run",
        "sql_persistence_experiments_run",
        "new_proofs",
        "new_zkvm_executions",
    ]:
        assert design[key] == 0
    assert design["proof_attempts_used"] == 2 and design["proof_attempts_unused"] == 1
    assert not design["production_restart_approved"] and not design["stages_2_3_complete"]
    limits = design["pilot_limits"]
    for key in [
        "swap_bytes",
        "workers",
        "cpu_threads",
        "command_seconds",
        "aggregate_seconds",
        "synthetic_case_limit",
    ]:
        assert limits[key] == config[key]
    assert limits["whole_tree_memory_bytes"] == config["memory_bytes"] == 268435456
    assert limits["sqlite_file_bytes"] == limits["sqlite_page_size"] * limits["sqlite_max_pages"]
    assert limits["sqlite_file_bytes"] < limits["per_file_limit_bytes"] == 1048576
    assert limits["checkpoint_bytes"] == 65536
    assert limits["temporary_storage_bytes"] < config["output_bytes"]
    assert limits["new_output_bytes"] == config["output_bytes"]
    assert config["functional_tests_run"] == config["process_crash_experiments_run"] == 0
    doc = P / "docs/stage2_recovery_authority_design.md"
    text = doc.read_text()
    assert set(re.findall(r"^\| (T\d{2}) \|", text, re.M)) == {
        t["id"] for t in design["future_tests"]
    }
    assert set(re.findall(r"^\| (F\d{2}) \|", text, re.M)) == {
        f["id"] for f in design["failure_model"]
    }
    for required in [
        environment["sqlite_version"],
        environment["sqlite_source_id"],
        host["package_version"],
        "journal_mode=DELETE",
        "synchronous=EXTRA",
        "512 KiB",
        "64 KiB",
        "1 MiB per-file",
        "PREPARING/CLAIMED",
        "two attempts used, one unused",
        design["next_package"],
        "__getattr__",
        "not implemented",
        "cannot detect",
    ]:
        assert required in text, required
    for source in sources["sources"]:
        assert source["url"].split("#")[0] in text
    links = 0
    optional = {(P / name).resolve() for name in scope["new_optional_evidence_files"]}
    for name in [str(doc), *scope["original_permitted_documentation"]]:
        path = Path(name) if Path(name).is_absolute() else P / name
        body = path.read_text()
        assert body.count("```") % 2 == 0
        assert all(line.rstrip() == line for line in body.splitlines())
        for target in re.findall(r"\[[^\]\n]*\]\(([^)\s]+)\)", body):
            parsed = urlsplit(target.strip("<>"))
            if parsed.scheme or not parsed.path:
                continue
            destination = (path.parent / unquote(parsed.path)).resolve()
            assert destination.exists() or destination in optional, target
            links += 1
    for name in ["run_checks.py", "audit.py", "inspect_environment.py", "validate_design.py"]:
        ast.parse((BASE / name).read_text(), filename=name)
    result = {
        "package": design["package"],
        "passed": True,
        "roles": 7,
        "failure_scenarios": 8,
        "planned_acceptance_groups": 16,
        "primary_sources": 8,
        "local_document_links_checked": links,
        "environment_design_consistent": True,
        "document_data_consistent": True,
        "resource_limits_consistent": True,
        "functional_tests_run": 0,
        "crash_tests_run": 0,
        "persistence_experiments_run": 0,
        "meaning": (
            "Static design checks, not implementation, SQLite durability or rollback evidence"
        ),
    }
    (BASE / "design-validation.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
