"""Audit the closed preflight package; no execution or proving APIs are used."""

import ast
import hashlib
import json
import math
import re
import subprocess
import tomllib
from collections import Counter
from pathlib import Path

R = Path(__file__).resolve().parents[1]
P = R.parents[1]
N = R.parent / "r0_enrol_po17_1"
E = R.parent / "r0_credvalid_exec24_1"
C = R.parent / "r0_credvalid_cycle_1"
A = R.parent / "r0_succinct_proof_1"
B = R.parent / "r0_succinct_feasibility_1"


def load(p):
    return json.loads(p.read_text())


def sha(p):
    with p.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def close(a, b):
    assert math.isclose(a, b, rel_tol=0, abs_tol=1e-7), (a, b)


before = load(R / "evidence/protected_before.json")
allowed = {"docs/status.md", "docs/traceability.md"}
changed = []
for name, digest in before.items():
    if sha(P / name) != digest:
        assert name in allowed, name
        changed.append(name)
assert set(changed) == allowed
manifest = load(R / "evidence/manifest-before-launch.json")
for name, digest in manifest["frozen_sha256"].items():
    assert sha(R / name) == digest, name
cfg = load(R / "config.json")
assert cfg == manifest["config"]
previous = load(N / "config.json")
config_changes = {k for k, v in cfg.items() if previous.get(k) != v}
assert config_changes == {
    "package",
    "prior_proof_attempts",
    "sequence",
    "session_limit_user_cycles",
    "retained_segment_records",
    "cost_uncertainty_fraction",
}
assert cfg["session_limit_user_cycles"] == {"cred-valid": 2**24}
assert cfg["segment_limit_po2"] == 17 and cfg["memory_bytes"] == 2**31
assert cfg["retained_segment_records"] == load(E / "config.json")["retained_segment_records"]
assert cfg["execution_wall_seconds"] == 60 and cfg["max_execution_only_runs"] == 1
assert cfg["proof_pipeline_wall_seconds"] == 600
base = load(R / "evidence/baseline.json")
source_bundle = C / "snapshots/builds/corrected-plain"
for name, digest in base["corrected_guest"]["source_sha256"].items():
    assert sha(source_bundle / name) == digest, name
assert sha(R / "artifacts/cred_valid.elf") == base["corrected_guest"]["elf_sha256"]
assert sha(R / "artifacts/cred_valid.bin") == base["corrected_guest"]["program_sha256"]
case = load(R / "fixtures/cases.json")["cases"][0]
for key in ["public", "private"]:
    assert sha(R / case[key]) == case[key + "_sha256"]


def encode(tag, fields):
    out = len(tag).to_bytes(4, "big") + tag + len(fields).to_bytes(4, "big")
    return out + b"".join(len(v).to_bytes(4, "big") + v for v in fields)


want = encode(b"r0-result", [b"PQDID-R0S-DIAG1", b"cred-valid", (R / case["public"]).read_bytes()])
assert want == (R / case["expected_journal"]).read_bytes()
assert want == (E / "evidence/valid.public-journal.bin").read_bytes()
assert want == (R / "evidence/execution.public-journal.bin").read_bytes()
exe = load(R / "evidence/execution.result.json")
res = load(R / "evidence/execution.json")
pre = load(R / "evidence/preflight.result.json")
a = load(R / "evidence/admission.result.json")
i = load(R / "evidence/cost-model-inputs.json")
assert exe["accepted"] and exe["journal_matches_expected"] and exe["exit_code"] == "Halted(0)"
records = exe["segment_records"]
assert len(records) == exe["segments"] == 182
assert [s["index"] for s in records] == list(range(182))
counts = Counter(s["po2"] for s in records)
assert counts == {17: 181, 15: 1}
assert exe["segment_size_distribution"] == {str(k): v for k, v in counts.items()}
assert sum(s["user_cycles"] for s in records) == exe["user_cycles"] == 16313474
assert sum(2 ** s["po2"] for s in records) == exe["padded_capacity"] == 23756800
assert exe["other_capacity"] == exe["padded_capacity"] - exe["user_cycles"] == 7443326
assert exe["user_cycles"] < 2**24
assert all(s["padded_capacity"] == 2 ** s["po2"] for s in records)
assert res["status"] == "pass" and res["cgroup_memory_peak_bytes"] < 2**31
assert res["wall_seconds"] < 60 and res["sampled_swap_peak"] == 0
assert res["mem_available_at_admission"] >= 2**32
assert res["sampled_temporary_bytes_peak"] == res["temporary_bytes_at_exit"] == 0
assert "max 0\n" in res["memory_events"] and "oom 0\n" in res["memory_events"]
assert set(counts).issubset(pre["supported_segment_po2"])
archive = load(A / "evidence/recursion-artifacts.json")
for po2 in counts:
    assert any(x["name"] == f"lift_rv32im_v2_{po2}.zkr" for x in archive["entries"])
opts = pre["host_inspection"]["prover_options"]
assert opts["receipt_kind"] == "Succinct" and opts["hashfn"] == "poseidon2"
assert opts["max_segment_po2"] == 22 and not opts["dev_mode"]
assert not opts["prove_guest_errors"]
for name, row in i["source_review"].items():
    assert sha(P / name) == row["sha256"]
assert sha(P / i["source_log"]) == i["source_log_sha256"]
assert i["source_log_complete"]
close(sum(x["combined_seconds"] for x in i["base_segments"]), i["observed_segment_block_seconds"])
for x in i["base_segments"]:
    close(
        x["preflight_observed_seconds"] + x["core_through_next_boundary_seconds"],
        x["combined_seconds"],
    )
close(
    sum(x["seconds"] for x in i["recursion_operations"]) + sum(i["recursion_handoff_seconds"]),
    i["observed_recursion_block_seconds"],
)
close(
    i["observed_segment_block_seconds"]
    + i["observed_recursion_block_seconds"]
    + i["combined_unattributed_guarded_residual_seconds"],
    i["guarded_pipeline_seconds"],
)
close(a["rates_seconds"]["base_po17"], max(x["combined_seconds"] for x in i["base_segments"]))
for kind in ["lift", "join"]:
    rate = a["rates_seconds"]["lift_po17" if kind == "lift" else kind]
    close(
        rate,
        max(x["seconds"] for x in i["recursion_operations"] if x["kind"] == kind)
        + max(i["recursion_handoff_seconds"]),
    )
x = a["components_before_uncertainty"]
close(x["base_segments_seconds"], 182 * a["rates_seconds"]["base_po17"])
close(x["lifts_seconds"], 182 * a["rates_seconds"]["lift_po17"])
close(x["joins_seconds"], 181 * a["rates_seconds"]["join"])
close(sum(x.values()), a["subtotal_seconds"])
close(a["subtotal_seconds"] * 0.5, a["uncertainty_seconds"])
close(a["subtotal_seconds"] * 1.5, a["conservative_estimate_seconds"])
assert not a["proof_admitted"] and a["conservative_estimate_seconds"] > 600
assert not a["memory_admitted"] and not a["all_segment_types_measured"]
sensitivity = 181 * sum(
    min(x["seconds"] for x in i["recursion_operations"] if x["kind"] == kind)
    for kind in ["lift", "join"]
)
close(sensitivity, 15844.47393)
ledger = load(R / "evidence/run_ledger.json")
assert ledger["execution_runs"] == 1 and ledger["proof_attempts"] == 0
assert sum(x["phase"] == "execute" for x in ledger["runs"]) == 1
assert not any(x["phase"] == "prove" for x in ledger["runs"])
assert not list((R / "receipts").iterdir())
cumulative = load(R / "evidence/cumulative_attempt_ledger.json")
assert (
    cumulative["attempts_used"] == 2
    and cumulative["remaining"] == 1
    and cumulative["package_closed"]
)
assert sha(R / cumulative["previous_ledger"]) == cumulative["previous_ledger_sha256"]
assert cumulative["admission_sha256"] == sha(R / "evidence/admission.result.json")
assert load(R / "evidence/STOP.json")["package_closed"]
# Probe refusal only: STOP is checked before any subprocess/service creation.
ledger_bytes = (R / "evidence/run_ledger.json").read_bytes()
probes = []
for args in [
    [
        "--seconds",
        "60",
        "--slot",
        "1",
        "execute",
        "execution",
        "--",
        "target/release/pqdid-r0-host",
        "execute",
    ],
    [
        "--seconds",
        "600",
        "--slot",
        "3",
        "prove",
        "attempt3",
        "--",
        "target/release/pqdid-r0-host",
        "prove",
        "cred-alpha-42",
        "receipts/attempt3.bin",
    ],
]:
    q = subprocess.run(
        ["/usr/bin/python3", str(R / "scripts/run_limited.py"), *args],
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert q.returncode != 0 and "package resource stop recorded" in q.stderr
    assert (R / "evidence/run_ledger.json").read_bytes() == ledger_bytes
    probes.append({"arguments": args, "exit": q.returncode, "reason": q.stderr.strip()})
for p in R.rglob("*.json"):
    if "target" not in p.parts and "tooling" not in p.parts:
        load(p)
for p in [R / "Cargo.toml", R / "host/Cargo.toml", R / "relation/Cargo.toml", R / "Cargo.lock"]:
    tomllib.loads(p.read_text())
for p in (R / "scripts").glob("*.py"):
    ast.parse(p.read_text())
checks = [
    [str(P / ".venv/bin/ruff"), "check", str(R / "scripts")],
    [str(P / ".venv/bin/ruff"), "format", "--check", str(R / "scripts")],
    [
        str(B / "tooling/guest-r0.1.97.0/bin/rustfmt"),
        "--check",
        "--edition",
        "2021",
        str(R / "host/src/main.rs"),
    ],
    ["/bin/bash", "-n", str(R / "scripts/build_host.sh")],
]
for cmd in checks:
    subprocess.run(cmd, check=True, timeout=20)
link_count = 0
report = P / "docs/stage3_r0_credvalid_po17.md"
for target in re.findall(r"\]\(([^)]+)\)", report.read_text()):
    name = target.split("#", 1)[0]
    if not name or "://" in name:
        continue
    if name.endswith("/evidence/final-audit.result.json") or name.endswith(
        "/evidence/manifest.json"
    ):
        continue  # Created after this check returns.
    assert (report.parent / name).exists(), name
    link_count += 1
assert "35615.571973" in report.read_text() and "182 segments" in report.read_text()
extra_sources = [
    C
    / (
        "tooling/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/risc0-circ"
        "uit-rv32im-4.0.5/src/execute/executor.rs"
    ),
    source_bundle / "methods/guest/src/lib.rs",
    source_bundle / "relation/src/lib.rs",
]
result = {
    "passed": True,
    "protected_files": len(before),
    "allowed_modified_files": changed,
    "frozen_files_checked": len(manifest["frozen_sha256"]),
    "native_validation_reused": True,
    "actual_partition": dict(counts),
    "checks": (
        "identity, config/envelope, source controls, journal framing, all segme"
        "nt sums, typed phase arithmetic, explicit uncertainty, no proof, ledge"
        "r, STOP, lint/format/syntax, links"
    ),
    "stop_probes": probes,
    "report_links_checked": link_count,
    "additional_source_sha256": {str(p.relative_to(P)): sha(p) for p in extra_sources},
    "sensitivity_seconds": sensitivity,
    "sensitivity_description": (
        "181 po17 lifts and 181 ordinary joins at their respective minimum obse"
        "rved times, excluding all base proofs, unmatched terminal po15 lift an"
        "d other overhead; illustrative optimistic projection, not a rigorous l"
        "ower bound"
    ),
    "reference_enrolment_receipt_sha256": sha(N / "receipts/attempt2.bin"),
    "proof_attempts_this_package": 0,
    "cumulative_attempts_used": 2,
    "remaining": 1,
}
(R / "evidence/final-audit.result.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({"passed": True, "preserved_files": len(before), "new_proofs": 0, "remaining": 1}))
