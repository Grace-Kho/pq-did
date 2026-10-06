"""Repair-2: separate immutable case inputs from current audit outputs."""

import gzip
import hashlib
import json
import lzma
import resource
import subprocess
import sys
import types
from pathlib import Path

S = Path(__file__).resolve().parent
B = S.parent
P = B.parents[2]
W = Path("/tmp/pqdid-aurora-preservation-r2")
PIN = "ac605331b5f6daf46a41318ce25481e365fa2e42736bb92dc2c76c093db593b9"


def load(path, substitutions=()):
    obj = types.ModuleType(path.stem)
    obj.__file__ = str(path)
    source = path.read_text()
    for before, after in substitutions:
        assert source.count(before) == 1
        source = source.replace(before, after)
    exec(compile(source, str(path), "exec"), obj.__dict__)
    return obj


r = load(B / "repair-1/repair.py")
runner = load(B / "repair-1/run.py", (("pqdid-aurorarepair-", "pqdid-aurorarepair2-"),))
g = runner.guard
read = r.read
r.R = runner.R = g.D = g.BASE = W
g.__file__ = str(S / "run.py")
g.CONFIG = read(B / "repair-1/config.json")
g.CONFIG.update(
    package="S3-AURORA-TRANSCRIPT-PRESERVATION-REPAIR-2",
    package_seconds=35,
    operator_charge_seconds=18.60807852295693,
    original_package_charged_seconds=13.60807852295693,
    opening_remaining_implementation_seconds=28.21513981500175,
    repair_seconds_remaining_at_start=21.39192147704307,
)
g.CONFIG["accounting"] = (
    "Prior combined13.60807852295693 + new5 bookkeeping + actual guards; cap35; "
    "implementation unchanged374; reserve10 retained conservatively."
)
g.COMMANDS = {
    k: [str(P / ".venv/bin/python"), "-I", "-B", str(S / "run.py"), "work", k]
    for k in ("checks", "prepare", "full-audit")
}
g.FILES = [str(W / "driver.py"), str(S / "run.py")]
size = g.size
g.size = lambda path: size(W) if path == W / "tmp" else size(path)
g.package_size = r.package_bytes


def code_module(name):
    edits = ()
    if name == "audit":
        edits = (
            (
                '(D / row["evidence"]).is_file()',
                '(REGRESSION_EVIDENCE_INPUT / row["evidence"]).is_file()',
            ),
            ("package_charge + 10 <= 25", "package_charge + 10 <= 35"),
        )
    obj = load(B / (name + ".py"), edits)
    obj.REGRESSION_EVIDENCE_INPUT = B
    return obj


r.module = code_module


def original_read(path):
    obj = read(path)
    if path == B / "config.json":
        obj["operator_charge_seconds"] += 7.931766077992506
    return obj


r.read = original_read


def scope():
    with gzip.open(B / "repair-1/scope.json.gz", "rb") as stream:
        data = stream.read(1048577)
    assert len(data) <= 1048576
    value = json.loads(data)
    parent = read(P / value["inherited_required_names_from"])
    required = set(parent["required_names"]) | set(value["required_names"])
    required.update(n for n in value["optional_names"] if (P / n).exists())
    required.update(str((S / n).relative_to(P)) for n in ("run.py", "evidence.json.xz"))
    value["required_names"] = sorted(required)
    pins = read(B / "repair-1/manifest.json")["sha256"]
    for name, expected in pins.items():
        if name not in r.DOCS:
            assert value["frozen_package_inputs"].get(name, expected) == expected
            value["frozen_package_inputs"][name] = expected
    value["frozen_package_inputs"][str((B / "repair-1/manifest.json").relative_to(P))] = PIN
    value["frozen_package_inputs"].update(read(W / "checked-inputs.json")["files"])
    value["repair_prefixes"] = read(W / "prefixes.json")
    return value


r.load_scope = scope


def checks():
    assert r.audit.digest_file(B / "repair-1/manifest.json") == PIN
    pins = read(B / "repair-1/manifest.json")["sha256"]
    for name, expected in pins.items():
        assert r.audit.digest_file(P / name) == expected, name
    outcomes = read(B / "case-ledger.json")
    assert (
        r.audit.digest_file(B / "manifest.json")
        == read(B / "repair-1/manifest.json")["previous_manifest_sha256"]
    )
    original = read(B / "manifest.json")["sha256"]
    refs = []
    for i, row in enumerate(outcomes, 1):
        name = f"TR-{i:02d}.json"
        assert row["id"] == f"TR-{i:02d}" and row["evidence"] == name and row["status"] == "pass"
        path = B / name
        assert path.is_file() and r.audit.digest_file(path) == original[str(path.relative_to(P))]
        refs.append(str(path.relative_to(P)))
    assert len(refs) == len(set(refs)) == 16
    files = [str(W / "driver.py"), str(S / "run.py")]
    for args in (
        ("check", "--select", "I", "--fix"),
        ("format",),
        ("check",),
        ("format", "--check"),
    ):
        subprocess.run(
            [str(P / ".venv/bin/ruff"), *args, "--no-cache", *files], check=True, timeout=0.4
        )
    r.audit.write_report(
        W / "prefixes.json",
        {n: {"bytes": (P / n).stat().st_size, "sha256": pins[n]} for n in r.DOCS},
    )
    r.audit.write_report(
        W / "checked-inputs.json",
        {
            "input_root": str(B),
            "output_root": str(W),
            "archive_root": str(S),
            "case_references": refs,
            "original_manifest_sha256": r.audit.digest_file(B / "manifest.json"),
            "previous_manifest_sha256": PIN,
            "files": {str((S / "run.py").relative_to(P)): r.audit.digest_file(S / "run.py")},
            "driver_sha256": r.audit.digest_file(W / "driver.py"),
        },
    )


def prepare():
    value = scope()
    assert (
        value["additional_name_inventory_roots"][-1] == "experiments/aurora_transcript_regression_1"
    )
    result = r.audit.inventory_check(
        P,
        value["additional_name_inventory_roots"],
        set(value["required_names"]),
        optional_names=set(value["optional_names"]),
    )
    assert result["passed"], result
    r.audit.write_report(
        W / "preparation.json",
        {
            "inventory": result,
            "inherited_scope": "repair-1/scope.json.gz",
            "inherited_scope_sha256": r.audit.digest_file(B / "repair-1/scope.json.gz"),
            "scope_sha256": hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
            "input_root": str(B),
            "output_root": str(W),
            "baseline_regenerated": False,
        },
    )


def audit_run():
    assert r.audit.digest_file(W / "driver.py") == read(W / "checked-inputs.json")["driver_sha256"]
    assert (
        hashlib.sha256(json.dumps(scope(), sort_keys=True).encode()).hexdigest()
        == read(W / "preparation.json")["scope_sha256"]
    )
    r.full_audit()


def pack():
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    records = {
        str(x.relative_to(W)): x.read_text()
        for x in W.rglob("*")
        if x.is_file() and x.name != "driver.py"
    }
    bundle = {"source": (W / "driver.py").read_text(), "files": records}
    data = lzma.compress(json.dumps(bundle, separators=(",", ":")).encode(), preset=6)
    path = S / "evidence.json.xz"
    assert g.package_size() - path.stat().st_size + len(data) + 1100 < 262144
    path.write_bytes(data)
    assert json.loads(lzma.decompress(path.read_bytes())) == bundle


if __name__ == "__main__":
    if sys.argv[1] == "--worker":
        raise SystemExit(g.worker(sys.argv[2]))
    if sys.argv[1] == "work":
        {"checks": checks, "prepare": prepare, "full-audit": audit_run}[sys.argv[2]]()
    else:
        (W / "config.json").write_text(json.dumps(g.CONFIG, separators=(",", ":")))
        result = g.main(sys.argv[1])
        pack()
        print(
            json.dumps(
                {"retained_package_bytes": g.package_size(), "reserve_for_final_bytes": 1100}
            )
        )
        raise SystemExit(result)
