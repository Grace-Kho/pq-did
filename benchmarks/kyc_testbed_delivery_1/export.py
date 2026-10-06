"""Bounded derivative catalogue; historical raw records remain authoritative."""

import csv
import hashlib
import io
import json
from collections import Counter
from pathlib import Path

from benchmarks.kyc_milestone_1.export import BoundedWriter

P = Path(__file__).resolve().parents[2]
FIELDS = (
    "dataset",
    "id",
    "scenario",
    "category",
    "phase",
    "duration_ns",
    "setup_ns",
    "source",
    "source_sha256",
    "locator",
    "issuer_version",
    "manager_version",
)
EXPECTED = {"baseline-v1": 276, "testbed-v1": 19, "issuer-v2": 3, "manager-v2": 4}


class IntegrityError(ValueError):
    pass


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(65536):
            h.update(block)
    return h.hexdigest()


def retained(seals):
    identities = {}

    def checked(name):
        path = P / name
        expected = seals.get(name)
        if expected is None or digest(path) != expected:
            raise IntegrityError("untrusted or altered retained input: " + name)
        identities[name] = expected
        return path

    def read(name):
        return json.loads(checked(name).read_text())

    rows, failures = [], []
    base = "docs/data/oct31_kyc_native_milestone_1"
    ledger = read(base + "/ledger.json")
    inv = {x["invocation_id"]: x for x in ledger["invocations"]}
    summary = read(base + "/benchmarks/oct31-reference-01/summary.json")
    read(base + "/benchmark-source-provenance.json")
    for session in summary["sessions"]:
        folder = P / session["output"]
        if not folder.is_relative_to(P / base):
            raise IntegrityError("session path outside retained dataset")
        for path in sorted(folder.glob("trials-*.jsonl")):
            name = path.relative_to(P).as_posix()
            checked(name)
            for line, raw in enumerate(path.open(), 1):
                x = json.loads(raw)
                assert inv[x["invocation_id"]]["status"] == "pass"
                assert x["outcome"] == "accepted" and x["measurement_origin"] == "actual"
                assert x["category"] == "mldsa_reference_measured"
                rows.append(
                    dict(
                        zip(
                            FIELDS,
                            (
                                "baseline-v1",
                                x["invocation_id"],
                                x["scenario_id"],
                                "disclosed-baseline",
                                x["phase"],
                                x["duration_ns"],
                                x["setup_ns"],
                                name,
                                identities[name],
                                line,
                                1,
                                1,
                            ),
                            strict=True,
                        )
                    )
                )
    series = [
        ("testbed-v1", "kyc_testbed_execution_1", "measurements.json"),
        ("issuer-v2", "kyc_issuer_incremental_storage_1", "measurements-v2.json"),
        ("manager-v2", "kyc_manager_incremental_storage_1", "measurements-manager-v2.json"),
    ]
    for dataset, package, filename in series:
        prefix = "docs/data/" + package
        summary = read(prefix + "/" + filename)
        ledger = read(prefix + "/ledger.json")
        records = {x["invocation_id"]: x for x in ledger["invocations"]}
        names = summary.get("source_case_files")
        if names is None:
            names = [
                prefix + "/cases/" + x["invocation_id"] + ".json" for x in summary["observations"]
            ]
        for name in names:
            x = read(name)
            assert x["status"] == "pass" and records[x["invocation_id"]]["status"] == "pass"
            if "observations" in summary:
                assert x == next(
                    v for v in summary["observations"] if v["invocation_id"] == x["invocation_id"]
                )
            details = x["details"]
            rows.append(
                dict(
                    zip(
                        FIELDS,
                        (
                            dataset,
                            x["invocation_id"],
                            x["case_id"],
                            "disclosed-baseline",
                            "observation",
                            details["operation_ns"],
                            details.get("setup_ns"),
                            name,
                            identities[name],
                            "details",
                            2 if dataset in {"issuer-v2", "manager-v2"} else 1,
                            2 if dataset == "manager-v2" else 1,
                        ),
                        strict=True,
                    )
                )
            )
        for x in ledger["invocations"]:
            if x["status"] != "pass":
                name = prefix + "/cases/" + x["invocation_id"] + ".json"
                case = read(name)
                assert case["status"] == x["status"]
                failures.append(
                    {
                        "dataset": dataset,
                        "id": x["invocation_id"],
                        "case": x["case_id"],
                        "status": x["status"],
                        "source": name,
                        "sha256": identities[name],
                    }
                )
    # v1 failures include validation history; no failed benchmark observation is invented.
    for x in inv.values():
        if x["status"] != "pass":
            failures.append(
                {
                    "dataset": "baseline-v1-validation-history",
                    "id": x["invocation_id"],
                    "case": x["case_id"],
                    "status": x["status"],
                    "source": base + "/ledger.json",
                    "sha256": identities[base + "/ledger.json"],
                }
            )
    validate(rows)
    assert dict(Counter(x["dataset"] for x in rows)) == EXPECTED
    return rows, failures, identities


def validate(rows):
    seen = set()
    for row in rows:
        if set(row) != set(FIELDS) or row["category"] != "disclosed-baseline":
            raise ValueError("category or fields")
        key = row["dataset"], row["id"]
        if key in seen:
            raise ValueError("duplicate dataset/observation identity")
        seen.add(key)
        if row["dataset"] not in {*EXPECTED, "delivery-v2-smoke"}:
            raise ValueError("unsupported measured dataset")
        if type(row["duration_ns"]) is not int or row["duration_ns"] < 0:
            raise ValueError("duration")


def encode_csv(values):
    f = io.StringIO(newline="")
    csv.writer(f, lineterminator="\n").writerow(values)
    return f.getvalue().encode()


def write(output, rows, failures):
    validate(rows)
    output = Path(output)
    output.mkdir(mode=0o700, exist_ok=False)
    j = BoundedWriter(output, "observations", "jsonl", cap=262144)
    c = BoundedWriter(output, "observations", "csv", cap=262144, header=encode_csv(FIELDS))
    try:
        for row in rows:
            j.append(json.dumps(row, separators=(",", ":")).encode() + b"\n")
            c.append(encode_csv([row[k] for k in FIELDS]))
    finally:
        j.close()
        c.close()
    meta = {
        "version": "kyc-delivery-export/1",
        "counts": dict(Counter(x["dataset"] for x in rows)),
        "pooled_statistics": None,
        "failures": failures,
        "component_measurements": {
            "category": "component-only",
            "source": "docs/implementation_consolidation.md",
            "included_in_baseline_rows": False,
        },
        "private_proof_metrics": {
            k: {"value": None, "reason": "complete private authentication unavailable"}
            for k in [
                "prove_seconds",
                "verify_seconds",
                "proof_bytes",
                "peak_memory",
                "throughput",
                "privacy_overhead",
            ]
        },
        "interpretation": (
            "Separate datasets; four smoke trials do not establish distributions or capacity."
        ),
    }
    (output / "summary.json").write_text(json.dumps(meta, indent=2) + "\n")
    (output / "manifest.json").write_text(
        json.dumps({f.name: digest(f) for f in sorted(output.iterdir())}, indent=2) + "\n"
    )
    return meta


def readback(output):
    output = Path(output)
    for name, expected in json.loads((output / "manifest.json").read_text()).items():
        if Path(name).name != name or digest(output / name) != expected:
            raise IntegrityError("export readback")
    rows = []
    csvrows = []
    for f in sorted(output.glob("observations-*.jsonl")):
        rows.extend(json.loads(x) for x in f.open())
    for f in sorted(output.glob("observations-*.csv")):
        with f.open(newline="") as s:
            csvrows.extend(csv.DictReader(s))
    validate(rows)
    assert len(rows) == len(csvrows)
    for row, c in zip(rows, csvrows, strict=True):
        assert all(c[k] == ("" if row[k] is None else str(row[k])) for k in FIELDS)
    assert (
        dict(Counter(x["dataset"] for x in rows))
        == json.loads((output / "summary.json").read_text())["counts"]
    )
    return rows
