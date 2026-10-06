"""Close the stopped run and package retained evidence; never runs native cases."""

import hashlib
import io
import json
import resource
import stat
import sys
import time
import zipfile
from pathlib import Path, PurePosixPath

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.ligetron_full_path_engineering_1 import preservation  # noqa: E402
from experiments.ligetron_full_path_engineering_1 import run as guard  # noqa: E402

D, N = guard.D, guard.N


def h(b):
    return hashlib.sha256(b).hexdigest()


def padded(value, size):
    b = (json.dumps(value, indent=2) + "\n").encode()
    assert len(b) <= size
    return b + b" " * (size - len(b))


def main():
    started = time.monotonic()
    assert guard.read(D / "result.json")["passed"]
    assert guard.read(D / "report-readback.json")["passed"]
    assert guard.read(D / "shutdown.json")["all_units_terminated"]
    value = guard.read(D / "ledger.json")
    assert not value["builds"] and not value["invocations"] and not value["proofs"]
    value["bookkeeping"].append(
        {
            "seconds": 3,
            "phase": "completion",
            "basis": (
                "conservative bounded packaging/readback charge; measured time retained separately"
            ),
        }
    )
    guard.write(D / "ledger.json", value)
    charged = guard.consumed(value) - guard.POLICY["historical_seconds"]
    old = guard.read(D / "opening.json")["prior"]
    assert charged < 7200
    for path, expected in guard.read(D / "manifest.json")["sha256"].items():
        assert preservation.audit.digest_file(P / path) == expected, path
    for path, prefix in guard.read(D / "prefixes.json").items():
        assert (
            preservation.audit.digest_file(P / path, prefix_bytes=prefix["bytes"])
            == prefix["sha256"]
        )
    result = guard.read(D / "result.json")
    audit_job = guard.read(D / "jobs/full-audit-2.json")
    receipt_bytes = 16384
    evidence_added = guard.storage()["new_evidence_bytes"] + 8192 + 8192 + receipt_bytes
    assert evidence_added < 3145728
    assert guard.POLICY["shared_headroom_bytes"] - evidence_added >= 2097152
    archive_path = P / "handover/ligetron_full_path_engineering_review_v1.zip"
    assert not archive_path.exists()
    resources = {
        "package": "LIGETRON-FULL-PATH-ENGINEERING-1",
        "status": "blocked-memory-gate; source-only progress preserved",
        "package_charge_seconds": charged,
        "package_ceiling_seconds": 7200,
        "package_remaining_seconds": 7200 - charged,
        "completion_reserve_seconds": 300,
        "implementation_ceiling_seconds": 13874,
        "implementation_aggregate_charged_seconds": old["implementation_aggregate_charged_seconds"]
        + charged,
        "implementation_remaining_seconds": old["implementation_remaining_seconds"]
        + 7200
        - charged,
        "outside_KYC_remaining_seconds": old["outside_KYC_remaining_seconds"] + 7200 - charged,
        "KYC_remaining_seconds_unchanged": 383.7084432235879,
        "KYC_protected_seconds_unchanged": 300,
        "analysis_remaining_seconds_unchanged": 11.510943178986167,
        "isolation_remaining_seconds_unchanged": 250.22,
        "cumulative_invocations": 1250,
        "invocation_ceiling": 1313,
        "package_invocations_used": 0,
        "package_invocations_remaining": 48,
        "older_reserved_slots_unchanged": 15,
        "builds": 13,
        "build_ceiling": 17,
        "package_builds_used": 0,
        "package_builds_remaining": 4,
        "proofs_used": 2,
        "proof_ceiling": 4,
        "historical_unused_attempt_reserved": 1,
        "new_synthetic_attempt_used": 0,
        "new_synthetic_attempt_unspent": 1,
        "work_events": 144593603,
        "work_event_ceiling": 4294967296,
        "historical_acquisition_memory_observation_unresolved": True,
        "new_evidence_bytes": evidence_added,
        "cumulative_evidence_bytes": old["cumulative_evidence_bytes"] + evidence_added,
        "cumulative_evidence_ceiling_bytes": 46137344,
        "shared_headroom_bytes": guard.POLICY["shared_headroom_bytes"] - evidence_added,
        "shared_completion_reserve_bytes": 2097152,
        "new_artifact_bytes": 0,
        "cumulative_artifact_bytes": old["cumulative_artifact_bytes"],
        "cumulative_artifact_ceiling_bytes": 4294967296,
        "temporary_bytes": 0,
        "audit_seconds": audit_job["seconds"],
        "audit_worker_peak_bytes": int(audit_job["worker"]["after"]["memory.peak"]),
        "memory_admission": "failed; exact readings in memory-admission.json",
        "all_amendments_prospective": True,
    }
    closure = {
        "package": "LIGETRON-FULL-PATH-ENGINEERING-1",
        "complete": False,
        "outcome": "stopped at approved dual-environment memory gate",
        "preservation_complete": True,
        "audit_launcher_attempts": 2,
        "complete_audit_executions": 1,
        "full_audit_exit_code": audit_job["exit_code"],
        "historical_audit_result": result,
        "inventory_and_report_readback": guard.read(D / "report-readback.json"),
        "worker_termination": guard.read(D / "shutdown.json"),
        "all_40_native_cases": "unrun",
        "synthetic_proof": "unrun",
        "prepared_overlay": "partial, source-only; not native validated or proof admitted",
        "source_overlay_sha256": guard.read(D / "prepared-overlay-seal.json")["patch_sha256"],
        "baseline_and_historical_failures_preserved": True,
        "private_verification": "fail-closed",
        "Binius": "closed-unresolved",
        "private_proving_and_isolation": "paused; approved synthetic exception unspent",
        "no_automatic_resumption": True,
    }
    # Keep bulky historical result in its original payload rather than duplicate it.
    closure["historical_audit_result"] = {
        "path": "docs/data/ligetron_full_path_engineering_1/result.json",
        "sha256": h((D / "result.json").read_bytes()),
        "passed": result["passed"],
    }
    paths = [f for root in (D, N) for f in root.rglob("*") if f.is_file()]
    paths += [
        P / "docs/ligetron_full_path_engineering.md",
        P / "docs/status.md",
        P / "docs/spec_issues.md",
        P / "docs/traceability.md",
        P / "handover/ligetron_full_path_preflight_v1.zip",
    ]
    for pkg in ("ligetron_domain_mask_correction_1", "ligetron_correction_admission_1"):
        paths.append(P / "docs/data" / pkg / "reviewed-overlay.patch")
    payload = {p.relative_to(P).as_posix(): p.read_bytes() for p in paths}
    origins = {p.relative_to(P).as_posix(): str(p) for p in paths}
    rn = "docs/data/ligetron_full_path_engineering_1/resource-closure.json"
    cn = "docs/data/ligetron_full_path_engineering_1/validation-closure.json"
    origins[rn], origins[cn] = str(P / rn), str(P / cn)
    payload["README.txt"] = b"""LIGETRON-FULL-PATH-ENGINEERING-1: memory-gated continuation

Read docs/ligetron_full_path_engineering.md, then this package's memory-admission,
prepared-overlay-seal, outcomes, validation-closure and resource-closure JSON files.
All E01-E40 outcomes are UNRUN. No native binary, generated/loaded shader, adapter
execution, native expectations, new dependency installation or proof exists here.
No compilation success or privacy/security claim is made.

The approved preflight ZIP under handover/ is included unchanged. It contains the
exact dependency/source provenance, inactive commands, original source snapshots,
both preceding overlays, component harnesses/expectations, all67 historical
component outcomes and closures. No archived program should be executed for review.

Patch order: pinned Ligero4b1cdef1bfdf4497fb3e38170db4541fba3f6c12; randomness
overlay043ee96f...; domain/mask overlay31f1515e...; prepared-overlay.patch here.
The last is an INCOMPLETE, UNCOMPILED source continuation, not a finished repair.
Full statement/protobuf/harness/actual-device work remains unimplemented or unrun.

The fresh memory observations failed4 GiB in both environments. All4 new builds,
48 new invocations and the new synthetic-only proof attempt remain unspent.
The original unused proof attempt and KYC reserves remain protected. Production
private verification stays fail-closed; genuine private proving/isolation paused.
Degree/masking, commitment/compiler, challenge expansion, extraction and quantum
obligations remain open. This archive is not evidence of complete authentication.

Exact commands actually run are in jobs/*.input.json and memory-admission.json.
The source-only edits, metadata failure/correction and measured guarded completion
records are retained. A complete historical audit ran once at this checkpoint;
archive CRC/path/hash verification did not execute functional tests or proofs.
MANIFEST.json indexes payloads and this reader guide; it does not hash itself.
Archive final identity and post-package inventory are in the external
archive-result.json and chat; a ZIP cannot embed its own final SHA-256.
"""
    origins["README.txt"] = "generated reader guide"

    def pack():
        payload[rn] = padded(resources, 8192)
        payload[cn] = padded(closure, 8192)
        manifest = {
            "files": [
                {"original_path": origins[n], "archive_path": n, "bytes": len(b), "sha256": h(b)}
                for n, b in sorted(payload.items())
            ]
        }
        records = dict(payload)
        records["MANIFEST.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as z:
            for n, b in sorted(records.items()):
                i = zipfile.ZipInfo(n, (2026, 10, 3, 0, 0, 0))
                i.external_attr = (stat.S_IFREG | 0o644) << 16
                i.compress_type = (
                    zipfile.ZIP_STORED if n in {rn, cn, "MANIFEST.json"} else zipfile.ZIP_DEFLATED
                )
                z.writestr(i, b, compresslevel=6)
        return buffer.getvalue()

    archive = pack()
    resources["new_artifact_bytes"] = len(archive)
    resources["cumulative_artifact_bytes"] += len(archive)
    final = pack()
    assert len(final) == len(archive)
    assert len(final) < 1048576  # This handover fits even the ordinary file ceiling.
    (P / rn).write_bytes(payload[rn])
    (P / cn).write_bytes(payload[cn])
    archive_path.write_bytes(final)
    with zipfile.ZipFile(archive_path) as z:
        names = z.namelist()
        assert len(names) == len(set(names)) and set(names) == set(payload) | {"MANIFEST.json"}
        assert z.testzip() is None
        for n in names:
            path = PurePosixPath(n)
            assert not path.is_absolute() and ".." not in path.parts and "\\" not in n
            assert not stat.S_ISLNK(z.getinfo(n).external_attr >> 16)
        for row in json.loads(z.read("MANIFEST.json"))["files"]:
            b = z.read(row["archive_path"])
            assert len(b) == row["bytes"] and h(b) == row["sha256"]
            source = row["original_path"]
            if source.startswith(str(P)):
                assert Path(source).read_bytes() == b
    inv = preservation.inventory(preservation.scope())
    assert inv["passed"]
    elapsed = time.monotonic() - started
    assert elapsed < 3
    receipt = {
        "archive": str(archive_path),
        "bytes": len(final),
        "sha256": h(final),
        "members": len(payload) + 1,
        "archive_verification_passed": True,
        "post_archive_inventory": inv,
        "measured_packaging_seconds": elapsed,
        "packaging_peak_RSS_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        "resource_closure_sha256": h((P / rn).read_bytes()),
        "validation_closure_sha256": h((P / cn).read_bytes()),
    }
    (D / "archive-result.json").write_bytes(padded(receipt, receipt_bytes))
    assert guard.storage()["new_evidence_bytes"] == evidence_added
    print(json.dumps({k: v for k, v in receipt.items() if k != "post_archive_inventory"}, indent=2))
    print(json.dumps(resources, indent=2))


if __name__ == "__main__":
    main()
