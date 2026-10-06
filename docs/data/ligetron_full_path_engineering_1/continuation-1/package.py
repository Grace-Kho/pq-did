"""Bounded failed-memory-admission handover; no implementation or native execution."""

import hashlib
import io
import json
import resource
import stat
import time
import zipfile
from pathlib import Path, PurePosixPath

P = Path(__file__).resolve().parents[4]
D = Path(__file__).resolve().parent
OLD = D.parent
ARCHIVE = P / "handover/ligetron_full_path_engineering_review_v2.zip"
PREVIOUS = P / "handover/ligetron_full_path_engineering_review_v1.zip"
HASH = "a75cc5e86185f1efabb4d9c905aa29a45037f07ee76125cbc44d339a0131e850"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def write(name, value):
    f = D / name
    assert not f.exists(), name
    f.write_bytes(encoded(value))


def fixed(value):
    b = encoded(value)
    assert len(b) <= 8192
    return b + b" " * (8192 - len(b))


def main():
    start = time.monotonic()
    assert P == Path("/home/grace/projects/pq-did")
    assert not ARCHIVE.exists()
    old_bytes = PREVIOUS.read_bytes()
    assert len(old_bytes) == 987389 and sha(old_bytes) == HASH
    old = json.loads((OLD / "resource-closure.json").read_text())
    close = json.loads((OLD / "validation-closure.json").read_text())
    assert close["preservation_complete"] and not close["complete"]
    assert old["package_remaining_seconds"] == 6904.125801613787
    assert old["KYC_remaining_seconds_unchanged"] == 383.7084432235879
    # Reuse the completed audit. Only previous archive and selected payload
    # identities are checked here, not the whole historical tree or test suites.
    payload, origins = {}, {}
    with zipfile.ZipFile(io.BytesIO(old_bytes)) as z:
        assert z.testzip() is None
        names = z.namelist()
        assert len(names) == len(set(names))
        manifest = json.loads(z.read("MANIFEST.json"))
        assert set(names) == {r["archive_path"] for r in manifest["files"]} | {"MANIFEST.json"}
        for row in manifest["files"]:
            n = row["archive_path"]
            q = PurePosixPath(n)
            assert not q.is_absolute() and ".." not in q.parts and "\\" not in n
            assert not stat.S_ISLNK(z.getinfo(n).external_attr >> 16)
            b = z.read(n)
            assert len(b) == row["bytes"] and sha(b) == row["sha256"], n
            if n != "README.txt":
                f = Path(row["original_path"])
                assert f.is_relative_to(P) and not f.is_symlink()
                assert f.read_bytes() == b, str(f)
                payload[n], origins[n] = b, str(f)
    disk = P.stat().st_dev
    import os
    fs = os.statvfs(P)
    available_disk = fs.f_bavail * fs.f_frsize
    evidence_reservation = 65536
    artifact_reservation = 2 * 1048576
    assert available_disk >= 9663676416 + evidence_reservation + artifact_reservation
    assert old["new_evidence_bytes"] + evidence_reservation < 3145728 - 524288
    assert old["cumulative_evidence_bytes"] + evidence_reservation < 46137344
    assert old["shared_headroom_bytes"] - evidence_reservation >= 2097152
    assert old["cumulative_artifact_bytes"] + artifact_reservation < 4294967296
    measured = 0.6773259141482413 + 0.5504720148164779
    charge = 20 + measured
    assert old["package_remaining_seconds"] - charge >= 300
    write("opening.json", {
        "package": "LIGETRON-FULL-PATH-ENGINEERING-1",
        "continuation": "same package, failed fresh memory gate",
        "prior_resource_closure": str(OLD / "resource-closure.json"),
        "prior_resource_sha256": sha((OLD / "resource-closure.json").read_bytes()),
        "prior_validation_sha256": sha((OLD / "validation-closure.json").read_bytes()),
        "previous_archive_sha256": HASH,
        "old_consumption_and_reservations_preserved": True,
        "new_evidence_reservation_bytes": evidence_reservation,
        "new_archive_artifact_reservation_bytes": artifact_reservation,
        "registered_artifact": str(ARCHIVE),
        "artifact_per_file_ceiling_bytes": 268435456,
        "classification": "ZIP artifact; diagnostics, script, ledger and reports evidence",
        "available_disk_bytes": available_disk,
        "filesystem_device": disk,
        "no_limits_or_allocations_changed": True,
    })
    write("memory-admission.json", {
        "utc": "2026-10-03T08:24:55.524207+00:00",
        "command": ["/mnt/c/windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                    "-NoProfile", "-NonInteractive", "-Command",
                    "Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | ConvertTo-Json -Compress"],
        "exit_code": 0,
        "stdout": '{"TotalVisibleMemorySize":16389632,"FreePhysicalMemory":2359232}\n',
        "stderr": "", "WSL_available_bytes": 3896512512,
        "Windows_free_bytes": 2415853568, "required_each_bytes": 4294967296,
        "passed": False, "reads_this_continuation": 1,
        "WSL_memory_bytes": {"MemTotal": 8126111744, "MemFree": 2991611904,
            "MemAvailable": 3896512512, "Buffers": 47095808, "Cached": 635506688,
            "SReclaimable": 427200512, "Shmem": 4313088,
            "SwapTotal": 2147483648, "SwapFree": 2147483648},
        "elapsed_seconds": 0.6773259141482413, "self_peak_RSS_bytes": 13406208,
        "metric_limit": "diagnostic Python worker RSS, not Windows process-tree memory",
    })
    windows = [
        ["vmmemWSL", 14116, 3059531776, 5532700672],
        ["Memory Compression", 4188, 1440833536, 8130560],
        ["chrome", 11656, 649805824, 817446912],
        ["Code", 18224, 571449344, 740646912],
        ["chrome", 18580, 476299264, 568770560],
        ["chrome", 29944, 451190784, 583823360],
        ["chrome", 15996, 416313344, 509161472],
        ["mc-fw-host", 6744, 380174336, 790683648],
        ["Code", 19356, 314347520, 420241408],
        ["explorer", 15820, 268070912, 555925504],
        ["chrome", 26992, 230387712, 190984192],
        ["msedgewebview2", 7912, 165351424, 542449664],
    ]
    wsl = [[10106,"MainThread",1752228],[4616,"MainThread",779116],
           [4731,"codex",406968],[1053,"MainThread",273708],
           [965,"MainThread",194160],[1028,"MainThread",149400],
           [28208,"MainThread",97748],[4604,"MainThread",96152],
           [2920,"MainThread",78808],[3175568,"MainThread",77808],
           [4598,"MainThread",73828],[4589,"MainThread",69236],
           [242,"unattended-upgr",32640],[6146,"codex-code-mode",32184],
           [128,"networkd-dispat",29880]]
    write("memory-consumers.json", {
        "commands": [
            ["/mnt/c/windows/System32/WindowsPowerShell/v1.0/powershell.exe",
             "-NoProfile", "-NonInteractive", "-Command",
             "Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 12 ProcessName,Id,WorkingSet64,PrivateMemorySize64 | ConvertTo-Json -Compress"],
            ["ps", "-eo", "pid,comm,rss", "--sort=-rss"]],
        "exit_codes": [0,0], "Windows_columns": ["ProcessName","Id","WorkingSet64","PrivateMemorySize64"],
        "Windows_largest_processes": windows,
        "WSL_columns": ["PID","comm","RSS_KiB"], "WSL_largest_processes": wsl,
        "elapsed_seconds": 0.5504720148164779, "self_peak_RSS_bytes": 12910592,
        "limitations": ["Working sets/RSS can share pages; do not sum as exclusive physical use.",
            "Windows vmmemWSL working set and guest MemAvailable are different metrics.",
            "Readlink of /proc/10106/exe, /proc/4616/exe and /proc/4731/exe yielded no identity in the sandbox; MainThread application attribution remains unknown.",
            "No memory values were refreshed to seek a passing gate; no processes/configuration changed."],
    })
    write("ledger.json", {
        "parent_ledger": str(OLD / "ledger.json"),
        "parent_resource_closure_sha256": sha((OLD / "resource-closure.json").read_bytes()),
        "measured_diagnostic_seconds": measured,
        "conservative_completion_and_bookkeeping_seconds": 20,
        "conservative_basis": "inspection, selected-file preservation, packaging, accounting and final reporting; not labelled measured runtime",
        "charged_seconds": charge, "invocations": [], "builds": [], "proofs": [],
        "allocation_charged": "existing package and overall outside-KYC capacity, once",
        "functional_revalidation": "none", "memory_repolls": 0,
        "minor_read_diagnostics": "Two case-sensitive runbook-name searches missed uppercase filenames; corrected by reading existing RUNBOOK.md; no source changes or tests.",
    })
    report = """# Continuation 1 — memory admission still blocked

One fresh reading at 2026-10-03T08:24:55.524207+00:00 found Windows free
2,415,853,568 bytes and WSL available 3,896,512,512 bytes. Both fail the
unchanged 4,294,967,296-byte gate. No acquisition, implementation, build,
functional case, device workload or proof was admitted; E01–E40 remain unrun.
No actual Dawn adapter has been selected. The retained partial source overlay
remains uncompiled and unvalidated. All four builds, 48 package invocations and
the new synthetic-only proof attempt remain unspent; the older proof reservation
and KYC balances are unchanged.

Largest Windows working sets include vmmemWSL (2.85 GiB), Memory Compression
(1.34 GiB), multiple Chrome processes (largest 620 MiB) and Code (largest
545 MiB). WSL's largest reported processes are MainThread PID10106 (1.67 GiB),
MainThread PID4616 (761 MiB) and codex PID4731 (397 MiB). MainThread's application
identity was unavailable from the bounded readlink attempt. Do not sum RSS or
working-set figures as exclusive physical usage or conflate host/guest metrics.
WSL has about 606 MiB Cached, 407 MiB SReclaimable and 45 MiB Buffers, with
all 2 GiB swap free. MemAvailable already estimates reclaimable memory; adding
these figures to it would double-count potential headroom. No cache flush,
process termination, driver/host change or repeated admission polling occurred.

Reuse the previous complete 10,901-comparison preservation audit and closures.
This continuation checks prior archive identity, CRC and manifest, every included
source against its retained payload, new output inventory and archive readback.
It does not claim a new full historical audit or rerun any functional validation.
The previous report and all failures remain unchanged. All diagnostic children
exited; no transient guard service or long-lived worker was started this turn.

Next action: resume the already-approved package only after a fresh admission
at a subsequent resumption satisfies both memory gates. No limits are lowered
and no host intervention is performed automatically. Degree/masking correspondence,
joint committed-view simulation, challenge expansion, compiler binding,
same-assignment extraction and quantum/Fiat–Shamir obligations remain open.
Production private verification is fail-closed; private proving and isolation
remain paused. The synthetic exception remains unspent. The full PQ-DID scope,
31 October target, baseline and all historical datasets remain unchanged.
"""
    (D / "report.md").write_text(report)
    write("preservation.json", {
        "method": "reuse completed audit, selected-file and archive-only continuation",
        "previous_archive_identity_verified": True, "previous_payloads_match_sources": True,
        "historical_audit_reused": str(OLD / "result.json"),
        "historical_audit_sha256": sha((OLD / "result.json").read_bytes()),
        "historical_comparisons_reused": 10901,
        "historical_audit_rerun": False, "historical_files_modified": [],
        "no_background_workers_started": True, "diagnostic_children_exited": True,
    })
    # Every new evidence byte, including final receipt, is budgeted before ZIP write.
    added = sum(f.stat().st_size for f in D.iterdir() if f.is_file()) + 3 * 8192
    assert added <= evidence_reservation
    resources = dict(old)
    resources.update({
        "continuation": 1, "continuation_charge_seconds": charge,
        "package_charge_seconds": old["package_charge_seconds"] + charge,
        "package_remaining_seconds": old["package_remaining_seconds"] - charge,
        "implementation_aggregate_charged_seconds": old["implementation_aggregate_charged_seconds"] + charge,
        "implementation_remaining_seconds": old["implementation_remaining_seconds"] - charge,
        "outside_KYC_remaining_seconds": old["outside_KYC_remaining_seconds"] - charge,
        "new_evidence_bytes": old["new_evidence_bytes"] + added,
        "continuation_evidence_bytes": added,
        "cumulative_evidence_bytes": old["cumulative_evidence_bytes"] + added,
        "shared_headroom_bytes": old["shared_headroom_bytes"] - added,
        "new_artifact_bytes": old["new_artifact_bytes"],
        "continuation_archive_bytes": 0,
        "memory_admission": "failed again; continuation-1/memory-admission.json",
        "audit_seconds": old["audit_seconds"],
        "audit_seconds_note": "retained earlier measurement, no repeated audit",
    })
    closure = {
        "package": "LIGETRON-FULL-PATH-ENGINEERING-1", "continuation": 1,
        "complete": False, "outcome": "failed dual-environment memory gate",
        "preservation_complete": True, "preservation_method": "selected-file continuation, prior full audit reused",
        "prior_validation_sha256": sha((OLD / "validation-closure.json").read_bytes()),
        "all_E01_E40": "unrun", "actual_adapter": "none selected",
        "partial_overlay": "unchanged, uncompiled and unvalidated",
        "source_overlay_sha256": close["source_overlay_sha256"],
        "builds_consumed": 0, "invocations_consumed": 0, "proofs_consumed": 0,
        "no_new_workers_remaining": True,
        "archive_verification": "exact final identity and verification receipt in external archive-result.json",
        "private_verification": "fail-closed", "private_proving_and_isolation": "paused",
    }
    for f in D.iterdir():
        n = f.relative_to(P).as_posix()
        payload[n], origins[n] = f.read_bytes(), str(f)
    # Include the prior archive verification receipt too, without rewriting it.
    receipt = OLD / "archive-result.json"
    payload[receipt.relative_to(P).as_posix()] = receipt.read_bytes()
    origins[receipt.relative_to(P).as_posix()] = str(receipt)
    rn = (D / "resource-closure.json").relative_to(P).as_posix()
    cn = (D / "validation-closure.json").relative_to(P).as_posix()
    origins[rn], origins[cn] = str(P / rn), str(P / cn)
    payload["README.txt"] = (
        "LIGETRON-FULL-PATH-ENGINEERING-1: continuation 1 memory stop\n\n"
        "Read docs/data/ligetron_full_path_engineering_1/continuation-1/report.md,\n"
        "memory-admission.json, memory-consumers.json and the new resource/validation\n"
        "closures first. The earlier report, patch chain, commands, all E01-E40 unrun\n"
        "outcomes, audit evidence and preflight ZIP remain included unchanged.\n"
        "No executable or proof was generated and no adapter was selected.\n\n"
        "Patch order: base Ligetron 4b1cdef1bfdf4497fb3e38170db4541fba3f6c12;\n"
        "randomness overlay 043ee96fbae51b9416b3435be7e7ad27cfc076ddb7790e14f14be6ea09c0dc3c;\n"
        "domain/mask overlay 31f1515e498182664f51e92d91925416c0063d5b117494948e4a52dc6fcc5723;\n"
        "partial prepared-overlay.patch 59f3c8e415e2899730e4d4792a980b4c0a9914036d1201d759e4c3f15b2d7654.\n"
        "The last overlay is uncompiled and incomplete. Do not execute archived code.\n"
        "The included handover/ligetron_full_path_preflight_v1.zip retains dependency\n"
        "provenance, original source snapshots and completed component evidence.\n"
        "No native-path, security, privacy or complete-authentication result is claimed.\n"
        "MANIFEST.json covers every payload and this guide, excluding itself.\n"
        "The final archive hash is reported externally to avoid a self-hash cycle.\n"
    ).encode()
    origins["README.txt"] = "generated reader guide"

    def pack():
        payload[rn], payload[cn] = fixed(resources), fixed(closure)
        man = {"files": [{"archive_path": n, "original_path": origins[n],
                          "bytes": len(b), "sha256": sha(b)}
                         for n, b in sorted(payload.items())]}
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as z:
            for n, b in sorted({**payload, "MANIFEST.json": encoded(man)}.items()):
                i = zipfile.ZipInfo(n, (2026, 10, 3, 0, 0, 0))
                i.external_attr = (stat.S_IFREG | 0o644) << 16
                i.compress_type = zipfile.ZIP_STORED if n in {rn, cn, "MANIFEST.json"} else zipfile.ZIP_DEFLATED
                z.writestr(i, b, compresslevel=6)
        return stream.getvalue()

    preliminary = pack()
    resources["continuation_archive_bytes"] = len(preliminary)
    resources["new_artifact_bytes"] += len(preliminary)
    resources["cumulative_artifact_bytes"] += len(preliminary)
    final = pack()
    assert len(final) == len(preliminary) <= artifact_reservation
    assert len(final) <= 268435456
    (P / rn).write_bytes(payload[rn])
    (P / cn).write_bytes(payload[cn])
    with ARCHIVE.open("xb") as f:
        f.write(final)
    with zipfile.ZipFile(ARCHIVE) as z:
        names = z.namelist()
        assert len(names) == len(set(names)) and set(names) == set(payload) | {"MANIFEST.json"}
        assert z.testzip() is None
        for n in names:
            q = PurePosixPath(n)
            assert not q.is_absolute() and ".." not in q.parts and "\\" not in n
            assert not stat.S_ISLNK(z.getinfo(n).external_attr >> 16)
        for row in json.loads(z.read("MANIFEST.json"))["files"]:
            b = z.read(row["archive_path"])
            assert len(b) == row["bytes"] and sha(b) == row["sha256"]
            if row["original_path"].startswith(str(P)):
                assert Path(row["original_path"]).read_bytes() == b
    assert PREVIOUS.read_bytes() == old_bytes
    elapsed = time.monotonic() - start
    assert elapsed < 10  # Included within the conservative 20-second charge.
    receipt = {"archive": str(ARCHIVE), "bytes": len(final), "sha256": sha(final),
               "members": len(payload) + 1, "verified": True,
               "archive_crc_paths_unique_members_manifest_payloads": "passed",
               "previous_archive_unchanged": True, "measured_packaging_seconds": elapsed,
               "packaging_peak_RSS_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
               "resource_closure_sha256": sha((P / rn).read_bytes()),
               "validation_closure_sha256": sha((P / cn).read_bytes())}
    (D / "archive-result.json").write_bytes(fixed(receipt))
    assert {f.name for f in D.iterdir()} == {"package.py", "opening.json", "memory-admission.json",
        "memory-consumers.json", "ledger.json", "report.md", "preservation.json",
        "resource-closure.json", "validation-closure.json", "archive-result.json"}
    assert sum(f.stat().st_size for f in D.iterdir()) == added
    print(json.dumps(receipt, indent=2))
    print(json.dumps({k: resources[k] for k in ["continuation_charge_seconds", "package_remaining_seconds",
        "implementation_remaining_seconds", "outside_KYC_remaining_seconds", "KYC_remaining_seconds_unchanged",
        "continuation_evidence_bytes", "cumulative_evidence_bytes", "cumulative_artifact_bytes"]}, indent=2))


if __name__ == "__main__":
    main()
