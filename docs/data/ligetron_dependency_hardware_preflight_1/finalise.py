"""Selected-file preparation closure and archive verification; no experiment execution."""

import hashlib
import io
import json
import math
import resource
import stat
import time
import zipfile
from pathlib import Path, PurePosixPath

D = Path(__file__).resolve().parent
P = D.parents[2]
start = time.monotonic()
opening = json.loads((D / "opening.json").read_bytes())
ledger = json.loads((D / "ledger.json").read_bytes())
prior = opening["prior"]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe(name):
    p = PurePosixPath(name)
    return (not p.is_absolute() and ".." not in p.parts and "\\" not in name
            and str(p) == name and not name.endswith("/"))


def padded(value, length):
    b = (json.dumps(value, indent=2) + "\n").encode()
    assert len(b) <= length
    return b + b" " * (length - len(b))


for name, expected in opening["protected"].items():
    assert digest((P / name).read_bytes()) == expected, name
assert digest((P / opening["prior_accounting"]).read_bytes()) == opening["prior_accounting_sha256"]
for row in ledger["source_inspection"]:
    if row["status"] == "retained-text-metadata":
        b = (P / row["path"]).read_bytes()
        assert len(b) == row["bytes"] and digest(b) == row["sha256"]

incoming = P / opening["incoming_reconciliation"]["path"]
incoming_bytes = incoming.read_bytes()
assert len(incoming_bytes) == 63229
assert digest(incoming_bytes) == opening["incoming_reconciliation"]["sha256"]
with zipfile.ZipFile(io.BytesIO(incoming_bytes)) as z:
    names = z.namelist()
    assert len(set(names)) == len(names) and all(safe(n) for n in names)
    assert z.testzip() is None
    for info in z.infolist():
        assert not stat.S_ISLNK(info.external_attr >> 16)
    manifest = json.loads(z.read("MANIFEST.json"))
    assert set(names) == {r["path"] for r in manifest["files"]} | {"MANIFEST.json"}
    for r in manifest["files"]:
        b = z.read(r["path"])
        assert len(b) == r["bytes"] and digest(b) == r["sha256"]
    assert z.read("received_ligetron_domain_mask_review_v1.zip") == (P / "handover/ligetron_domain_mask_review_v1.zip").read_bytes()
    external = {"incoming_review/" + n: z.read(n) for n in
                ("REVIEW.md", "CODEX_PROMPT.txt", "README.md", "MANIFEST.json", "verification.json")}

selected = {incoming}
for f in D.rglob("*"):
    if f.is_file():
        assert f.name not in {"resource-closure.json", "archive-result.json"}, "Do not overwrite closure"
        selected.add(f)
for name in ("AGENTS.md", "docs/ligetron_domain_mask_correction.md",
             "docs/ligetron_correction_and_admission.md", "docs/kyc_testbed_delivery.md"):
    selected.add(P / name)
for package in ("ligetron_domain_mask_correction_1", "ligetron_correction_admission_1"):
    base = P / "docs/data" / package
    for name in ("reviewed-overlay.patch", "build-input-seal.json", "expectations.json",
                 "expectation-seal.json", "outcomes.json", "validation-closure.json",
                 "resource-closure.json", "source-acquisition.json"):
        assert (base / name).is_file(), str(base / name)
        selected.add(base / name)
    selected.update((base / "cases").glob("*.json"))
    exp = P / "experiments" / package
    for sub in ("base", "sources", "overlay", "native"):
        if (exp / sub).exists():
            selected.update(f for f in (exp / sub).rglob("*") if f.is_file())
    harness_names = (("native.cpp", "expectations.py", "cases.py")
                     if package == "ligetron_domain_mask_correction_1"
                     else ("vectors.py", "cases.py"))
    for name in harness_names:
        assert (exp / name).is_file()
        selected.add(exp / name)
for name in ("component-contract.json", "references.json", "case-driver-amendment.json"):
    selected.add(P / "docs/data/ligetron_domain_mask_correction_1" / name)
for name in ("upstream-commit.json", "upstream-tree.json", "source-provenance.json",
             "additional-source.json", "header-closure.json"):
    selected.add(P / "docs/data/ligetron_correction_admission_1" / name)

payloads = {}
origins = {}
for f in sorted(selected):
    assert f.is_file() and not f.is_symlink(), str(f)
    name = f.relative_to(P).as_posix()
    assert safe(name)
    payloads[name] = f.read_bytes()
    origins[name] = str(f)
for name, b in external.items():
    payloads[name] = b
    origins[name] = str(incoming) + "!" + name.split("/", 1)[1]

measured = sum(r["seconds"] for key in ("diagnostics", "source_inspection") for r in ledger[key])
charge = 40 + math.ceil(measured) + 2
assert charge <= 90
assert prior["outside_KYC_remaining_seconds"] >= charge
closure_path = D / "resource-closure.json"
closure_name = closure_path.relative_to(P).as_posix()
evidence_added = 63229 + sum(f.stat().st_size for f in D.rglob("*") if f.is_file()) + 8192 + 4096
assert evidence_added < 524288
assert prior["shared_evidence_headroom_bytes"] - evidence_added >= 2097152
assert prior["cumulative_evidence_bytes"] + evidence_added <= 41943040
closure = {
    "package": "LIGETRON-DEPENDENCY-HARDWARE-PREFLIGHT-1",
    "status": "preparation complete; all execution amendments inactive",
    "scope": "installed diagnostics, pinned text metadata, source-derived proposal, selected-file and archive verification only",
    "conservative_operator_seconds": 40,
    "measured_diagnostics_and_metadata_seconds": measured,
    "rounded_diagnostics_and_metadata_charge_seconds": math.ceil(measured),
    "conservative_archive_finalisation_charge_seconds": 2,
    "package_charge_seconds": charge,
    "package_cap_seconds": 90,
    "implementation_ceiling_unchanged": 6674,
    "implementation_aggregate_charged_seconds": prior["implementation_aggregate_charged_seconds"] + charge,
    "implementation_remaining_seconds": prior["implementation_remaining_seconds"] - charge,
    "outside_KYC_remaining_seconds": prior["outside_KYC_remaining_seconds"] - charge,
    "KYC_remaining_seconds_unchanged": prior["KYC_remaining_seconds_unchanged"],
    "KYC_protected_reserve_seconds_unchanged": 300,
    "analysis_remaining_seconds_unchanged": 11.510943178986167,
    "isolation_remaining_seconds_unchanged": 250.22,
    "cumulative_invocations_unchanged": 1250,
    "invocation_ceiling_unchanged": 1265,
    "reserved_unused_slots_unchanged": 15,
    "builds_unchanged": "13/13",
    "proof_ledger_unchanged": {"used": 2, "unused": 1},
    "new_functional_tests_builds_proofs_GPU_workloads": 0,
    "memory_ceiling_bytes": 268435456,
    "memory_observation": "per-diagnostic self RSS in hardware records; packaging peak in archive-result.json; not an aggregate Windows process-tree peak measurement",
    "acquisition_memory_historical_observation_unresolved": True,
    "incoming_archive_charged_once_bytes": 63229,
    "new_evidence_bytes_including_padded_closures": evidence_added,
    "package_evidence_ceiling_bytes": 524288,
    "cumulative_evidence_bytes": prior["cumulative_evidence_bytes"] + evidence_added,
    "cumulative_evidence_ceiling_bytes_unchanged": 41943040,
    "shared_evidence_headroom_bytes": prior["shared_evidence_headroom_bytes"] - evidence_added,
    "shared_completion_reserve_bytes_unchanged": 2097152,
    "archive_artifact_allocation_bytes": 1048576,
    "cumulative_artifact_ceiling_bytes_unchanged": 134217728,
    "archive_bytes": 0,
    "cumulative_artifact_bytes": prior["cumulative_artifact_bytes"],
    "temporary_disk_bytes": 0,
    "archive_identity_receipt": "docs/data/ligetron_dependency_hardware_preflight_1/archive-result.json",
    "preservation": "selected protected files/patches and source metadata checked; archive full member readback; no full historical audit or functional rerun",
    "failures_retained": ["sandbox NVML and Windows interoperability blocked; normal approved host inventory succeeded", "vulkaninfo not installed", "Ubuntu WABT official file-list network lookup failed; package contents not claimed"],
    "pauses": "private verification fail-closed, private proving/isolation paused, closed components unchanged"
}
origins[closure_name] = str(closure_path)
readme = """LIGETRON dependency/hardware preflight and inactive engineering proposal

Start with docs/data/ligetron_dependency_hardware_preflight_1/PROPOSAL.md, then
RUNBOOK.md, dependency-lock.proposed.json, package-closure.json, hardware.json,
hardware-host.json, ledger.json and resource-closure.json in that same directory.
The full archive SHA-256 is supplied in the chat and external archive-result.json;
a ZIP cannot contain its own final cryptographic digest.

Incoming external review: incoming_review/REVIEW.md and CODEX_PROMPT.txt. The latest
user instruction separates engineering feasibility from cryptographic admission.
The original received ZIP is also included unchanged; its embedded return ZIP
matches our earlier handover. Reconciliation charges its63229 bytes only once.

Patch order: pinned Ligero4b1cdef1bfdf4497fb3e38170db4541fba3f6c12, randomness
overlay under docs/data/ligetron_correction_admission_1, then domain/mask overlay
under docs/data/ligetron_domain_mask_correction_1. Both patch hashes are preserved.
No proposed third integration overlay has yet been implemented.

Prior reports, component contract/references, original/overlaid source snapshots,
harnesses/expectations, all35+32 individual outcome records and closures are
included for review, not execution. No binaries or whole build directories.
MANIFEST.json records every payload's original location, size and SHA-256;
README is indexed, while MANIFEST intentionally does not hash itself.

Missing/unestablished evidence: complete new Dawn/WABT checkouts and package
payloads; native build compatibility; usable Dawn adapter; GPU/shader/full-VM
execution; corrected statement/parser third overlay; full-sized complete-path
resource measurement; exact updated primary theorem/Appendix C; complete degree,
masking, commitment/compiler, public-expansion, extraction and quantum arguments.
Existing Python/CPU component success establishes none of those native/security
claims. The known67 outcomes were reused, not rerun.

No private-proof admission, manuscript/profile change or resource amendment is
activated. KYC302 historical observations/four smoke observations remain preserved;
their datasets are not duplicated into this backend review. No complete historic
preservation audit was repeated. Private verification remains fail-closed,
proving/isolation paused, proof ledger2 used/1 unused. Do not execute archived code.
""".encode()
payloads["README.txt"] = readme
origins["README.txt"] = "generated reader guide for this authorised handover"


def make_archive():
    payloads[closure_name] = padded(closure, 8192)
    manifest = {"format": "selected-payload-sha256-v1", "files": [
        {"original_path": origins[n], "archive_path": n, "bytes": len(b), "sha256": digest(b)}
        for n, b in sorted(payloads.items())]}
    mb = (json.dumps(manifest, indent=2) + "\n").encode()
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        for n, b in sorted({**payloads, "MANIFEST.json": mb}.items()):
            zi = zipfile.ZipInfo(n, (2026, 10, 3, 0, 0, 0))
            zi.external_attr = (stat.S_IFREG | 0o644) << 16
            zi.compress_type = zipfile.ZIP_STORED if n in (closure_name, "MANIFEST.json") else zipfile.ZIP_DEFLATED
            z.writestr(zi, b, compresslevel=6)
    return bio.getvalue()


archive = make_archive()
for _ in range(3):
    closure["archive_bytes"] = len(archive)
    closure["cumulative_artifact_bytes"] = prior["cumulative_artifact_bytes"] + len(archive)
    updated = make_archive()
    if len(updated) == len(archive):
        archive = updated
        break
    archive = updated
else:
    raise RuntimeError("Archive accounting size did not stabilise")
assert len(archive) <= 1048576
assert closure["cumulative_artifact_bytes"] <= 134217728
out = P / "handover/ligetron_full_path_preflight_v1.zip"
assert not out.exists(), "Preserve existing versions"
closure_path.write_bytes(payloads[closure_name])
out.write_bytes(archive)
with zipfile.ZipFile(out) as z:
    names = z.namelist()
    assert len(names) == len(set(names)) and all(safe(n) for n in names)
    assert z.testzip() is None
    assert set(names) == set(payloads) | {"MANIFEST.json"}
    m = json.loads(z.read("MANIFEST.json"))
    for r in m["files"]:
        b = z.read(r["archive_path"])
        assert b == payloads[r["archive_path"]]
        assert len(b) == r["bytes"] and digest(b) == r["sha256"]
        original = origins[r["archive_path"]]
        if original.startswith(str(P)) and "!" not in original:
            assert Path(original).read_bytes() == b
for name, expected in opening["protected"].items():
    assert digest((P / name).read_bytes()) == expected
elapsed = time.monotonic() - start
assert elapsed <= 2, "Conservative finalisation charge exceeded; retain outcome and report"
receipt = {"archive": str(out), "bytes": len(archive), "sha256": digest(archive),
           "members": len(payloads) + 1, "verification": "pass: CRC, safe unique regular paths, exact member set, every payload/source/manifest, immutable selected inputs",
           "measured_selected_file_and_archive_seconds": elapsed,
           "conservative_archive_seconds_charged": 2,
           "peak_packaging_process_RSS_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
           "incoming_review_manifest": "5 payloads, CRC, safe names and returned handover identity verified",
           "no_historical_audit_functional_tests_builds_or_proofs": True,
           "resource_closure": str(closure_path),
           "package_charge_seconds": charge,
           "implementation_remaining_seconds": closure["implementation_remaining_seconds"],
           "outside_KYC_remaining_seconds": closure["outside_KYC_remaining_seconds"],
           "KYC_remaining_seconds_unchanged": closure["KYC_remaining_seconds_unchanged"],
           "new_evidence_bytes": evidence_added,
           "cumulative_evidence_bytes": closure["cumulative_evidence_bytes"],
           "shared_headroom_bytes": closure["shared_evidence_headroom_bytes"],
           "cumulative_artifact_bytes": closure["cumulative_artifact_bytes"]}
(D / "archive-result.json").write_bytes(padded(receipt, 4096))
assert 63229 + sum(f.stat().st_size for f in D.rglob("*") if f.is_file()) == evidence_added
print(json.dumps(receipt, indent=2))
