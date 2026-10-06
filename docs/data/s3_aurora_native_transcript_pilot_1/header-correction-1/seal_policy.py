"""Exact report allowlist; immutable full hashes and authenticated report snapshots."""

import hashlib
import json
from pathlib import Path

REPORTS = frozenset(
    {
        "docs/spec_issues.md",
        "docs/status.md",
        "docs/traceability.md",
        "docs/stage3_aurora_native_transcript_pilot.md",
        "docs/stage3_aurora_compiler_compatibility_contract.md",
    }
)
LATEST = "b654553f67533c37c4906c6d73e8fe891677048fb978ac52e03dfa909ed805ee"
PREFIXES = "448e26c28ed0703a52e5430744331ebc71d0d61cad56479aada6f14c8625323b"
OLD_SEAL = "3dc73504668e70fc011e3ddd97d02fabdf930fc780ac17005730fbd015cb26cf"
LIMIT = 1048576


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def small(path):
    with Path(path).open("rb") as stream:
        value = stream.read(LIMIT + 1)
    require(len(value) <= LIMIT, "input ceiling")
    return value


def manifest(raw, trusted_hash):
    require(type(raw) is bytes and len(raw) <= LIMIT, "missing/oversized seal")
    require(type(trusted_hash) is str and sha(raw) == trusted_hash, "untrusted/stale seal")
    value = json.loads(raw)
    require(type(value) is dict and type(value.get("sha256")) is dict, "missing seal entries")
    return value["sha256"]


def verify_file(path, name, immutable_hash, reports, latest_raw, trusted_hash):
    data = small(path)
    if name not in REPORTS:
        require(sha(data) == immutable_hash, "immutable hash mismatch")
        return
    latest = manifest(latest_raw, trusted_hash)
    require(name in latest and name in reports, "missing report seal/length")
    spec = reports[name]
    prefix, final = spec["prefix_bytes"], spec["final_bytes"]
    require(type(prefix) is int and type(final) is int, "invalid length type")
    require(0 <= prefix <= final <= LIMIT, "invalid coverage bounds")
    require(len(data) == final, "final length mismatch")
    require(spec["prefix_sha256"] == immutable_hash, "untrusted historical prefix")
    require(sha(data[:prefix]) == immutable_hash, "historical prefix mismatch")
    require(spec["full_sha256"] == latest[name], "untrusted full report hash")
    require(sha(data) == latest[name], "complete report mismatch")


def anchors(project):
    root = project / "docs/data/s3_aurora_native_transcript_pilot_1"
    latest_raw = small(root / "seal-repair-1/manifest.json")
    latest = manifest(latest_raw, LATEST)
    old_raw = small(root / "build-4-admission-1/manifest.json")
    old = manifest(old_raw, OLD_SEAL)
    prefix_raw = small(root / "build-4-resumption-1/prefixes.json")
    require(sha(prefix_raw) == PREFIXES, "untrusted prefix lengths")
    prefixes = json.loads(prefix_raw)
    require(set(prefixes) == REPORTS, "report allowlist mismatch")
    return root, latest_raw, latest, old, prefixes


def snapshot(project):
    _, latest_raw, latest, old, prefixes = anchors(project)
    specs = {}
    for name in sorted(REPORTS):
        data = small(project / name)
        # The retained full hash authenticates every byte BEFORE length is recorded.
        # No new expected digest is derived from current workspace content.
        require(sha(data) == latest[name], "not the trusted completed snapshot")
        specs[name] = {
            "prefix_bytes": prefixes[name]["bytes"],
            "prefix_sha256": prefixes[name]["sha256"],
            "final_bytes": len(data),
            "full_sha256": latest[name],
        }
        verify_file(project / name, name, old[name], specs, latest_raw, LATEST)
    return {
        "trusted_latest_manifest_sha256": LATEST,
        "trusted_prefix_metadata_sha256": PREFIXES,
        "length_provenance": "Length of bytes first authenticated by retained full-file seal",
        "reports": specs,
    }


def verify_repository(project, snapshot_record):
    root, raw, latest, old, prefixes = anchors(project)
    require(snapshot_record["trusted_latest_manifest_sha256"] == LATEST, "snapshot anchor")
    require(set(snapshot_record["reports"]) == REPORTS, "snapshot allowlist")
    for name, spec in snapshot_record["reports"].items():
        require(spec["prefix_bytes"] == prefixes[name]["bytes"], "prefix length changed")
        require(spec["prefix_sha256"] == prefixes[name]["sha256"], "prefix hash changed")
        verify_file(project / name, name, old[name], snapshot_record["reports"], raw, LATEST)
    # Preserve all original immutable checks, including the pinned checked-inputs file.
    old_root = root / "build-4-admission-1"
    checked_name = str((old_root / "checked-inputs.json").relative_to(project))
    checked = small(project / checked_name)
    require(sha(checked) == old[checked_name], "untrusted original input inventory")
    for values in (old, json.loads(checked)["sha256"]):
        for name, expected in values.items():
            verify_file(project / name, name, expected, snapshot_record["reports"], raw, LATEST)
    # Also verify the latest completed admission evidence, not just its reports.
    checked_name = str((root / "seal-repair-1/checked-inputs.json").relative_to(project))
    checked = small(project / checked_name)
    require(sha(checked) == latest[checked_name], "untrusted latest input inventory")
    for values in (latest, json.loads(checked)["sha256"]):
        for name, expected in values.items():
            require(sha(small(project / name)) == expected, "latest sealed input mismatch: " + name)
    return True
