"""Package retained bytes only; no backend execution or new security analysis."""

import hashlib
import json
import lzma
import sys
import tarfile
from pathlib import Path

P = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(P))
sys.path.insert(0, str(Path(__file__).parent))
import run as guard  # noqa: E402

from experiments.kyc_manager_incremental_storage_1 import preservation as old  # noqa: E402
from scripts.preservation_audit import digest_file  # noqa: E402

D = guard.D
B = P / "docs/data/oct31_binius64_replacement_decision_1"
G = P / "docs/data/oct31_binius64_g0_1"
ARCHIVE = D / "binius64-g0-handover-v1.tar.xz"


def rel(path):
    return path.relative_to(P).as_posix()


def main():
    assert not ARCHIVE.exists(), "never replace retained archive"
    scope = old.scope()
    expected = scope["frozen_package_inputs"]
    for base in (B, G):
        manifest = base / "manifest.json"
        assert digest_file(manifest) == expected[rel(manifest)]
        for name, seal in guard.read(manifest)["sha256"].items():
            # Reports can have later approved appendices; selected sources cannot.
            if "/sources/" in name:
                assert digest_file(P / name) == seal, name
    selected = {}

    def add(path, category):
        path = P / path
        assert path.is_file() and not path.is_symlink(), str(path)
        assert path.stat().st_size <= guard.POLICY["ordinary_file_bytes"]
        selected[rel(path)] = category

    for name in (
        "oct31_binius64_g0.md",
        "oct31_binius64_replacement_decision.md",
        "implementation_spec.md",
        "stage2_relations.md",
        "oct31_auth_relation_integration.md",
        "kyc_manager_incremental_storage.md",
        "kyc_issuer_incremental_storage.md",
        "kyc_testbed_completion.md",
    ):
        add("docs/" + name, "retained report or relation specification")
    for name in (
        "decision.json",
        "source-acquisition.json",
        "source-acquisition-2.json",
        "manifest.json",
        "validation-closure.json",
    ):
        add(rel(G / name), "G0 decision/provenance")
    for name in (
        "source-index.json",
        "dependency-requirements.json",
        "decision.json",
        "manifest.json",
        "validation-closure.json",
    ):
        add(rel(B / name), "pinned identity/provenance")
    for base in (B, G):
        for path in sorted((base / "sources").iterdir()):
            if path.name != "fix-ancestry.json":
                add(rel(path), "retained native source/metadata/Blueprint")
    for name in (
        "docs/data/implementation_consolidation_1/handover.md",
        "docs/data/oct31_auth_relation_integration_1/relation-notes.md",
        "configs/suite.json",
        "configs/validation_profiles.json",
    ):
        add(name, "complete reference relation/boundary")
    modules = (
        "__init__",
        "relations",
        "binding",
        "codec",
        "credentials",
        "merkle",
        "parameters",
        "public_checks",
        "schema",
        "statements",
        "witnesses",
        "policy",
        "bounded_mldsa",
        "hash_domain",
        "backend",
        "expiry",
    )
    for name in modules:
        add("src/pqdid/" + name + ".py", "reference predicate and canonical contracts")
    for root in (
        "kyc_manager_incremental_storage_1",
        "kyc_issuer_incremental_storage_1",
        "kyc_testbed_execution_1",
    ):
        for name in (
            "manifest.json",
            "validation-closure.json",
            "resource-closure.json",
            "outcomes.json",
            "coverage.json",
        ):
            add("docs/data/" + root + "/" + name, "current KYC comparison identities/results")
    for path in (
        "docs/data/kyc_manager_incremental_storage_1/measurements-manager-v2.json",
        "docs/data/kyc_issuer_incremental_storage_1/measurements-v2.json",
        "docs/data/kyc_testbed_execution_1/measurements.json",
    ):
        add(path, "separate retained baseline series")

    index = guard.read(B / "source-index.json")
    tree = guard.read(B / "sources/implementation-tree.json")
    commit = guard.read(B / "sources/implementation-commit.json")
    assert commit["sha"] == index["implementation_commit"]
    assert commit["commit"]["tree"]["sha"] == tree["sha"] == index["implementation_tree"]
    source_rows = []
    for base, records in (
        (B, index["sources"]),
        (G, guard.read(G / "source-acquisition.json")["sources"]),
        (G, guard.read(G / "source-acquisition-2.json")["sources"]),
    ):
        for row in records:
            file = base / "sources" / row["path"]
            if rel(file) not in selected:
                continue
            assert file.stat().st_size == row["bytes"] and digest_file(file) == row["sha256"]
            if "git_blob" in row:
                data = file.read_bytes()
                blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
                assert blob == row["git_blob"]
                match = next(x for x in tree["tree"] if x["path"] == row["upstream_path"])
                assert match["sha"] == blob and match["type"] == "blob"
            source_rows.append(dict(row, retained_path=rel(file)))
    guard.write(
        D / "source-map.json",
        dict(
            implementation_commit=index["implementation_commit"],
            implementation_tree=tree["sha"],
            blueprint_sha256=index["blueprint_sha256"],
            sources=source_rows,
            provenance=(
                "Existing source indices and Git-tree blob identities; no source acquisition"
            ),
        ),
    )
    retained_native = {row["upstream_path"] for row in source_rows if "upstream_path" in row}
    missing = [
        row for row in tree["tree"] if row["type"] == "blob" and row["path"] not in retained_native
    ]
    (D / "missing-native-files.tsv").write_text(
        "upstream_path\tgit_blob\tbytes\n"
        + "".join(f"{row['path']}\t{row['sha']}\t{row.get('size', 'unknown')}\n" for row in missing)
    )
    missing_summary = dict(
        cargo_lock=(
            "Absent from retained pinned tree; no resolved transitive lock or crate archives"
        ),
        native_snapshot=(
            "Selected text files only; no complete checkout, compiled backend "
            "or runtime dependencies"
        ),
        native_not_included=len(missing),
        full_native_inventory="missing-native-files.tsv",
        omitted_retained_metadata=[
            dict(
                path=rel(B / "sources/fix-ancestry.json"),
                sha256=digest_file(B / "sources/fix-ancestry.json"),
                reason=(
                    "Large ancestry response omitted; pin, correction record and "
                    "prior findings included"
                ),
            )
        ],
        missing_construction=[
            "No justified source overlay or cross-commitment terminal-key equality proof",
            "No native-basis support/rank certificate or joint-view simulator",
            "No completed IntMul auxiliary-oracle privacy correspondence",
            "No standalone executed minimal privacy example; algebra is in complete G0 report",
        ],
        blueprint=(
            "Retained PDF and extracted text included; reproducible "
            "PDF-to-website-source build not established"
        ),
        dependency_reference="repo/" + rel(B / "dependency-requirements.json"),
        permission=(
            "Packaging only. Missing files were not acquired; copied tests "
            "must not be interpreted as executed."
        ),
    )
    guard.write(D / "missing-evidence.json", missing_summary)

    previous = guard.read(P / "docs/data/kyc_manager_incremental_storage_1/resource-closure.json")
    baseline_roots = (
        "experiments/kyc_manager_incremental_storage_1",
        "experiments/kyc_issuer_incremental_storage_1",
        "experiments/kyc_testbed_execution_1",
    )
    baseline_seals = {}
    for root in (
        "kyc_manager_incremental_storage_1",
        "kyc_issuer_incremental_storage_1",
        "kyc_testbed_execution_1",
    ):
        base = P / "docs/data" / root
        for name in ("manifest.json", "validation-closure.json", "resource-closure.json"):
            baseline_seals[rel(base / name)] = digest_file(base / name)
        for path, seal in guard.read(base / "manifest.json")["sha256"].items():
            if any(path.startswith(prefix + "/") for prefix in baseline_roots):
                assert digest_file(P / path) == seal
                baseline_seals[path] = seal
    baseline_seals["src/pqdid/holder_wallet.py"] = digest_file(P / "src/pqdid/holder_wallet.py")
    baseline_seals["docs/data/oct31_auth_relation_integration_1/comparison-point.json"] = (
        digest_file(P / "docs/data/oct31_auth_relation_integration_1/comparison-point.json")
    )
    guard.write(
        D / "comparison-point.json",
        dict(
            version="KYC-BASELINE-ISSUER2-MANAGER2-WALLET-PAGED-1",
            status=(
                "Current isolated KYC baseline comparison point; no superseded evidence modified"
            ),
            sha256=baseline_seals,
            largest_update_history=8,
            encoding_limit=65536,
            series=dict(v1=276, subsequent=19, issuer_v2=3, manager_v2=4),
            retained_separately=True,
            invocations=previous["cumulative_invocations"],
            measurements=(
                "Genuine disclosed ML-DSA baseline; no private-proof or "
                "privacy-overhead measurements"
            ),
            limitations=(
                "Standards interoperability, private authentication and "
                "production security remain open"
            ),
        ),
    )

    for name in (
        "README.md",
        "source-map.json",
        "missing-native-files.tsv",
        "missing-evidence.json",
        "comparison-point.json",
    ):
        assert (D / name).is_file()
    entries = [
        dict(
            archive_path="repo/" + name,
            original_path=name,
            bytes=(P / name).stat().st_size,
            sha256=digest_file(P / name),
            category=category,
        )
        for name, category in sorted(selected.items())
    ]
    for name in (
        "README.md",
        "source-map.json",
        "missing-native-files.tsv",
        "missing-evidence.json",
        "comparison-point.json",
    ):
        entries.append(
            dict(
                archive_path=name,
                original_path=rel(D / name),
                bytes=(D / name).stat().st_size,
                sha256=digest_file(D / name),
                category="Packaging index; no new analysis",
            )
        )
    assert len({x["archive_path"] for x in entries}) == len(entries)
    inventory = dict(
        format=1,
        files=entries,
        original_bytes=sum(x["bytes"] for x in entries),
        inputs_unchanged=True,
        complete_build_checkout=False,
    )
    guard.write(D / "file-list.json", inventory)
    (D / "SHA256SUMS").write_text("".join(f"{x['sha256']}  {x['archive_path']}\n" for x in entries))
    # Direct streaming from retained files: no duplicate unpacked source/build tree.
    with lzma.open(ARCHIVE, "xb", preset=3) as output:
        with tarfile.open(fileobj=output, mode="w|", format=tarfile.PAX_FORMAT) as tar:
            for row in entries + [
                dict(archive_path=n, original_path=rel(D / n))
                for n in ("file-list.json", "SHA256SUMS")
            ]:
                path = P / row["original_path"]
                info = tarfile.TarInfo(row["archive_path"])
                info.size = path.stat().st_size
                info.mode = 0o644
                info.mtime = 0
                with path.open("rb") as inp:
                    tar.addfile(info, inp)
                assert ARCHIVE.stat().st_size <= guard.POLICY["ordinary_file_bytes"]
    assert ARCHIVE.stat().st_size <= guard.POLICY["ordinary_file_bytes"]
    expected_members = {x["archive_path"]: x["sha256"] for x in entries}
    expected_members.update({n: digest_file(D / n) for n in ("file-list.json", "SHA256SUMS")})
    seen = set()
    with tarfile.open(ARCHIVE, "r|xz") as tar:
        for member in tar:
            assert member.isfile() and member.name in expected_members and member.name not in seen
            assert member.size <= guard.POLICY["ordinary_file_bytes"]
            stream = tar.extractfile(member)
            assert stream is not None
            h = hashlib.sha256()
            while block := stream.read(65536):
                h.update(block)
            assert h.hexdigest() == expected_members[member.name], member.name
            seen.add(member.name)
    assert seen == set(expected_members)
    for row in entries:
        assert digest_file(P / row["original_path"]) == row["sha256"]
    archive = dict(
        path=rel(ARCHIVE),
        absolute_path=str(ARCHIVE),
        bytes=ARCHIVE.stat().st_size,
        sha256=digest_file(ARCHIVE),
        members=len(seen),
        readback_passed=True,
        original_inputs_unchanged=True,
        compression="tar.xz preset 3; direct stream",
        accounting="Evidence, ordinary per-file cap 1 MiB; not a build artifact",
    )
    guard.write(D / "archive.json", archive)
    (D / "archive.sha256").write_text(f"{archive['sha256']}  {ARCHIVE.name}\n")
    guard.write(
        D / "preflight.json",
        dict(
            passed=True,
            programme_complete=False,
            packaging_only=True,
            archive=archive,
            source_pins_verified=True,
        ),
    )
    print(json.dumps(archive))


if __name__ == "__main__":
    main()
