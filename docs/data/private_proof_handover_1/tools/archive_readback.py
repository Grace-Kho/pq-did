"""Verify retained handover bytes; only repackage an interrupted archive."""

import hashlib
import json
import lzma
import sys
import tarfile
from pathlib import Path, PurePosixPath

P = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(P))
sys.path.insert(0, str(Path(__file__).parent))
import run as guard  # noqa: E402

from scripts.preservation_audit import digest_file  # noqa: E402

D = guard.D
C = D / "continuation-1"


def expected_inputs():
    amendment = guard.read(C / "amendment.json")
    assert digest_file(D / "file-list.json") == amendment["source_file_list_sha256"]
    assert digest_file(D / "SHA256SUMS") == amendment["payload_sums_sha256"]
    rows = guard.read(D / "file-list.json")["files"]
    assert (D / "SHA256SUMS").read_text() == "".join(
        f"{row['sha256']}  {row['archive_path']}\n" for row in rows
    )
    for name in ("file-list.json", "SHA256SUMS"):
        rows.append(
            dict(
                archive_path=name,
                original_path=(D / name).relative_to(P).as_posix(),
                bytes=(D / name).stat().st_size,
                sha256=digest_file(D / name),
            )
        )
    result = {}
    for row in rows:
        name = row["archive_path"]
        path = PurePosixPath(name)
        assert not path.is_absolute() and ".." not in path.parts and str(path) == name
        assert name not in result
        source = P / row["original_path"]
        assert source.is_file() and not source.is_symlink()
        assert source.stat().st_size == row["bytes"]
        assert digest_file(source) == row["sha256"], row["original_path"]
        result[name] = row
    return result


def inspect_archive(path, expected):
    # Exhaust the single compressed stream, checking the footer/CRC and output bound.
    # No extraction, path creation or execution of payload files occurs.
    limit = sum(x["bytes"] for x in expected.values()) + 4096 * len(expected) + 20480
    decoder = lzma.LZMADecompressor(memlimit=128 * 1024 * 1024)
    total = 0
    compression_error = None
    try:
        with path.open("rb") as stream:
            while block := stream.read(65536):
                assert not decoder.eof, "unexpected data after compressed stream"
                total += len(decoder.decompress(block, max_length=65536))
                while not decoder.eof and not decoder.needs_input:
                    total += len(decoder.decompress(b"", max_length=65536))
                    assert total <= limit, "expanded archive bound"
                assert total <= limit and not decoder.unused_data
        if not decoder.eof:
            compression_error = "Interrupted/truncated compressed stream"
    except lzma.LZMAError as error:
        compression_error = "Compression integrity failed: " + str(error)
    observed = {}
    archive_error = None
    try:
        with tarfile.open(path, "r|xz") as archive:
            for member in archive:
                name = member.name
                lexical = PurePosixPath(name)
                assert not lexical.is_absolute() and ".." not in lexical.parts
                assert str(lexical) == name and name in expected and name not in observed
                assert member.isfile() and not member.issym() and not member.islnk()
                assert not member.linkname and not member.sparse
                assert member.size == expected[name]["bytes"]
                stream = archive.extractfile(member)
                assert stream is not None
                h = hashlib.sha256()
                count = 0
                while block := stream.read(65536):
                    h.update(block)
                    count += len(block)
                assert count == member.size and h.hexdigest() == expected[name]["sha256"], name
                observed[name] = h.hexdigest()
    except (tarfile.ReadError, EOFError, lzma.LZMAError) as error:
        archive_error = "Interrupted archive: " + str(error)
    missing = sorted(set(expected) - set(observed))
    return dict(
        passed=not compression_error and not archive_error and not missing,
        compression_integrity=not compression_error,
        compression_error=compression_error,
        archive_error=archive_error,
        decompressed_bytes=total,
        member_count=len(observed),
        expected_count=len(expected),
        safe_members=True,
        payload_sha256=observed,
        missing=missing,
        unexpected=[],
    )


class BoundedWriter:
    """Reject a compressed write before it could exceed the exact approved path cap."""

    def __init__(self, stream, limit):
        self.stream, self.limit, self.count = stream, limit, 0

    def write(self, data):
        if self.count + len(data) > self.limit:
            raise RuntimeError("archive prospective per-file bound")
        count = self.stream.write(data)
        self.count += count
        return count

    def flush(self):
        self.stream.flush()


def main():
    expected = expected_inputs()
    retained = guard.read(C / "amendment.json")["v1_identity"]
    v1 = D / "binius64-g0-handover-v1.tar.xz"
    assert v1.stat().st_size == retained["bytes"] and digest_file(v1) == retained["sha256"]
    first = inspect_archive(v1, expected)
    guard.write(C / "v1-readback.json", first)
    selected, result = v1, first
    if not first["passed"]:
        assert first["missing"] or first["compression_error"] or first["archive_error"]
        # Source checks cannot be waived in the interrupted-output branch.
        assert expected_inputs() == expected
        selected = D / "binius64-g0-handover-v2.tar.xz"
        assert not selected.exists()
        usage = guard.storage()
        reservation = 2097152 + 200000  # archive and bounded final evidence, not new allowance
        reserve = guard.POLICY["evidence_completion_reserve_bytes"]
        assert (
            usage["new_evidence_bytes"] + reservation + reserve
            < guard.POLICY["new_evidence_cap_bytes"]
        )
        assert (
            usage["evidence_bytes"] + reservation + reserve < guard.POLICY["evidence_ceiling_bytes"]
        )
        guard.write(
            C / "replacement-admission.json",
            dict(usage=usage, reservation=reservation, completion_reserve=reserve, passed=True),
        )
        with selected.open("xb") as stream:
            sink = BoundedWriter(stream, guard.output_role(selected)[1])
            with lzma.LZMAFile(sink, "wb", preset=3) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as tar:
                    for name, row in expected.items():
                        info = tarfile.TarInfo(name)
                        info.size, info.mode, info.mtime = row["bytes"], 0o644, 0
                        with (P / row["original_path"]).open("rb") as source:
                            tar.addfile(info, source)
        result = inspect_archive(selected, expected)
        guard.write(C / "v2-readback.json", result)
        assert result["passed"], result
    assert expected_inputs() == expected
    assert v1.stat().st_size == retained["bytes"] and digest_file(v1) == retained["sha256"]
    identity = dict(
        passed=True,
        path=selected.relative_to(P).as_posix(),
        absolute_path=str(selected),
        bytes=selected.stat().st_size,
        sha256=digest_file(selected),
        members=len(expected),
        reused_v1=selected == v1,
        historical_v1_failure_unchanged=True,
        complete_payload_readback=True,
        source_inputs_unchanged=True,
        classification="evidence",
        per_file_limit=2097152,
    )
    guard.write(C / "archive-verified.json", identity)
    (C / "archive-verified.sha256").write_text(f"{identity['sha256']}  {selected.name}\n")
    guard.write(
        D / "preflight.json",
        dict(passed=True, programme_complete=False, packaging_only=True, archive=identity),
    )
    print(json.dumps(identity))


if __name__ == "__main__":
    main()
