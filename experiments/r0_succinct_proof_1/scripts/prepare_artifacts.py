"""Inspect the pinned binary's embedded recursion archive; no download or proving."""

import hashlib
import io
import json
import mmap
import struct
import zipfile
from pathlib import Path

R = Path(__file__).resolve().parents[1]
B = R.parent / "r0_succinct_feasibility_1"
p = B / "tooling/sdk-3.0.6/r0vm"
expected = "744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849"
assert (
    hashlib.file_digest(p.open("rb"), "sha256").hexdigest()
    == "751b9b188d341e8bec5e02060086b7b1dc3f7289e90f726c38589bb6735dd6d7"
)
with p.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
    offset = 0
    found = None
    while True:
        pos = m.find(b"PK\x05\x06", offset)
        if pos < 0:
            break
        offset = pos + 4
        if pos + 22 > len(m):
            continue
        size, cd, comment = struct.unpack_from("<IIH", m, pos + 12)
        begin = pos - size - cd
        end = pos + 22 + comment
        if begin < 0 or end > len(m) or m[begin : begin + 4] != b"PK\x03\x04":
            continue
        content = m[begin:end]
        if hashlib.sha256(content).hexdigest() == expected:
            found = content
            break
    assert found is not None, "pinned embedded recursion archive absent"
    (R / "tooling/recursion_zkr.zip").write_bytes(found)
    with zipfile.ZipFile(io.BytesIO(found)) as z:
        entries = [
            {
                "name": x.filename,
                "compressed_bytes": x.compress_size,
                "uncompressed_bytes": x.file_size,
            }
            for x in z.infolist()
        ]
        assert all(
            any(x["name"] == f"{name}.zkr" for x in entries)
            for name in ["lift_rv32im_v2_15", "lift_rv32im_v2_16", "join"]
        )
    record = {
        "prover_path": str(p),
        "prover_sha256": hashlib.sha256(m).hexdigest(),
        "source": "recursion 4.0.5 build.rs pin and include_bytes in src/prove/zkr.rs",
        "archive_sha256": expected,
        "archive_bytes": len(found),
        "embedded_offset": begin,
        "upstream_url": f"https://risc0-artifacts.s3.us-west-2.amazonaws.com/zkr/{expected}.zip",
        "downloaded_bytes": 0,
        "preparation": "Exact embedded ZIP extracted; runtime uses unchanged built-in bytes",
        "entries": entries,
        "cuda_driver_string_present": m.find(b"libcuda.so") >= 0,
        "cpu_hal_string_present": m.find(b"CpuHal") >= 0,
    }
    (R / "evidence/recursion-artifacts.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({k: v for k, v in record.items() if k != "entries"}, indent=2))
    print("entries", len(entries))
