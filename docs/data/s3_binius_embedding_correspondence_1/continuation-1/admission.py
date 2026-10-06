"""Bounded identity admission and acquisition of the fifteen approved blobs only."""

import hashlib
import json
import signal
import time
import urllib.request
from pathlib import Path

R = Path(__file__).resolve().parent
D = R.parent
P = R.parents[3]
PIN = "441fbf51ff0bcb0bcd28f3f1b73f4954029e8577"


def read(p):
    return json.loads(p.read_text())


def sha(p):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for part in iter(lambda: f.read(65536), b""):
            h.update(part)
    return h.hexdigest()


def verify():
    amendment = read(R / "amendment.json")
    prior = D / "execution"
    assert sha(prior / "manifest.json") == amendment["prior_manifest_sha256"]
    assert sha(prior / "validation-closure.json") == amendment["prior_closure_sha256"]
    treepath = (
        P / "docs/data/oct31_binius64_replacement_decision_1/sources/implementation-tree.json"
    )
    assert sha(treepath) == "c1d21269c495f6cd12b0a20c6f82252d807fea536dc0e3de8a2d230100f052c0"
    row = amendment["additional_source"]
    tree = {v["path"]: v for v in read(treepath)["tree"]}
    assert row == tree[row["path"]]
    for old in read(prior / "source-acquisition.json")["sources"]:
        assert sha(P / old["retained_path"]) == old["sha256"]
    return {"files": [row]}


def run(phase):
    allowed = verify()
    if phase == "preflight":
        record = {
            "passed": True,
            "proposal_verified": True,
            "exact_tree_entries": 15,
            "new_evidence_reservation": 1048576,
            "shared_opening_headroom": 7136327,
            "shared_completion_reserve": 2097152,
            "implementation_opening_seconds": 810.6179695621813,
            "outside_KYC_seconds": 367.2276139201385,
            "implementation_allocation_seconds": 200,
            "invocations_opening": 1140,
            "ceiling_prospectively_amended": 1168,
            "builds": "10/13 unchanged",
            "EC-08": "declared parity mismatch; not arbitrary raw-vector recognisability",
        }
        (R / "admission.json").write_text(json.dumps(record, indent=2) + "\n")
        return
    started = time.monotonic()
    record = {
        "commit": PIN,
        "sources": [],
        "passed": False,
        "downloaded_code_executed": False,
        "memory_scope": (
            "256 MiB cgroup established before interpreter; measured in acquire.service.json"
        ),
    }
    (R / "sources").mkdir()

    def expired(*_):
        raise TimeoutError("14-second acquisition child limit")

    signal.signal(signal.SIGALRM, expired)
    signal.alarm(14)
    try:
        for row in allowed["files"]:
            url = f"https://raw.githubusercontent.com/binius-zk/binius64/{PIN}/{row['path']}"
            with urllib.request.urlopen(url, timeout=2) as response:
                assert response.url == url, "unexpected redirect"
                data = response.read(row["size"] + 1)
            assert len(data) == row["size"], row["path"]
            blob = hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
            assert blob == row["sha"], row["path"]
            path = R / "sources" / row["path"].replace("/", "--")
            with path.open("xb") as f:
                f.write(data)
            record["sources"].append(
                {
                    "upstream_path": row["path"],
                    "retained_path": str(path.relative_to(P)),
                    "url": url,
                    "bytes": len(data),
                    "git_blob": blob,
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        record["passed"] = True
    except Exception as error:
        record["failure"] = repr(error)
        raise
    finally:
        signal.alarm(0)
        record["seconds"] = time.monotonic() - started
        (R / "source-acquisition.json").write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps({k: v for k, v in record.items() if k != "sources"}))
