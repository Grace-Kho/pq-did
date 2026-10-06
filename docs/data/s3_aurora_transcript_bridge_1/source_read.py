"""Bounded primary-source retrieval only; downloaded text is never executed."""

import concurrent.futures
import hashlib
import json
import os
import resource
import signal
import time
import urllib.request
from pathlib import Path

D = Path(__file__).resolve().parent
PIN = "a2ed2ec2f3e85f29b6035951553b02cb737c817a"
FILES = [
    "libiop/bcs/hashing/blake2b.tcc",
    "libiop/bcs/bcs_common.tcc",
    "libiop/bcs/bcs_prover.tcc",
    "libiop/bcs/bcs_verifier.tcc",
    "libiop/bcs/merkle_tree.tcc",
    "libiop/bcs/pow.tcc",
    "libiop/snark/aurora_snark.tcc",
    "libiop/protocols/aurora_iop.tcc",
    "libiop/protocols/encoded/r1cs_rs_iop/r1cs_rs_iop.tcc",
    "libiop/protocols/encoded/lincheck/basic_lincheck.hpp",
    "libiop/protocols/ldt/ldt_reducer.tcc",
    "libiop/protocols/ldt/fri/fri_ldt.tcc",
    "libiop/protocols/ldt/fri/fri_ldt.hpp",
    "libiop/bcs/hashing/blake2b.hpp",
    "libiop/iop/iop.tcc",
    "LICENSE",
]


def fetch(name):
    url = f"https://raw.githubusercontent.com/scipr-lab/libiop/{PIN}/{name}"
    start = time.monotonic()
    row = {"path": name, "commit": PIN, "url": url}
    try:
        with urllib.request.urlopen(url, timeout=0.65) as stream:
            body = stream.read(100001)
        if len(body) > 100000:
            raise ValueError("source exceeds per-read bound")
        target = D / "sources" / (name.replace("/", "__") + ".txt")
        target.write_bytes(body)
        row.update(
            status="read",
            bytes=len(body),
            local=str(target.relative_to(D)),
            sha256=hashlib.sha256(body).hexdigest(),
            git_blob_sha1=hashlib.sha1(
                b"blob " + str(len(body)).encode() + b"\0" + body
            ).hexdigest(),
        )
    except Exception as error:
        row.update(status="unavailable", error=f"{type(error).__name__}: {error}"[:250])
    row["seconds"] = time.monotonic() - start
    return row


def main():
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    signal.alarm(3)
    os.sched_setaffinity(0, set(sorted(os.sched_getaffinity(0))[:2]))
    started = time.monotonic()
    (D / "sources").mkdir(exist_ok=False)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        rows = list(pool.map(fetch, FILES))
    record = {
        "kind": "Primary-source text retrieval, not execution of reviewed code",
        "commit": PIN,
        "rows": rows,
        "wall_seconds": time.monotonic() - started,
        "peak_self_RSS_KiB": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "limits": "256MiB address space,3s CPU/alarm,two threads/CPUs,100000B/read,1MiB/file",
        "accounting": "Included in five-second analysis operator/bookkeeping charge",
        "preceding_source_read_diagnostics": [
            {"status": "sandbox DNS failure", "seconds": 0.007994811050593853},
            {"status": "bounded exact-pin blake2b source read", "seconds": 0.32082743605133146},
        ],
        "code_executed": False,
        "new_test_invocations": 0,
    }
    (D / "sources.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({k: v for k, v in record.items() if k != "rows"}))
    print(json.dumps({row["path"]: row["status"] for row in rows}))


if __name__ == "__main__":
    main()
