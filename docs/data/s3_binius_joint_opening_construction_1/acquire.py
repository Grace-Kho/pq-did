"""Acquire only the missing encoder/IntMul source at the retained commit; never execute it."""

import hashlib
import json
import os
import resource
import signal
import time
import urllib.request
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
B = P / "docs/data/oct31_binius64_replacement_decision_1"
PIN = "441fbf51ff0bcb0bcd28f3f1b73f4954029e8577"
PATHS = [
    "crates/math/src/bit_reverse.rs",
    "crates/math/src/ntt/mod.rs",
    "crates/math/src/ntt/domain_context.rs",
    "crates/math/src/ntt/neighbors_last.rs",
    "crates/math/src/ntt/reference.rs",
    "crates/math/src/ntt/subspace_polys.rs",
    "crates/prover/src/protocols/intmul/prove.rs",
    "crates/prover/src/protocols/intmul/witness.rs",
    "crates/verifier/src/protocols/intmul/common.rs",
    "crates/verifier/src/protocols/intmul/verify.rs",
]


def expire(*_):
    raise TimeoutError("12-second source-acquisition admission exhausted")


def main():
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:2])
    started = time.monotonic()
    signal.signal(signal.SIGALRM, expire)
    signal.alarm(12)
    result = {"pin": PIN, "sources": [], "passed": False, "code_executed": False}
    try:
        tree = json.loads((B / "sources/implementation-tree.json").read_text())
        assert tree["sha"] == "544452a781fee0f9b262d4ecfdcc47326fb6974f"
        assert not tree["truncated"]
        index = {item["path"]: item for item in tree["tree"]}
        assert sum(index[path]["size"] for path in PATHS) < 200000
        (D / "sources").mkdir(exist_ok=True)
        for path in PATHS:
            expected = index[path]
            assert expected["type"] == "blob" and expected["size"] < 1048576
            url = f"https://raw.githubusercontent.com/binius-zk/binius64/{PIN}/{path}"
            with urllib.request.urlopen(url, timeout=3) as response:
                data = response.read(expected["size"] + 1)
            assert len(data) == expected["size"], path
            blob = hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
            assert blob == expected["sha"], path
            destination = D / "sources" / path.replace("/", "--")
            with destination.open("xb") as output:
                output.write(data)
            result["sources"].append(
                {
                    "upstream_path": path,
                    "retained_path": str(destination.relative_to(P)),
                    "url": url,
                    "bytes": len(data),
                    "git_blob": blob,
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        result["passed"] = True
    except Exception as error:
        result["failure"] = repr(error)
        raise
    finally:
        signal.alarm(0)
        result.update(
            seconds=time.monotonic() - started,
            peak_process_RSS_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
            memory_enforcement="256 MiB RLIMIT_AS; single process, no child; no cgroup measurement",
        )
        with (D / "source-acquisition.json").open("x") as output:
            json.dump(result, output, indent=2)
            output.write("\n")
        print(json.dumps({key: value for key, value in result.items() if key != "sources"}))


if __name__ == "__main__":
    main()
