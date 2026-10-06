"""Metadata/documentation only, using the established analysis resource guard."""

import gzip
import hashlib
import json
import resource
import subprocess
import sys
import time
import types
import urllib.error
import urllib.request
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
OLD = P / "docs/data/s3_aurora_transcript_correction_contract_1/run_checks.py"
g = types.ModuleType("analysis_guard")
g.__file__ = str(OLD)
source = OLD.read_text()
source = source.replace(
    'assert len(Path("/proc/net/route").read_text().splitlines()) == 1',
    'assert name.startswith("metadata-") or '
    'len(Path("/proc/net/route").read_text().splitlines()) == 1',
)
source = source.replace(
    '"PrivateNetwork=yes",',
    '"PrivateNetwork=" + ("no" if name.startswith("metadata-") else "yes"),',
)
source = source.replace(
    '"network": "private-no-routes",',
    '"network": "read-only HTTPS metadata" if name.startswith("metadata-") '
    'else "private-no-routes",',
)
source = source.replace('unit = "pqdid-auroracontract-" + name',
                        'unit = "pqdid-auroradeplock-" + name')
exec(compile(source, str(OLD), "exec"), g.__dict__)
g.D = g.BASE = D
g.__file__ = str(D / "run.py")
g.CONFIG = json.loads((D / "config.json").read_text())
g.FILES = [str(D)]
g.COMMANDS = {
    name: [str(P / ".venv/bin/python"), "-I", "-B", str(D / "run.py"), "work", name]
    for name in g.CONFIG["command_reservations_seconds"]
}


def metadata(name):
    rows = []
    if name == "metadata-3":
        local = []
        for args in (
            ["dpkg-query", "-W", "-f=${Package} ${Version} ${Status}\n", "libgmp-dev",
             "libgmp10", "libsodium23", "libsodium-dev", "libstdc++6", "libc6",
             "libgcc-s1", "g++", "cmake", "ninja-build", "pkg-config", "git"],
            ["apt-cache", "show", "libsodium-dev", "libgmp-dev"],
            ["dpkg-query", "-L", "libgmp-dev"],
        ):
            completed = subprocess.run(args, capture_output=True, text=True, timeout=2)
            local.append({"argv": args, "exit_code": completed.returncode,
                          "stdout": completed.stdout, "stderr": completed.stderr})
        g.write("local-packages.json", local)
    requests = json.loads((D / (name + "-requests.json")).read_text())
    for request in requests:
        started = time.monotonic()
        row = dict(request)
        try:
            req = urllib.request.Request(request["url"], headers={"User-Agent": "PQDID-metadata-review"})
            with urllib.request.urlopen(req, timeout=4) as response:
                data = response.read(1048577)
                assert len(data) <= 1048576, "metadata response ceiling"
                row.update(status=response.status, final_url=response.url)
            path = D / "metadata" / (request["id"] + ".gz")
            assert not path.exists(), "no overwrite"
            path.write_bytes(gzip.compress(data, mtime=0))
            row.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                       retained=str(path.relative_to(P)))
            print(request["id"], data.decode() if request.get("display", True) else "retained")
        except urllib.error.HTTPError as error:
            row.update(status=error.code, error=str(error))
            print(request["id"], row["error"])
        row["seconds"] = time.monotonic() - started
        rows.append(row)
        g.write(name + "-results.json", rows)


def work(name):
    if name.startswith("metadata-"):
        metadata(name)
    else:
        helper = types.ModuleType("documentation_work")
        helper.__file__ = str(D / "checks.py")
        exec(compile((D / "checks.py").read_text(), helper.__file__, "exec"), helper.__dict__)
        helper.run(name)


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    if sys.argv[1] == "--worker":
        raise SystemExit(g.worker(sys.argv[2]))
    if sys.argv[1] == "work":
        work(sys.argv[2])
    else:
        raise SystemExit(g.main(sys.argv[1]))
