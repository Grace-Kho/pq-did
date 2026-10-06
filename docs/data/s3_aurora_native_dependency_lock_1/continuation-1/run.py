"""Authorised one-time continuation of the existing analysis guard."""

import gzip
import hashlib
import json
import resource
import sys
import time
import types
import urllib.request
from pathlib import Path

R = Path(__file__).resolve().parent
D = R.parent
P = D.parents[2]
REPORT = P / "docs/stage3_aurora_native_dependency_lock.md"
PROPOSAL = P / "docs/proposals/s3_aurora_native_dependency_lock_1"
OLD = P / "docs/data/s3_aurora_transcript_correction_contract_1/run_checks.py"
g = types.ModuleType("analysis_guard")
g.__file__ = str(OLD)
source = OLD.read_text()
for before, after in (
    (
        'assert len(Path("/proc/net/route").read_text().splitlines()) == 1',
        'assert name == "metadata-resume" or '
        'len(Path("/proc/net/route").read_text().splitlines()) == 1',
    ),
    (
        '"PrivateNetwork=yes",',
        '"PrivateNetwork=" + ("no" if name == "metadata-resume" else "yes"),',
    ),
    (
        '"network": "private-no-routes",',
        '"network": "read-only HTTPS metadata" if name == "metadata-resume" '
        'else "private-no-routes",',
    ),
    ('unit = "pqdid-auroracontract-" + name', 'unit = "pqdid-auroradeplock-cont-" + name'),
    ("size(BASE)", "package_size()"),
):
    assert before in source
    source = source.replace(before, after)
exec(compile(source, str(OLD), "exec"), g.__dict__)
g.BASE = g.D = R
g.__file__ = str(R / "run.py")
g.CONFIG = json.loads((R / "config.json").read_text())
g.FILES = [str(R)]


def package_size():
    count = g.size(D) + g.size(PROPOSAL)
    if REPORT.exists():
        count += REPORT.stat().st_size
    prefixes = json.loads((D / "prefixes.json").read_text())
    count += sum((P / n).stat().st_size - row["bytes"] for n, row in prefixes.items())
    assert count < 2097152, "unchanged new-package ceiling"
    return count


g.package_size = package_size
g.COMMANDS = {
    name: [str(P / ".venv/bin/python"), "-I", "-B", str(R / "run.py"), "work", name]
    for name in g.CONFIG["command_reservations_seconds"]
}


def metadata():
    requests = json.loads((R / "metadata-resume-requests.json").read_text())
    assert sum(row["maximum_bytes"] for row in requests) <= 262144
    assert g.CONFIG["prior_output_bytes"] + package_size() + 262144 + 524288 < 12386485
    rows = []
    for request in requests:
        started = time.monotonic()
        req = urllib.request.Request(
            request["url"], headers={"User-Agent": "PQDID-metadata-review"}
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            data = response.read(request["maximum_bytes"] + 1)
            assert len(data) <= request["maximum_bytes"]
            row = {**request, "status": response.status, "final_url": response.url}
        path = R / "metadata" / (request["id"] + ".gz")
        assert not path.exists()
        path.write_bytes(gzip.compress(data, mtime=0))
        row.update(
            bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            retained=str(path.relative_to(P)),
            seconds=time.monotonic() - started,
        )
        rows.append(row)
        g.write("metadata-resume-results.json", rows)
        print(request["id"], response.status, len(data))


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    if sys.argv[1] == "--worker":
        raise SystemExit(g.worker(sys.argv[2]))
    if sys.argv[1] == "work":
        if sys.argv[2] == "metadata-resume":
            metadata()
        else:
            helper = types.ModuleType("documentation_work")
            helper.__file__ = str(R / "checks.py")
            exec(compile((R / "checks.py").read_text(), helper.__file__, "exec"), helper.__dict__)
            helper.run(sys.argv[2])
    else:
        raise SystemExit(g.main(sys.argv[1]))
