"""Bounded preparation only: installed diagnostics and pinned text metadata."""

import hashlib
import json
import os
import resource
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]


def read(name):
    return json.loads((D / name).read_bytes())


def write(name, value):
    data = (json.dumps(value, indent=2) + "\n").encode()
    assert len(data) < 1048576
    (D / name).write_bytes(data)


def charge(kind, row):
    ledger = read("ledger.json")
    ledger[kind].append(row)
    write("ledger.json", ledger)
    used = ledger["operator_conservative_seconds"] + sum(
        r["seconds"] for key in ("diagnostics", "source_inspection") for r in ledger[key]
    )
    assert used < 60, "Preserve 30 seconds for completion"
    total = 63229 + sum(p.stat().st_size for p in D.rglob("*") if p.is_file())
    assert total < 524288, "Preparation evidence allocation"


def diagnostic(host=False):
    commands = [["uname", "-rmo"], ["free", "-b"],
                ["df", "-B1", "--output=size,used,avail,target", str(P), "/tmp", "/mnt/c"],
                ["lscpu"], ["g++-15", "--version"], ["cmake", "--version"],
                ["ninja", "--version"], ["pkg-config", "--version"],
                ["dpkg-query", "-W", "-f=${Package} ${Version} ${Architecture} ${db:Status-Status}\\n",
                 "cmake", "ninja-build", "g++-15", "libgmp*", "libssl*", "libboost*",
                 "zlib1g*", "libprotobuf*", "protobuf-compiler", "wabt", "libvulkan*",
                 "mesa-vulkan-drivers", "vulkan-tools", "*dawn*"],
                ["/usr/lib/wsl/lib/nvidia-smi", "--query-gpu=name,driver_version,memory.total,memory.free", "--format=csv,noheader,nounits"],
                ["vulkaninfo", "--summary"]]
    ps = shutil.which("powershell.exe")
    if ps:
        commands.append([ps, "-NoProfile", "-NonInteractive", "-Command",
                         "@{Memory=(Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory);GPU=(Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion,AdapterRAM)} | ConvertTo-Json -Compress"])
    if host:
        commands = [a for a in commands if a[0].endswith(("nvidia-smi", "powershell.exe"))]
    output = []
    for argv in commands:
        start = time.monotonic()
        exe = shutil.which(argv[0]) if "/" not in argv[0] else argv[0]
        if not exe or not Path(exe).exists():
            row = {"argv": argv, "status": "not-installed", "seconds": time.monotonic()-start}
        else:
            try:
                r = subprocess.run(argv, capture_output=True, timeout=5, check=False,
                                   env=dict(os.environ, LC_ALL="C", PYTHONDONTWRITEBYTECODE="1"))
                assert len(r.stdout)+len(r.stderr) <= 61440
                row = {"argv": argv, "exit_code": r.returncode, "stdout": r.stdout.decode(errors="replace"),
                       "stderr": r.stderr.decode(errors="replace"), "seconds": time.monotonic()-start}
            except subprocess.TimeoutExpired:
                row = {"argv": argv, "status": "bounded-timeout", "seconds": time.monotonic()-start}
        output.append(row)
        charge("diagnostics", {k: v for k, v in row.items() if k not in ("stdout", "stderr")})
    files = {}
    for name in ("/dev/dxg", "/dev/dri", "/usr/lib/wsl/lib/libdxcore.so", "/usr/lib/wsl/lib/libd3d12.so", "/usr/share/vulkan/icd.d"):
        f = Path(name)
        files[name] = {"exists": f.exists(), "entries": sorted(x.name for x in f.iterdir()) if f.is_dir() else None}
    write("hardware-host.json" if host else "hardware.json", {"diagnostics": output, "paths": files,
                           "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                           "GPU_workloads": 0, "Dawn_adapter_demonstrated": False,
                           "ru_maxrss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024})
    print(json.dumps({"diagnostics": len(output), "GPU_workloads": 0}))


def fetch(url, name, cap):
    assert name.replace("-", "").replace("_", "").replace(".", "").isalnum()
    dest = D / "sources" / name
    assert not dest.exists()
    start = time.monotonic()
    row = {"url": url, "path": str(dest.relative_to(P)), "cap": cap}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PQ-DID-read-only-preflight", "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=5) as response:
            b = response.read(cap+1)
            assert len(b) <= cap
            row.update(final_url=response.url, content_type=response.headers.get("Content-Type"),
                       etag=response.headers.get("ETag"))
        dest.parent.mkdir(exist_ok=True)
        dest.write_bytes(b)
        row.update(status="retained-text-metadata", bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
    except Exception as error:
        row.update(status="failed", error=str(error))
    row["seconds"] = time.monotonic()-start
    charge("source_inspection", row)
    print(json.dumps(row))


if __name__ == "__main__":
    if sys.argv[1] == "diagnostic":
        diagnostic()
    elif sys.argv[1] == "diagnostic-host":
        diagnostic(host=True)
    elif sys.argv[1] == "fetch":
        fetch(sys.argv[2], sys.argv[3], int(sys.argv[4]))
