"""Install the pinned Linux x86_64 uv executable locally, without pip or sudo."""

import hashlib
import io
import platform
import urllib.request
import zipfile
from pathlib import Path

VERSION = "0.12.15"
URL = (
    "https://files.pythonhosted.org/packages/1e/fd/"
    "432451d732917c49152a291de3ef171aa6b0f1a22d39780fb2c1f085ca4c/"
    "uv-0.12.15-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
)
SHA256 = "aee9802f46bae436bd91751bb33ddeb379ef1596b5c19df193219d545d244b60"
ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SystemExit("This bootstrap targets Linux x86_64, including Ubuntu on WSL2.")
    destination = ROOT / ".tools" / "uv"
    with urllib.request.urlopen(URL, timeout=60) as response:
        wheel = response.read()
    if hashlib.sha256(wheel).hexdigest() != SHA256:
        raise SystemExit("uv wheel checksum mismatch; nothing installed.")
    with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
        executable = archive.read(f"uv-{VERSION}.data/scripts/uv")
    destination.parent.mkdir(exist_ok=True)
    destination.write_bytes(executable)
    destination.chmod(0o755)
    print(f"Installed uv {VERSION}: {destination}")


if __name__ == "__main__":
    main()
