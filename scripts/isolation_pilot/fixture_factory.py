"""Unprivileged fresh synthetic inputs from unchanged native/reference test fixtures.

No live deployment capability or private signing key is exported. This helper is
not installed in the protected runtime and never runs as host administrator.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from layout import check, json_bytes, write_new  # noqa: E402


def generate(target):
    check(os.getuid() != 0, "unprivileged-fixture-generation-only")
    project = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(project))
    sys.path.insert(0, str(project / "tests/integration"))
    from test_durable_authority import fixtures

    target = Path(target)
    check(not target.exists(), "fixture-target-exists")
    target.mkdir(mode=0o700)
    values = fixtures.__wrapped__()
    for name, data in values.items():
        check(
            name
            in {
                "manager.fixture",
                "issuer.fixture",
                "issued.fixture",
                "verifier0.fixture",
                "verifier1.fixture",
                "verifier0.public",
                "verifier1.public",
            },
            "unexpected-fixture",
        )
        write_new(target / name, data, uid=os.getuid(), gid=os.getgid())
    write_new(
        target / "label.json",
        json_bytes({"synthetic": True, "proofs": False, "private_signing_keys_exported": False}),
        uid=os.getuid(),
        gid=os.getgid(),
    )


if __name__ == "__main__":
    generate(sys.argv[1])
