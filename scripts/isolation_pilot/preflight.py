"""Unprivileged system-interpreter preflight; no import from the new venv before checking it."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from layout import RELEASE, check  # noqa: E402
from runtime import release_check  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=("owner", "client"))
    parser.add_argument("name")
    parser.add_argument("credentials")
    parser.add_argument("--slot", default="primary")
    parser.add_argument("--fresh", action="store_true")
    args = parser.parse_args()
    release_check()
    # Only verified root-owned code can be added; the system interpreter stays in use.
    sys.path.insert(0, str(RELEASE / "src"))
    from runtime import startup

    check(args.slot in {"primary", "replacement"}, "owner-slot")
    startup(args.kind, args.name, args.credentials, slot=args.slot, require_store=not args.fresh)
    print(json.dumps({"preflight": "passed", "kind": args.kind, "name": args.name}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"preflight": "failed", "error_type": type(error).__name__}))
        raise SystemExit(1) from None
