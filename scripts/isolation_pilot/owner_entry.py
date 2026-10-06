"""Trusted configured owner entry; no client-selected store, SQL or executable."""

import argparse
import os
import signal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from layout import check  # noqa: E402
from runtime import event, make_owner, startup  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--owner", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--credentials-directory", required=True)
    parser.add_argument("--slot", default="primary")
    parser.add_argument("--bootstrap", action="store_true")
    args = parser.parse_args()
    from runtime import config_path

    check(Path(args.policy) == config_path("owner", args.owner), "policy-binding")
    cfg, secrets = startup(
        "owner",
        args.owner,
        args.credentials_directory,
        slot=args.slot,
        require_store=not args.bootstrap,
    )
    owner = make_owner(cfg, secrets, args.slot)
    if args.bootstrap:
        from layout import CONFIG, STATE, protected, read_bytes, write_new

        from pqdid.persistence.codec import decode, encode

        protected(CONFIG / "owners" / args.owner / "BOOTSTRAP", mode=0o644)
        ticket = owner._store.initialise(
            b"admin", decode(read_bytes(CONFIG / "owners" / args.owner / "bootstrap.bin"))
        )
        write_new(
            STATE / "clients" / cfg["account"] / "bootstrap-result.bin",
            encode(ticket.record()),
            uid=os.getuid(),
            gid=os.getgid(),
        )
        return

    def stop(_number, _frame):
        raise KeyboardInterrupt

    # Strict SQL/service/checkpoint integrity gate runs before binding a listener.
    owner._store.inspect(owner._writer)
    signal.signal(signal.SIGTERM, stop)
    metrics = owner.serve(
        ready=lambda: event(
            {
                "ready": True,
                "uid": os.getuid(),
                "gid": os.getgid(),
                "groups": os.getgroups(),
                "pid": os.getpid(),
                "scope": cfg["scope"],
            }
        )
    )
    event({"metrics": metrics, "uid": os.getuid()})


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(0) from None
    except Exception as error:
        event({"ready": False, "error_type": type(error).__name__})
        raise SystemExit(1) from None
