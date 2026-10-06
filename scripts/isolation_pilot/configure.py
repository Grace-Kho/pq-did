"""Root-only fresh synthetic configuration; no secret is printed or put in argv."""

import grp
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from layout import (
    ACCOUNTS,
    CONFIG,
    ROLES,
    RUN,
    STATE,
    check,
    identities,
    json_bytes,
    read_bytes,
    root_required,
    write_new,
)


def main():
    root_required()
    from pqdid.parameters import decode_parameters
    from pqdid.persistence.codec import decode
    from pqdid.persistence.owner_auth import (
        ADMIN,
        ISSUER,
        MANAGER,
        OBSERVER,
        RECIPIENT,
        VERIFIER,
        AuthorityPolicy,
    )
    from pqdid.persistence.records import ServiceKey

    ids = identities()
    configs, bundles = {}, {a: {} for a in ACCOUNTS}
    for short, role in ROLES.items():
        cp = decode(read_bytes(STATE / "inputs" / (role + ".fixture")))
        pp = decode_parameters(cp.parameters)
        audience = cp.state.audience if short in {"va", "vb"} else b""
        key = ServiceKey(cp.role, cp.service_id, role.encode()[:1] * 32, pp, audience)
        owner = "pqiso-o-" + short
        service = {
            "role": cp.role.value,
            "service_id": cp.service_id.hex(),
            "authority_id": key.authority_id.hex(),
            "parameters": cp.parameters.hex(),
            "audience": audience.hex(),
        }
        scope = AuthorityPolicy(key, (b"owner-1", b"owner-2")).scope.hex()
        cfg = {
            "version": 1,
            "synthetic_only": True,
            "short_role": short,
            "account": owner,
            "identity": ids[owner],
            "service": service,
            "scope": scope,
            "transport_gid": grp.getgrnam("pqiso-ipc-" + short).gr_gid,
            "store": str(STATE / "stores" / short / "authority.sqlite3"),
            "slots": {
                "primary": {"endpoint": str(RUN / short / "owner.sock"), "writer": "owner-1"}
            },
            "grants": [],
        }
        if short == "m":
            cfg["slots"]["replacement"] = {
                "endpoint": str(RUN / short / "replacement.sock"),
                "writer": "owner-2",
            }
        if short in {"va", "vb"}:
            cfg["request_key"] = cp.state.request_key.hex()
            write_new(
                CONFIG / "owners" / short / "public.bin",
                read_bytes(STATE / "inputs" / (role + ".public")),
                gid=ids[owner]["gid"],
                mode=0o640,
            )
        grants = [
            ("pqiso-admin", "admin", ADMIN),
            ("pqiso-observer", "observer", OBSERVER),
            (
                "pqiso-w-" + short,
                "writer",
                MANAGER if short == "m" else ISSUER if short == "i" else VERIFIER,
            ),
        ]
        if short == "m":
            grants.append(
                ("pqiso-o-i", "issuer-bridge", frozenset({b"allocation-count", b"reservation"}))
            )
        if short == "i":
            grants += [
                ("pqiso-rec-a", "recipient-a", RECIPIENT),
                ("pqiso-rec-b", "recipient-b", RECIPIENT),
            ]
        for account, name, permissions in grants:
            token = short + ":" + name
            secret = os.urandom(32).hex()
            bundles[owner][token] = secret
            bundles[account][token] = secret
            cfg["grants"].append(
                {
                    "account": account,
                    "name": name,
                    "token": token,
                    "permissions": sorted(p.decode() for p in permissions),
                    "identity": ids[account],
                    "issuer_service": (b"S" * 32).hex() if b"reservation" in permissions else None,
                    "recipient": (
                        b"recipient-A" if account.endswith("-a") else b"recipient-B"
                    ).hex()
                    if b"retrieve" in permissions
                    else None,
                }
            )
        configs[short] = cfg
        write_new(CONFIG / "owners" / short / "BOOTSTRAP", b"fresh-only\n", mode=0o644)
        write_new(
            CONFIG / "owners" / short / "bootstrap.bin",
            read_bytes(STATE / "inputs" / (role + ".fixture")),
            gid=ids[owner]["gid"],
            mode=0o640,
        )
    bindings = {
        r: {
            "endpoint": c["slots"]["primary"]["endpoint"],
            "scope": c["scope"],
            "owner_uid": c["identity"]["uid"],
            "owner_gid": c["identity"]["gid"],
            "transport_gid": c["transport_gid"],
            "service": c["service"],
        }
        for r, c in configs.items()
    }
    configs["i"]["manager"] = {**bindings["m"], "token": "m:issuer-bridge"}
    for short, cfg in configs.items():
        cfg["tokens"] = sorted(bundles[cfg["account"]])
        write_new(
            CONFIG / "owners" / short / "policy.json",
            json_bytes(cfg),
            gid=cfg["identity"]["gid"],
            mode=0o640,
        )
    for account in ACCOUNTS:
        # Owners have a client probe configuration too, without additional grants.
        directory = CONFIG / "clients" / account
        if not directory.exists():
            directory.mkdir(mode=0o750)
            os.chown(directory, 0, ids[account]["gid"])
            state = STATE / "clients" / account
            state.mkdir(mode=0o700)
            os.chown(state, ids[account]["uid"], ids[account]["gid"])
        cfg = {
            "version": 1,
            "synthetic_only": True,
            "account": account,
            "identity": ids[account],
            "tokens": sorted(bundles[account]),
            "bindings": bindings,
        }
        write_new(directory / "policy.json", json_bytes(cfg), gid=ids[account]["gid"], mode=0o640)
        data = json_bytes({"version": 1, "account": account, "tokens": bundles[account]})
        write_new(CONFIG / "credentials" / ("client-" + account + ".bin"), data, mode=0o400)
        if account.startswith("pqiso-o-"):
            write_new(
                CONFIG / "credentials" / ("owner-" + account.rsplit("-", 1)[1] + ".bin"),
                data,
                mode=0o400,
            )
    check(len(configs) == 4, "configuration-count")


if __name__ == "__main__":
    main()
