"""Fixed-role startup and TEST-ONLY synthetic public adapters for the isolation pilot."""

import grp
import json
import os
import stat
import sys
from pathlib import Path

from layout import (
    ACCOUNTS,
    CONFIG,
    RELEASE,
    ROLES,
    RUN,
    STATE,
    check,
    digest,
    identities,
    no_acl,
    protected,
    read_bytes,
    read_json,
)


def release_check():
    protected(RELEASE, directory=True, mode=0o755)
    seal = RELEASE / "release-manifest.json"
    protected(seal, mode=0o644)
    record = read_json(seal)
    check(record["version"] == 1 and 1 <= len(record["files"]) <= 512, "release-manifest")
    names = set()
    for name, expected in record["files"].items():
        path = Path(name)
        check(
            not path.is_absolute() and ".." not in path.parts and str(path) == name, "release-path"
        )
        target = RELEASE / path
        if target.is_symlink():
            resolved = target.resolve()
            check(
                resolved.is_relative_to(RELEASE) or resolved == Path("/usr/bin/python3.14"),
                "runtime-symlink",
            )
            info = target.lstat()
            check(info.st_uid == 0, "runtime-link-owner")
            protected(target.parent, directory=True)
            protected(resolved)
        else:
            protected(target)
        check(digest(target) == expected, "runtime-digest")
        names.add(name)
    for directory in RELEASE.rglob("*"):
        if directory.is_dir() and not directory.is_symlink():
            protected(directory, directory=True)
    current = {
        str(p.relative_to(RELEASE)) for p in RELEASE.rglob("*") if p.is_file() or p.is_symlink()
    }
    check(current == names | {"release-manifest.json"}, "runtime-inventory")
    check(Path(sys.base_prefix) == Path("/usr"), "runtime-base")


def config_path(kind, name):
    check(kind in {"owner", "client"}, "startup-kind")
    check(name in (ROLES if kind == "owner" else ACCOUNTS), "startup-name")
    return CONFIG / ("owners" if kind == "owner" else "clients") / name / "policy.json"


def startup(kind, name, credentials, *, slot="primary", require_store=True):
    release_check()
    account = "pqiso-o-" + name if kind == "owner" else name
    actual = identities()
    identity = actual[account]
    check((os.getuid(), os.getgid()) == (identity["uid"], identity["gid"]), "process-identity")
    check(sorted(set(os.getgroups()) | {os.getgid()}) == identity["groups"], "process-groups")
    path = config_path(kind, name)
    protected(path, gid=identity["gid"], mode=0o640)
    cfg = read_json(path)
    check(cfg["version"] == 1 and cfg["synthetic_only"] is True, "pilot-scope")
    check(cfg["account"] == account and cfg["identity"] == identity, "configured-identity")
    directory = Path(credentials)
    check(
        directory.is_absolute()
        and directory.resolve() == directory
        and directory.is_relative_to("/run/credentials"),
        "credential-directory",
    )
    info = directory.lstat()
    check(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid in {0, os.getuid()}
        and not stat.S_IMODE(info.st_mode) & 0o077,
        "credential-directory-mode",
    )
    no_acl(directory)
    path = directory / "auth"
    info = path.lstat()
    check(
        stat.S_ISREG(info.st_mode)
        and info.st_uid in {0, os.getuid()}
        and stat.S_IMODE(info.st_mode) == 0o400,
        "credential-file",
    )
    no_acl(path)
    secrets = read_json(path)
    check(secrets["version"] == 1 and secrets["account"] == account, "credential-binding")
    check(set(secrets["tokens"]) == set(cfg["tokens"]), "credential-scope")
    for key, value in secrets["tokens"].items():
        check(
            type(value) is str and len(value) == 64 and len(bytes.fromhex(value)) == 32,
            "credential-length",
        )
        check(type(key) is str and len(key) <= 128, "credential-key")
    check(slot in {"primary", "replacement"}, "owner-slot")
    if kind == "owner":
        check(slot == "primary" or name == "m", "owner-slot")
        from pqdid.persistence.endpoint_policy import EndpointPolicy

        endpoint = Path(cfg["slots"][slot]["endpoint"])
        check(
            endpoint == RUN / name / ("owner.sock" if slot == "primary" else "replacement.sock"),
            "endpoint-binding",
        )
        policy = EndpointPolicy(
            identity["uid"], identity["gid"], grp.getgrnam("pqiso-ipc-" + name).gr_gid
        )
        policy.bind_identity()
        policy.validate(endpoint, exists=endpoint.exists())
        check(Path(cfg["store"]) == STATE / "stores" / name / "authority.sqlite3", "store-binding")
        # Store itself has an owner-private parent; validate higher ancestry separately.
        parent = Path(cfg["store"]).parent
        protected(parent, uid=identity["uid"], gid=identity["gid"], mode=0o700, directory=True)
        if not require_store:
            check(not Path(cfg["store"]).exists(), "bootstrap-existing-store")
        if require_store:
            protected(
                Path(cfg["store"]),
                uid=identity["uid"],
                gid=identity["gid"],
                mode=0o600,
                ancestors=False,
            )
        for grant in cfg["grants"]:
            check(grant["identity"] == actual[grant["account"]], "grant-identity")
    return cfg, secrets


def key_from(cfg):
    from pqdid.parameters import decode_parameters
    from pqdid.persistence.records import ServiceKey
    from pqdid.recovery_records import Role

    row = cfg["service"]
    return ServiceKey(
        Role(row["role"]),
        bytes.fromhex(row["service_id"]),
        bytes.fromhex(row["authority_id"]),
        decode_parameters(bytes.fromhex(row["parameters"])),
        bytes.fromhex(row["audience"]),
    )


def client_for(binding, token):
    from pqdid.persistence.endpoint_policy import EndpointPolicy
    from pqdid.persistence.owner_ipc import OwnerClient

    policy = EndpointPolicy(binding["owner_uid"], binding["owner_gid"], binding["transport_gid"])
    return OwnerClient(
        binding["endpoint"],
        bytes.fromhex(binding["scope"]),
        bytes.fromhex(token),
        owner_uid=policy.owner_uid,
        owner_gid=policy.owner_gid,
        endpoint_policy=policy,
    )


def make_owner(cfg, secrets, slot):
    from pqdid.persistence.codec import decode
    from pqdid.persistence.endpoint_policy import EndpointPolicy
    from pqdid.persistence.owner_auth import AuthorityPolicy, Principal
    from pqdid.persistence.owner_service import ContextStore, ManagerClient, Owner
    from pqdid.recovery import DEFAULT_DEPENDENCIES, Dependencies
    from pqdid.statements import decode_state, encode_auth_statement
    from pqdid.verifier_state import CurrentStateReply, ProofVerdict

    key = key_from(cfg)
    grants = tuple(
        Principal(
            g["name"].encode(),
            bytes.fromhex(secrets["tokens"][g["token"]]),
            frozenset(p.encode() for p in g["permissions"]),
            g["identity"]["uid"],
            g["identity"]["gid"],
            bytes.fromhex(g["issuer_service"]) if g.get("issuer_service") else None,
            bytes.fromhex(g["recipient"]) if g.get("recipient") else None,
        )
        for g in cfg["grants"]
    )
    policy = AuthorityPolicy(key, (b"owner-1", b"owner-2"), grants)
    check(policy.scope.hex() == cfg["scope"], "service-scope")
    manager = None
    deps = DEFAULT_DEPENDENCIES
    if cfg["short_role"] == "i":
        bridge = cfg["manager"]
        manager = ManagerClient(
            client_for(bridge, secrets["tokens"][bridge["token"]]), key_from(bridge), key.service_id
        )
        deps = Dependencies(manager=manager, resolver=object(), authorisation=object())
    elif cfg["short_role"] in {"va", "vb"}:
        fixture = decode(read_bytes(CONFIG / "owners" / cfg["short_role"] / "public.bin"))

        class Clock:
            def now(self):
                return 99

        class Nonces:
            def nonce(self):
                return (1).to_bytes(32)

        class Provider:
            def instance(self, expected):
                return key.parameters if expected == key.parameters else None

            def current(self, expected, nonce):
                return CurrentStateReply(
                    nonce, decode_state(key.parameters, fixture[4]), fixture[5]
                )

        class PublicFixtureVerdict:
            """Exact already evaluated synthetic public token; never a cryptographic proof."""

            def verify(self, statement, proof):
                return (
                    ProofVerdict.VALID
                    if (encode_auth_statement(key.parameters, statement), proof)
                    == (fixture[0], fixture[3])
                    else ProofVerdict.INVALID
                )

        deps = Dependencies(
            clock=Clock(),
            provider=Provider(),
            proof_verifier=PublicFixtureVerdict(),
            nonces=Nonces(),
            audience=key.audience,
            request_key=bytes.fromhex(cfg["request_key"]),
        )
    store = ContextStore(Path(cfg["store"]), key, dependencies=deps, authorisation=policy)
    identity = cfg["identity"]
    endpoint_policy = EndpointPolicy(identity["uid"], identity["gid"], cfg["transport_gid"])
    return Owner(
        store,
        policy,
        cfg["slots"][slot]["endpoint"],
        cfg["slots"][slot]["writer"].encode(),
        manager=manager,
        delivery_sessions=((b"pilot-session", b"recipient-A"),) if manager else (),
        endpoint_policy=endpoint_policy,
    )


def event(value):
    print(json.dumps(value), flush=True)
