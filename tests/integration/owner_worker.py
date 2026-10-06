"""TEST-ONLY provisioning and independent owner/client processes; no production secrets."""

import hashlib
import json
import os
import resource
import select
import socket
import sys
from dataclasses import replace
from pathlib import Path

import durable_worker as legacy

from pqdid.persistence import lifecycle, sqlite_store
from pqdid.persistence.codec import Unavailable, decode, encode
from pqdid.persistence.owner_auth import AuthorityPolicy, Principal
from pqdid.persistence.owner_ipc import OwnerClient, receive
from pqdid.persistence.owner_service import ContextStore, ManagerClient, Owner


def policy(root, role):
    metadata = decode((root / (role + ".grants")).read_bytes())
    principals = tuple(
        Principal(name, secret, frozenset(permissions), uid, gid, issuer, recipient)
        for name, secret, permissions, uid, gid, issuer, recipient in metadata
    )
    key = legacy.store(root, role).key
    return AuthorityPolicy(key, (b"owner-1", b"owner-2"), principals)


def client(root, role, principal, endpoint=None):
    config = policy(root, role)
    grant = next(p for p in config._principals if p.name == principal)
    return OwnerClient(
        endpoint or root / (role + "-ipc") / "s",
        config.scope,
        grant.secret,
        owner_uid=os.getuid(),
        owner_gid=os.getgid(),
    )


def make_owner(root, role, writer, endpoint):
    original = legacy.store(root, role)
    config = policy(root, role)
    deps = original._deps
    manager = None
    if role == "issuer":
        manager = ManagerClient(
            client(root, "manager", b"writer"),
            legacy.store(root, "manager").key,
            original.key.service_id,
        )
        deps = replace(deps, manager=manager)
    store = ContextStore(original._path, original.key, dependencies=deps, authorisation=config)
    delivery = ((b"pilot-session", b"recipient-A"),) if role == "issuer" else ()
    return Owner(store, config, endpoint, writer, manager=manager, delivery_sessions=delivery)


def emit(value):
    print(json.dumps(value), flush=True)


def summary(value):
    if isinstance(value, tuple) and value and value[0] == b"ERROR":
        return {"error": value[1].decode()}
    return {
        "response_sha256": hashlib.sha256(encode(value)).hexdigest(),
        "response_bytes": len(encode(value)),
    }


def main():
    root, mode, name = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    if mode == "owner":
        role, writer, endpoint, fault_op, fault_point = (
            name,
            sys.argv[4].encode(),
            Path(sys.argv[5]),
            sys.argv[6],
            sys.argv[7],
        )
        owner = make_owner(root, role, writer, endpoint)

        fault_hit = False

        def barrier(point):
            nonlocal fault_hit
            if (
                not fault_hit
                and owner.metrics["peers"]
                and owner.metrics["peers"][-1][2] == fault_op
                and point == fault_point
            ):
                fault_hit = True
                emit({"barrier": point, "pid": os.getpid()})
                assert select.select([sys.stdin], [], [], 5)[0]
                assert sys.stdin.readline().strip() == "go"

        sqlite_store._fault = barrier
        lifecycle._fault = barrier
        metrics = owner.serve(
            stop_fd=sys.stdin.fileno(),
            ready=lambda: emit(
                {
                    "ready": True,
                    "pid": os.getpid(),
                    "uid": os.getuid(),
                    "gid": os.getgid(),
                    "scope": owner._policy.scope.hex(),
                    "socket_mode": oct(endpoint.stat().st_mode & 0o777),
                }
            ),
        )
        emit(
            {
                "metrics": metrics,
                "maxrss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
            }
        )
    elif mode == "client":
        # This file is supervisor-provided synthetic input, never an owner request for file access.
        request = decode((root / name).read_bytes())
        endpoint, scope, secret, operation, args, transport_mode = request
        response = None
        try:
            if transport_mode == b"call":
                response = OwnerClient(
                    Path(os.fsdecode(endpoint)),
                    scope,
                    secret,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                ).call(operation, args)
            elif transport_mode == b"capacity":
                connections = []
                try:
                    for _ in range(5):
                        item = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                        item.settimeout(2)
                        item.connect(os.fsdecode(endpoint))
                        connections.append(item)
                    response = (b"CAPACITY", connections[-1].recv(1) == b"")
                finally:
                    for item in connections:
                        item.close()
            else:
                with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
                    connection.settimeout(2)
                    connection.connect(os.fsdecode(endpoint))
                    if transport_mode == b"connected":
                        emit({"connected": True, "pid": os.getpid()})
                        assert select.select([sys.stdin], [], [], 5)[0]
                        assert sys.stdin.readline().strip() == "go"
                    packet = (
                        args
                        if transport_mode == b"raw"
                        else encode((1, scope, secret, operation, args))
                    )
                    if transport_mode == b"raw" and packet == b"OVERSIZE":
                        packet = b"x" * 65537
                    if transport_mode != b"idle":
                        connection.send(packet)
                    if transport_mode == b"lost":
                        emit({"sent_without_reading": True, "pid": os.getpid()})
                        assert select.select([sys.stdin], [], [], 5)[0]
                    else:
                        response = receive(connection)
        except (Unavailable, OSError) as error:
            response = (
                b"ERROR",
                str(error).encode() if type(error) is Unavailable else b"ipc-unavailable",
            )
        # Return the actual bounded payload to the test coordinator over a private stdout pipe.
        # The coordinator records only tags/digests/counts, never this payload or a capability.
        if response is not None:
            sys.stdout.buffer.write(b"RESULT " + encode(response).hex().encode() + b"\n")
            sys.stdout.buffer.flush()
    else:
        raise AssertionError("unknown fixture mode")


if __name__ == "__main__":
    main()
