"""Bounded pathname AF_UNIX/SEQPACKET frames and explicit one-shot client calls."""

import os
import socket
import stat
import struct
from pathlib import Path

from .codec import CAP, Unavailable, decode, encode, require
from .endpoint_policy import EndpointPolicy

CONNECTIONS = 4
ACCEPTS = 64
IDLE_SECONDS = 0.5
OPERATION_SECONDS = 1.0
OWNER_SECONDS = 20
CLIENT_SECONDS = 2.0


def endpoint_path(value, *, exists, policy=None):
    if policy is not None:
        require(type(policy) is EndpointPolicy, "endpoint-policy")
        return policy.validate(value, exists=exists)
    path = Path(value)
    require(path.is_absolute() and path.resolve() == path, "endpoint-path")
    require(len(os.fsencode(path)) <= 107, "endpoint-path")
    require(all(not p.is_symlink() for p in (path, *path.parents)), "endpoint-path")
    info = path.parent.stat()
    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "endpoint-owner")
    if exists:
        info = path.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid(), "endpoint-owner")
        require(stat.S_IMODE(info.st_mode) == 0o600, "endpoint-mode")
    else:
        require(not path.exists(), "endpoint-exists")
    return path


def peer_credentials(connection):
    # Kernel result, never a request field. PID is evidence only, not an authorisation key.
    return struct.unpack("iII", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))


def receive(connection):
    data, ancillary, flags, _ = connection.recvmsg(CAP + 1, 0)
    require(data and len(data) <= CAP, "malformed-frame")
    require(not ancillary and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), "malformed-frame")
    return decode(data)


def send(connection, value):
    packet = encode(value)
    require(
        connection.send(packet, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL) == len(packet),
        "unavailable",
    )


class OwnerClient:
    """Configured endpoint/scope/capability; no database fallback and no automatic retry."""

    def __init__(self, path, scope, secret, *, owner_uid, owner_gid, endpoint_policy=None):
        self._path, self._scope, self._secret = Path(path), scope, secret
        self._peer = (owner_uid, owner_gid)
        require(
            endpoint_policy is None
            or (
                type(endpoint_policy) is EndpointPolicy
                and (endpoint_policy.owner_uid, endpoint_policy.owner_gid) == self._peer
            ),
            "endpoint-policy",
        )
        self._endpoint_policy = endpoint_policy

    def call(self, operation, arguments=()):
        request = encode((1, self._scope, self._secret, operation, arguments))
        try:
            endpoint_path(self._path, exists=True, policy=self._endpoint_policy)
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
                connection.settimeout(CLIENT_SECONDS)
                connection.connect(str(self._path))
                require(peer_credentials(connection)[1:] == self._peer, "owner-peer")
                require(connection.send(request) == len(request), "unavailable")
                result = receive(connection)
            if type(result) is tuple and result[:1] == (b"ERROR",):
                require(len(result) == 2 and type(result[1]) is bytes, "malformed-reply")
                raise Unavailable(result[1].decode("ascii"))
            return result
        except OSError:
            raise Unavailable("ipc-unavailable") from None
