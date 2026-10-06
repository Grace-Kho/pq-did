"""Fixed actual-identity test client; private result files, bounded public metadata."""

import argparse
import array
import errno
import os
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from layout import CONFIG, RELEASE, STATE, check, json_bytes, read_json, write_new
from runtime import client_for, config_path, startup


def probes(paths):
    rows = []
    for name in paths:
        path = Path(name)
        check(path.is_absolute() and ".." not in path.parts, "probe-path")
        check(
            any(
                path.is_relative_to(p)
                for p in (CONFIG, RELEASE, STATE, Path("/run/pqiso"), Path("/proc"))
            ),
            "probe-scope",
        )
        for action in ("read", "write", "unlink", "replace"):
            try:
                if action == "read":
                    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    os.close(fd)
                elif action == "write":
                    fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    os.close(
                        fd
                    )  # Never overwrite bytes even if a permission is unexpectedly granted.
                elif action == "unlink":
                    # Use a same-parent root-authored sacrificial leaf, not retained state.
                    (path.parent / ".denial-probe").unlink()
                else:
                    fd = os.open(
                        path.parent / ".replacement-probe",
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                    )
                    os.close(fd)
                rows.append((action.encode(), name.encode(), b"UNEXPECTED-ACCESS"))
            except OSError as error:
                check(
                    error.errno in {errno.EACCES, errno.EPERM, errno.EROFS, errno.ENOENT},
                    "probe-harness-error",
                )
                # ENOENT is valid only for hidden /proc. A missing fixture is a harness failure.
                check(
                    error.errno != errno.ENOENT or path.is_relative_to("/proc"),
                    "missing-probe-fixture",
                )
                rows.append((action.encode(), name.encode(), str(error.errno).encode()))
    return tuple(rows)


def execute(cfg, secrets, request):
    from pqdid.persistence.codec import Unavailable, decode, encode
    from pqdid.persistence.owner_ipc import peer_credentials, receive

    mode = request["mode"]
    if mode == "probe":
        return probes(request["paths"])
    if mode == "runtime":
        from importlib.metadata import version

        from pqdid.backend import LIBRARY, load_backend

        backend = load_backend()
        check(version("liboqs-python") == "0.16.0", "runtime-version")
        check(Path(backend.__file__).is_relative_to(RELEASE), "binding-origin")
        check(Path(sys.prefix) == RELEASE / ".venv", "runtime-prefix")
        check(str(LIBRARY.resolve()) in Path("/proc/self/maps").read_text(), "native-mapping")
        for entry in sys.path:
            check(
                entry
                and (Path(entry).is_relative_to(RELEASE) or Path(entry).is_relative_to("/usr")),
                "import-origin",
            )
        for protected_path in (RELEASE / "owner_entry.py", RELEASE / "release-manifest.json"):
            try:
                fd = os.open(protected_path, os.O_WRONLY | os.O_NOFOLLOW)
            except PermissionError:
                pass
            except OSError as error:
                check(error.errno == errno.EROFS, "runtime-write-harness")
            else:
                os.close(fd)
                raise PermissionError("mutable-runtime")
        return (b"RUNTIME", str(LIBRARY.resolve()).encode(), version("liboqs-python").encode())
    if mode == "fds":
        rows = []
        for path in Path("/proc/self/fd").iterdir():
            try:
                target = os.readlink(path)
            except FileNotFoundError:
                continue
            check(int(path.name) <= 2, "inherited-descriptor")
            rows.append((path.name.encode(), target.encode()))
        return tuple(rows)
    binding = dict(cfg["bindings"][request["role"]])
    if request.get("replacement"):
        check(request["role"] == "m", "replacement-role")
        binding["endpoint"] = "/run/pqiso/m/replacement.sock"
    token = secrets["tokens"].get(request.get("token"), "00" * 32)
    # Root-only synthetic test injection; never accepted as owner authentication identity.
    if request.get("injected_token") is not None:
        token = request["injected_token"]
    client = client_for(binding, token)
    operation = request.get("operation", "status").encode()
    arguments = decode(bytes.fromhex(request.get("arguments", encode(()).hex())))
    if mode == "rpc":
        try:
            return client.call(operation, arguments)
        except Unavailable as error:
            return (b"ERROR", str(error).encode())
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
        connection.settimeout(2)
        try:
            connection.connect(binding["endpoint"])
        except PermissionError:
            return (b"DAC-DENIED",)
        check(
            peer_credentials(connection)[1:] == (binding["owner_uid"], binding["owner_gid"]),
            "actual-owner-peer",
        )
        packet = encode(
            (1, bytes.fromhex(binding["scope"]), bytes.fromhex(token), operation, arguments)
        )
        if mode == "rights":
            fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
            try:
                connection.sendmsg(
                    [packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))]
                )
            finally:
                os.close(fd)
            return receive(connection)
        if mode == "drop":
            connection.send(packet)
            return (b"REPLY-NOT-OBSERVED",)
        check(mode == "connected", "client-mode")
        # Handshake with root coordinator without passing a socket or capability to it.
        root = STATE / "clients" / cfg["account"]
        write_new(root / "connected", b"connected", uid=os.getuid(), gid=os.getgid())
        import time

        until = time.monotonic() + 0.4
        while time.monotonic() < until:
            if (CONFIG / "clients" / cfg["account"] / "go").exists():
                connection.send(packet)
                return receive(connection)
            time.sleep(0.001)
        raise TimeoutError("connected-client-barrier")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--principal", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--credentials-directory", required=True)
    args = parser.parse_args()
    check(Path(args.policy) == config_path("client", args.principal), "policy-binding")
    cfg, secrets = startup("client", args.principal, args.credentials_directory)
    from layout import protected

    request_path = config_path("client", args.principal).parent / "request.json"
    protected(request_path, gid=os.getgid(), mode=0o640)
    request = read_json(request_path)
    from pqdid.persistence.codec import encode

    result = execute(cfg, secrets, request)
    root = STATE / "clients" / args.principal
    write_new(root / "response.bin", encode(result), uid=os.getuid(), gid=os.getgid())
    write_new(
        root / "identity.json",
        json_bytes(
            {
                "uid": os.getuid(),
                "gid": os.getgid(),
                "groups": sorted(set(os.getgroups()) | {os.getgid()}),
                "pid": os.getpid(),
                "mode": request["mode"],
            }
        ),
        uid=os.getuid(),
        gid=os.getgid(),
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json_bytes({"client": "failed", "error_type": type(error).__name__}).decode())
        raise SystemExit(1) from None
