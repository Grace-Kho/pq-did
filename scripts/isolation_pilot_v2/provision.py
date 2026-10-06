"""Explicit fresh-only host provisioning. Imported only by the approved controller."""

import os
import shutil
import subprocess
from pathlib import Path

from layout import (
    ACCOUNTS,
    CONFIG,
    PROJECT,
    PROPOSAL,
    RELEASE,
    RUN,
    STATE,
    UNITS,
    check,
    collision_report,
    digest,
    identities,
    json_bytes,
    protected,
    read_bytes,
    read_json,
    root_required,
    write_new,
)


def source_files():
    paths = list((PROJECT / "src/pqdid").rglob("*.py"))
    site = PROJECT / ".venv/lib/python3.14/site-packages"
    paths += list((site / "oqs").glob("*.py"))
    paths += [p for p in (site / "liboqs_python-0.16.0.dist-info").rglob("*") if p.is_file()]
    paths += [p for p in (PROJECT / "native/.deps/install").rglob("*") if p.is_file()]
    paths += [
        p
        for p in (PROJECT / "scripts/isolation_pilot_v2").glob("*.py")
        if p.name not in {"fixture_factory.py", "isolation_pytest.py"}
    ]
    paths += list(PROPOSAL.glob("*.in"))
    return sorted(set(paths))


def destination(source):
    relative = source.relative_to(PROJECT)
    name = str(relative)
    if name.startswith("scripts/isolation_pilot_v2/"):
        return RELEASE / source.name
    if source.parent == PROPOSAL:
        return RELEASE / "templates" / source.name
    return RELEASE / relative


def verify_authorisation():
    """Verify the corrected runtime AND frozen local admission inputs before mutation."""
    seal = read_json(PROPOSAL / "source-manifest.json", 262144)
    check(seal.get("version") == 2, "corrected-authorisation-version")
    sources = source_files()
    check(set(seal["sha256"]) == {str(p.relative_to(PROJECT)) for p in sources}, "source-inventory")
    for name, expected in {**seal["sha256"], **seal["control_inputs_sha256"]}.items():
        relative = Path(name)
        check(
            not relative.is_absolute() and ".." not in relative.parts and str(relative) == name,
            "sealed-control-path",
        )
        check(digest(PROJECT / relative) == expected, "sealed-input-changed")
    return seal


def mkdir(path, uid=0, gid=0, mode=0o755):
    path.mkdir(mode=mode)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def run(*args):
    return subprocess.run(
        args,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        close_fds=True,
    )


def record(path, value, gid=0, mode=0o640):
    write_new(path, json_bytes(value), gid=gid, mode=mode)


def track_installed(path):
    from layout import atomic_json

    creation = read_json(CONFIG / "creation.json")
    creation["created_files"][str(path)] = digest(path)
    atomic_json(CONFIG / "creation.json", creation)


def provision():
    root_required()
    check(not collision_report(), "existing-pilot-resource")
    for parent in (
        "/etc",
        "/opt",
        "/var/lib",
        "/run",
        "/etc/systemd/system",
        "/etc/tmpfiles.d",
    ):
        protected(Path(parent), directory=True)
    units = subprocess.run(
        ["/usr/bin/systemctl", "list-units", "--all", "--no-legend", "--plain", "pqiso*"],
        capture_output=True,
        timeout=5,
        check=True,
    )
    check(len(units.stdout) < 32768 and not units.stderr, "unit-collision-inspection")
    check(
        all(
            line.split()[0] == b"pqiso-guard-provision.service"
            for line in units.stdout.splitlines()
            if line.split()
        ),
        "existing-pilot-unit",
    )
    from shared_parent import inspect_parent

    parent_existed = inspect_parent()
    seal = read_json(PROPOSAL / "source-manifest.json", 262144)
    sources = source_files()
    check(set(seal["sha256"]) == {str(p.relative_to(PROJECT)) for p in sources}, "source-inventory")
    for source in sources:
        check(digest(source) == seal["sha256"][str(source.relative_to(PROJECT))], "source-changed")
    inputs = PROJECT / "docs/data/s2_authority_isolation_pilot_1/activation-inputs"
    check(read_json(inputs / "label.json")["synthetic"] is True, "synthetic-inputs")
    expected_inputs = seal["synthetic_inputs_sha256"]
    check({p.name for p in inputs.iterdir()} == set(expected_inputs), "approved-input-inventory")
    for name, expected in expected_inputs.items():
        check(digest(inputs / name) == expected, "approved-input-digest")
    check(sum(p.stat().st_size for p in sources) < 64 * 1024 * 1024, "release-storage")
    # First marker reserves the entire previously absent pilot namespace. Partial failure
    # is retained for review, never adopted by a subsequent invocation.
    mkdir(CONFIG)
    record(
        CONFIG / "creation.json",
        {
            "version": 1,
            "status": "provisioning",
            "source_manifest_sha256": digest(PROPOSAL / "source-manifest.json"),
            "accounts": list(ACCOUNTS),
            "created_files": {},
            "shared_sysusers_parent": {
                "path": "/etc/sysusers.d",
                "existed_before": parent_existed,
                "created_by_pilot": None,
                "status": "intent",
                "retain": True,
            },
            "retained_paths": [str(CONFIG), str(STATE), str(RELEASE.parent), str(RUN)],
        },
        mode=0o600,
    )
    from layout import atomic_json
    from shared_parent import ensure_parent

    made_parent = ensure_parent()
    creation = read_json(CONFIG / "creation.json")
    creation["shared_sysusers_parent"].update(
        created_by_pilot=made_parent, status="created" if made_parent else "validated-existing"
    )
    atomic_json(CONFIG / "creation.json", creation)
    account_file = Path("/etc/sysusers.d/pqiso.conf")
    write_new(account_file, read_bytes(PROPOSAL / "accounts.sysusers.conf.in"), mode=0o644)
    track_installed(account_file)
    run("/usr/bin/systemd-sysusers", str(account_file))
    ids = identities()
    directory_file = Path("/etc/tmpfiles.d/pqiso.conf")
    # CONFIG was exclusively created above; exclude its one already established line.
    lines = read_bytes(PROPOSAL / "directories.tmpfiles.conf.in").decode().splitlines()
    data = "\n".join(line for line in lines if not line.startswith("d /etc/pqiso ")) + "\n"
    write_new(directory_file, data.encode(), mode=0o644)
    track_installed(directory_file)
    run("/usr/bin/systemd-tmpfiles", "--create", str(directory_file))
    mkdir(STATE / "inputs", mode=0o700)
    for path in inputs.iterdir():
        check(
            path.name
            in {
                "manager.fixture",
                "issuer.fixture",
                "issued.fixture",
                "verifier0.fixture",
                "verifier1.fixture",
                "verifier0.public",
                "verifier1.public",
                "label.json",
            },
            "fixture-inventory",
        )
        write_new(STATE / "inputs" / path.name, read_bytes(path))
    mkdir(RELEASE.parent)
    mkdir(RELEASE)
    run("/usr/bin/python3.14", "-I", "-B", "-m", "venv", "--without-pip", str(RELEASE / ".venv"))
    compatibility_link = RELEASE / ".venv/lib64"
    if compatibility_link.is_symlink():
        check(os.readlink(compatibility_link) == "lib", "venv-lib64-link")
        # The canonical lib site avoids a duplicate directory inventory.
        compatibility_link.unlink()
    for source in sources:
        target = destination(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            check(source.resolve().is_relative_to(PROJECT / "native/.deps/install"), "native-link")
            check(not Path(os.readlink(source)).is_absolute(), "absolute-native-link")
            target.symlink_to(os.readlink(source))
        else:
            with source.open("rb") as src, target.open("xb") as dst:
                shutil.copyfileobj(src, dst, length=65536)
            os.chmod(target, 0o644)
    for source in sources:
        check(
            digest(destination(source)) == seal["sha256"][str(source.relative_to(PROJECT))],
            "copy-digest",
        )
    site = RELEASE / ".venv/lib/python3.14/site-packages"
    write_new(site / "pqdid.pth", (str(RELEASE / "src") + "\n").encode(), mode=0o644)
    for path in RELEASE.rglob("*"):
        if not path.is_symlink():
            os.chmod(
                path, 0o755 if path.is_dir() or path.parent == RELEASE / ".venv/bin" else 0o644
            )
    hashes = {
        str(p.relative_to(RELEASE)): digest(p)
        for p in RELEASE.rglob("*")
        if p.is_file() or p.is_symlink()
    }
    record(RELEASE / "release-manifest.json", {"version": 1, "files": hashes}, mode=0o644)
    # Public structure/private credentials are constructed only by the protected runtime.
    run(str(RELEASE / ".venv/bin/python"), "-I", "-B", str(RELEASE / "configure.py"))
    installed = [account_file, directory_file]
    for name in UNITS:
        source = PROPOSAL / (name + ".in")
        if not source.exists():
            continue
        target = Path("/etc/systemd/system") / name
        write_new(target, read_bytes(source), mode=0o644)
        track_installed(target)
        installed.append(target)
    run(
        "/usr/bin/systemd-analyze",
        "verify",
        *[str(p) for p in installed if p.suffix in {".service", ".slice"}],
    )
    from layout import atomic_json

    creation = read_json(CONFIG / "creation.json")
    creation.update(
        status="provisioned-inactive",
        identities=ids,
        created_files={str(p): digest(p) for p in installed},
    )
    atomic_json(CONFIG / "creation.json", creation)
    record(
        CONFIG / "ACTIVATION-AUTHORISED",
        {
            "source_manifest": seal["package"],
            "release_manifest_sha256": digest(RELEASE / "release-manifest.json"),
        },
        mode=0o600,
    )
    run("/usr/bin/systemctl", "daemon-reload")


def rollback():
    """Quarantine data/account IDs; remove only matching installed control files."""
    root_required()
    protected(CONFIG / "creation.json", mode=0o600)
    record = read_json(CONFIG / "creation.json")
    from control import shutdown

    stopped = shutdown(final=True)
    check(type(stopped) is dict and stopped.get("complete") is True, "rollback-shutdown-incomplete")
    # Validate the complete removal list before removing any file.
    allowed = {str(Path("/etc/systemd/system") / n) for n in UNITS}
    allowed |= {"/etc/sysusers.d/pqiso.conf", "/etc/tmpfiles.d/pqiso.conf"}
    files = record["created_files"]
    check(set(files) <= allowed, "rollback-scope")
    for name, expected in files.items():
        protected(Path(name), mode=0o644)
        check(digest(name) == expected, "rollback-file-changed")
    marker = CONFIG / "ACTIVATION-AUTHORISED"
    if marker.exists():
        protected(marker, mode=0o600)
        marker.unlink()
    for name in files:
        Path(name).unlink()
    from layout import atomic_json

    record.update(status="quarantined", removed_files=list(files), created_files={})
    atomic_json(CONFIG / "creation.json", record)
    run("/usr/bin/systemctl", "daemon-reload")
