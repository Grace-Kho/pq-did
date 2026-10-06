"""Read-only SQLite/runtime/filesystem inspection; no persistent database or experiments."""

import _sqlite3
import datetime
import json
import os
import platform
import sqlite3
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
P = BASE.parents[2]


def command(args):
    value = subprocess.run(args, capture_output=True, text=True, timeout=5, check=True)
    assert len(value.stdout) + len(value.stderr) < 16384
    return {"command": args, "exit_code": value.returncode, "stdout": value.stdout.strip()}


def main():
    # No disk filename; queries only. Memory-database defaults are NOT proposed
    # settings and do not establish existing disk-database configuration.
    with sqlite3.connect(":memory:", autocommit=True, timeout=0.0) as connection:
        options = sorted(row[0] for row in connection.execute("PRAGMA compile_options"))
        defaults = {
            name: connection.execute("PRAGMA " + name).fetchall()
            for name in [
                "journal_mode",
                "synchronous",
                "locking_mode",
                "temp_store",
                "foreign_keys",
                "busy_timeout",
                "page_size",
                "cache_size",
            ]
        }
        source_id = connection.execute("SELECT sqlite_source_id()").fetchone()[0]
        linked = connection.execute("SELECT sqlite_version()").fetchone()[0]
        assert linked == sqlite3.sqlite_version
        limits = {
            name: connection.getlimit(getattr(sqlite3, name))
            for name in [
                "SQLITE_LIMIT_LENGTH",
                "SQLITE_LIMIT_SQL_LENGTH",
                "SQLITE_LIMIT_VARIABLE_NUMBER",
                "SQLITE_LIMIT_ATTACHED",
            ]
        }
    fs = os.statvfs(P)
    facts = {
        "package": "S2-RECOVERY-AUTHORITY-DESIGN-1",
        "observed_utc": datetime.datetime.now(datetime.UTC).isoformat(),
        "python": sys.version,
        "executable": sys.executable,
        "sqlite_version": linked,
        "sqlite_version_info": list(sqlite3.sqlite_version_info),
        "sqlite_source_id": source_id,
        "sqlite_threadsafety": sqlite3.threadsafety,
        "sqlite_extension": _sqlite3.__file__,
        "compile_options": options,
        "memory_database_query_defaults_only": defaults,
        "connection_limits_observed_only": limits,
        "kernel": platform.release(),
        "project_path": str(P),
        "project_mode": oct(P.stat().st_mode & 0o777),
        "project_is_symlink": P.is_symlink(),
        "filesystem": command(
            ["findmnt", "--target", str(P), "--output", "TARGET,SOURCE,FSTYPE,OPTIONS", "--json"]
        ),
        "sqlite_linkage": command(["ldd", _sqlite3.__file__]),
        "filesystem_block_bytes": fs.f_frsize,
        "filesystem_available_bytes": fs.f_bavail * fs.f_frsize,
        "persistent_databases_opened": 0,
        "persistent_databases_created": 0,
        "settings_changed": False,
        "dependencies_installed": 0,
        "wal_enabled": False,
        "crash_experiments": 0,
        "power_loss_guarantee_tested": False,
        "hardware_flush_and_VHD_durability_verified": False,
    }
    assert len(options) <= 200
    encoded = json.dumps(facts, indent=2) + "\n"
    assert len(encoded.encode()) < 32768
    (BASE / "sqlite-environment.json").write_text(encoded)
    print(
        json.dumps(
            {
                key: facts[key]
                for key in [
                    "sqlite_version",
                    "sqlite_source_id",
                    "kernel",
                    "persistent_databases_created",
                    "settings_changed",
                ]
            }
        )
    )


if __name__ == "__main__":
    main()
