"""Five explicitly counted tooling fixtures; no native/protocol test execution."""

import json
import subprocess
import time


def run(guard):
    r = guard.R
    policy, safety = guard.policy, guard.safety
    assert not (r / "fixture-ledger.json").exists()
    rows = []
    known = str(guard.NEXT / "build/CMakeFiles/exp2_native.dir/exp2_native.cpp.o")
    unknown = str(guard.NEXT / "build/CMakeFiles/exp2_native.dir/unregistered.cpp.o")

    def save(name, value):
        (r / name).write_text(json.dumps(value, indent=2) + "\n")

    for n in range(1, 6):
        row = {"id": f"GUARD-{n:02d}", "invocation": 419 + n, "status": "admitted"}
        rows.append(row)
        save("fixture-ledger.json", rows)
        began = time.monotonic()
        try:
            if n == 1:
                result = policy.account([(known, 1387120)], r, guard.NEXT, compiler_active=True)
                assert result["artifacts"] == 1387120 and result["evidence"] == 0
                assert result["roles"][known] == "compiled-binary"
            elif n in {2, 3}:
                path, size = (unknown, 1048577) if n == 2 else (known, 33554433)
                try:
                    policy.account([(path, size)], r, guard.NEXT, compiler_active=True)
                except ValueError as error:
                    expected = "ordinary per-file limit" if n == 2 else "artifact per-file limit"
                    assert str(error) == expected
                    result = {"expected_rejection": expected, "synthetic_size_only": size}
                else:
                    raise AssertionError("expected size rejection was absent")
            else:
                command = ["/usr/bin/sleep", "10"] if n == 4 else ["/usr/bin/true"]
                child = subprocess.Popen(command, start_new_session=True)
                if n == 5:
                    assert child.wait(timeout=1) == 0
                else:
                    assert child.poll() is None
                try:
                    raise RuntimeError("synthetic monitor exception " + str(n))
                except RuntimeError as error:
                    result = safety.failure(
                        error,
                        {
                            "process": child,
                            "owned_process_group": True,
                            "started": began if n == 4 else None,
                        },
                        lambda value, case=n: save(f"GUARD-{case:02d}.failure.json", value),
                    )
                assert result["status"] == "failed" and result["resource_guard_passed"] is False
                assert result["contained"] and result["reaped"] and child.poll() is not None
                assert result["original_error"]["message"] == "synthetic monitor exception " + str(
                    n
                )
                assert result["cgroup_memory_peak"] is None
                if n == 5:
                    assert result["seconds"] is None and result["sampled_tree_RSS_peak"] is None
                    assert result["conservative_charge_seconds"] == 60
            save(f"GUARD-{n:02d}.json", {"outcome": result, "expected_failure_fixture": n >= 2})
            row.update(status="pass", seconds=time.monotonic() - began)
        except BaseException as error:
            row.update(status="failed", seconds=time.monotonic() - began, error=str(error))
            save("fixture-ledger.json", rows)
            raise
        save("fixture-ledger.json", rows)
