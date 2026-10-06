"""Bounded control-only subprocess checks; no cryptographic probe runs here."""

import runpy
import sys
from pathlib import Path

import pytest

SUPPORT = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts/validation_support.py"))
extended_profile, supervise = SUPPORT["extended_profile"], SUPPORT["supervise"]


@pytest.mark.parametrize("guard", ["rss", "time", "log"])
def test_supervisor_stops_child_and_reports_limit(tmp_path, guard):
    profile = extended_profile()
    profile["rss_poll_seconds"] = 0.001
    program = "import time; time.sleep(2)"
    if guard == "rss":
        profile["rss_ceiling_bytes"] = 1024 * 1024
        expected = "RSS watchdog ceiling"
    elif guard == "time":
        profile["case_wall_seconds"] = 0.02
        expected = "case wall-time limit"
    else:
        profile["case_log_bytes"] = 100
        program = "import time; print('x'*1000, flush=True); time.sleep(2)"
        expected = "case log-storage limit"
    result = supervise([sys.executable, "-c", program], profile=profile, log=tmp_path / "log")
    assert result["reason"] == expected
    assert result["returncode"] != 0
    assert result["supervised_seconds"] < 2


def test_supervisor_preserves_successful_exit(tmp_path):
    result = supervise(
        [sys.executable, "-c", "print('ok')"], profile=extended_profile(), log=tmp_path / "log"
    )
    assert result["reason"] is None
    assert result["returncode"] == 0
    assert (tmp_path / "log").read_text() == "ok\n"
