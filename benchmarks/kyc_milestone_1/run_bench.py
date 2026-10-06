"""Guarded runner. Every scenario requires a coordinator-issued invocation receipt."""

import argparse
import fcntl
import json
import os
import sys
import time
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "benchmarks.kyc_milestone_1"

from .backends import ReferenceBackend, unavailable_operations
from .export import BoundedWriter, Exporter, require, validate_record
from .measure import environment, input_identities, resource_observation, sha256_file
from .scenarios import Trial, session_trials


class ExclusiveMeasurement:
    """The coordinator additionally excludes all unrelated jobs during this lock."""

    def __init__(self, path):
        self.path, self.fd = Path(path), None

    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise
        return self

    def __exit__(self, *_):
        os.close(self.fd)
        self.fd = None


class InvocationClaims:
    """Duplicate prevention only. Resource admission belongs to the shared coordinator."""

    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(mode=0o700, exist_ok=True)

    def claim(self, receipt):
        required = {"invocation_id", "case_id", "ordinal", "cumulative_invocations"}
        require(type(receipt) is dict and required <= set(receipt), "coordinator receipt fields")
        identifier = receipt["invocation_id"]
        require(type(identifier) in {str, int}, "receipt invocation identifier")
        name = str(identifier)
        require(
            name and len(name) <= 100 and all(c.isalnum() or c in "_-" for c in name),
            "receipt filename",
        )
        require(type(receipt["ordinal"]) is int and receipt["ordinal"] > 0, "receipt ordinal")
        require(type(receipt["cumulative_invocations"]) is int, "receipt cumulative counter")
        descriptor = os.open(self.root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(receipt, stream, sort_keys=True)


class SessionRunner:
    def __init__(self, config):
        self.config = config
        self.trials = session_trials(config["scenario"], config["session"])
        self.export = Exporter(config["output"])
        self.disposals = BoundedWriter(self.export.root, "store-disposition", "jsonl")
        self.claims = InvocationClaims(config["claims_root"])
        self.backend = None
        self.position = 0
        self.last_record = None
        self.env = environment(config["guard"])
        self.identities = input_identities()
        self.store_root = Path(config["store_root"])
        self.store_root.mkdir(mode=0o700, exist_ok=False)

    def trial(self, trial, receipt):
        require(
            self.position < len(self.trials) and trial == self.trials[self.position],
            "session trial order; cold requires a fresh process",
        )
        self.claims.claim(receipt)
        self.position += 1  # Failed trials consume their position; no silent retry.
        setup_start = time.monotonic_ns()
        keygen_ns = 0
        start = setup_start
        outcome, reason, details = "incomplete", None, {}
        stages, parents, messages = {}, {}, {}
        fixture_hash, instance_hash = None, None
        signing = {
            "attempts": None,
            "exhaustion": None,
            "reason": "underlying bounded signer does not export aggregate attempt counts",
        }
        censoring = None
        try:
            if self.backend is None:
                self.backend = ReferenceBackend(epoch_base=self.config["epoch_base"])
                keygen_ns = self.backend.keygen_ns
            self.backend.setup(self.store_root / trial.name, trial.scenario)
            start = time.monotonic_ns()
            if trial.scenario == "ISSUE":
                result = self.backend.issue()
            elif trial.scenario.startswith("PRESENT-"):
                result = self.backend.present(trial.scenario[-1])
            else:
                result = self.backend.revoke_update()
            observed_end = time.monotonic_ns()
            operation_start = result.get("operation_start_monotonic_ns", start)
            operation_end = result.get("operation_end_monotonic_ns", observed_end)
            require(
                start <= operation_start <= operation_end <= observed_end,
                "scenario operation timing bounds",
            )
            start, end = operation_start, operation_end
            outcome = result["outcome"]
            stages = result.get("stages_ns", {})
            parents = result.get("stage_parents", {name: None for name in stages})
            messages = {
                name: ({"canonical": size, "transport": size} if type(size) is int else size)
                for name, size in result.get("message_bytes", {}).items()
            }
            fixture_hash = result.get("fixture_sha256")
            instance_hash = result.get("instance_sha256")
            signing = result.get("signing", signing)
            details = {
                name: result[name]
                for name in (
                    "disclosure",
                    "state",
                    "outcome_details",
                    "fixture_encoding",
                    "source_fixture_sha256",
                )
                if name in result
            }
        except Exception as error:
            end = time.monotonic_ns()
            if start == setup_start:
                start = end
            reason = f"{type(error).__name__}: scenario did not complete; no retry"
            outcome = "unexpected-rejection"
            if isinstance(error, TimeoutError):
                outcome = "resource-abort"
                censoring = {
                    "observed_complete": False,
                    "deadline_seconds": self.config["deadline_seconds"],
                }
        setup_ns = start - setup_start
        record = {
            "version": 1,
            "run_id": self.config["run_id"],
            "attempt_id": trial.name,
            "invocation_id": receipt["invocation_id"],
            "session_id": f"session-{trial.session}",
            "scenario_id": trial.scenario,
            "phase": trial.phase,
            "trial_index": trial.index,
            "capability": self.backend.capabilities() if self.backend else {"private_auth": False},
            "category": "mldsa_reference_measured",
            "measurement_origin": "actual",
            "outcome": outcome,
            "reason": reason,
            "start_monotonic_ns": start,
            "end_monotonic_ns": end,
            "duration_ns": end - start,
            "stages_ns": stages,
            "stage_parents": parents,
            "setup_ns": setup_ns,
            "keygen_ns": keygen_ns,
            "message_bytes": messages,
            "identities": self.identities,
            "fixture_sha256": fixture_hash,
            "instance_sha256": instance_hash,
            "signing": signing,
            "resources": resource_observation(),
            "counters": {**receipt, "reserved": True, "trial_in_session": self.position},
            "environment": self.env,
            "unavailable": unavailable_operations(),
            "censoring": censoring,
            "details": {
                **details,
                "epoch_base": self.config["epoch_base"],
                "valid_until_substitution": self.config["epoch_base"] + 86400,
                "session_lifetime_seconds": 120,
                "require_did_state": False,
                "semantic_fixture": "alpha-42-old-002c",
                "clock": "synthetic epoch plus monotonic elapsed",
                "message_transport": "local canonical binary payloads; no network envelope",
                "timing": "outer duration only is end-to-end; nested stage values are not summed",
                "resource_measurement": "job/process cumulative observations; not per-trial peaks",
            },
        }
        self.last_record = record
        output_stage = "validation"
        try:
            validate_record(record)
            output_stage = "export"
            self.export.append(record)
            if outcome == "accepted" and self.config.get("dispose_trial_stores") is True:
                output_stage = "store-disposition"
                self._dispose(trial)
        except Exception as error:
            # Preserve the actual operation observation without labelling output
            # failure a completed case. The coordinator must charge/mark failure.
            failure = {
                "attempt_id": trial.name,
                "invocation_id": receipt["invocation_id"],
                "case_completed": False,
                "output_stage": output_stage,
                "error_type": type(error).__name__,
                "record": record,
            }
            try:
                contents = json.dumps(failure, sort_keys=True, allow_nan=False).encode() + b"\n"
                self.export._exclusive_file(trial.name + ".incomplete.json", contents)
            except Exception as preservation_error:
                error.add_note(
                    "failure evidence write also failed: " + type(preservation_error).__name__
                )
            raise
        return record

    def _dispose(self, trial):
        """Dispose only this successful, fresh, registered synthetic trial's stores.

        Retain per-file hashes/sizes before removal, excluding secret key hashes.
        Failed trials remain available for diagnosis. The baseline's exact owned
        file allowlist rejects symlinks, hardlinks and unknown entries.
        """
        directory = self.store_root / trial.name
        require(directory.parent == self.store_root and not directory.is_symlink(), "store scope")
        files = self.backend.storage_inventory()
        for item in files:
            if not item["secret_material"]:
                item["sha256"] = sha256_file(directory / item["path"])
            else:
                item["sha256"] = None
                item["reason"] = "secret-key contents excluded from evidence"
        before = {
            "attempt_id": trial.name,
            "action": "registered-disposable-store-hashes",
            "files": files,
        }
        self.disposals.append(json.dumps(before, sort_keys=True).encode() + b"\n")
        self.backend.cleanup()
        self.disposals.append(
            json.dumps(
                {
                    "attempt_id": trial.name,
                    "action": "disposed",
                    "bytes": sum(item["bytes"] for item in files),
                }
            ).encode()
            + b"\n"
        )

    def finalise(self):
        self.disposals.close()
        return self.export.finalise()


def run_session(config, reserve_trial):
    """One fresh guarded process per call; reserve_trial(Trial) charges each attempt first.

    The callback is supplied by the coordinator and must atomically check/charge its
    shared ledger. This module never manufactures receipts or reserves extra trials.
    """
    with ExclusiveMeasurement(config["lock_path"]):
        runner = SessionRunner(config)
        try:
            for trial in runner.trials:
                receipt = reserve_trial(trial)
                result = runner.trial(trial, receipt)
                if result["outcome"] != "accepted":
                    raise RuntimeError("counted benchmark trial failed; retained for correction")
        finally:
            runner.finalise()
    return runner.export.records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("worker",))
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    with ExclusiveMeasurement(config["lock_path"]):
        runner = SessionRunner(config)
        try:
            # A long-lived process keeps loaded parameters for the two warm-ups
            # and twenty warm samples. The parent reserves each request separately.
            for line in sys.stdin:
                request = json.loads(line)
                if request.get("command") == "finish":
                    break
                trial = Trial(**request["trial"])
                row = runner.trial(trial, request["receipt"])
                print(
                    json.dumps(
                        {
                            "attempt_id": row["attempt_id"],
                            "outcome": row["outcome"],
                            "invocation_id": row["invocation_id"],
                        }
                    ),
                    flush=True,
                )
                if row["outcome"] != "accepted":
                    raise RuntimeError("counted benchmark trial failed; retained for correction")
        finally:
            runner.finalise()


if __name__ == "__main__":
    main()
