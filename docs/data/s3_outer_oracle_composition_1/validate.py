"""One documentation-contract consistency check; no mathematical or crypto tests."""

# ruff: noqa: E402

import json
import sys
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
sys.path.insert(0, str(P))
from scripts import preservation_audit as audit


def main():
    contract = json.loads((D / "games.json").read_text())
    sources = json.loads((D / "sources.json").read_text())
    report = (P / "docs/stage3_outer_oracle_composition.md").read_text()
    games = {row["id"]: row for row in contract["games"]}
    obligations = {row["id"] for row in contract["obligations"]}
    source_ids = {row["id"] for row in sources["sources"]}
    assert len(games) == len(contract["games"]) == 6
    assert set(games) == set(contract["game_ids"])
    assert obligations == {"OC-REL", "OC-EXT", "OC-PRIV", "OC-BUDGET", "A-K-MODEL"}
    transitions = contract["transitions"]
    assert len({row["id"] for row in transitions}) == len(transitions) == 7
    for row in transitions:
        assert row["from"] in games
        assert row["status"] in {"supported", "conditional", "unresolved"}
        assert row["source"] in source_ids | {"A-K-MODEL", "missing-lemma"}
        assert set(row.get("requires", [])) <= obligations
        assert row["budget"] and row["covers"] and row["id"] in report
        if row["status"] == "unresolved":
            assert row["source"] == "missing-lemma" and row["requires"]
        assert row.get("full_protocol_claim") is not True
    for name in [*games, *obligations, "J-BIT", "J-EX", "J-PRIV"]:
        assert name in report
    assert not contract["actors"]["S_perm"]["programming"]
    assert not contract["actors"]["S_perm"]["shared_oracle_state_read"]
    assert not contract["actors"]["S_perm"]["reset_at_cutoff"]
    assert not contract["actors"]["Sim_proof"]["witness_or_selected_index"]
    assert not contract["actors"]["E_DFMS"]["external_service_rewind"]
    assert all(value is None for value in contract["unknowns"].values())
    assert contract["concrete_security_number"] is None
    assert not contract["unresolved_terms_are_additive_bounds"]
    assert contract["new_numerical_calculations"] == 0
    assert contract["next_package"] == "S2-BOUNDED-MLDSA-KEYGEN-SIGN-1"
    assert not contract["next_package_started"] and not contract["stages_2_3_complete"]
    assert contract["proof_attempts_used"] == 2 and contract["proof_attempts_unused"] == 1
    for name in ["docs/status.md", "docs/traceability.md", "docs/spec_issues.md"]:
        text = (P / name).read_text()
        assert contract["package"] in text and contract["next_package"] in text
    audit.write_report(
        D / "documentation-checks.json",
        [
            {
                "name": "game-interface-classification-and-documentation-consistency",
                "passed": True,
                "games": 6,
                "transitions": 7,
                "open_obligations": 5,
                "mathematical_proof_or_numeric_validation": False,
            }
        ],
    )
    print(json.dumps({"documentation_checks": 1, "passed": True, "new_calculations": 0}))


if __name__ == "__main__":
    main()
