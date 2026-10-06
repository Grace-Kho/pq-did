"""Conservative range review of the cached primary advisory database, not a security proof."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
audit = json.loads((ROOT / "evidence/dependency_audit.json").read_text())


def version(s):
    core, sep, pre = s.partition("-")
    values = tuple(map(int, core.split(".")))
    return values + (0,) * (3 - len(values)) + (0 if sep else 1, pre)


def matches(v, expression):
    actual = version(v)
    for part in expression.split(","):
        m = re.fullmatch(r"\s*(>=|<=|>|<|=|\^)?\s*(\d+(?:\.\d+){0,2}(?:-[\w.]+)?)\s*", part)
        if not m:
            raise ValueError("unreviewed syntax: " + expression)
        op, text = m.groups()
        target = version(text)
        if op in (None, "^"):
            major, minor, patch = target[:3]
            upper = (
                (major + 1, 0, 0, 1, "")
                if major
                else ((0, minor + 1, 0, 1, "") if minor else (0, 0, patch + 1, 1, ""))
            )
            ok = target <= actual < upper
        else:
            ok = {
                ">=": actual >= target,
                "<=": actual <= target,
                ">": actual > target,
                "<": actual < target,
                "=": actual == target,
            }[op]
        if not ok:
            return False
    return True


rows = []
for scope, packages in audit["locked_packages"].items():
    for package in packages:
        for advisory in audit["package_name_advisory_matches"]:
            if package["name"] != advisory["package"]:
                continue
            safe = advisory["versions"].get("patched", []) + advisory["versions"].get(
                "unaffected", []
            )
            withdrawn = bool(advisory["withdrawn"])
            affected = not withdrawn and not any(matches(package["version"], x) for x in safe)
            rows.append(
                {
                    "scope": scope,
                    "package": package["name"],
                    "version": package["version"],
                    "advisory": advisory["id"],
                    "affected_version": affected,
                    "withdrawn": withdrawn,
                    "informational": advisory["informational"],
                }
            )
result = {
    "rustsec_commit": audit["rustsec_commit"],
    "lock_SHA256": audit["lock_SHA256"],
    "range_review": rows,
    "caveat": (
        "Version-range screening, including optional/uncompiled packages; ups"
        "tream SDK workspace lock is an over-approximation, not an attested b"
        "inary SBOM. Feature and call-path review remains separate. No absenc"
        "e-of-vulnerability claim."
    ),
}
(ROOT / "evidence/dependency_review.json").write_text(json.dumps(result, indent=2) + "\n")
for row in rows:
    if row["affected_version"]:
        print(row["scope"], row["package"], row["version"], row["advisory"], row["informational"])
