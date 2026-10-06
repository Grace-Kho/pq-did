"""Expand a delta inventory using the sealed preceding scope; omit no names."""

import json
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]


def load_scope():
    scope = json.loads((D / "scope.json").read_text())
    parent = json.loads((P / scope["inherited_required_names_from"]).read_text())
    inherited, added = set(parent["required_names"]), set(scope["required_names"])
    if inherited & added:
        raise ValueError("duplicated inventory delta")
    scope["required_names"] = sorted(inherited | added)
    return scope
