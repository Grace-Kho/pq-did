"""Explicit approved operational limits; no cryptographic/profile defaults changed."""

import json
from pathlib import Path

from pqdid.circuits.emitter import Limits

ROOT = Path(__file__).resolve().parents[2]


def extended_limits():
    profile = json.loads((ROOT / "configs/validation_profiles.json").read_text())[
        "hash_enrolment_extended_v1"
    ]
    return Limits(
        max_gates=profile["max_gates"],
        max_output_bytes=profile["max_output_bytes"],
        max_seconds=profile["generation_seconds"],
        max_inputs=profile["max_inputs"],
    )
