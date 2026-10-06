"""Private, synthetic intermediate checked by the unchanged Python implementation."""

import hashlib
import json
from pathlib import Path

from pqdid.bounded_mldsa import _PrefixReader, _rej_ntt_poly
from pqdid.parameters import decode_parameters

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parents[1]
vectors = json.loads((PROJECT / "tests/fixtures/relations_vectors.json").read_text())
instance = next(x for x in vectors["instances"] if x["name"] == "alpha")
pk = decode_parameters(bytes.fromhex(instance["parameters"])).issuer_public_key
seed = pk[:32] + bytes((0, 0))
prefix = hashlib.shake_128(seed).digest(1026)
expected = _rej_ntt_poly(_PrefixReader(prefix))
# Also cross-check the reference with a separate literal integer decoder.
candidates = [int.from_bytes(prefix[i : i + 3], "little") & 0x7FFFFF for i in range(0, 1026, 3)]
accepted = [v for v in candidates if v < 8380417][:256]
assert accepted == expected and len(expected) == 256
consumed = next(i * 3 for i in range(1, 343) if sum(v < 8380417 for v in candidates[:i]) == 256)


def lp(value):
    return len(value).to_bytes(4, "big") + value


encoded = b"".join(int(v).to_bytes(8, "little", signed=True) for v in expected)
payload = lp(b"r0-component-matrix") + (2).to_bytes(4, "big") + lp(seed) + lp(encoded)
directory = ROOT / "fixtures/components"
directory.mkdir(exist_ok=True, mode=0o700)
path = directory / "matrix-00.bin"
assert not path.exists()
path.write_bytes(payload)
path.chmod(0o600)
(ROOT / "evidence/component_fixture.json").write_text(
    json.dumps(
        {
            "fixture": "fixtures/components/matrix-00.bin",
            "SHA256": hashlib.sha256(payload).hexdigest(),
            "source": "unchanged alpha issuer key from tests/fixtures/relations_vectors.json",
            "reference": "unchanged bounded_mldsa._rej_ntt_poly and independent integer decoding",
            "row": 0,
            "column": 0,
            "consumed": consumed,
            "budget": 1026,
            "synthetic_private_intermediate": True,
            "values_not_logged": True,
            "full_relation_evidence": False,
        },
        indent=2,
    )
    + "\n"
)
print("One isolated matrix fixture independently checked; no values logged")
