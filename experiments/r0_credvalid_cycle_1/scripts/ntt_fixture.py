"""Independently check the unchanged NTT using the original first response row."""

import hashlib
import json
from pathlib import Path

from pqdid.bounded_mldsa import _ntt, _unpack_poly
from pqdid.credentials import decode_credential
from pqdid.parameters import decode_parameters

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parents[1]
vectors = json.loads((PROJECT / "tests/fixtures/relations_vectors.json").read_text())
instance = next(x for x in vectors["instances"] if x["name"] == "alpha")
pp = decode_parameters(bytes.fromhex(instance["parameters"]))
credential = next(x for x in vectors["credentials"] if x["name"] == "alpha-42")
sig = decode_credential(pp, bytes.fromhex(credential["encoded"])).certificate.signature
response = [(1 << 19) - v for v in _unpack_poly(sig[48:688], 20)]
expected = _ntt(response)


def lp(value):
    return len(value).to_bytes(4, "big") + value


fields = [
    b"".join(int(v).to_bytes(8, "little", signed=True) for v in p) for p in [response, expected]
]
payload = lp(b"r0-component-ntt") + (2).to_bytes(4, "big") + b"".join(lp(f) for f in fields)
path = ROOT / "fixtures/components/ntt-z0.bin"
assert not path.exists()
path.write_bytes(payload)
path.chmod(0o600)
(ROOT / "evidence/ntt_fixture.json").write_text(
    json.dumps(
        {
            "fixture": "fixtures/components/ntt-z0.bin",
            "SHA256": hashlib.sha256(payload).hexdigest(),
            "source": "unchanged alpha-42 credential response polynomial zero",
            "reference": "unchanged Python bounded_mldsa._unpack_poly and _ntt",
            "synthetic_private_intermediate": True,
            "values_not_logged": True,
            "full_relation_evidence": False,
        },
        indent=2,
    )
    + "\n"
)
print("One isolated NTT fixture independently checked; no values logged")
