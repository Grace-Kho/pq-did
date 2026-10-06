"""Local projection binding and privacy checks, distinct from W3C conformance."""

from copy import deepcopy

from pqdid.did_state import DIDResolution, DIDStatus
from tests.unit.relation_cases import auth_case

from .mapping import ISSUER, LocalMapping, date_time, encode_view
from .wallet_cases import denied


def run(number, app, cache):
    s = app.scenario
    mapping = LocalMapping(s.pp)
    credential = s.holder.credential
    expected = mapping.baseline(credential)
    if number == 1:
        assert expected["issuer"] == ISSUER
        assert mapping.validate_baseline(encode_view(expected), credential) == expected
    elif number == 2:
        from experiments.kyc_milestone_1.baseline.records import encode_credential
        from pqdid.containers import _b64

        assert _b64(expected["canonical"], 65536) == encode_credential(s.pp, credential)
        assert mapping.validate_baseline(encode_view(expected), credential) == expected
    elif number == 3:
        bad = deepcopy(expected)
        bad["issuerKey"] = expected["issuerReference"]
        denied(lambda: mapping.validate_baseline(encode_view(bad), credential))
    elif number == 4:
        bad = deepcopy(expected)
        bad["accepted"] = True
        denied(lambda: mapping.validate_baseline(encode_view(bad), credential))
    elif number == 5:
        answer = cache["resolution"]
        key = mapping.did(answer)
        assert mapping.validate_did(encode_view(key), answer) == key
        key["localKey"]["encoding"] = "JsonWebKey2020"
        denied(lambda: mapping.validate_did(encode_view(key), answer))
    elif number == 6:
        absent, failed = DIDResolution(DIDStatus.UNKNOWN), DIDResolution(DIDStatus.UNAVAILABLE)
        a, b = mapping.did(absent), mapping.did(failed)
        assert a["status"] != b["status"] and a["document"] is b["document"] is None
        denied(lambda: mapping.validate_did(encode_view(a), failed))
    elif number == 7:
        assert date_time(253402300799) == "9999-12-31T23:59:59Z"
        denied(lambda: date_time(1 << 64))
    elif number == 8:
        pp, statement, _ = auth_case()
        projection = LocalMapping(pp).anonymous(statement)
        assert projection["sessionExpiresAtSeconds"] == str(statement.context.expires_at)
        assert LocalMapping(pp).validate_anonymous(encode_view(projection), statement) == projection
        # Only certified disclosed fields get a validity date; session expiry is separate.
        assert "validUntil" not in projection
    elif number == 9:
        pp, statement, _ = auth_case()
        m = LocalMapping(pp)
        view = m.anonymous(statement)
        assert not {"holderKey", "holderSecret", "rid", "did"}.intersection(view)
        view["holderKey"] = "injected-stable-key"
        denied(lambda: m.validate_anonymous(encode_view(view), statement))
    elif number == 10:
        bad = deepcopy(expected)
        bad["proof"] = {"type": "DataIntegrityProof", "proofValue": "synthetic"}
        denied(lambda: mapping.validate_baseline(encode_view(bad), credential))
    else:
        raise AssertionError("unregistered mapping case")
    return {
        "result": "local canonical projection assertions passed",
        "external_interoperability": False,
    }
