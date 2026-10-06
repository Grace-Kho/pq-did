# KYC testbed interoperability boundary

The implemented `pqdid-local-kyc-projection/1` is an approved experimental local
projection, **not a secured VC/VP, cryptosuite or external interoperability claim**.
Reuse the dated official-specification assessment in
[the interoperability contract](stage2_kyc_interoperability_contract.md#dated-w3c-requirements-and-proposed-mapping)
and the completed M-01–M-10 results. No new standards profile is adopted here.

## Approved and implemented local bindings

Trusted issuer `https://issuer.kyc.example/` and vocabulary
`https://vocab.kyc.example/pqdid/v1#` are tied to the exact internal parameters,
issuer reference/key and schema. Claims use canonical schema indices. `kycPassed`
is Boolean; assurance/validity integers use exact decimal strings; country remains
`countryOctets`, not an invented ISO-country interpretation. Incoming projections
are matched in full against trusted canonical objects/configuration, not accepted
from caller-selected issuer/key/instance/context metadata.

DID projection keeps the minimal document and separate local raw-ML-DSA-65 public-key,
version and record-digest metadata. It invents no JWK, multicodec, verification-method
identifier or cryptosuite. Resolver failure differs from authenticated absence.
Anonymous projections include only already-public statement/disclosed fields; no
holder public key, new stable identifier, hidden rid/path or private credential is
added. A baseline holder key is explicitly disclosed in a different comparison flow.
Session expiry is distinct from certified credential validity. No parser fetches
contexts, schemas, DIDs or status URLs. Existing canonical signed messages are unchanged.

## Requirements still requiring decisions and external evidence

| Register item | Requirement and concrete decision | Existing boundary / acceptance evidence still missing |
| --- | --- | --- |
| KYC-INT-001 | Project/issuer must select governed issuer identity and immutable vocabulary semantics, and specify precisely which claims the securing algorithm authenticates. | Local `.example` bindings work; no external issuer governance or certified JSON-LD graph correspondence is established. |
| KYC-INT-002 | Construction owner must specify a real securing mechanism: transformed input/graph coverage, canonical binding, proof encoding, key selection and fail-closed verification. Any suite identifier requires an actual suite specification. | JSON conversion and original credential signature do not secure arbitrary VC/VP graphs. Complete private proof and CV-ONLINE-SAME-OBJECT-1 remain unresolved. |
| KYC-INT-003 | DID method owner must supply method rules, interoperable ML-DSA verification-method/key representation, verification relationships and resolution/document/error metadata. | In-memory authenticated reference resolver and separate local raw-key metadata are not method conformance. External consumer and conformance tests are absent. |
| KYC-INT-004 | Construction/product owners must specify authenticated shared namespace/epoch/root status mapping without credential-specific identifier/URL leakage. | Public bounded history exists; no standard status type/IRI or private credential status mechanism is adopted. Validity mappings must bind only certified/disclosed values and reject unrepresentable dates. |

The retained targets are DID Core 1.0 Recommendation (19 July 2022), VC Data Model
2.0 Recommendation (15 May 2025) and Data Integrity 1.0 Recommendation (15 May 2025).
Their dated links and section mappings are in the cited contract. This package
reuses that evidence and does not claim a new review of later drafts. A future
conformance claim needs the selected mechanism/method specification and meaningful
cross-implementation tests, not another JSON roundtrip.

The baseline demonstration, local reference relations, synthetic-proof fixture
scenarios and unavailable genuine private authentication remain four separate
coverage categories. No local mapping decision authorises changing the manuscript
relation, signed encodings, trust model or disclosure boundary. Production operation,
private authentication and standards-level interoperability remain unfinished;
Stages 2–3 and the original programme remain open.
