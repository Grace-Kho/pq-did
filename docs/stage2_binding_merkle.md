# Stage 2: holder binding and Merkle reference primitives

Implemented 17 September 2026. Authority remains **Sections II–VIII only** of
`docs/manuscript/PQ_DID__Implementation.pdf`, SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`, plus agreed
SPEC-001/002. The relevant definitions were checked against VII opening/A.1/A.5,
pp. 14–15. No new ambiguity or conflicting definition was found. The manuscript,
parameter manifest, existing encoding vectors and verified environment are unchanged.

These are executable local reference computations using real SHA3-384. Overall
Stage 2 remains in progress; these functions do not implement credential certification,
the complete authentication relation, a proof system or lifecycle services.

## Operations, inputs and manuscript references

| Module and operation | Inputs and output | Source/coverage |
|---|---|---|
| [hash_domain.py](../src/pqdid/hash_domain.py): `HashDomain`, `encode_metadata` | Public suite, canonical issuer reference and namespace; derive the schema from `refI` and encode `E(µ)` | VII-A.1 `refI/µ`, p. 14; R-001/R-005 subset |
| [binding.py](../src/pqdid/binding.py): `encode_holder_input`, `holder_binding_value` | Public domain and private 32-byte `xH`; private canonical preimage and 48-byte `Y` respectively | VII-A.5 holder-binding equation, p. 15; R-010/R-020/R-023 subset |
| `BindingRepresentation`, `create_binding`, `encode_binding`, `decode_binding` | `B=(Y,Esch(m))`; the complete private 1024-byte canonical attribute vector remains separate from Y | VII-A.5 `B` and `binding` tag, p. 15; R-005/R-020/R-023 subset |
| `check_binding_consistency` | Public expected domain plus private B, xH and canonical attributes; Boolean opening consistency | V-B `BindOpen` equations/domains, pp. 7–8; VII-A.5, p. 15; part of R-023, not `CredValid` |
| [merkle.py](../src/pqdid/merkle.py): `leaf_hash`, `node_hash` | Public domain and leaf status or node level/child hashes; 48-byte SHA3-384 output | VII-A.1 `Lb/Fj`, p. 14; R-010/R-029 subset |
| `default_subtree_roots` | Public domain; tuple `Z0,…,Z20`, with `Z20` the all-unrevoked root | VII-A.1 initial tree, p. 14; mathematical part of R-029 |
| `path_root` | Public domain, local identifier/status/raw path; computed root | VII-A.5 `PathRoot`, p. 15; mathematical part of R-029 |
| `verify_non_revocation_path` | Public domain and supplied root, local identifier/path; check the zero-leaf condition | V-B `NRVerify` separation, pp. 7–8; VII-A.5, p. 15; root/path subset of R-029 |

The issuer observes B and approved attributes during confidential enrolment; these
remain private in anonymous presentations. The reference binding check receives the
secret locally and must not be exposed as a presentation-verifier API. Likewise,
identifier/path inputs are holder-local in anonymous authentication. A revoked
identifier's published update path is a different, public lifecycle record.

## Canonical bytes and validation

The public `HashDomain` validates the exact supported suite bytes `PQ-DID-MITH-1`,
a 32-byte namespace, and `refI=enc_iref(didI,kid,E(sch))`. Both identifiers are
non-empty byte strings of at most 256 bytes; the embedded schema is parsed using
the existing strict schema decoder. The schema is derived from this reference,
preventing a separate contradictory schema argument. This is an engineering API
choice within VII-A.1, not a substitute for `pp`, trust configuration or public keys.

```text
E(µ) = enc_meta(refI, ns)
Y    = SHA3-384(enc_holder(suite, E(µ), xH))
B    = (Y, Esch(m))
E(B) = enc_binding(Y, Esch(m))
```

The existing `codec.encode_record` handles each field's length prefix exactly once.
There is no JSON, implicit text conversion, extra suite inside µ, extra namespace
field, attribute hash in place of the complete block, or implicit concatenation.
Y is 48 bytes; the complete canonical E(B) is 1095 bytes. Changing attributes alone
does not change Y, but changes B. Changing the issuer/key/schema reference or namespace
changes the holder hash's domain. Unsupported suites reject rather than defining an
unreviewed alternative profile.

`BindingRepresentation` checks lengths; its domain-aware encode/decode/check functions
also validate all attribute types, field padding and tail padding using the schema
inside `refI`. A well-formed B can be parsed under another structurally compatible
schema; only the opening check tests the holder hash against the expected domain.
Parsing B alone is not instance binding or issuer certification.

The local consistency check compares Y to the recomputed holder hash and the complete
canonical attributes to the supplied attributes. It returns `False` for valid mismatches
and raises the existing `EncodingError` for malformed types/lengths/encodings. No
certification table, signature, identifier or issuer key is consulted. The complete
`BindRep`/`CredValid` certificate-domain and signature checks remain unimplemented;
the empty-ρ rule will be enforced by those later typed credential interfaces.

No function logs, prints, generates or persists holder secrets. The representation
stores Y and attributes, never xH, and suppresses its private fields in `repr`.
`encode_holder_input` returns secret-containing bytes for local reference use; callers
must treat them as private. Tests use explicitly labelled synthetic public material.
`compare_digest` is used for byte comparisons; this Python reference implementation
does not claim constant-time processing or secure erasure of Python objects.

## Merkle mathematics and verification boundary

```text
Lb     = SHA3-384(enc_leaf(suite, E(µ), [b]1)), b in {0,1}
Fj(u,v)= SHA3-384(enc_node(suite, E(µ), [j]1, u, v)), j in 1..20
Z0=L0; Zj=Fj(Zj-1,Zj-1)
```

Leaves contain no identifier. Identifier r determines the path directions, not leaf
contents. Validate `0 <= r < 2^20`; integer inputs exclude Python Booleans, following
the existing uint convention. Both node children and the supplied root must be exactly
48 immutable bytes; status is integer 0 or 1. The API always uses the actual depth 20.

The path argument is the raw 960-byte payload decoded by the existing
`unpack_sibling_path`. Sibling index j runs from 0 to 19, leaf to root. At that step,
numeric identifier bit j selects whether the current value is the left child (bit 0)
or right child (bit 1). The parent hash uses **node level j+1**, not sibling index j.
The corresponding sibling's tree index is `(floor(r/2^j) xor 1)`. Path packing remains
separate from the `update`/`rupdate` record framing agreed in SPEC-001.

`default_subtree_roots` computes only 21 hashes; no million-leaf tree is allocated.
`path_root` folds twenty siblings from the chosen leaf. `verify_non_revocation_path`
checks only `path_root(domain,r,0,w) == supplied_root`, with malformed inputs rejected.

This primitive does **not** establish that the root is authenticated/current, that r
was allocated, that a credential or signature exists, or that a secret was certified.
It does not parse an epoch/state signature or enforce a pending context. It accepts
mathematically valid old-root paths even after a later root exists. State authentication,
current-state/context agreement and atomic expiry/consumption are later mandatory
checks. No production witness-update algorithm or revocation service was added.

## Independent fixture provenance

The fixed [binding_merkle_vectors.json](../tests/fixtures/binding_merkle_vectors.json)
has SHA-256 `55c318b8ca2a1bcb42556ad07f52d54694ee598a191ec255ce5f77414feb3059`.
It is clearly labelled synthetic-only and contains a published synthetic test secret,
never a real holder secret. All existing `configs/encoding_examples.json` bytes are
unchanged; no previous vector correction was needed.

[binding_merkle_reference.py](../tests/unit/binding_merkle_reference.py) independently
renders the manuscript's LP/tag/count equations using `struct`, with no `pqdid`
imports. It reconstructs the E29 schema from its field descriptors and checks it
against the earlier fixed schema bytes. SHA3-384 operates on those independently
encoded preimages. Expected input bytes, digests, full B, leaf/node examples, all 21
default roots and paths were frozen before production tests ran. Tests read those
fixed expectations; they never derive expected roots using production `path_root`.

The reference tree stores a dictionary of revoked leaves, then groups their global
indices by parent to compute only affected nodes at each level. Missing subtrees use
their level's default root. It obtains the root from the final indexed level and each
sibling from the relevant global tree index; it never traverses a target PathRoot to
manufacture the expected root. Tests also rebuild the fixture in memory to verify
provenance, without modifying the JSON. The explicit builder uses exclusive file
creation and refuses to overwrite an existing fixture.

| Fixture | Revoked identifiers | Stored non-default nodes | Meaning |
|---|---|---|---|
| `empty` | none | 0 | Every valid identifier, including unallocated ones, has the same default path |
| `old` | 1, 7, 9, 1024, 524291, 1048574 | 78 | Non-uniform tree with low/high boundaries and both child directions |
| `updated` | old set plus 42 | 84 | Recomputes the tree independently after revoking 42; no production update service |

Each tree supplies 16 fixed paths, including 0, 1048575, alternating-bit identifiers,
revoked leaves, newly revoked 42 and surviving neighbour 43. Their paths exercise the
actual depth-20 profile. The fixture includes five issuer/key/schema/namespace domains,
two leaf preimages and four internal-node preimages/digests for level/ordering checks.

The tests deliberately distinguish these cases:

- Empty-tree paths may be identical for different identifiers; this is valid and is
  not allocation evidence. Identifier 0's path in the non-uniform old tree fails for
  unrevoked identifier 2 because their relevant sibling subtrees differ.
- Identifier 42 has identical siblings before and after its own revocation. Its
  zero-leaf path still matches the old root, while its one-leaf path matches the new
  root; zero-leaf verification against the new root fails.
- Surviving neighbour 43 changes sibling 0 from L0 to L1. Its old path matches the
  old root, fails against the new root, and its independently rebuilt path matches
  the new root. Other sibling levels are unchanged in this single-leaf transition.

## Tests and commands

Actual tests are [test_hash_domain.py](../tests/unit/test_hash_domain.py),
[test_binding.py](../tests/unit/test_binding.py) and
[test_merkle.py](../tests/unit/test_merkle.py). They cover fixed encoded inputs/digests,
correct and mismatched openings, altered attributes/binding bytes, malformed references,
schema/length/padding checks, domain separation, fixed roots/paths, revoked leaves,
identifier/status/level bounds, every altered sibling position, reversed paths and
incorrect roots. Hash-input capture tests compare production preimages to fixed bytes
while still invoking real SHA3-384. No secret-bearing logging occurs in the tested calls.

Executed using the unchanged environment:

```bash
.venv/bin/python tests/unit/binding_merkle_reference.py --output tests/fixtures/binding_merkle_vectors.json
.venv/bin/ruff format src/pqdid/hash_domain.py src/pqdid/binding.py src/pqdid/merkle.py tests/unit/binding_merkle_reference.py tests/unit/binding_merkle_cases.py tests/unit/test_hash_domain.py tests/unit/test_binding.py tests/unit/test_merkle.py
.venv/bin/python -m pytest tests/unit/test_hash_domain.py tests/unit/test_binding.py tests/unit/test_merkle.py -q
.venv/bin/python -m pytest tests/unit -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Results: **179 new focused tests passed**; the full unit suite including all 189 earlier
codec/schema/policy/expiry cases passed **368 tests**. Lint passed and formatting
reported **39 files already formatted**. Initial lint-only findings in the new fixture/
test code were corrected; the expected fixture data and production algorithms were
unchanged. No installation, native build or completed environment smoke verification
was repeated. Test durations are not reported as cryptographic performance evidence.

The final data/document audit confirmed that all 38 protected existing files retain
their original SHA-256 digests, including the manuscript, suite manifest, previous
vectors, earlier code/tests and environment/toolchain/editor records. New constants
match the manifest; all 52 main traceability entries resolve; the fixture digest,
78 local links and 20 Markdown tables checked successfully.

## Pending work and next task

R-020/R-023 remain partial because enrolment, issuer certification and bounded signature
verification are absent. R-029's hash/path mathematics is implemented, while authenticated
state handling, allocation/epoch rules and lifecycle freshness remain later work. The
complete R-024/R-025 conjunction, BC-1 gadgets and proofs are unimplemented. These local
tests do not prove collision resistance, soundness, privacy or a security theorem.

Next implement typed parameter/certificate/credential parsing and exact `Mcred`
construction with instance/schema agreement, identifier bounds and empty ρ checks.
Then implement and validate the separately instrumented bounded ML-DSA verifier before
claiming `CredValid` or assembling the complete authentication relation. DEP-001
signing-tail/Δtail validation and DEP-002 bounded-adapter work remain open; proof
feasibility remains Stage 3. No cryptographic parameters or agreed conventions changed.
