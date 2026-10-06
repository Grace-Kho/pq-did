# Stage 2: canonical codec, schema, public policy and expiry

Implemented on 17 September 2026 under the selected manuscript's **Sections II–VIII
only**, principally VII opening/A.1/A.5/A.8, with user-agreed SPEC-001/002. The PDF,
dependency pins, Python environment, native backend, existing smoke tests and VS Code
configuration are unchanged. This is the first part of Stage 2; it is not a complete
authentication relation, credential validator, circuit/proof or lifecycle service.

## Interfaces and scope

| Module | Public interface and behaviour |
|---|---|
| [codec.py](../src/pqdid/codec.py) | `encode_uint`/`decode_uint`, `encode_length_prefixed`/`decode_length_prefixed`, `encode_record`/`decode_record`, `pack_sibling_path`/`unpack_sibling_path`; literal protocol tags/arity, exact lengths, unsigned big-endian bytes, no trailing bytes |
| [schema.py](../src/pqdid/schema.py) | Frozen `AttributeField`/`Schema`; schema and attribute encode/decode; two-byte disclosure masks; selected padded-field projection and disclosure decoding |
| [policy.py](../src/pqdid/policy.py) | `Equality`, `Range`, `Policy`; clause/policy encode/decode; `make_policy` sorts application-supplied clauses; `evaluate_policy` uses only public disclosed bytes |
| [expiry.py](../src/pqdid/expiry.py) | `encode_timestamp`/`decode_timestamp` and `is_unexpired(texp, now=...)`; unsigned uint64 POSIX seconds and strict inequality, with no clock access |

These are reference Python routines. `EncodingError` (a `ValueError` subclass)
denotes malformed encodings or invalid domains. Errors do not embed attribute values.
An otherwise valid but unsatisfied public policy returns `False`; a valid expired
timestamp pair also returns `False`. Malformed inputs raise rather than being silently
coerced, padded, truncated, normalised or accepted as an empty policy.

Engineering API choices preserve the protocol's byte domains:

- Byte inputs are immutable `bytes`; no implicit text, bytearray or memoryview conversion.
  Scalar unsigned inputs require Python `int` exactly, excluding `bool`, floats and
  integer-like objects. Boolean attributes require `bool` exactly and decode to `bool`.
- Schema fields, policies and clauses use frozen data objects. A schema owns an
  immutable tuple of descriptors; a policy owns immutable tuples of increasing
  disclosure indices and canonically ordered distinct clauses. Ordinary record/attribute
  lists may be tuples or lists; generators are not consumed implicitly.
- Attribute type 0 remains an opaque byte string. Schema validation enforces the
  designated DID/version indices, type and minimum capacities. It does not resolve
  a DID, validate a registry/controller record or assert that bytes identify a live DID.
  Those issuance/controller checks remain later work.
- `make_policy` is the explicit construction convenience that sorts clause encodings.
  `encode_policy`, `decode_policy` and evaluation reject an unsorted/duplicate policy.
  Range endpoints are inclusive, uint64 and permitted only for type-2 fields. Every
  tested field must be disclosed; unsupported predicates are rejected.
- Context-dependent requirements are explicit registered clauses. For example, the
  research fixture uses `Range(validUntil_index, texp, 2**64-1)`. The evaluator does
  not supply a lifetime, inspect a clock or infer predicates over hidden attributes.
- Integer widths are explicit positive byte widths; all protocol widths retain the
  manuscript's values. Empty protocol byte strings use ordinary bytes/LP, not a
  zero-width integer API. FIPS internal byte order is outside these modules.

The decoder uses memory views and validates declared lengths against remaining actual
input before slicing/advancing or copying payloads. It checks the number of available
length words before iterating over fields. Fixed tags have exact arities; schema,
policy and DID-chain list counts have their specified structural bounds. Typed schema
and policy decoders additionally validate nested domains/count relationships. Generic
record framing intentionally does not claim validation of every other protocol object,
signature, credential, state, instance or request. Those typed validators are pending.

SPEC-001 packing preserves the twenty 48-byte siblings in order without internal
prefixes. The enclosing record still length-prefixes the single payload. Tests separately
check `update(suite,E(µ),E(refe),E(refe+1),[r*]4,path)` and
`rupdate(E(rse),E(rse+1),[r*]4,path,υ)`; they are not interchangeable signed bytes.

SPEC-002 rejects non-uint64 values and wrong-length encodings. `now=texp` is expired.
Trusted time, request/presentation checks, the final ordered current-state read and
atomic recheck/consumption remain future service responsibilities. The helper cannot
by itself establish freshness or replay resistance.

## Verification evidence

Reviewed the original E01–E32 against the specification before using them. All original
vector objects remain unchanged. Added E33–E46 directly from the encoding equations
and agreed clarifications without using `pqdid` functions to generate expected outputs.
Forty-four applicable vector records are exercised; proof-view vectors E15/E28 and
the eight proof-size arithmetic cases remain Stage 3 data, not claimed proof tests.

Executed commands in the existing environment:

```bash
.venv/bin/ruff format src/pqdid/codec.py src/pqdid/schema.py src/pqdid/policy.py src/pqdid/expiry.py tests/unit
.venv/bin/python -m pytest tests/unit -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Final results: **189 tests passed**; Ruff lint passed; Ruff formatting reported
**30 files already formatted**. The initial run exposed a new test fixture's capacity
sum error (1022 rather than 1024 bytes); corrected that new fixture to 936 + 56 +
32 length bytes. An adjacent-clause iterator was made explicit for lint. Neither
change altered a manuscript parameter or existing fixed vector.

Tests cover exact bytes, independent construction of fixed schema/policy/context
examples, round trips, scalar/type/range boundaries, all record truncations, hostile
declared lengths, canonical field/tail padding, required schema fields, disclosure
masks/projection, supported policy success/failure, hidden-field and ordering rejection,
path order/count/length and expiry before/equal/after plus uint64 endpoints. A hostile
four-byte length prefix is checked to reject without allocating its purported 4 GiB
payload. This is a parser regression check, not a performance or memory budget claim.

Existing environment/native/crypto smoke verification was reused and not rerun.
The focused tests import only pure modules, not the native backend. Default pytest
and VS Code selections still target `tests/smoke`; the explicit command above selects
the new unit tests without changing the preserved editor/test configuration.

## Pending work

The next holder-binding/Merkle work package has now been implemented and tested; see
[stage2_binding_merkle.md](stage2_binding_merkle.md). Typed statement/credential
validation and the separately instrumented bounded ML-DSA adapter remain required
before the complete local authentication/enrolment relations.
Keep DEP-001 signing-tail validation and DEP-002 bounded-adapter work open. BC-1,
raw-view proof execution and feasibility belong to Stage 3; lifecycle/KYC/W3C services
remain later integration. No security theorem or cryptographic acceptance is established
by the codec tests.
