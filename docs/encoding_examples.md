# Canonical encoding examples

[configs/encoding_examples.json](../configs/encoding_examples.json) supplies 46
encoding/predicate specification vectors and eight proof-size arithmetic cases. The
source is the selected manuscript's Section VII, principally the opening codec and
A.1 schema/policy equations (p. 14); the file records its SHA-256. These are data
records consumed by the Stage 2 tests where implemented; they do not establish
cryptographic validity or proof implementation.

Each vector names the exact layer being exercised. Acceptance of bytes at that layer
does not assert a valid credential, authenticated root, proof, live request or trusted
instance. In particular, the context vector E31 uses synthetic identifiers, repeated
nonce bytes and an unauthenticated root solely to make its expected encoding legible.
It must never become a production randomness or trust configuration.

| Examples | Coverage |
|---|---|
| E01–E03 | Unsigned big-endian integer and four-byte length prefix, including empty bytes |
| E04–E08 | Boolean, padded byte string and eight-byte unsigned integer fields |
| E09–E14 | Tagged equality/range/policy tuples, disclosure masks and empty DID chain |
| E15, E28 | View padding only: 258 meaningful bits in 33 bytes, six low padding bits |
| E16–E27 | Overflow, invalid Boolean/length/padding/mask, duplicate/hidden policy clause, inverted range, truncation, trailing byte and wrong count |
| E29–E32 | Labelled synthetic six-field schema, policy A, complete context bytes and padded disclosure projection |
| E33–E35, E44–E46 | Agreed SPEC-001 raw paths, invalid sibling counts/lengths and distinct signed-message/transport framing |
| E36–E43 | Agreed SPEC-002 uint64 POSIX timestamp bytes, invalid representations/ranges and before/equal/after expiry |
| Arithmetic cases | Enrolment/authentication size formula at g=0,1,4,1,000,000; not claims that such circuits exist |

Small independently inspectable examples:

```text
I2OSP(256,2)                        = 0100
LP(empty)                          = 00000000
LP(000102)                         = 00000003000102
Ej(true), type 1, capacity 1        = 000101
Ej("SG"), type 0, capacity 4        = 000253470000
Ej(257), type 2, capacity 8         = 00080000000000000101
mask({3,4,6})                      = 002c
mask({3,5,6})                      = 0034
```

The E29 schema is the engineering fixture in
[implementation_spec.md](implementation_spec.md), E-002, not a required suite schema.
Its encoded descriptor object is 285 bytes; its attribute capacities consume 258 bytes
including length words, leaving 766 zero bytes in the 1024-byte attribute vector.
E31's existing integer bytes now have the agreed SPEC-002 POSIX interpretation; the
original vector still asserts byte framing only. E44 freezes the six-field `update`
signing-body framing; E45 freezes the five-field `rupdate` transport framing. Their
raw path bytes agree, while the tags and other fields differ. Neither contains
authentic fixture signatures or proves valid Merkle transitions.

The canonical tuple equation makes E09's equality clause 22 bytes and E10's one-clause
policy 46 bytes. For proof sizes, a view is `ceil((d+2g)/8)` bytes, so the g=0 floors
are 277,984 bytes for enrolment and 5,363,104 bytes for authentication. An extra
million AND gates adds 240,000,000 bytes under this formula. These statements follow
from the in-scope VII closing equation (p. 17) and supply no performance measurement.

The first Stage 2 implementation imports 44 applicable records as fixed expectations;
E15/E28 remain Stage 3 proof-view work. Additional tests cover complete attribute-vector
padding, schema boundaries and policy/domain mutations. Further typed protocol tuple,
cross-instance and whole-statement checks remain future relation work. Do not equate
a codec round trip with signature/proof verification.

All original E01–E32 objects, including expected bytes and source labels, are preserved
exactly. They were checked against the in-scope specification before tests used them;
no existing vector correction was necessary. E33–E46 were calculated directly from
VII's encoding equations and the agreed decisions, without importing implementation
functions. These added user clarifications are identified explicitly in each source.
See [stage2_codec.md](stage2_codec.md) for executed tests and API behaviour.
