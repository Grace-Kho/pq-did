# PQ-DID implementation specification — Stage 1 record, version 2

This is the specification and implementation contract; a complete PQ-DID system
is not yet implemented. Codec, schema, public-policy and expiry functions are recorded
in [stage2_codec.md](stage2_codec.md). Holder-binding consistency and Merkle reference
primitives are recorded in [stage2_binding_merkle.md](stage2_binding_merkle.md).
Typed pp/µ/cert/vc structures and exact Mcred are recorded in
[stage2_credentials.md](stage2_credentials.md). The separate bounded Python verifier
and complete local CredValid are recorded in [stage2_bounded_mldsa.md](stage2_bounded_mldsa.md).
Typed statements/witnesses and complete executable local enrolment/authentication
relations are recorded in [stage2_relations.md](stage2_relations.md), with separate
public state/policy checks and lifecycle boundaries.
Other module/function names remain planned.
Executable relations belong to Stage 2; circuits and proofs to Stage 3.

## Authority, notation and evidence

The selected source is [PQ_DID__Implementation.pdf](manuscript/PQ_DID__Implementation.pdf),
SHA-256 `d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
Only **Sections II–VIII** are authoritative, by the user's instruction of 17 September
2026. These are section numbers, not page numbers. No alternative manuscript or
matching LaTeX source was found. Equations were checked against rendered PDF pages
14, 16, 17 and 19 where extraction could lose superscripts, indices or square roots.
The implementation plan supplies work sequencing, not authority to override this source.

Requirement labels:

- **M:** explicitly specified by the authoritative manuscript, including its referenced
  FIPS algorithms; citations identify section/subsection, named equation/procedure and
  printed PDF page. The display equations are generally unnumbered.
- **E:** a documented engineering/deployment choice within the manuscript's constraints.
- **U:** an explicitly agreed user clarification, distinguished from manuscript quotations.
- **A:** an agreed user clarification, distinct from original manuscript wording.
- **U:** an unresolved prerequisite, tracked in [spec_issues.md](spec_issues.md).

Every `R-001`–`R-052` requirement has a row in [traceability.md](traceability.md).
[configs/suite.json](../configs/suite.json) records confirmed parameters with source
references and explicit nulls for unset inputs. [Encoding examples](encoding_examples.md)
are specification vectors, not successful protocol executions. Existing ordinary-library
smoke evidence remains in [environment.md](environment.md); it is not rerun here.

Notation: `ε` is the zero-length byte string; `⊥` is failure; `||` is byte/bit
concatenation as indicated. `E(o)` is the canonical encoding of a structured object;
already encoded byte strings are not encoded as tuples a second time. Superscripts
on powers denote arithmetic exponentiation. `X` below denotes the statement appropriate
to `kind`; the enrolment and authentication statements have different field lists.

## Roles, information and instance boundaries

**R-001 — Instance and trust [M].** One instance fixes an issuer verification-key
version, immutable schema, namespace and authorised revocation key. `refI` identifies
issuer/key/schema; it cannot later denote a different schema encoding. Multiple accepted
instances are an application choice; cross-instance aggregation and authority-key
rotation are outside this baseline. Trust explicitly pins accepted instances, registry
keys and audience request keys. DID resolution does not itself establish issuer trust.
Sources: III-B; IV-A, instance definition, pp. 3, 5; VII-A.1, `pp/µ/cfgD/params`, p. 14.
Issuer and key identifiers are non-empty byte strings of at most 256 bytes each
(VII-A.1, `refI` definition, p. 14).

**R-002 — Owner separation and visibility [M].** Preserve this information boundary:

| Owner or audience | Inputs/records visible to it |
|---|---|
| Issuer | Its signing key, evidence, approved complete attributes including issuance-time `(did,vD)`, binding `B`, allocated `rid`, enrolment/controller proofs and its authorisation/session records |
| Revocation manager | Its own signing key, registration/request records, tree, allocation counter, state history and authorised revocations; not the issuer's secret key |
| Holder | `xH`, controller keys/state, approved attributes, complete credential, `rid`, witness, request approval and transient proof randomness |
| Registry | Registry signing key and ordered DID records/updates; method records expose controller public keys |
| Audience verifier | Pinned public configuration, expected request and signature, `X`, `D,mD,π`, current-state replies, its pending/consumed session state; only explicitly disclosed DID data |
| Public observers | Method records/resolution traffic, accepted instance/schema, namespace, context/policy, epoch/root, disclosed values and proof bytes/lengths; later updates expose revoked `r*` and its old sibling path `w*` |

`xH`, credential signature, binding, hidden attributes, authentication `rid` and current
private witness do not become presentation fields. Authority private records are not
shared with verifiers in the privacy model. A proof statement described as public in
enrolment is visible to that enrolment's participants over the confidential channel;
it is not a public directory record. Sources: III-A–C, pp. 3–4; IV-B Issue, p. 6;
V-A/C, pp. 7–8; VI-A leakage, pp. 9–10; VII-A.5/.6/.8, pp. 15–17.

**R-003 — Service assumptions [M].** Issuance is authenticated and confidential.
Registry ordering/integrity, authenticated latest-state reads, trusted time, request
authentication/holder approval and atomic shared verifier state remain explicit
assumptions. An unavailable, inconsistent or unauthenticated required service causes
failure. Signatures alone do not make a state current. Sources: III-B/C; IV-A,
Current-state assumption; VI-E; VIII-E, pp. 3–5, 13, 20.

**R-004 — Parameters and persistent state [M].**

```text
pp     = (suite, refI, ns, pkI, pkR, sch)
µ      = (refI, ns)
cfgD   = (γ, pkG)
params = (pp, cfgD, trust)
rse    = (ns, e, Ae, τe)          refe = (ns, e, Ae)
stH    = (xH, stctl)
```

Authority secret outputs stay with their owners. Issuer state includes approvals,
sessions/nonces and the certification table; manager state includes the permanent
allocation counter/registrations, tree, request nonces and authenticated history.
Registry state includes its key, versioned map and ordered reads. Controller state
includes keys, salt, last reference and any pending publication. Verifier replicas
share the complete pending/consumed contexts and audience nonce/session state.
Credentials and epoch-dependent witnesses are distinct holder records. Sources:
IV-A/B, pp. 5–6; V-A, p. 7; VII-A.1–.3/.7/.8, pp. 14–17.

## Encodings, domains and concrete primitives

**R-005 — Canonical codec [M/E/A].** Section VII's
opening equations, p. 14, prescribe

```text
[a]k = I2OSP(a,k), unsigned big-endian
LP(s) = [len(s)]4 || s
enc_tag(s1,…,sk) = LP(ASCII(tag)) || [k]4 || LP(s1) || … || LP(sk)
L = 2^32 - 1 bytes per length-prefixed field
```

Recursively encode structured fields in the displayed order. Lists contribute one
field per element. Reject wrong tags, field counts/types/domains/lengths, duplicate
or unexpected fields, non-canonical order, non-zero padding, truncation, trailing
bytes and disagreement between repeated instance fields. Check bounds before
allocation/arithmetic. Never truncate overflowing integers. FIPS internal byte order
remains FIPS-defined. Exact byte equality applies to opaque identifiers (E); tags and
schema names use the explicit ASCII rule. No `params`, `trust` or publication-metadata
wire tag is invented for local API/configuration objects that are not serialised here.

The following table expands `E` into typed field lists. `enc_t(…)` always length-prefixes
each listed payload; writing `E(o)` in the table means that payload is already encoded.
The table's source is VII opening and VII-A.1–.8, pp. 14–17, with the individual
algorithm number in the final column. There are no hidden JSON encodings in signed bytes.

| Object/tag | Ordered field payloads | Source |
|---|---|---|
| `iref` | `didI, kid, E(sch)` | A.1 |
| `field` | `ASCII(namej), [typej]1, [Mj]2` | A.1 |
| `schema` | `[ℓ]1, [did_index]1, [version_index]1, E(field1), …, E(fieldℓ)` | A.1 |
| `parameters` | `suite, refI, ns, pkI, pkR, E(sch)` | A.1 |
| `meta` | `refI, ns` | A.1 |
| `rstate` | `ns, [e]8, Ae, τe` | A.1; IV-A |
| `rref` | `ns, [e]8, Ae` | A.1; IV-A |
| `eq` | `[j]1, Ej(c)` | A.1 |
| `range` | `[j]1, [a]8, [b]8` | A.1 |
| `policy` | `[mask(D)]2, E(clause1), …, E(clausek)` | A.1 |
| `context` | `suite, aud, sid, n, E(policy), refI, E(refe), [texp]8` | A.1; IV-A |
| `leaf` | `suite, E(µ), [b]1` | A.1 |
| `node` | `suite, E(µ), [j]1, u, v` | A.1 |
| `state` (signed body) | `suite, E(µ), [e]8, Ae` | A.1 |
| `did-id` | `suite, γ, pkC, ζ` | A.2 |
| `did-body` | `γ, did, [k]8, δk-1, pkC,k, [ak]1, ζ` | A.3 |
| `did-record` | `E(qk), αk` | A.3 |
| `did-chain` | `E(R0), …, E(Rk)`; zero fields for absence | A.4 |
| `did-read` (signed body) | `γ, did, ν, nG, [status]1, E(chain)` | A.4 |
| `holder` | `suite, E(µ), xH` | A.5 |
| `binding` | `Y, Esch(m)` | A.5 |
| `cred` (signed body) | `suite, E(µ), E(B), [rid]4` | A.5 |
| `certificate` | `E(B), σ` | A.5 |
| `credential` (private record) | `E(cert), Esch(m), [rid]4, ε, E(µ)` | A.5 |
| `enrol-statement` | `E(pp), E(µ), Esch(mapp), [rid]4, E(B), nI, E(rse)` | A.5 |
| `auth-statement` | `E(pp), E(µ), E(ctx), E(rse), [mask(D)]2, mD` | A.6; V-B |
| `current` (signed body) | `suite, E(µ), nS, E(rse)` | A.7 |
| `revreq` (signed body) | `suite, E(µ), [rid]4, E(refe), nR` | A.8 |
| `update` (signed body) | `suite, E(µ), E(refe), E(refe+1), [r*]4, s*0 \|\| … \|\| s*19` | A.8 |
| `rupdate` | `E(rse), E(rse+1), [r*]4, s0 \|\| … \|\| s19, υ`; raw path payload per agreed SPEC-001 | A.8 |
| `view` (commitment preimage) | `suite, kind, E(X), [j]2, [i]1, sj,i, vj,i` | A.6 |
| `challenge` (challenge preimage) | `suite, kind, E(X), ν, A` | A.6 |

The presentation itself is the special flat format `[mask(D)]2 || mD || π` (VII-A.6),
not a new `enc_presentation` tuple. Its lengths derive from the schema and circuit.
Use ASCII `enrol` and `auth` for the displayed proof-kind literals (E interpretation
of VII's literal-tag convention). The exact bytes for several small encodings are
provided in `configs/encoding_examples.json`.

**R-006 — Schema and attribute vector [M].** Require `2 ≤ ℓ ≤ 16`; descriptor names
are distinct, non-empty ASCII, at most 64 bytes. Type is one byte; capacity is two.
Type 0 holds bytes, type 1 exactly one Boolean byte `00`/`01`, type 2 an eight-byte
unsigned integer. Fixed types need adequate capacity. The two designated DID/version
indices are distinct members of `1…ℓ`; both have type 0 and capacities at least 171
and 56. Require `Σj(2+Mj) ≤ 1024`.

```text
Ej(mj) = [len(bj)]2 || bj || zero_bytes(Mj-len(bj))
Esch(m) = E1(m1) || … || Eℓ(mℓ) || zero_bytes(1024-Σj(2+Mj))
```

Validate the payload's canonical type/length and both field/tail padding. A fixed-capacity
field is not an excuse to accept several encodings for the same value. Sources:
VII-A.1 schema/encoding equations, p. 14; V-A/B domain checking, pp. 7–8.

**R-007 — Disclosure and policy [M/E].** `D` indexes `1…ℓ`, with two-byte mask
`mask(D)=Σj∈D 2^(j-1)` (E: encode this integer big-endian). Unused bits are zero.
`mD` is the concatenation of the selected **complete padded** `Ej` fields in increasing
index order. A policy has this mask and at most 32 distinct, lexicographically sorted
canonical `eq`/`range` clauses (E: sort encoded bytes). Every tested field is disclosed;
ranges require type 2 and `a≤b`. `Ppub` is their conjunction, not a hidden-attribute
predicate. Any validity field relied upon must be certified and disclosed. Holder
approval covers the policy, including DID disclosure. Sources: V-A, p. 7; VII-A.1, p. 14.

**R-008 — Complete challenge context [M/A].**
`ctx=(tag,aud,sid,n,policy,refI,refe,texp)`, with `tag=suite`, non-empty audience/session
bytes of at most 256 bytes, 32-byte audience-unused random `n`, and eight-byte UTC
expiry seconds. Bind all fields into the statement and transcript; use the verifier's
registered expected context. Its state reference equals the supplied authenticated
state. Agreed SPEC-002 interprets this as unsigned 64-bit POSIX seconds since
`1970-01-01T00:00:00Z`, encoded big-endian. Require `now < texp`; equality and
later times are expired. Reject invalid representations/ranges. This user clarification
is not quoted manuscript wording; application lifetime has no default.
Sources: IV-A context/current-state paragraphs, p. 5; VII-A.1/.7, pp. 14, 16–17.

**R-009 — Signatures and contexts [M].** Use August 2024 FIPS 204 ML-DSA-65 with
fresh hedging randomness. Public key, expanded secret key and detached signature
occupy 1952, 4032 and 3309 bytes. All roles use the genuine external context
`PQ-DID/<role>/v1`, not message concatenation or prehash substitution:

| Role | Signing key | Signed body |
|---|---|---|
| `credential` | issuer | `enc_cred(suite,µ,B,rid)` |
| `state` | manager | `enc_state(suite,µ,e,Ae)` |
| `update` | manager | `Mu` from R-030 |
| `did-record` | controller (previous controller for a successor) | `E(qk)` |
| `did-read` | registry | registered read-response body |
| `control` | issuance-time controller | `E(Xen)` |
| `request` | pinned audience request key | `E(ctx)`; retain signature outside `ctx,vp` |
| `current` | manager | current-state response body |
| `revreq` | issuer | `MR` from R-030 |

`Sign_cred` abbreviates the **credential** context; the message tuple tag is **cred**.
Validate expected lengths, domains and keys/expansions. Sources: VII-A.1–.8, pp. 14–17.
The ordinary existing backend is a reference aid; R-032/R-033 still require new work.

**R-010 — Hashes and randomness [M].** Use `H=SHA3-384` with 48-byte outputs for
binding/tree/DID-record purposes and `HRO=SHAKE256(·,1024 bits)` with 128-byte outputs
only for the outer proof commitments/challenge. Internal SHA3/SHAKE remain the actual
FIPS 202 algorithms. `xH` and DID salt `ζ` are independent uniform 32-byte values;
namespace is uniform 32 bytes; registry identifier is 32 bytes. Read, issuance,
revocation-request and verifier nonces are 32 bytes; proof salts/nonce are 64 bytes.
Do not confuse the 128-byte XOF output with 128 bits. Sources: VII-A.1/.2/.4–.8;
VIII-A, pp. 14–18.

## Eight lifecycle algorithms and supporting procedures

**R-011 — Setup [M].**
`Setup(1^λ) → (params,stI,stR,rs0) or ⊥` accepts only `λ=128`, with the literal
ASCII suite identifier `PQ-DID-MITH-1` and circuit profile `BC-1`. Application
configuration is an implicit input fixed before setup. Generate independent issuer/
manager keys and namespace, establish the registry key/configuration and trust anchors,
validate keys/bounded expansions, initialise empty tables, allocation counter zero and
the empty revoked set/root, sign `rs0` and initialise the current-state register.
Failure activates no partial instance. `SetupDAA` supplies the same cryptographic
outputs once; the DID wrapper does not create another independent instance. Sources:
IV-B Setup, p. 5; V-C Setup, p. 8; VII-A.1, p. 14.

**R-012 — DID.KeyGen [M].**
`DID.KeyGen(params) → (did,stH) or ⊥`. Generate/validate controller keys separately
from `xH`; sample independent `xH,ζ`; compute

```text
d   = H(enc_did-id(suite,γ,pkC,ζ))
did = ASCII("did:pqdid:") || lowercase_hex(γ) || ASCII(":") || lowercase_hex(d)
```

The identifier is 171 ASCII bytes. Controller state stores DID, keys, salt, empty
reference and no pending operation. Generation neither publishes nor registers anything.
Sources: IV-B, p. 5; VII-A.2, p. 14.

**R-013 — DID.Publish [M].**
`DID.Publish(params,did,meta,stctl) → (stctl',vD) or ⊥`, with
`meta=(a,r)∈{(1,0),(1,1),(0,0)}` and one-byte flags. Define

```text
qk = (γ,did,k,δk-1,pkC,k,ak,ζ)
Rk = (qk,αk)              δk = H(E(Rk))              vD = [k]8 || δk
0 ≤ k < 2^16             δ-1 = zero_bytes(48)
```

`vD` is 56 bytes. Genesis requires `(1,0)`, authenticated absence, `k=0`, DID
recomputation and a signature by the genesis controller. A successor requires a fresh
current read matching the retained reference/key, active predecessor, next index,
unchanged DID/salt and previous digest; the predecessor key signs it. Rotation installs
new validated keys; otherwise retain the key. Deactivation is terminal. The registry
validates transitions and atomically appends against the expected predecessor/absence,
preserving history. Success is confirmed by an authenticated read and changes only
controller state. Sources: IV-B, pp. 5–6; VII-A.3, pp. 14–15.

**R-014 — Publication recovery [M].** Retain the pending record and possibly active
keys before submission. Resolve a pending attempt before another operation: resend
identical records while the predecessor remains current; accept confirmed occurrence,
including after deactivation; retire an attempt when a conflicting successor wins.
Timeouts retain potentially active keys. Invalid/unsupported operations fail, but delivery
failure cannot undo a committed record. Source: VII-A.3 recovery paragraph, p. 15.

**R-015 — DID.Resolve [M].**
`DID.Resolve(params,did,ν) → (doc,vD) or ⊥`. Selector `00` requests current state;
`01 || vD` requests history. Validate DID/method/registry; send fresh 32-byte `nG`.
The registry signs `(γ,did,ν,nG,status,(R0,…,Rk))`, using `did-read` and `did-chain`.
Status 0 denotes an endpoint; 1 denotes absence with an empty chain. Validate signature,
nonce, selector, all chain transitions/keys/bounded expansions and endpoint. Ordered
current reads choose the latest endpoint. Only an active endpoint returns exact
whitespace-free UTF-8 `{"id":"<did>"}`, media type `application/did+json`.
All other outcomes fail; no untrusted redirects. Controller keys come from validated
method records, not extra fields in that minimal document. Historical resolution does
not assert current control. Sources: IV-B Resolve, p. 6; VII-A.4, p. 15.

**R-016 — Request creation/approval [M].** An honest verifier obtains current state,
chooses an audience-unused random nonce, creates/registers the complete pending `ctx`
and signs `E(ctx)` with its request key. Replicas use consistent nonce/session state;
used nonces are not reused. The holder checks the pinned audience key, audience,
instance, request/policy and expiry and gives approval before responding. Keep the
request signature outside `ctx` and `vp`; do not insert a holder identifier in the request
or proof. Lifetime is explicit application policy. Sources: IV-A, p. 5; VII-A.7, p. 17.

**R-017 — CurrentState and logical epoch [M].** `CurrentState(ns)` uses a fresh
32-byte `nS` and the manager-signed `enc_current(suite,E(µ),nS,E(rse))` for an
ordered snapshot. Verify response signature, nonce, instance and `StateAuth`; otherwise
fail. Read both when creating the request and immediately before final acceptance.
The final ordered read defines the verification epoch. An update after that read does
not retrospectively invalidate acceptance; one ordered before it must be reflected.
An old signed root is insufficient. A different current reference requires a new request
and updated witness, not substitution in the existing context. Sources: IV-A current-state
assumption, p. 5; VII-A.7, p. 17.

**R-018 — Allocation and issuer challenge [M].** During issuance, the manager
permanently allocates the next four-byte `rid<2^20`, advances its counter without
changing the root and supplies a zero-leaf path/current state matching the issuance
state. Exhaustion fails. Never recycle identifiers, including aborted issuances.
Register a fresh instance-unused 32-byte `nI` as pending. Sources: IV-B Issue, p. 6;
V-C Enroll, p. 8; VII-A.5, p. 15.

**R-019 — Issue inputs and external validation [M].**

```text
Issue(qiss; I:(stI,ev); R:stR; H:(stH,did,vD,attr))
  → (stI',stR'; outH),        outH=(vc,we) or ⊥
qiss=(params,µ,rse)
```

The issuer validates evidence and attributes, resolves the current DID matching `vD`
and validates controller authorisation, then obtains holder approval of the exact
`mapp`, including canonical `(did,vD)`, over the confidential authenticated channel.
The manager's secret state stays at the manager. Recheck the DID reference and current
revocation state immediately before certification; mismatch aborts. These reads fix
issuance-time references; no later hidden-DID-control claim is implied. Sources:
III-B; IV-B/D, pp. 3, 6–7; VII-A.5, p. 15.

**R-020 — Enrolment and input separation [M].**
`EnrollDAA(qen; I:(stI,mapp); R:stR; H:(xH,mapp))`, where `qen=(pp,µ,rse)`, uses

```text
Y   = H(enc_holder(suite,µ,xH))
B   = (Y,Esch(mapp))
Xen = (pp,µ,mapp,rid,B,nI,rse)
```

The holder sends `B`, `Prove(enrol,Xen,xH)` and `Sign_control(skC,E(Xen))`.
The 256-bit private witness is only `xH`; the circuit checks its binding opening.
Public/session checks validate domains, the approved message encoding, registration,
pending nonce, instance/state, proof and controller signature under the resolved key.
The issuer constructs/checks the message part from its own approved vector, not an
unchecked holder-selected message. Never transmit `xH` (or non-empty private opening
material in a different instantiation) to the issuer. The proof remains required even
though direct certification avoids extracting every enrolment witness in the security
reduction. Sources: V-C Enroll, p. 8; VI-B.3, p. 11; VII-A.5, p. 15; VIII-B, p. 18.

**R-021 — Certification and release [M].** Set
`Mcred=enc_cred(suite,µ,B,rid)`, sign it under the credential context, let
`cert=(B,σ)` and `vc=cred=(cert,mapp,rid,ε,µ)`. Bounded-verify before release and
record `(µ,mapp,rid,B)` in `Tauth` **before** release. Serialise logging, challenge
consumption and release. The holder verifies approved attributes, credential, state
and initial witness before accepting; retain `we` separately. The issuer's log matches
original certified `B`, not a new presentation commitment. Sources: V-C, p. 8;
VI-B.1/.3, pp. 10–11; VII-A.5, p. 15; VIII-B Theorem 4, p. 18.

**R-022 — Issuance abort semantics [M].** Abort stops further processing and retires
the issuer nonce. It does not undo allocations, recorded/released certificates or
committed public updates. Return updated authority states even if `outH=⊥`; record
released responses whether or not the holder later accepts them. Sources: IV-B Issue,
p. 6; V-C, p. 8; VI-A, pp. 9–10; VII-A.5, p. 15.

## Complete relation and check placement

**R-023 — Credential binding interfaces [M].** Private credential record is
`cred=(cert,m,rid,ρ,µ)` and generic witness `ωe=(cert,xH,m,rid,ρ,we)`.
Here `ρ=ε`, `cert=(B,σ)` and `B=(Y,Esch(m))`.
`BindRep(pp,µ,cert,ρ)` checks domains/instance/certificate and empty `ρ`, returning
the original `B` or failure. `BindOpen(pp,B,xH,m,ρ)` checks domains, the holder hash
and equality of the entire canonical attributes. `CredValid` additionally checks the
same `rid` and credential-context signature. It does not consult private issuer logs.
Those logs enter the certification experiment, not the verifier's inputs.
Sources: V-A/B, pp. 7–8; VII-A.5, p. 15; VI-B.1, p. 10.

**R-024 — Joint authentication relation [M].** Public statement and concrete witness:

```text
X = (pp,µ,ctx,rse,D,mD)
ξ = xH || Esch(m) || [rid]4 || σ || (s0 || … || s19)
    32       1024       4    3309          960         bytes
len(ξ)=5329 bytes=42632 bits
ωe = ((B,σ),xH,m,rid,ε,we), reconstructed from the same ξ
```

The complete predicate is exactly

```text
Rauth(X,ωe) = PubOK(X)
             AND CredValid(pp,µ,cert,xH,m,rid,ρ)
             AND NRVerify(pp,rse,rid,we)
             AND (projD(m)=mD)
             AND Ppub(mD,ctx).
```

Reconstruct `Y` from **this** `xH`, `B` from **this** `Y` and attribute block and
`Mcred` from **this** `B`, instance and `rid`; check **this** signature over that body,
**this** identifier's zero-leaf path and **this** vector's projection. Mix-and-match
credentials, signatures, secrets, attributes or paths must fail. No auxiliary relation
data are used: `a=η=ε`. Tapes/shares are fresh prover randomness, not extra credential
witnesses. Sources: V-B displayed complete relation, p. 8; VII-A.6, pp. 15–16;
VIII-C Theorem 6 witness decoding, p. 19.

**R-025 — Private, public and lifecycle checks [M].** This division is mandatory:

| Location | Required checks |
|---|---|
| Private circuit/reference predicate | Parse and validate every private field/range/padding; recompute holder hash and canonical binding/body; bounded FIPS credential verification including all invoked hashes/decoding/arithmetic; zero-leaf path for the same certified `rid`; equality of disclosed fields to the same canonical `m` |
| Public cryptographic verifier (`PubOK`,`Ppub`) | Parse public values; match suite/tag/issuer/key/schema/namespace and repeated fields; validate supported policy/mask/order/encodings; match `ctx.refe` to `rse`; verify state signature; evaluate clauses on certified disclosed values |
| Lifecycle/services | Issuer trust, external evidence/controller authorisation, request authentication, holder approval, expected audience/session/context, trusted-time expiry, current-state reads, optional disclosed DID checks and atomic challenge consumption |

The full reference relation includes the public conjunction even though its public
checks can be performed outside the private circuit. A service must not receive `ξ`
to perform those private checks directly. A Stage 2 local reference evaluator may
inspect test witnesses; it is not the eventual presentation verifier. Sources: V-B
`PubOK`/`Rauth`, p. 8; VII-A.6/.7, pp. 15–17.

**R-026 — Present/AuthDAA [M].**
`Present(params,vc,stH,we,ctx,rse) → vp or ⊥` validates the authenticated request,
holder approval, instance, expiry, policy, state, credential and witness. Update witnesses
locally when needed; a changed request state requires a new request. `AuthDAA` uses
`xH`, not controller state, checks the complete relation and creates a fresh proof.
Return `vp=auth=(D,mD,π)` in R-005's flat encoding. Do not alter the certified credential
or issuer/manager records, reveal additional holder data or reuse proof randomness.
Sources: IV-B Present, p. 6; V-C/D, pp. 8–9; VII-A.6, pp. 15–16.

**R-027 — VerifyDAA [M].**
`VerifyDAA(pp,auth,ctx,rse) → b` is stateless. Derive the expected instance metadata,
parse `D,mD,π`, build `X`, check `PubOK` and `Ppub`, then run `Check(auth,X,π)`.
Reject malformed encodings, unsupported policies, mismatched disclosures and invalid
proofs. This alone does not establish freshness, trust, expiry or challenge consumption.
Sources: V-C Verify, pp. 8–9; VII-A.7, p. 16.

**R-028 — Stateful Verify/atomic acceptance [M/A].**
`Verify(params,vp,ctx,rse,stV) → (b,stV')`. Check the complete registered pending
context, audience/session, unexpired time, trusted issuer/key/schema, policy, state and
DAA proof. Any application validity claim used for acceptance must be certified and
disclosed. A configured DID-state check requires **both** `did,vD` disclosed plus
validated resolution; do not resolve a hidden DID. Finally perform R-017's ordered
current-state read and match its reference. Atomically recheck the complete pending
context/session/expiry and consume the challenge before returning success. The
agreed SPEC-002 expiry predicate is `now < texp`, including this final atomic check. Failed
calls do not consume it; concurrent calls may change shared state. Replicas permit
at most one acceptance. Do not change the logical epoch to a later global transaction
snapshot. Sources: IV-B Verify, p. 6; VII-A.7, pp. 16–17; VIII-E Theorem 10, p. 20.

## Merkle revocation and witness maintenance

**R-029 — Tree and PathRoot [M].** Use fixed depth 20 and at most `2^20` permanently
allocated identifiers. All leaves, including unallocated ones, initially use revoked
bit 0; allocation itself does not change the root. Hashes are 48 bytes:

```text
Lb = H(enc_leaf(suite,µ,[b]1)),                 b∈{0,1}
Fj(u,v) = H(enc_node(suite,µ,[j]1,u,v)),        j∈{1,…,20}
Te[0,i] = L_(1[i∈Re])
Te[j,k] = Fj(Te[j-1,2k],Te[j-1,2k+1]);        Ae=Te[20,0]
Z0=L0; Zj=Fj(Zj-1,Zj-1);                     A0=Z20
```

`w=(s0,…,s19)`, with `sj=Te[j,(floor(r/2^j) xor 1)]` and each sibling exactly
48 bytes. `PathRoot(r,b,w)` starts `v0=Lb`, then sets `vj+1=Fj+1(vj,sj)` if
numeric bit `j` of `r` is zero and `Fj+1(sj,vj)` otherwise. `NRVerify` validates
identifier/path/state domains and requires `PathRoot(r,0,w)=Ae`. State authenticity
is public; latest-state freshness belongs to the wrapper. Epochs use eight bytes with
no wraparound. Sources: VII-A.1/.5, pp. 14–15; V-B, pp. 7–8.

**R-030 — Revoke [M/A].**
`Revoke(params,stR,rse,rid,req) → (stR',rse+1,ue+1) or ⊥` permits the issuer to
revoke any allocated identifier, including an aborted issuance. For fresh `nR`, use

```text
MR  = enc_revreq(suite,E(µ),[rid]4,E(refe),nR)
req = (nR, Sign_revreq(skI,MR))
Mu  = enc_update(suite,E(µ),E(refe),E(refe+1),[r*]4,s*0||…||s*19)
υ   = Sign_update(skR,Mu)
ue+1= (rse,rse+1,r*,w*,υ), tagged rupdate
```

Check authorisation signature, unused nonce, registration, namespace, exact current
state and non-revocation. Set the leaf for `r*=rid` to `L1`, recompute ancestors
`a0=L1,…,a20=Ae+1`, increment the epoch, sign the state/update and bounded-validate
both signatures. Atomically commit tree, epoch, nonce consumption and public records.
Invalid/duplicate/failed pre-commit operations cause no state change; committed updates
remain retrievable despite delivery failure. DID deactivation is independent. Agreed SPEC-001 makes the outer `rupdate` path field the same raw 960-byte
concatenation, LP-wrapped once. Its five fields remain distinct from the six-field
`update` signing body; do not sign the transport record instead. This is an agreed
clarification of missing wording, not a change to `Mu`. Sources: IV-B Revoke, p. 6; VII-A.8, p. 17.

**R-031 — UpdateWit [M].**
`UpdateWit(pp,r,we,rse,rse',Ue→e') → we' or ⊥`, with `e'≥e`, stays holder-local.
Validate old witness, both endpoint state signatures and each update signature,
namespace, consecutive epochs, matching chain endpoints and
`PathRoot(r*,b,w*)=Ae+b` for `b∈{0,1}`. If `r=r*`, fail. Otherwise recompute
changed ancestors from `(r*,1,w*)` and, for `j=0…19`, set

```text
sj' = aj if (floor(r/2^j) xor 1) == floor(r*/2^j), otherwise sj.
```

Check the new path, then iterate. Missing, reordered, inconsistent updates or invalid
witnesses fail. An empty chain is allowed only at the same state with a valid witness.
Update no certified attribute, binding or identifier. Do not send the holder's private
`rid,w` to a remote update service; the already public `r*,w*` are a different record.
Sources: IV-C, pp. 6–7; V-D, p. 9; VII-A.8 Local witness update, p. 17.

## Bounded operations and circuit profile

**R-032 — Exact bounded computation [M].** Execute FIPS 204 Algorithms 3 and 8 and
all invoked context/hash processing, key/matrix expansion, signature/hint decoding,
polynomial arithmetic, norm checks and challenge comparison. Execute every relevant
FIPS 202 block/round/suffix/padding operation. An external hash/signature call is not
a private-input circuit implementation. Use standard coefficient-assignment order and
consume rejected sampler bytes. Sources: VII-A.6 Bounded computation, pp. 15–16.
DEP-001 records algorithm/editorial errata disposition; exact operation traces remain
to be implemented and checked against admissible ordinary-library results.

**R-033 — Caps and release policy [M].** Per invocation: `RejNTTPoly ≤1026` bytes;
`RejBoundedPoly ≤512` bytes; `SampleInBall ≤256` total bytes (8 sign bytes, at most
248 index bytes); at most 1024 `ML-DSA.Sign_internal` attempts. Exhaustion rejects
verification or aborts setup/signing. Bounded-verify **every** signature before release,
without an internal retry after failure. These constraints cover all signature roles,
not just issuer certificates. No existing smoke test establishes them. Sources:
VII-A.6, pp. 15–16; VIII-A cap accounting, pp. 17–18.

**R-034 — BC-1 arithmetic [M].** Use signed 64-bit integer words, sign-extended
65-bit addition/subtraction, 128-bit products and checked representability before
narrowing. Reduce every ring operation modulo `q=8380417`, retaining FIPS centred
representatives. Bytes/Keccak lanes are 8-/64-bit bitstrings. Attribute integers stay
eight-byte strings inside the circuit; disclosed range checks use unsigned arithmetic
publicly. Serialised bytes enter most-significant-bit first; arithmetic bit `i` weighs
`2^i`; implement required FIPS bit-order conversions by rewiring. Source: VII-A.6,
BC-1 paragraph, p. 16.

**R-035 — BC-1 gates and ordering [M].** Use XOR/AND/NOT/constants; expand OR as
`a xor b xor (a and b)`. Ripple addition emits low bit first:
`ti=ai xor bi`, `si=ti xor ci`, `ci+1=(ai and bi) xor (ti and ci)`, with carry zero;
subtraction complements the second operand and starts carry one. Equality left-folds
XNOR bits; signed comparison uses the extended difference's sign. Multiply magnitudes
by summing shifted partial products in increasing bit order, then apply the sign.
Positive-constant division/reduction scans magnitude bits high-to-low with conditional
subtraction and signed floor/remainder correction. Bitstring shifts/permutations rewire;
integer shifts use checked multiplication/floor division. `mux(s,a,b)=a xor (s and
(a xor b))`. Evaluate operands left-to-right, matrix/vector operations componentwise,
sums by left fold, arrays by increasing indices. Source: VII-A.6 BC-1, p. 16.

**SPEC-003 [U, agreed 17 September 2026]:** “Initialise equality with public 1.
Initialise magnitude multiplication with a public 128-bit zero accumulator; add all
64 shifted partial products in increasing order using full-width ripple addition,
retaining terminal carry operations.” This clarifies the missing initialisers in
VII-A.6; it is a user decision, not a quotation from the manuscript. Preserve the
existing gate/operand order, checked arithmetic and public-only folding rules.
The canonical construction exposes no alternate initialiser. Diagnostic alternatives
remain test-only. This decision does not approve every previously proposed derived
recipe or establish full BC-1 conformance; see [SPEC-003](spec_issues.md#spec-003--fold-initialisers-and-derived-gadget-recipes-affect-gate-identity).

**R-036 — BC-1 control flow, rejection and optimisation [M].** Scan all cells for
private reads using equality selectors; multiplex writes from a snapshot, retaining
sequential assignments. Compile both branches, true before false; merge with multiplexers.
Unroll array loops to capacity and sampler loops to byte caps, preserving source
initialisation/tests/increments; share one byte counter per sampler invocation and mask
iterations after termination. Parsing/index/overflow errors set a sticky reject bit
only on active paths; invalid reads yield zero and invalid writes do nothing. Parallel
FIPS updates read the prior state. Reserve wires 0/1 for constants; number inputs by
serialised order, outputs and AND gates by emission order; copies reuse wires. Fold
only all-public operations: no reassociation, common-subexpression elimination or
partial-constant simplification. Output the conjunction of required checks and no
rejection. Source: VII-A.6 BC-1, p. 16.

**R-037 — Circuit identity and admission [M/E].** Both sides derive
`CGen(kind,X)`; never accept a prover-selected circuit. Use `d=256` enrolment bits or
`d=42632` authentication bits. Before proving/checking validate public domains and
`len(E(X))≤L`, `V=ceil((d+2g)/8)≤L`, hence `g≤floor((8L-d)/2)`.
`Bmax=2L+2^18` bounds outer-oracle input length strictly from above. Admission only
establishes encoding capacity, not feasible memory/time. E: pin the eventual reference
source/emitter version and circuit-vector digests alongside the unchanged suite/profile;
any proposed change to the defined lowering requires review. Sources: VII-A.6 admission,
p. 16; VIII-A, p. 18.

## Raw-view MPC-in-the-head proof

**R-038 — Shares and tapes [M].** `Prove(kind,X,ξ)` first derives the admitted
circuit and rejects wrong-length witnesses or `fX(ξ)≠1`. Run exactly 480 independent
three-party repetitions `j=0…479`, party indices modulo three. Sample independent
uniform `ξ0,ξ1`; set `ξ2=ξ xor ξ0 xor ξ1`. Each party receives an independent raw
uniform `g`-bit tape. Constants share as `(a,0,0)`, XOR is local and NOT flips party 0.
At AND gate `k`, compute

```text
zi=(ai AND bi) XOR (ai+1 AND bi) XOR (ai AND bi+1) XOR ri,k XOR ri+1,k.
```

No seeded-tape substitution, repetition reduction or unrelated inner relation is
permitted. Source: VII-A.6 Shared prover, p. 16.

**R-039 — Views and commitments [M].** Each `vj,i` concatenates the input share,
raw tape and AND outputs in gate order, `d+2g` bits, packed MSB-first with zero low
terminal padding. Reconstruct other wires locally. Sample independent 64-byte salts
`sj,i`; compute `cj,i=HRO(enc_view(suite,kind,E(X),[j]2,[i]1,sj,i,vj,i))`.
`A` concatenates `(yj,0,yj,1,yj,2,cj,0,cj,1,cj,2)` for increasing `j`; each output
share is the byte 0 or 1. Source: VII-A.6 Shared prover, p. 16.

**R-040 — Fiat–Shamir challenge [M].** After committing, sample an independent
64-byte proof nonce `ν`; compute

```text
u  = HRO(enc_challenge(suite,kind,E(X),ν,A))
ej = floor((OS2IP(u) mod 3^480)/3^j) mod 3
```

`OS2IP` is unsigned big-endian. Preserve this modulo distribution; do not substitute
rejection sampling, independent trits, a shorter hash or a different transcript.
Source: VII-A.6, challenge equations, p. 16; VIII-C/D, pp. 18–19.

**R-041 — Proof serialisation and size [M].** `π=ν || A || Z`; for each increasing
`j`, `Z` contains `(salt,view)` of `ej`, then `(ej+1) mod 3`. There are no hidden
seeds or additional opening indices. Each repetition contributes `3+3×128=387`
bytes to `A` and `2×64+2V` bytes to `Z`, giving

```text
len(π) = 64 + 480*(515 + 2*ceil((d+2g)/8)).
```

The authentication gate-independent term is 5,363,104 bytes; an additional million
AND gates contributes 240,000,000 bytes. These are mathematical sizes, not generated
circuits or timing evidence. Sources: VII-A.6, p. 16; proof-length display after
VII-A.8, p. 17; VIII-A, p. 18.

**R-042 — Proof checking [M].** `Check(kind,X,π)` independently derives admitted
`fX,d,g`, validates the exact proof length and recomputes challenges. In every repetition,
require three advertised output bytes in `{0,1}` with XOR 1, both opened commitments
and padding valid, reconstructed outputs equal to their advertised shares, and every
AND equation of the **first** opened party valid using both views/tapes. Accept only
if all repetitions pass. Do not invent a check of the second party's unavailable
third view. Public `PubOK/Ppub` checks remain mandatory in DAA verification. Source:
VII-A.7, p. 16; VIII-C complete-witness decoding, p. 19.

**R-043 — Fresh randomness and erasure [M].** Refresh shares, tapes, salts and proof
nonce for every attempt; erase transient proof state and never reopen committed views
under another challenge. Keep no selection-dependent credential/authority mutation.
E: prohibit secret-bearing logs and retained test keys; document later native erasure
limitations instead of claiming Python object deletion securely wipes memory.
Sources: VII-A.6, p. 16; VIII-D Theorems 7–9, pp. 19–20.

## Security contract and limits of evidence

**R-044 — Certification, binding and non-membership [M].** Authorised certification
requires accepted openings to match the recorded `(µ,mapp,rid,B)`. Binding separately
excludes two valid openings with different `(xH,m)` for the same `B`. Non-membership
soundness excludes a zero-leaf witness for the extracted certified identifier when
that identifier is revoked at the target authenticated epoch. A different genuinely
unrevoked credential is not a revocation forgery. Direct certification uses the exact
approved encoded vector; no optional issuance-extraction contract is assumed for this
construction. Security depends on ML-DSA quantum EUF-CMA with classical signing
queries and SHA3 quantum collision resistance; hiding a uniform holder secret adds
preimage resistance on its 256-bit domain. Sources: III-D, p. 4; VI-B.1–.3/D.1,
pp. 10–12; VIII-A/B Theorems 4–5, pp. 17–18.

**R-045 — Complete-witness knowledge [M].** A fresh base statement has not been
answered by an honest presentation/challenge oracle; changing auxiliary proof data
does not make it fresh. The required quantum extractor preserves the specified target
acceptance predicate and actual authorisation/revocation history, and decodes the same
complete `ωe`. It may not rewind/invert external classical service/signing oracles or
substitute an unrelated history. State query dependence, error, runtime and truncation
losses. No API that claims to extract a witness from one accepted transcript is part
of the implementation. Sources: VI-B.4, p. 11; VIII-C Theorem 6, pp. 18–19.

**R-046 — Adaptive presentation privacy [M].** QPT adversaries have classical
protocol queries and quantum outer-oracle access. Enrolments are sequential, not
interleaved malicious enrolments. Verifiers and corrupted background holders may
collude. Target setup/issuer/manager/current-state service remain honest; DID integrity
is assumed. Protected holders remain uncorrupted throughout. Candidate credentials
must be accepted, eligible/unrevoked in the same state and match instance, context,
policy, disclosed positions/values and cumulative authorised public outcomes, with
approval by both holders. Check eligibility/update both before selecting by the hidden
bit. Proof bytes/lengths are observable and require the privacy argument; they are not
automatically authorised leakage. Sources: III-C, pp. 3–4; VI-A/C, pp. 9–12;
VIII-D Theorems 7–8, p. 19.

**R-047 — Historical privacy and exclusions [M].** In the two-phase experiment,
candidate credentials remain unrevoked during challenge queries. After an adaptive
cut-off, close the challenge oracle permanently, allow named revocations (including
at least one challenged credential), and include all actual published identifiers,
old paths, auxiliary information and quantum residual state in the joint view.
No service receives the historical hidden candidate index; challenge holders stay
uncorrupted and no hidden-index presentation resumes after cut-off. The claim is
post-revocation unlinkability, not post-compromise/forward security. Authority–verifier
collusion, leaked authority records, network timing/addresses and availability are
excluded. Voluntary credential/secret sharing and live relay within the intended
session are not prevented. Sources: IV-D, p. 7; V-E, p. 9; VI-D.2/E, pp. 12–13;
VIII-D/E Theorems 9–11, pp. 19–20.

**R-048 — Correctness scope [M].** Correctness applies to admissible executions with
successful issuance, accepted instance, satisfied policy, eligible unrevoked credential,
valid updated witness, matching request/final state, unexpired pending context and no
competing successful consumption. It does not require stale/revoked/unsupported cases
to succeed. Proof completeness for true admitted circuits is perfect; operational
correctness still includes cap aborts and service conditions. Sources: IV-C, pp. 6–7;
V-E, p. 9; VII conclusion and VIII-A, pp. 17–18.

**R-049 — Cap-loss and runtime accounting [M; validation pending].** Count all setup,
controller/service operations and pre-release honest verification. With honest-operation
budgets `nK,nS,nV,nA`, Section VIII-A bounds

```text
cT ≤ 30*(nK+nS+nV+nA);  cB ≤ 11*nK;  cC ≤ 1024*nS+nV;  cS=nS
C ≤ 41*nK + 1055*nS + 31*nV + 30*nA
F(n,p,k) = Σi=0..k binom(n,i)*p^i*(1-p)^(n-i)
βT=F(342,8380417/2^23,255); βB=F(1024,9/16,255)
βC=F(248,13/16,48);        βS=(41/51)^1024  [reported model; DEP-001]
δcap(E) ≤ Δtail(E) + Σj cj*βj ≤ Δtail(E) + C*2^-304 [conditional]
εΣ(B)=Adv_qEUF-CMA_ML-DSA-65(B)+δcap(B)
```

Cache a deterministic expansion's count once only when actually reused. Malformed
adversarial signatures are rejection cases, not honest cap failures. `Δtail=0` is
not asserted for arbitrary adaptive SHAKE inputs. Component advantages include full
query/runtime budgets; extraction-based cost includes
`TA+Thon+Tgen+O(Q^2)*poly(1024,8*Bmax)+O(480*|fX|)`. Do not infer a total security
level from `λ=128` or an average signing attempt count. Source: VIII-A, pp. 17–18;
DEP-001 explains the reviewed external-standard dependency.

**R-050 — Conditional QROM terms [M; not independently proved here].** Only `HRO`
is an ideal quantum-accessible oracle; internal hashes remain specified algorithms.
For `Q≥1` including honest/hybrid and post-challenge continuation queries and `N`
replaced proofs, record the manuscript's expressions:

```text
p* = (2/3)^480 + 2^-544
εex(Q) = min(1,31740*Q^3*2^-1024 + 20*Q^2*p*)
κ(Q)=εex(Q); Fauth(εS;128,Q)=max(εS-εex(Q),0)
α(Q)=sqrt(Q*2^-512) + (1/2)*Q*2^-512
δZK(N,Q)=min(1,N*(481*α(Q)+960*Q*2^-256))
```

Theorem 6 covers target/history-preserving extraction; Theorem 7 online simulation of
the complete view; Theorems 8–9 bound adaptive/historical privacy by `δZK`. Erasure,
fresh salts and exact modulo challenges are part of that stated argument. Illustrative
resource evaluations in VIII-E are conditional calculations, not parameter choices or
benchmarks. Sources: VIII-A/C/D/E, pp. 17–20, Theorems 6–9 and resource evaluation.

**R-051 — Lifecycle security composition [M].** Retain honest ordering, latest-state,
trusted-time and atomic services, plus cryptographic service-authenticity loss:

```text
εsys ≤ Σk∈Ksys εΣ(Bk) + Adv_qCR_H(Brecord) + qn*(qn-1)*2^-257
pgood ≥ max(ε - εsys - εex(Q) - εΣ(Bcert) - Adv_qCR_H(Btree), 0)
Adv_priv/pru_PQ-DID ≤ δZK(N,Q) + εsys
```

Service keys include relevant issuer, manager, registry, controller and request keys;
component reductions account for all signing purposes and corruption timing. Read
nonces use the collision term; other used-set nonce types cannot successfully repeat.
These are conditional extraction/privacy guarantees under the actual history, not
claims proved by regression tests. Sources: VI-E Theorems 2–3, p. 13; VIII-E
Theorems 10–11 and service-authenticity bound, p. 20.

## Representation and research profile decisions

**R-052 — W3C architectural mapping [M/E].** Section III-A, p. 3, maps DID publication/
resolution, a private credential `vc`, a disclosure/proof presentation `vp` and revocation
state to the DID/VC lifecycle. It explicitly does not establish data-model conformance
or standardise this DID method. VII-A.4 prescribes only the minimal DID JSON document.
No extra controller key or stable holder identifier may be inserted into an anonymous
presentation to simplify an adapter. This is the binding constraint on the design below.

### E-001 — Planned modules and error handling

Use Python for the reference orchestration and exact-byte codecs. The separately named
bounded ML-DSA reference also uses Python integers with native stdlib hashing; any later
native optimisation and circuit/proof code must preserve its specified computation.
`pqdid.backend` loads the ordinary pinned library; `pqdid.bounded_mldsa` supplies the
separate bounded verifier. Planned module paths
appear in traceability, not as success-returning stubs. A local relation evaluator may
take `ξ`; public DAA/service APIs will take only their specified public inputs/proof.
Represent internal errors distinctly for testing (encoding/domain, invalid signature,
cap exhaustion, stale state, unavailable service, expired/consumed challenge, capacity),
then map to the specified interface failure without leaking witness material.

### E-002 — Synthetic Stage 2 schema fixture (not manuscript constants)

Use this explicitly labelled research fixture to exercise the manuscript's configurable
schema. It asserts only synthetic issuer-approved claims, not real-world KYC compliance.

| Index | Name | Type | Capacity bytes | Meaning |
|---|---|---|---|---|
| 1 | `did` | 0 | 171 | Issuance-time DID bytes; designated DID index |
| 2 | `didVersion` | 0 | 56 | `[k]8 \|\| δk`; designated version index |
| 3 | `kycPassed` | 1 | 1 | Synthetic issuer-approved Boolean |
| 4 | `assuranceLevel` | 2 | 8 | Synthetic unsigned level |
| 5 | `countryOfResidence` | 0 | 2 | Two-byte synthetic country code, e.g. ASCII `SG` |
| 6 | `validUntil` | 2 | 8 | Certified POSIX expiry seconds; agreed SPEC-002 |

This uses `Σ(2+Mj)=258` bytes plus 766 zero tail bytes. The two scenarios are separate
holder-approved policies: A discloses `{3,4,6}` (mask `002c`), checks `kycPassed=true`,
`assuranceLevel≥2` and `validUntil≥ctx.texp`; B discloses `{3,5,6}` (mask `0034`),
checks `kycPassed=true`, `countryOfResidence=SG` and `validUntil≥ctx.texp`. Express
unsigned lower bounds with `range(lower,2^64-1)` and sort the encoded clauses.
Neither scenario requests DID checks. Both explicitly disclose expiry before relying
on it; neither proves a predicate on a hidden birth date or other hidden value.
Fixture values are inputs to the configurable suite and are not installed as defaults
in `suite.json`. Distinct synthetic audience/session/key configuration will be supplied
when creating test instances; no trust keys or deadlines are invented here.

### E-003 — W3C representation design, with integration prerequisites

Use a deterministic adapter between the canonical binary objects and the planned W3C
application representation. The targets named in the implementation plan are
[DID Core 1.0](https://www.w3.org/TR/2022/REC-did-core-20220719/) and
[VC Data Model 2.0](https://www.w3.org/TR/2025/REC-vc-data-model-2.0-20250515/).
Custom securing/status mechanisms need their own specification and validation; no
compatibility with a standardised PQ-DAA cryptosuite is claimed.

| Representation | Mapping and disclosure rule |
|---|---|
| DID resolution | Exact VII-A.4 JSON and `application/did+json`; `vD`/controller records remain authenticated method metadata outside the document |
| Original credential, holder-local | Complete schema claims and issuance-time DID/version map to `Esch(m)`; certificate/binding/signature/identifier map to the private canonical credential. This original object is not sent to anonymous verifiers |
| Derived claim set | Public issuer reference and only claims selected by `D`, decoded from `mD` under the immutable schema. Omit stable subject/credential/holder IDs unless their disclosure is explicitly approved and encoded |
| Presentation | Carry the canonical `D,mD,π` and the expected public statement/instance references through an experimental securing mechanism; retain the audience request signature separately. No original credential signature, binding, `rid` or path is copied into it |
| Status extension | Refer to the public namespace/authenticated epoch/root; the proof supplies hidden-identifier non-revocation. Do not invent a credential-specific status URL/index that exposes `rid` |
| Acceptance | Reconstruct exact `X`; require equality of every externally asserted claim/instance/context/state field with the canonical counterpart, then perform public proof and lifecycle checks. Reject unknown acceptance-relevant fields or conflicts; a JSON wrapper cannot add unsigned claims |

Engineering design: canonical bytes are the cryptographic source of truth. Binary values
in a future JSON envelope use a single specified lossless encoding; no arbitrary JSON
serialisation is fed to the manuscript signature/proof. Custom context/type/proof/status
IRIs, the envelope's media type and its conformance adapter remain **integration inputs**
to finalise before Stage 5. No illustrative JSON is presented as a conforming credential.
The mapping above fixes privacy and verification boundaries without inventing protocol
bytes or adding public information. Relevant plan deliverable: W3C representation
design; conformance execution remains subsequent work.

### E-004 — Resource policy and unresolved input handling

Preserve the already recorded two-job native builds and WSL limits; do not reinterpret
the manuscript's huge encoding bounds as a RAM allocation. Stage 2 tests must distinguish
mathematical/domain rejection, cap exhaustion and harness resource exhaustion. Before
experiments, require explicit timeout, memory and scratch budgets in a run profile;
missing values must not silently select unbounded execution. No performance claims or
benchmark defaults are taken from excluded sections. Resource admission may stop an
experiment with an explicit non-completion result; it must not silently change the
relation, tree depth, transcript or proof repetitions.

## Readiness boundary

SPEC-001/002 were agreed by the user on 17 September 2026 and checked against the
in-scope text without finding a conflict. Stage 1 is complete; the PDF wording updates
remain author edits recorded in `spec_issues.md`. The first Stage 2 codec/schema/policy/
expiry work is implemented and tested as recorded in `stage2_codec.md` and traceability.
Holder-binding consistency, domain validation and depth-20 Merkle root/path mathematics
are now implemented and tested in `stage2_binding_merkle.md`; they do not establish
issuer certification, full state validity, currentness or proof possession.
DEP-001/002 remain open validation/implementation work; proof feasibility remains Stage 3.
Parameter/certificate/credential structural validators and exact Mcred construction now
compose with bounded signature verification and the same-B holder opening in complete
local `credentials.cred_valid`. [stage2_bounded_mldsa.md](stage2_bounded_mldsa.md) records
the independent verifier validation, real signed fixtures and cap tests. Its success
does not establish remote knowledge, issuer trust, non-revocation or freshness.
[bounded_mldsa_plan.md](bounded_mldsa_plan.md) records remaining keygen/signing/release
obligations. Complete local enrolment/authentication relations, typed statements/witnesses
and their public state/policy checks are now implemented and tested in
[stage2_relations.md](stage2_relations.md). Canonical E(X) prepares proof inputs; actual
transcript binding, circuit/proof and lifecycle services remain unimplemented. Bounded
key generation/signing and production authenticated witness updates remain separate work.

Stage 3 now includes the bounded foundation, full SHA3/SHAKE schedules and complete
local enrolment compiler. SPEC-003 is agreed as recorded under R-035; the canonical
path already uses that convention. All 17 deferred tests and nine probes complete
under the separate approved operational profile. [The validation report](stage3_hash_enrolment.md#confirmed-convention-and-extended-validation)
records literal fresh trace stability, historical fingerprint equality and remaining
conformance boundaries. Authentication private parsing and checked division/reduction/
ring gadgets are ready as the next bounded package. Full canonical BC-1 conformance,
privacy-preserving proofs and complete feasibility remain open; no proof result is
inferred from the calculated 9587104-byte enrolment size. Stage 2 obligations persist.

The following two paragraphs preserve the earlier package boundaries; their pending
SPEC-004 status and count limits are superseded by the adoption record below.

The subsequent [authentication parsing/scalar package](stage3_auth_parsing_arithmetic.md)
implements private 5329-byte witness/schema/projection checks and public-positive-
constant signed64 division, canonical/centred residues, checked scalar ring operations,
Decompose/UseHint/norm helpers and one forward NTT butterfly. [SPEC-004](spec_issues.md#spec-004--restoring-division-work-registers-and-exact-emission-schedule)
records the precise unresolved restoring-division emission recipe, separately from
its fixed mathematical semantics. This development path is deterministic but does
not establish full canonical CGen/authentication or a proof. FIPS signature decoding,
full NTT/matrix/sampling and same-witness cryptographic composition remain subsequent
work; public policy/state/lifecycle boundaries and all agreed parameters are unchanged.


The [private signature/input preparation package](stage3_signature_inputs.md) now
implements response/hint decoding and exact same-witness holder/B/Mcred/pure-ML-DSA
input wiring. Named validity results are preparation-only: full hint reconstruction
and full message/input composition stop at the authorised 2000000-gate cap. Executed
component/fragment tests do not replace those missing complete executions. The
expected pp key is public; no independent decoded coefficients, hints, B or Mcred
are added to the 5329-byte authentication witness. SPEC-004 remains pending; the
issue register contains the complete recommended wording and measured alternatives.
All earlier private/public boundaries, full BC-1/proof obligations and Stage 2 work
remain unchanged.


SPEC-004 was agreed on 18 September 2026 with the complete explicit correction
sequence in [the issue register](spec_issues.md#spec-004--restoring-division-work-registers-and-exact-emission-schedule).
Use `mux(nz,public_zero65,b_minus_R)` for corrected_negative_R; retain named 65-bit
intermediates once in source order, both outputs for every div/mod call, Q-then-R
representability checks and `(Q_valid AND R_valid) AND (b>0)`. MIN's unsigned magnitude
2^63 is valid. Zero constructs and rejects; unsupported divisors fail at construction.
This supersedes the earlier pending implementation notes, not the independent full
BC-1 conformance obligation. A separate count-only operational preflight is recorded
in [stage3_resource_preflight.md](stage3_resource_preflight.md); it changes no crypto
parameter, witness or ordinary/materialised evaluation limit.
