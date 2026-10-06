# Replacement integrated construction: handover and admission contract

Scope remains the complete privacy-preserving PQ-DID scheme, KYC testbed and
benchmarking, targeting 31 October without a currently supported completion
commitment. No backend is selected by this handover. Only manuscript II–VIII and
agreed clarifications govern the predicate; experimental proof changes require
explicit approval. Preserve comparison point v1 and all 276 observations.

1. **One complete relation.** Public X contains trusted pp, instance metadata,
   complete request context, authenticated revocation state, disclosure mask and
   disclosed attributes. Private witness is exactly xH32 || m1024 || rid4 ||
   sigma3309 || path960 (5,329 bytes/42,632 bits). Reconstruct the same holder
   binding and Mcred; bounded-verify its issuer signature, project the same m,
   and verify non-revocation at that certified rid. Preserve canonical bytes,
   role contexts, policy, namespace/key/state binding and valid input domains.
   No synthetic acceptance, public private-witness checks, supplied mu or unrelated
   credential/path witnesses. Enrolment is a separate relation, not a substitute.
2. **Public/hidden boundary.** Recompute A, t1, tr, zero leaf and fixed public
   constants only from independently bound public inputs. State signatures do not
   imply currentness. Keep lifecycle service ordering, holder approval, trusted
   time and final atomic expiry/consumption distinct from proof checks.
3. **Exact implementation.** Specify field, representations, ranges/overflow,
   byte links, auxiliary constraints, domains, masks, transcript and encoding.
   Preserve ML-DSA-65 internal SHAKE, malformed hints/norm rejection, 1,026-byte
   ExpandA and 256-byte SampleInBall bounds and exhaustion propagation. Show both
   directions of relation correspondence, including adversarial auxiliaries and
   unusable invalid outputs. Complete lowering is separate from component tests
   and canonical BC-1 conformance. Bind RID/PID to the full descriptor and X.
4. **Security admission.** Provide the precise theorem application or missing
   argument for joint masking and all disclosed messages/openings, commitment
   simulation, adaptive/historical privacy, fresh-statement actual-history quantum
   knowledge/extraction, concrete hashes and finite parameters. Account for query
   unions, reductions, salts/tapes, terminal coefficients and continuation games.
   Independent masks cannot become reused or seeded tapes without an approved
   construction change. Keep adaptive Delta_tail, component advantages and
   production-security assumptions explicit. Classical/ideal exploratory evidence
   cannot replace the intended post-quantum goal.
5. **Whole-resource admission before allocation.** Count all parsing, arithmetic,
   SHA3/SHAKE/sampling, holder binding, disclosure/policy and Merkle operations,
   matrix nonzeros, witness/auxiliaries, masks, padded/expanded domains, codewords,
   commitment trees/salts, transcript, copies and simultaneous temporary buffers.
   Distinguish calculated bounds, measurements and unknowns. Streaming/recomputation
   must retain transcript/randomness distribution and count extra work/storage.
   Current ceilings/reserves apply; no sufficient ceiling can be derived from a
   lower bound. No native instance may be allocated merely because a fragment fits.
6. **Proof/lifecycle interface.** Bounded parser, exact versions/lengths/field
   encodings and complete byte consumption; trusted descriptor/key/context selection;
   independent verification of exact public X. Reject synthetic placeholders,
   unsupported profiles, truncation and resource failures. Ordinary private-proof
   acceptance remains fail-closed until admission and integration pass. Preserve
   issuer commit-before-release, exact recipient redelivery without resigning,
   manager public retrieval and verifier at-most-once acceptance.
7. **Meaningful validation and measurement.** Independent reference agreement plus
   wrong credential/secret/attributes/disclosure/rid/path/instance/key/context,
   malformed and exhaustion cases, auxiliary manipulation and transcript mutation.
   The 21 existing full-relation cases remain unrun until individually admitted.
   Count builds/cases/failures/proofs separately. Benchmark complete raw proof and
   presentation bytes, generation, independent verification, end-to-end freshness,
   simultaneous memory and failure/censoring. Preserve null unavailable values and
   v1 identity; justify any baseline rerun by changed inputs or measurement conditions.

Required user decision: approve a concrete named construction, exact profile delta,
security-claim boundary and fully costed bounded plan; approve any sufficient
resource amendment separately within that same proposal. No such candidate is
admitted today. A failure to satisfy these gates is a construction stop, not licence
to remove private authentication from the original programme.
