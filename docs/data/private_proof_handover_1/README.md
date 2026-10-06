# Retained private-proof construction handover

This is a packaging of existing evidence for independent examination, not a new
review, proposed repair or working proof implementation. Start with the complete
`repo/docs/oct31_binius64_g0.md`. **G0 is NO-GO; Binius64 remains paused.** G1–G3,
private proofs and profile adoption are not authorised. Private verification is
fail-closed. The full PQ-DID/KYC/benchmarking scope and 31 October target are
unchanged; the retained evidence does not support a full-completion commitment.
Only manuscript Sections II–VIII and SPEC-001–004 are authoritative. Stages 2–3
and the security obligations remain open; proof ledger: two used, one unused.

## Identity and reading order

- Implementation commit: `441fbf51ff0bcb0bcd28f3f1b73f4954029e8577`.
- Root tree: `544452a781fee0f9b262d4ecfdcc47326fb6974f`.
- Blueprint: retained 15 August 2026 PDF, SHA-256
  `0dfdfd2fb8066842e0c0914901930b6b4f276284983838ad40ff0f2e8f0d9803`.
- `repo/docs/data/oct31_binius64_replacement_decision_1/source-index.json`
  contains the original source identities. Its `sources/implementation-commit.json`
  and `sources/implementation-tree.json` contain the recorded commit/tree metadata.
- `repo/docs/data/oct31_binius64_g0_1/source-acquisition.json` and
  `source-acquisition-2.json` identify the eight G0 additions.
- `source-map.json` joins those retained indices without changing source bytes.
  `file-list.json` and `SHA256SUMS` enumerate all included payloads and SHA-256s.
  The archive's external checksum is supplied separately (no self-hash claim).

The source filenames preserve the original flattened retained names. Below, B means
`repo/docs/data/oct31_binius64_replacement_decision_1/sources/`; G means
`repo/docs/data/oct31_binius64_g0_1/sources/`. Replacing `/` with `--` and adding
`native--` for B yields the exact included filename. The source map also records
all original upstream paths, URLs and Git blob identities.

| Trace | Included upstream paths and report section |
| --- | --- |
| Witness packing/padding | B `crates/prover/src/prove.rs`, `pack_witness`; G `crates/prover/src/ring_switch.rs`; G0 “B64-ZK-001” |
| Terminal claim and verifier check | B `crates/spartan-prover/src/wrapper/zk_wrapped_prover_channel.rs`; G `crates/spartan-verifier/src/wrapper/zk_wrapped_channel.rs`, `builder_channel.rs`; G `crates/verifier/src/ring_switch.rs` |
| Outer constraints/random support | B `crates/spartan-prover/src/lib.rs`, `crates/spartan-verifier/src/lib.rs`, both wrapper `mod.rs` files, frontend/verifier `constraint_system.rs` |
| Masked encoding/commitment | G `crates/iop-prover/src/fri/encode.rs`, `crates/math/src/reed_solomon.rs`; B `crates/iop-prover/src/merkle_channel.rs` |
| Query openings/folds | G `crates/iop-prover/src/fri/query.rs`, `crates/iop/src/basefold/channel.rs`; B `crates/iop-prover/src/basefold/channel.rs`, `opening.rs`, both BaseFold compiler files and `crates/iop/src/fri/mod.rs` |
| Exceptional challenges/masking distribution | Both BaseFold channel files, encoder and outer prover above; G0 “Affine gamma and exceptional challenges” |
| Public-input transcript correction | B `ottersec-fix.json`, prover/verifier entry files and retained integration/wrapper tests; earlier decision qualifies coverage. Tests are copied text, not executed here. |

B `spec.pdf` and `spec.txt` are the retained Blueprint and extracted text. Website
commit/tree metadata is included; reproducible PDF/source-build correspondence was
not established. Reading a current website must not replace these retained bytes.

## Findings, derivations and unresolved assumptions

**Source findings** are the G0 report's step-by-step native trace: the terminal
claim bypasses OTP wrapping; `encode_masked` leaves the message row unchanged;
original query leaves expose the message and companion mask rows separately.
These are retained source findings, not results of new execution or a forgery.

**Derived conclusions/examples** already appear in the full G0 report:
`Pi=J*w+U*r`, the image/rank condition for equal linear-view distributions;
the positive-power support/evaluation-at-zero counterexample to a cardinality-only
argument; the missing inner/outer terminal-key equality equation; and the conditional
affine-gamma change of variables with its two exceptional field values. They are
structural arguments with stated limits, not finite native tests or complete
security theorems. No separate executable minimal example or justified overlay
was delivered by G0, and none is invented in this bundle.

**Unresolved premises** remain the actual encoder/support map and rank condition,
semantically inert support, cross-commitment terminal-key equality, adaptive joint
view simulation, commitment hiding, the additional IntMul oracle shapes, affine
transcript transfer, CSPRNG/entropy assumptions, extraction/QROM and finite/concrete
hash bounds. This packaging neither reopens nor resolves them.

## Complete PQ-DID relation and trust boundary

Read the included `repo/docs/implementation_spec.md`,
`repo/docs/stage2_relations.md`, `repo/docs/data/oct31_auth_relation_integration_1/relation-notes.md`
and `repo/docs/data/implementation_consolidation_1/handover.md`.
The first relation sections and source mapping specify public X, private witness,
canonical encodings, trusted preprocessing and lifecycle context. Later Aurora
matrix/field sections are historical experimental proposals, not an adopted
Binius64 relation or authoritative scheme change.

The included `repo/src/pqdid/relations.py` is the executable reference target;
its canonical schema/statement/witness, binding, credential, public-check, policy,
Merkle and bounded ML-DSA dependencies are included as text. The exact witness is
`xH32 || m1024 || rid4 || sigma3309 || path960`; the same credential attributes and
certified identifier must link signature, disclosure and non-revocation. This is
a local reference relation, not an accepted private proof. The manuscript itself,
full development environment and unrelated experiment trees are not bundled.

## Missing material and reproduction limits

`missing-evidence.json` states the construction/dependency gaps.
`missing-native-files.tsv` lists every blob from the retained pinned native tree
not included in this selected snapshot, with its recorded blob ID and size. This
is an inventory of absent text, not a claim that every listed file is needed for
the trace or build. In particular, full helper implementations/dependency closure
are not supplied by the selected snippets; no complete checkout or native binary
is present. `dependency-requirements.json` contains requirements, not a resolved
transitive lock. The pinned tree had no Cargo.lock; exact resolved crate checksums,
artifacts and native compatibility were not established. No acquisition was made.

Some historical reports/manifests link to larger retained evidence outside this
bundle. They are retained verbatim; a link or manifest entry is not a claim that
its target was included. `file-list.json` is the exhaustive bundle inventory.
Large ancestry-response metadata is deliberately omitted and identified in the
missing-evidence record. No build directories, keys, synthetic stores or private
witness fixtures are copied. This is a source examination package, not a runnable
or independently reproduced prover distribution.

## Current KYC comparison point

`comparison-point.json` registers `KYC-BASELINE-ISSUER2-MANAGER2-WALLET-PAGED-1`
by exact retained code/evidence seals. Issuer-v2, manager-v2, wallet and bounded
history results are preserved; largest validated history is eight updates.
The original 276, subsequent 19, issuer-v2 three and manager-v2 four measurements
remain separate. Included closure/outcome summaries and the three newer measurement
files support examination; the original large benchmark dataset is referenced,
not duplicated. Historical failures remain failures. No private-proof timing,
throughput or privacy overhead is supplied. The 21 unrun full-relation checks
remain unrun. Production security and standards-level interoperability remain open.
