# PQ-DID project instructions

- Use UK English. Preserve existing files and work, including the working `.venv`,
  pinned dependencies, native toolchain and VS Code configuration.
- The selected manuscript is `docs/manuscript/PQ_DID__Implementation.pdf`.
  Its recorded SHA-256 is
  `d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
  Check its identity before manuscript-dependent changes; if another revision creates
  ambiguity, ask which source is authoritative before finalising requirements.
- **Only manuscript Sections II–VIII are authoritative for specification extraction,
  consistency checks, parameter selection and subsequent implementation. These are
  section numbers, not PDF page numbers.** The abstract, Section I and Sections IX
  onwards are unrevised and excluded. Do not use their constructions, claims,
  prototype results or timings as specification/performance evidence. Do not edit
  those sections; the user will revise them after implementation.
- Differences arising solely from excluded sections are deferred manuscript edits,
  not implementation blockers. Verify any alleged conflict against its exact source
  in Sections II–VIII. Keep dependency/API issues separate from manuscript issues.
- Record proposed manuscript corrections in `docs/spec_issues.md`; preserve the
  manuscript itself. Distinguish explicit requirements, routine engineering choices
  and unresolved protocol/security/privacy/interoperability decisions.
- Do not silently change the proof system, use seeded tapes, change repetition
  counts, move private checks outside the proof, omit required checks or weaken
  freshness. Material changes require a concrete proposal for the user's decision.
- Reuse the setup evidence in `docs/environment.md`; do not reinstall dependencies
  or rerun completed setup solely for documentation work. Ordinary library behaviour
  does not establish the manuscript-specific bounded-operation requirements.
- Keep unimplemented algorithms and unverified properties explicit. Stage 1 is only
  complete when its specification/traceability deliverables and material ambiguities
  are resolved. Executable relations belong to Stage 2; proof/circuit implementation
  belongs to Stage 3. Do not create placeholder proof functions that appear to succeed.

- Agreed user clarifications (17 September 2026), recorded in `docs/spec_issues.md`:
  SPEC-001 uses one raw 960-byte sibling-path payload, preserving the enclosing
  `rupdate` framing and the distinct `update` signing-message encoding. SPEC-002
  uses unsigned 64-bit big-endian POSIX seconds and strict `now < texp`, including
  the final atomic expiry recheck. These are agreed clarifications, not quotations
  from the manuscript. Do not reopen them without new conflicting evidence.
- SPEC-003 was also agreed on 17 September 2026: “Initialise equality with public 1.
  Initialise magnitude multiplication with a public 128-bit zero accumulator; add
  all 64 shifted partial products in increasing order using full-width ripple
  addition, retaining terminal carry operations.” Preserve gate/operand order,
  checked arithmetic and public-only folding. Diagnostic alternatives must stay
  outside the canonical compilation path. This settles those initialisers, not
  full BC-1 conformance; see `docs/spec_issues.md`.
- SPEC-004 was agreed on 18 September 2026, with explicit 65-bit correction wiring:
  `corrected_negative_R = mux(nz, public_zero65, b_minus_R)` (true selects the
  third operand), not the previous private-R false arm. Preserve named temporary
  reuse/order, the unsigned64 magnitude including 2^63, all 64 descending scan
  steps with full 65-bit subtraction/carries, and construction/checking of both
  outputs for every div/mod call. Check Q then R, AND those validity bits in that
  order, then AND with b>0. Zero divisor constructs and rejects; negative/private/
  out-of-signed64 divisors fail at construction. The complete adopted wording is
  in `docs/spec_issues.md`. This resolves SPEC-004, not full BC-1 conformance.
