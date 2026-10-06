PQ-DID — Ligetron correction handover
Prepared 1 October 2026

STATUS: UNTESTED EXPERIMENTAL PATCH PROPOSAL. NOT A COMPLETE ZK REPAIR.

This handover turns the source findings into concrete candidate edits and a
bounded validation proposal. It does not authorise native execution, adoption
of a proof profile, or changes to the live PQ-DID project limits.

Read in this order:
  1. correction-proposal.txt
  2. candidate-rng-corrections.patch
  3. native-validation-plan.json
  4. CODEX_TASK.txt

source-manifest.json identifies 19 retained source files from public commit
4b1cdef1bfdf4497fb3e38170db4541fba3f6c12 (ligeroinc/ligero-prover v1.7.0).
The original files are included in source_snapshot/. This is a partial source
snapshot, not a full dependency lock or a buildable checkout. SHA-256 and Git
blob hashes are computed from the retained bytes. They do not independently
authenticate membership in the upstream Git tree.

The patch proposes changes to five files:
  src/webgpu_prover.cpp
  src/webgpu_verifier.cpp
  include/zkp/random.hpp
  include/zkp/finite_field_gmp.hpp
  include/zkp/nonbatch_context.hpp

It replaces the weak encoding-seed derivation, corrects the query generator,
proposes bounded rejection sampling for field elements, and separates the
three public challenge streams. It changes the stage labels to an explicitly
experimental name. This changes transcript behaviour and proof compatibility.

It deliberately does not change masking polynomials, packing parameters,
commitment construction, SHA-256, the VM, the PQ-DID relation or any manuscript.
Those choices require the correspondence decisions in correction-proposal.txt.
In particular, passing all proposed component cases would not discharge them.

Checks performed during preparation:
  - Constructed the patch against the retained source bytes.
  - git apply --check succeeded against the included source snapshot.
  - Reconciled source/patch hashes and inspected the packaged file inventory.

Not performed:
  - C++ compilation, native regression execution, cryptographic experiments,
    WebGPU execution, PQ-DID tests, project preservation audits or proof attempts.
  - Complete source-tree, dependency or theorem-to-implementation certification.

No WSL project file, resource ledger, baseline result, dependency, host service
or manuscript has been modified. The source changes exist only as this draft
patch and a disposable preparation copy. The three old embedding-only slots
and other unused corrective allocations confer no authority for this work.

The genuine ML-DSA KYC baseline remains complete within its recorded scope.
Private authentication remains unimplemented; private verification must stay
fail-closed. Binius, private proving and isolation remain paused. The proof
ledger remains two used, one unused.

Source snapshot copyright: Ligero, Inc.; original notices are retained.
APACHE-2.0.txt accompanies the source excerpts. Candidate changes in the patch
are experimental modifications prepared for Grace's PQ-DID research; they are
not an upstream release or upstream security endorsement.
