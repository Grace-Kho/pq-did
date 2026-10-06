# Inactive fourth-build request

No native build command is enabled or executed in this repair. This request is
conditional on all eight tooling cases and the one full preservation audit passing.
The user must separately approve build attempt four; the present ceiling stays three.

Copy `dependency-prefix-v1/compatibility-v1/work` and `overlay` with `cp -a` to a
fresh `dependency-prefix-v1/guarded-build-v1/` subtree; refuse an existing destination.
Verify exact source/harness hashes, preserving the ten-reference postimage and EXP2.
Create only its `scratch` subdirectory. Set compiler `TMPDIR` to that fixed path;
never inherit an ambient or evidence-directory TMPDIR. Keep diagnostics captured in
the new evidence directory. Never run a compiler during this repair.

The exact proposed configure/build argv is in [next-build-request.json](next-build-request.json).
Only the fresh paths differ from the sealed commands. This is one build including
configuration/probes, 55-second deadline, one worker/two CPUs and 1 GiB. Use only
`exp2_native exp2_semantics --parallel 1`. No fourth-build correction/rebuild would
follow automatically. The approved binary/common libff workaround stays unchanged.

`policy.compiler_environment` supplies the fixed scratch destination.
`policy.account` and `enforce` classify and bound the complete live output snapshot:
all designated artifacts, including scratch and build metadata, enter 128 MiB;
compiler scratch also enters the unchanged 8 MiB temporary ceiling. Only controlled
compiler scratch and registered exact target outputs get the 32 MiB exception.
Evidence paths are always evidence irrespective of their extension. CMake logs,
cache, manifests and unregistered build outputs count as evidence and retain 1 MiB
per-file limits. Ordinary copied sources have 1 MiB limits. The classification is
an operator-defined producer/destination policy, not content or suffix guessing.
No input resource record can assign its own role or memory ceiling. This is not a
security boundary against a compromised compiler or same-UID arbitrary writer.

The correction guard admits tooling only and makes native artifact paths read-only.
A subsequent approved build must wire the existing guard's TMPDIR to this compiler
environment, monitor both output roots with this policy, and add precisely the
approved native phases to the trusted phase table. No existing failure is waived.
A failed record remains rejected; a successful audit of retained failures does not
make a prior failed build successful.

Retain 30 seconds for final audit/report/cleanup. Subsequent SEM-01–SEM-08 and
TR-01–TR-16 retain their exact order, independent expectations and two-second case
deadlines. Admit them only after both targets link and the remaining time can cover
48 case seconds plus finalisation. A slow build can therefore leave all cases
unrun. No extra invocations or time are requested. Final accounting will state
whether the remaining evidence reservation supports this request, with any needed
reservation amendment presented explicitly rather than applied automatically.

Keep all failures/artifacts, verify terminated cgroups and preserve each baseline,
sealed historical repair and partial-build record. Stages 2–3 and AURORA-BRIDGE-001
stay open. No proof, zkVM execution, installation, host activation or private
witness is involved.
