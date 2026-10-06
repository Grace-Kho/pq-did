# Native dependency runbook v2: verified identities and stopped build

This additive version preserves the [original proposal](../../../proposals/s3_aurora_native_dependency_lock_1/README.md), original lock and all previous seals. The selected commit revisions, source origins, package versions/archive digests and gitlink commit IDs are unchanged. Use [dependency-lock-v2.json](dependency-lock-v2.json) for the three corrected root-tree fields, together with [lock-correction.json](lock-correction.json) and [object-associations.json](object-associations.json). This is a metadata correction, not a new dependency revision.

Original lock SHA-256: `9f95bcb9f82d4cb5f8caaf2ca41e9e22b17ea39e8146474ca055e1d67eae617f`.
Corrected lock SHA-256: `0e33258c861764eacb8e4f04d21962425e7b7fedd7f27e79cecc4176deec1736`.

The original API responses were queried by commit and exposed that commit ID in their top-level `sha`; it was mistakenly copied as a root-tree identity. Local Git object contents establish the correction. With `GIT_NO_REPLACE_OBJECTS=1`, `GIT_OPTIONAL_LOCKS=0`, and `git --no-replace-objects -C CHECKOUT`, the recorded commands use `cat-file -t PIN`, `cat-file commit PIN`, `rev-parse PIN^{tree}`, `cat-file -t TREE`, `remote get-url origin`, and explicit complete tree/blob comparisons. Each raw commit's Git object SHA-1 was independently recomputed. Existing successful libiop fsck evidence was reused; remaining selected repositories each received one pinned fetch and fsck. Full argv/stdout/exit records are in [commands.json](commands.json).

| Repository | Unchanged commit | Verified root tree |
| --- | --- | --- |
| libiop | a2ed2ec2f3e85f29b6035951553b02cb737c817a | 2e2588ccb085242dd2237875c3b9adf1a0fc958c |
| libff | 9769030a06b7ab933d6c064db120019decd359f1 | 265df78b1b15fcf061a9c34bf8ce195b6bd9b9f8 |
| libfqfft | 7d460caa27b87574fe0e8144e6a3a66b7bcfe770 | 6c7875366ca607a2b12caa5cbfd8b3c020bce9aa |

The approved continuation reused the retained libiop checkout and inspected all three associations before checkout/use of the remaining dependencies. The actual guarded commands were:

```sh
.venv/bin/python -I -B docs/data/s3_aurora_native_transcript_pilot_1/reconciliation-1/run.py provision
.venv/bin/python -I -B docs/data/s3_aurora_native_transcript_pilot_1/reconciliation-1/run.py build-1
.venv/bin/python -I -B docs/data/s3_aurora_native_transcript_pilot_1/reconciliation-1/run.py build-2
```

These are historical commands, **not permission to rerun**. Provisioning passed. Both builds failed, consuming both attempts. No native comparison was admitted. Build 1's compiled target unnecessarily included elliptic-curve source that GCC 15 rejected. The sole permitted build-only correction restricted target `ff` to its pinned binary fields and common support. It changed only the isolated overlay CMake target selection; [build-only-correction.json](build-only-correction.json) records before/after hashes. Build 2 built that library and reached libiop's stale `index`/`coeff` names in `relations/variable.tcc`, then stopped. No third build, suppressing compiler flag, source repair, replacement version or mock was attempted.

The complete configuration/build argv and command-scoped environment removals are in [build-1-commands.json](build-1-commands.json) and [build-2-commands.json](build-2-commands.json). The selected local prefix is `experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1/prefix`; acquired Git trees remain under `src`, the isolated patch under `work`, harness/build inputs under `overlay`, and incomplete build outputs under `build`. Both binary development archives remain under `packages`. The archived headers, versions, architecture and static libraries passed the original static checks. Runtime shared-library aliases included in the development archives can be dangling; the build selects the verified static `.a` paths explicitly. No package scripts or install target ran.

Cleanup is retention only: all guarded workers exited; no persistent service was activated. Keep checkouts, archives, local prefix, patched sources, incomplete outputs, original and amended build inputs, failed logs and stop records. No evidence deletion, source relocation, host/package changes or unguarded rebuild. Native admission requires a separately bounded compiler-compatibility correction proposal and a new build-attempt authorisation; the existing native invocation allowance alone does not authorise another build.
