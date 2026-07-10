# Stage 6.1 Workspace Dependency Fix

Stage 6.1 configured `pqc-test-harness` to inherit `serde` and `serde_json`
from `[workspace.dependencies]`, but the root workspace manifest did not define
those dependencies.

Run from the repository root:

```bash
python3 scripts/patch-stage6-workspace-deps.py
```

The patch is idempotent and preserves all existing manifest content.
