# Stage 8D

Copy these files into the PQC-rs repository root.

Apply the dependency and module update:

```bash
python3 scripts/patch-stage8d-secret-hygiene.py
```

Run the automated review gate:

```bash
./scripts/run-stage8d.sh
```

Then classify the generated inventories:

```text
target/stage8d-secret-inventory.txt
target/stage8d-secret-branch-inventory.txt
target/stage8d-debug-findings.txt
target/stage8d-unsafe-inventory.txt
```

The new `pqc_core::secret` wrappers are intended for public API hardening and
incremental migration. Do not replace validated internal representations in a
single broad patch.
