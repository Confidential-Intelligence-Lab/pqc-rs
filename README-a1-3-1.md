# Milestone A1.3.1 — Standards Engine v2

This overlay replaces the A1.2 Python standards engine with a backward-compatible v2 engine.

## Improvements

- Normalizes `kind`, `classification`, and legacy `source_kind` into one classification field.
- Automatically discovers `compliance/matrix.toml` and every `compliance/standards/*.toml` file.
- Uses `catalog.toml` as optional metadata rather than the sole registry.
- Accepts document schema versions 1 and 2 and rejects unsupported versions clearly.
- Validates requirement classes and statuses as enumerated values.
- Enforces requirement ID uniqueness both within and across documents.
- Resolves implementation, test, evidence-path, and path-like reference metadata.
- Produces stable aggregate and per-document JSON with `schema_version = 2`.
- Adds implementation, verification, ownership, CI, tests, evidence, and staleness metrics.
- Generates Markdown documentation from TOML under `docs/standards/generated/`.
- Generates Graphviz dependency graphs under `target/standards/graphs/`.

## Apply and validate

Copy the overlay into the repository root, then run:

```bash
python3 scripts/validate-a1-3-1.py
cargo xtask standards --strict
```

Expected output includes three discovered documents after A1.3:

```text
decision=pass
documents=3
```

Generated files include:

```text
target/standards/report.{md,json}
target/standards/findings.json
target/standards/<document>/report.{md,json}
target/standards/graphs/<document>.dot
docs/standards/generated/<DOCUMENT>.generated.md
```

The engine preserves the existing claim boundary: internal traceability is not NIST validation or certification.
