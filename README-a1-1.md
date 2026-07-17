# Milestone A1.1 — Standards Traceability Framework

This additive overlay introduces:

- `compliance/matrix.toml` as the canonical requirements source;
- a standalone Rust `xtask` generator;
- Markdown, JSON, and HTML reports;
- structural and path-aware validation;
- conservative initial RFC 9958 topic mapping;
- documentation that separates informational guidance from normative conformance.

## Apply

From the repository root, copy the overlay into place and run:

```bash
./scripts/install-a1-1.sh
python3 scripts/validate-a1-1.py
cargo xtask compliance --strict
```

Reports are written to `target/compliance/`.
