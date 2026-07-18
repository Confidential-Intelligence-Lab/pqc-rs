# Milestone A1.3 — FIPS 204 ML-DSA Normative Traceability

This additive overlay extends the A1.2 standards engine with a FIPS 204 module.

## Apply

Copy the overlay into the repository, then run:

```bash
python3 scripts/install-a1-3.py
python3 scripts/validate-a1-3.py
cargo xtask standards --strict
```

The installer is idempotent and registers FIPS 204 in `compliance/catalog.toml` without replacing the existing catalog.

The module begins conservatively at `mapped` status. Promote individual requirements only after the referenced implementation, tests, ACVP artifacts, and assurance evidence have been confirmed locally.
