# Milestone A1.2 — Standards Engine and FIPS 203 Traceability

This overlay adds a reusable multi-document standards catalog and the first normative module for FIPS 203. It retains the A1.1 RFC 9958 matrix, adds a structured FIPS 203 matrix, validates code/test references, emits aggregate and per-document reports, and preserves conservative claim boundaries.

Run:

```bash
python3 scripts/validate-a1-2.py
cargo xtask standards --strict
```
