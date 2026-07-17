# FIPS 203 traceability

FIPS 203 is the normative specification for ML-KEM. The canonical structured mapping is maintained in [`compliance/standards/fips203.toml`](../../compliance/standards/fips203.toml).

The mapping covers secret handling, approved primitives, encoding, sampling, NTT arithmetic, K-PKE subroutines, ML-KEM internal and public algorithms, input validation, all three parameter sets, and local ACVP harnesses.

Generate the complete standards dashboard with:

```bash
cargo xtask standards --strict
```

or directly:

```bash
python3 scripts/standards_engine.py report --strict
```

A passing report establishes internal traceability and evidence consistency. It does not constitute NIST CAVP, CMVP, or FIPS 140-3 validation.
