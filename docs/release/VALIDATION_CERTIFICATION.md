# Validation Certification

> Generated from `compliance/validation-policy.toml`. Do not edit manually.

This report consolidates repository-local engineering evidence. It is not third-party certification.

| Item | Scope | Status | Evidence |
|---|---|---|---|
| `unit_and_conformance` | Correctness | **PASS** | `Cargo.toml`<br>`tests` |
| `acvp_ml_kem` | FIPS 203 | **PASS** | `docs/stage6-4-keygen-acvp-milestone.md`<br>`docs/stage6-5b-acvp-encapsulation.md`<br>`docs/stage6-5c-decapsulation.md` |
| `acvp_ml_dsa` | FIPS 204 | **PASS** | `docs/stage9e1-nist-acvp-keygen.md`<br>`docs/stage9e2a-nist-acvp-siggen.md`<br>`docs/stage9e3-nist-acvp-sigver.md` |
| `interoperability` | Interop | **PASS** | `scripts/interop_engine.py`<br>`docs/stage7c-hpke-pq-vectors.md` |
| `fuzzing` | Robustness | **PASS** | `compliance/fuzz-policy.toml`<br>`docs/security/STRUCTURED_FUZZING.md` |
| `performance` | Performance | **PASS** | `compliance/performance-policy.toml`<br>`docs/performance/PERFORMANCE_BASELINE.md` |

## Decision

**PASS**
