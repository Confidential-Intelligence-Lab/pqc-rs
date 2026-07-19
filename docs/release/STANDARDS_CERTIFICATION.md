# Standards Certification

> Generated from `compliance/standards-certification-policy.toml`. Do not edit manually.

This report consolidates repository-local engineering evidence. It is not third-party certification.

| Item | Scope | Status | Evidence |
|---|---|---|---|
| `FIPS 203` | ML-KEM key generation, encapsulation, decapsulation, key checks | **PASS** | `docs/fips203-traceability.md`<br>`docs/stage6-6-acvp-key-check.md` |
| `FIPS 204` | ML-DSA key generation, signing, verification, HashML-DSA | **PASS** | `docs/stage9d6-validation.md`<br>`docs/stage9e5-hash-mldsa.md` |
| `RFC 9180` | HPKE key schedule and base-mode context | **PASS** | `docs/stage7b1-rfc9180-kdf-key-schedule.md`<br>`docs/stage7b4-base-context-aead.md` |
| `RFC 9958` | ML-KEM integration with HPKE | **PASS** | `docs/rfc9958-traceability.md`<br>`docs/rfc9958-traceability-stage7a.md` |

## Decision

**PASS**
