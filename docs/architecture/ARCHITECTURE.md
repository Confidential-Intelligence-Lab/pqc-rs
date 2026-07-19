# Architecture Snapshot

> Generated from `compliance/architecture-policy.toml`. Do not edit manually.

This report consolidates repository-local engineering evidence. It is not third-party certification.

| Item | Scope | Status | Evidence |
|---|---|---|---|
| `Public API and protocol profiles` | Application-facing APIs, RFC 9958 and HPKE profiles | **PASS** | `crates/pqc-hpke`<br>`crates/pqc-hybrid` |
| `Post-quantum primitives` | ML-KEM and ML-DSA algorithms and parameter sets | **PASS** | `crates/pqc-ml-kem`<br>`crates/pqc-ml-dsa` |
| `Core security types` | Errors, secret containers, constant-time helpers, serialization boundaries | **PASS** | `crates/pqc-core` |
| `Assurance and evidence` | Conformance, fuzzing, interoperability, audits, and benchmarks | **PASS** | `compliance`<br>`fuzz`<br>`scripts`<br>`docs` |

## Decision

**PASS**
