# Architecture Snapshot

> Generated from `compliance/architecture-policy.toml`. Do not edit manually.

This report consolidates repository-local engineering evidence. It is not third-party certification.

| Item | Scope | Status | Evidence |
|---|---|---|---|
| `Protocol framework` | Transport-independent roles, identifiers, versioning, and future wire-protocol orchestration | **PASS** | `crates/pqc-protocol` |
| `Protocol implementations and profiles` | Application-facing HPKE APIs, RFC 9180 profiles, and hybrid protocol composition | **PASS** | `crates/pqc-hpke`<br>`crates/pqc-hybrid` |
| `Post-quantum primitives` | ML-KEM, ML-DSA, and SLH-DSA algorithms and parameter sets | **PASS** | `crates/pqc-ml-kem`<br>`crates/pqc-ml-dsa`<br>`crates/pqc-slh-dsa` |
| `Core security types` | Errors, secret containers, constant-time helpers, and shared codec boundaries | **PASS** | `crates/pqc-core` |
| `Assurance and evidence` | Conformance, fuzzing, interoperability, audits, and benchmarks | **PASS** | `compliance`<br>`fuzz`<br>`scripts`<br>`docs` |

## Decision

**PASS**
