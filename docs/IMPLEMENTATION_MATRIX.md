# Implementation Matrix

> This document is generated. Edit `compliance/implementation-matrix.toml` and run `cargo xtask implementation-matrix`.

- Project: `pqc-rfc9958-rs`
- Schema: `1`
- Last verified: `2026-07-17`
- HPKE message suites: **27**
- Base/PSK configurations: **54**

## Standards Coverage

| Standard | Scope | Status | Evidence |
|---|---|---|---|
| FIPS 203 | ML-KEM | **verified** | `compliance/standards/fips203.toml` |
| FIPS 204 | ML-DSA | **verified** | `compliance/standards/fips204.toml` |
| RFC 9958 | KEM-oriented API guidance | **mapped** | `docs/rfc9958-traceability.md` |
| RFC 9180 | HPKE Base and PSK modes | **verified** | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |

## Algorithm Coverage

| Primitive | Variant | Status | Evidence |
|---|---|---|---|
| ML-KEM | 512 | **verified** | FIPS 203 ACVP and workspace regression tests |
| ML-KEM | 768 | **verified** | FIPS 203 ACVP and workspace regression tests |
| ML-KEM | 1024 | **verified** | FIPS 203 ACVP and workspace regression tests |
| ML-DSA | 44 | **verified** | FIPS 204 ACVP and workspace regression tests |
| ML-DSA | 65 | **verified** | FIPS 204 ACVP and workspace regression tests |
| ML-DSA | 87 | **verified** | FIPS 204 ACVP and workspace regression tests |

## HPKE Ciphersuite Matrix

Every row is exercised in Base and PSK modes, including seal/open and exporter agreement.

| KEM | KDF | AEAD | Base | PSK | Exporter | Evidence |
|---|---|---|:---:|:---:|:---:|---|
| ML-KEM-512 | HKDF-SHA256 | AES-128-GCM | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-512 | HKDF-SHA256 | AES-256-GCM | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-512 | HKDF-SHA256 | ChaCha20-Poly1305 | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-512 | HKDF-SHA384 | AES-128-GCM | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-512 | HKDF-SHA384 | AES-256-GCM | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-512 | HKDF-SHA384 | ChaCha20-Poly1305 | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-512 | HKDF-SHA512 | AES-128-GCM | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-512 | HKDF-SHA512 | AES-256-GCM | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-512 | HKDF-SHA512 | ChaCha20-Poly1305 | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-768 | HKDF-SHA256 | AES-128-GCM | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-768 | HKDF-SHA256 | AES-256-GCM | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-768 | HKDF-SHA256 | ChaCha20-Poly1305 | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-768 | HKDF-SHA384 | AES-128-GCM | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-768 | HKDF-SHA384 | AES-256-GCM | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-768 | HKDF-SHA384 | ChaCha20-Poly1305 | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-768 | HKDF-SHA512 | AES-128-GCM | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-768 | HKDF-SHA512 | AES-256-GCM | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-768 | HKDF-SHA512 | ChaCha20-Poly1305 | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-1024 | HKDF-SHA256 | AES-128-GCM | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-1024 | HKDF-SHA256 | AES-256-GCM | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-1024 | HKDF-SHA256 | ChaCha20-Poly1305 | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-1024 | HKDF-SHA384 | AES-128-GCM | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-1024 | HKDF-SHA384 | AES-256-GCM | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-1024 | HKDF-SHA384 | ChaCha20-Poly1305 | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-1024 | HKDF-SHA512 | AES-128-GCM | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-1024 | HKDF-SHA512 | AES-256-GCM | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |
| ML-KEM-1024 | HKDF-SHA512 | ChaCha20-Poly1305 | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |

## Validation Matrix

| Validation | Status | Reproduction command |
|---|:---:|---|
| Workspace formatting | **pass** | `cargo fmt --all -- --check` |
| Workspace linting | **pass** | `cargo clippy --all-targets --all-features -- -D warnings` |
| Workspace tests | **pass** | `cargo test --all-targets --all-features` |
| HPKE ciphersuite matrix | **pass** | `cargo test -p pqc-rs-hpke --test ciphersuite_matrix` |
| HPKE interoperability | **pass** | `cargo xtask interop-hpke --strict` |

## Milestone History

| Milestone | Capability | Status |
|---|---|:---:|
| A1 | ML-KEM standards and release preparation | **complete** |
| A2 | Cross-provider interoperability | **complete** |
| A3 | Native HPKE foundation | **complete** |
| B1.1 | HPKE PSK mode and context safety | **complete** |
| B1.2 | HPKE ciphersuite matrix | **complete** |
| B1.2.1 | Generated implementation matrix infrastructure | **complete** |

## Maintenance Contract

The TOML manifest is the machine-readable source of truth. CI runs `cargo xtask implementation-matrix --check` and fails when this generated document is stale. Capability claims must identify reproducible evidence and must not be promoted to `verified` without a passing validation gate.
