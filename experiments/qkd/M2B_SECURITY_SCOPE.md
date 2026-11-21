# M2.B security scope

- The M2.A Python runner produces a **public-only** evidence record. No raw key, privacy amplification output, PSK, seed, or authentication key crosses the Python/Rust boundary.
- Rust `production_handoff` **always denies** all simulated provenance. It also denies forged positive flags and returns `QualifiedProviderNotImplemented` for otherwise-positive external provenance. Public claims are never sufficient to authorize secrets.
- A **separate, intentionally insecure fixed 32-byte fixture** tests existing randomized ML-KEM-768 / RFC 9180 HPKE PSK sender and receiver and the paired one-time provider. This fixture is *not* an M2.A output or a QKD-generated secret.
- No real qualified provider or authorized key-export path is implemented.
- Quantum source, theorem conformance, entropy, reconciliation correctness, authentication key provisioning, and hybrid security composition remain unverified.
- All simulation and research outputs must preserve `SECURITY_MODEL_VALIDATED=false` and `HPKE_EXPORT_AUTHORIZED=false`.
