# Changelog

## [0.4.0-rc.1] - Unreleased

### Added
- ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
- ACVP KeyGen, Encaps, Decaps, and key-check harnesses.
- RFC 9180 HPKE foundation.
- Pure ML-KEM and PQ/traditional hybrid HPKE Base-mode vector execution.
- Negative tests, fuzzing, Miri, sanitizers, dependency policy, secret wrappers, and performance baselines.

### Security
- Removed general `Debug` support from secret-bearing aggregate types.
- Migrated selected HPKE and hybrid secrets to zeroizing containers.

### Known limitations
- No independent audit or formal constant-time proof.
- HPKE release scope is Base mode.
- Draft-based PQ/hybrid HPKE support is revision-pinned and experimental.
