# Documentation

The documentation is organized by audience and assurance purpose.

## Standards and compliance

`docs/standards/` contains standards mappings, traceability policy, and generated-report guidance. The canonical structured source is `compliance/matrix.toml`.

## Security and assurance

Security methodology, side-channel experiments, machine-code reviews, zeroization reviews, and assurance reports are maintained in the existing security, audit, side-channel, and assurance directories.

## User and developer documentation

Milestone A will add installation, API, interoperability, architecture, and release guides. Until those guides are complete, the root README and rustdoc are the primary entry points.

## Documentation policy

Documentation must distinguish normative requirements from informational guidance and distinguish test evidence from proof, certification, or independent audit.

- [Implementation matrix](IMPLEMENTATION_MATRIX.md)

## API governance

- [B1.3.1 Public API Review](api/API_REVIEW.md)
- [Generated Public API Inventory](api/API_INVENTORY.md)
- [ML-DSA feature contract](api/ML_DSA_FEATURE_CONTRACT.md)
- [ML-DSA public implementation boundary](api/ML_DSA_PUBLIC_BOUNDARY.md)
- [ML-DSA SemVer contract](api/ML_DSA_SEMVER_CONTRACT.md)

## Security assurance

- [Secret inventory](security/SECRET_INVENTORY.md) and [zeroization audit](security/ZEROIZATION_AUDIT.md) — B1.3.2 secret-lifetime policy and review.

## B1.3.3 security assurance

- [Constant-time audit](security/CONSTANT_TIME_AUDIT.md)
- [Secret-dependency register](security/SECRET_DEPENDENCY_REGISTER.md)
- [B1.3.3 milestone](../README-b1-3-3.md)

## B1.3.5 performance assurance

- [Performance baseline](performance/PERFORMANCE_BASELINE.md)
- [Benchmark register](performance/BENCHMARK_REGISTER.md)
- [B1.3.5 milestone](../README-b1-3-5.md)
