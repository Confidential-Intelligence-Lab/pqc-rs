# Documentation

The documentation is organized by audience and assurance purpose.

## Standards and compliance

`docs/standards/` contains standards mappings, traceability policy, and generated-report guidance. The canonical structured source is `compliance/matrix.toml`.

## Security and assurance

Security methodology, side-channel experiments, machine-code reviews, zeroization reviews, and assurance reports are maintained in the existing security, audit, side-channel, and assurance directories.

- [Stage 10B-5 cross-architecture validation](security/STAGE10B5_CROSS_ARCHITECTURE.md)

## User and developer documentation

Milestone A will add installation, API, interoperability, architecture, and release guides. Until those guides are complete, the root README and rustdoc are the primary entry points.

## Release planning and external review

- [Project roadmap](../ROADMAP.md)
- [v0.4.0 release checklist](release-checklist.md)
- [v0.4.0 external reviewer packet](release/V0.4.0_EXTERNAL_REVIEW.md)
- [Personal outreach templates](release/EXTERNAL_REVIEW_OUTREACH.md)
- [PQUIP and HPKE announcement drafts](release/IETF_REVIEW_ANNOUNCEMENTS.md)

## Documentation policy

Documentation must distinguish normative requirements from informational guidance and distinguish test evidence from proof, certification, or independent audit.

- [Implementation matrix](IMPLEMENTATION_MATRIX.md)

## API governance

- [B1.3.1 Public API Review](api/API_REVIEW.md)
- [Generated Public API Inventory](api/API_INVENTORY.md)

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
