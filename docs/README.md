# Documentation

PQC-rs documentation is organized around the evidence needed to understand,
use, evaluate, and release the stack.

## Start here

- [Project overview](../README.md) — capabilities, architecture, examples, and
  current project status.
- [Roadmap](../ROADMAP.md) — current development priorities.
- [Implementation matrix](IMPLEMENTATION_MATRIX.md) — generated capability and
  validation status.
- [Security policy](../SECURITY.md) — supported versions, limitations, and
  vulnerability reporting.
- [Release process](../RELEASE.md) — publication and release requirements.

## Standards

[`standards/`](standards/) contains standards traceability and claim policy.
The canonical machine-readable sources are maintained under `compliance/`.

Current coverage includes FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205
(SLH-DSA), RFC 9180 (HPKE), and mapped engineering guidance from RFC 9958.
Post-quantum and hybrid HPKE constructions remain explicitly revision-pinned
where their specifications are not final.

## Interoperability

[`interoperability/`](interoperability/) documents cross-provider validation,
including the canonical software-provider framework and HPKE KEM-provider
substitution experiments.

Interoperability evidence distinguishes byte-exact deterministic parity from
semantic interoperability when independent provider APIs expose different
controls.

## Architecture and API

- [Architecture](architecture/ARCHITECTURE.md)
- [Public API inventory](api/API_INVENTORY.md)
- Package-level rustdoc and crate READMEs

PQC-Forge documentation describes the negotiation, policy, resolution, binding,
activation, and provider boundaries used above the primitive cryptographic
layer.

## Security and assurance

Security and assurance documentation records constant-time engineering,
secret-dependency analysis, zeroization and secret-lifetime review, fuzzing,
Miri and sanitizer analysis, cross-architecture validation, performance
characterization, and release evidence.

These artifacts provide engineering evidence. They are not formal
verification, FIPS validation, certification, or an independent security
audit.

## Performance and release evidence

- [`performance/`](performance/) — benchmark methodology and baselines.
- [`release/`](release/) — release-specific records and review artifacts.
- [`../paper/evaluation/`](../paper/evaluation/) — reproducibility artifacts
  for research evaluations.

## Historical evidence

The repository retains stage-specific design, validation, and assurance
documents as development provenance. They record how capabilities were
established, but they are not the primary entry points for the current public
project state.

## Documentation policy

Canonical documentation should remain concise, current, and evidence-linked.
Normative requirements must be distinguished from informational guidance, and
test evidence must not be described as proof, certification, or independent
audit.
