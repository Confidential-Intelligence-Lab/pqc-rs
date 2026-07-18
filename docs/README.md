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
