# Changelog

All notable user-visible changes will be documented here.

The project follows the principles of Keep a Changelog and intends to adopt Semantic Versioning before the first stable release.

## [Unreleased]

### Added

- standards traceability and compliance-reporting framework;
- layered side-channel and release-assurance infrastructure;
- public project identity, contribution, security, governance, support, roadmap, citation, and release documentation.

### Changed

- clarified that RFC 9958 is an informational engineering guide and that normative conformance is assessed against the applicable FIPS and RFC specifications.

### Security

- documented conservative security-claim and responsible-disclosure policies.

## B1.3.1 — Public API review

- Added preferred suite-first HPKE Base and PSK setup entry points.
- Preserved identifier-based setup APIs as compatibility wrappers.
- Added generated workspace API inventory and classification.
- Added `cargo xtask api-review [--check]`.
