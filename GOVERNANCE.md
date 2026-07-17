# Governance

PQC-rs is currently a maintainer-led project in its pre-release phase.

## Roles

**Owners** set project direction, approve releases, manage security disclosures, and resolve governance questions.

**Maintainers** review changes, enforce engineering and security requirements, maintain standards traceability, and may merge changes within their assigned areas.

**Contributors** submit issues, reviews, documentation, tests, and code under the project contribution requirements.

## Decision process

Technical decisions favor:

1. normative standards and published specifications;
2. correctness and interoperability evidence;
3. conservative security claims;
4. maintainable and idiomatic Rust APIs;
5. portability before architecture-specific optimization.

Routine decisions are made through review. Material API, cryptographic, governance, licensing, or release-policy changes should be documented in an issue, design note, or architecture decision record before merge.

## Releases

Only owners may authorize public releases and security advisories. Release candidates must satisfy the applicable release checklist and assurance profile in `RELEASE.md`.

## Evolution

Governance will be revisited when the project gains independent maintainers, external users, or multiple algorithm repositories. Future governance should reduce single-maintainer risk while preserving clear accountability for cryptographic and standards decisions.
