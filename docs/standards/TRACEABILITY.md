# Standards Traceability Policy

`compliance/matrix.toml` is the canonical source for mappings between standards, implementation locations, tests, CI gates, and assurance evidence.

## Status semantics

`planned` means that a requirement has been identified but not yet mapped. `mapped` identifies likely code or documentation locations without claiming implementation. `implemented` claims that resolvable implementation references exist. `verified` additionally requires resolvable tests, named evidence, a verification date, and periodic review. `not-applicable` requires an explicit rationale.

## Evidence types

- `implementation`: source paths or glob patterns.
- `tests`: executable test paths or glob patterns.
- `evidence`: human-readable assurance records, campaigns, or external validation labels.
- `evidence_paths`: repository-resident, machine-resolvable evidence artifacts.
- `ci`: jobs or validation profiles that continuously exercise the requirement.

The generator resolves repository references relative to the repository root. In strict mode, errors and warnings fail the command. This makes missing ownership, stale verification, unresolved references, and insufficient evidence visible before release.

## Ownership and review

A requirement may define `owner`; otherwise `metadata.default_owner` applies. Verified entries must define `last_verified` in `YYYY-MM-DD` form. `review_due_days` may override the matrix-wide default.

## Querying

```bash
cargo xtask query --standard RFC9958
cargo xtask query --status verified
cargo xtask query --missing tests
cargo xtask query --missing evidence
cargo xtask query --missing owner
cargo xtask query --missing ci
```
