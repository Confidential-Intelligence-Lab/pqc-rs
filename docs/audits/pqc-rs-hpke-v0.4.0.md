# pqc-rs-hpke v0.4.0 Release Audit

Audit base: `cba81f9`

## Result

The published `pqc-rs-hpke v0.4.0` package remains compatible with
`pqc-rs-ml-kem v0.4.1`. No HPKE source repair or version increment was
required.

## Gates completed

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`
- `cargo package -p pqc-rs-hpke`
- `cargo publish -p pqc-rs-hpke --dry-run`

All gates passed.

Package verification rebuilt `pqc-rs-hpke v0.4.0` using the published
`pqc-rs-ml-kem v0.4.1` crate from crates.io.

## Scope

This audit establishes build, test, packaging, and dependency-resolution
assurance. It does not claim an independent security audit, certification,
or complete standards conformance.
