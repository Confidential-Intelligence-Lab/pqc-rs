# pqc-rs-hybrid

`pqc-rs-hybrid` provides support infrastructure for post-quantum and
traditional hybrid cryptographic composition in the PQC-rs workspace.

The crate is a lower-level building block used by higher-level PQC-rs
components. Applications will generally interact with a concrete protocol or
composition layer, such as `pqc-rs-hpke`, rather than using this crate
directly.

## Features

The crate exposes workspace-aligned feature flags including `std`, `alloc`,
`acvp`, and `bench`.

Portability and allocation requirements are feature- and API-specific; users
should verify the configuration required by the APIs they consume.

## Security

This crate is cryptographic infrastructure. Review the PQC-rs repository
security and assurance documentation before production use.

## License

MIT
