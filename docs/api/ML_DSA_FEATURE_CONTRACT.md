# ML-DSA feature contract

The initial `pqc-rs-ml-dsa` public contract requires the Rust standard
library. The implementation uses heap-backed collections and standard-library
functionality directly, so the crate does not currently claim allocation-only
or `no_std` support.

The supported feature surface is deliberately small:

| Feature | Default | Purpose |
|---|---:|---|
| `acvp` | No | Enables ACVP-oriented support shared with `pqc-rs-core`. |
| `bench` | No | Enables benchmark-oriented support shared with `pqc-rs-core`. |

The default feature set is empty because standard-library support is an
unconditional requirement, not an optional capability. Consequently,
`--no-default-features` still builds a standard-library crate; it must not be
interpreted as selecting `no_std`.

Allocation-only and `no_std` support may be introduced later only after the
implementation, API, dependency graph, tests, documentation, and assurance
evidence are designed and validated for those environments.
