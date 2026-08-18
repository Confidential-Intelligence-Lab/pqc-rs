# pqc-rs-hpke v0.4.1 Release Audit

## Purpose

This patch release aligns the published `pqc-rs-hpke` package with the
application-facing HPKE API already used by the PQC-Forge secure-channel
integration.

The release does not introduce a new secure-channel design. It publishes the
HPKE API surface that the current workspace and evaluated PQC-Forge integration
already depend on.

## Release scope

Version `0.4.1` includes the current application-facing HPKE interfaces,
including:

- public HPKE suite identifiers and suite types;
- public ML-KEM HPKE selection types;
- suite-driven sender setup;
- RNG-backed hybrid sender setup;
- the existing receiver setup and message-context APIs.

These interfaces are required by `pqc-rs-secure-channel` to resolve validated
protocol capabilities into closed HPKE profiles and activate sender and
receiver contexts.

## Compatibility motivation

The previously published `pqc-rs-hpke v0.4.0` predates parts of the current
application-facing sender/setup API.

As a result, packaging `pqc-rs-secure-channel` against crates.io resolved
`pqc-rs-hpke v0.4.0` and failed because the required sender setup functions and
root-level public re-exports were not present in that published package.

Version `0.4.1` publishes the API already present and tested in the workspace
so that the crates.io dependency graph matches the evaluated implementation.

## Validation

Before release, the following checks are required to pass:

    cargo fmt --all --check

    cargo clippy \
      -p pqc-rs-hpke \
      -p pqc-rs-secure-channel \
      --all-targets \
      --all-features \
      -- \
      -D warnings

    cargo test \
      -p pqc-rs-hpke \
      -p pqc-rs-secure-channel \
      --all-features

    RUSTDOCFLAGS="-D warnings" \
    cargo doc \
      -p pqc-rs-hpke \
      -p pqc-rs-secure-channel \
      --all-features \
      --no-deps

    cargo publish \
      -p pqc-rs-hpke \
      --dry-run \
      --allow-dirty

## Security and assurance

This release does not claim independent security certification or formal
verification.

The HPKE implementation remains covered by the repository's existing
interoperability, negative-test, fuzzing, timing, zeroization, and release-gate
infrastructure.

## Publication dependency

After `pqc-rs-hpke v0.4.1` is published and visible on crates.io,
`pqc-rs-secure-channel v0.4.0` must be re-checked with:

    cargo publish -p pqc-rs-secure-channel --dry-run

That dry-run is the final confirmation that the public dependency graph is
aligned.

## License

MIT
