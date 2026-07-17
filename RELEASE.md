# Release Process

Public releases are owner-authorized and evidence-driven.

## Release candidate checklist

1. Confirm a clean Git tree and reviewed version change.
2. Run formatting, Clippy, and all workspace tests.
3. Run applicable standards, ACVP, interoperability, and assurance gates.
4. Generate compliance reports, SBOMs, checksums, and evidence bundles.
5. Review public API and feature changes for semantic-versioning impact.
6. Run `cargo package` and `cargo publish --dry-run` for every publishable crate in dependency order.
7. Update `CHANGELOG.md`, documentation, and supported-version statements.
8. Review generated package contents and licensing metadata.
9. Create an annotated Git tag.
10. Build and sign public release artifacts from the tagged revision.

## Current package order

The definitive publication order must be generated from the workspace dependency graph. The anticipated initial order begins with shared core crates, followed by algorithm crates, protocol integration crates, and any umbrella package.

Internal test harnesses and experimental crates must not be published unless explicitly approved.

## Evidence

Release evidence should include machine-readable and human-readable compliance, test, environment, compiler, SBOM, checksum, and assurance outputs. The release notes must state which profiles ran and which checks were informational rather than gating.

## Security language

A release must not claim certification, formal verification, audit completion, constant-time behavior on all platforms, or standards validation unless the corresponding external process has actually completed.
