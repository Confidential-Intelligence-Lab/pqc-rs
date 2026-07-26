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

## Public package order

The dependency order for the current public packages is:

1. `pqc-rs-core`;
2. independent algorithm crates, currently `pqc-rs-ml-kem` and
   `pqc-rs-ml-dsa`;
3. protocol integration crates, currently `pqc-rs-hpke`, after their required
   algorithm crates are indexed.

Independent crates at the same dependency level do not require an ordering
between them. The dependency graph must be rechecked before every publication.
`pqc-rs-slh-dsa`, `pqc-rs-hybrid`, and `pqc-rs-test-harness` remain private
unless a separately reviewed release changes that boundary.

## Tags and registry provenance

Each independently published package uses an annotated tag named
`<package>-v<version>`, such as `pqc-rs-ml-dsa-v0.4.0`. The tag must peel to
the exact source commit embedded in the registry archive.

Before a tag is pushed, verify the registry version is unyanked, compare the
registry SHA-256 checksum with the downloaded `.crate` bytes, inspect the
embedded Cargo VCS metadata, and test the registry-served artifact outside the
repository workspace.

A documentation or policy commit made after publication must not move,
replace, delete, or recreate the published-source tag. Later corrections
belong on the branch and, when necessary, in a separately versioned patch
release.

## Evidence

Release evidence should include machine-readable and human-readable compliance, test, environment, compiler, SBOM, checksum, and assurance outputs. The release notes must state which profiles ran and which checks were informational rather than gating.

## Security language

A release must not claim certification, formal verification, audit completion, constant-time behavior on all platforms, or standards validation unless the corresponding external process has actually completed.
