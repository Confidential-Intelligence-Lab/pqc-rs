# Contributing

PQC-rs welcomes focused contributions that improve correctness, standards traceability, interoperability, security assurance, documentation, or developer experience.

## Before opening a change

For substantial work, open an issue or discussion describing the standard, algorithm, API, or engineering problem. Security vulnerabilities must follow `SECURITY.md` rather than a public issue.

## Required local checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
python3 scripts/validate-a1-1.py
cargo xtask compliance --strict
```

Run additional ACVP, fuzzing, side-channel, or assurance workflows when the change touches cryptographic behavior, secret-bearing types, serialization, arithmetic, compiler-sensitive code, or release infrastructure.

## Cryptographic change checklist

A cryptographic change should include:

- the exact normative or research reference;
- deterministic positive tests;
- malformed-input and negative tests where applicable;
- interoperability or vector evidence when available;
- analysis of secret-dependent branches and memory indexing;
- review of secret copying, formatting, and zeroization;
- updates to `compliance/matrix.toml` when standards coverage changes;
- documentation of compatibility or API implications.

## Pull requests

Keep pull requests narrow enough to review. Explain what changed, why it is correct, which standards sections are affected, and which commands produced the attached evidence. Do not combine unrelated refactoring with cryptographic changes.

Contributors certify that they have the right to submit their work under the project's MIT License.
