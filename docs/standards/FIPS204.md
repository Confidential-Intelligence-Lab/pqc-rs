# FIPS 204 — ML-DSA Traceability

This page describes repository traceability to **FIPS 204, Module-Lattice-Based Digital Signature Standard**.

The canonical machine-readable requirements are in:

```text
compliance/standards/fips204.toml
```

The initial module covers the approved ML-DSA parameter sets, arithmetic and encoding primitives, SHAKE usage and domain separation, public and internal key-generation/signing/verification operations, deterministic and hedged signing, context binding, pre-hash variants, rejection sampling, canonical encodings, input checking, secret protection, and ACVP key-generation/signature-generation/signature-verification workflows.

## Claim policy

A traceability result is not a NIST validation certificate.

- `mapped` identifies candidate code, test, and evidence locations.
- `implemented` requires resolvable implementation references.
- `verified` additionally requires resolvable tests and reviewable evidence.
- CAVP, CMVP, and FIPS 140-3 validation remain separate external processes.

## Commands

```bash
python3 scripts/install-a1-3.py
python3 scripts/validate-a1-3.py
cargo xtask standards --strict
```

Generated reports are expected under:

```text
target/standards/fips204/
```
