# Interoperability Framework

A2.1 defines a provider-neutral JSON protocol for replaying deterministic interoperability vectors against independent implementations.

## Commands

```bash
python3 scripts/install-a2-1.py
python3 scripts/validate-a2-1.py
cargo xtask interop --strict
```

Reports are written to `target/interop/report.md`, `report.json`, and `findings.json`.

## Provider protocol

A provider reads one JSON request from standard input and writes one JSON response to standard output. Protocol version 1 supports:

- `capabilities`: advertise algorithms, parameter sets, and operations;
- `execute`: run one vector and return normalized output fields.

Provider processes must not write non-JSON data to standard output. Diagnostics belong on standard error.

## Claim boundary

The built-in `selftest` provider validates the orchestration protocol, normalization, comparison, and reports. It is not an independent cryptographic implementation. Algorithm interoperability begins when an external provider such as liboqs or Botan is enabled and passes imported or cross-generated vectors.

## Planned increments

- A2.2: liboqs adapter and ML-KEM/ML-DSA cross-provider vectors.
- A2.3: Botan adapter and three-way result comparison.
- A2.4: malformed-input and negative interoperability corpus.
- A2.5: CI matrix and release evidence integration.
