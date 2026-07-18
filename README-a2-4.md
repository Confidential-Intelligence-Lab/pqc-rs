# Milestone A2.4 — OpenSSL Provider Interoperability

A2.4 adds bidirectional interoperability between the native Rust ML-KEM and ML-DSA implementations and OpenSSL 3.5 or later.

## Scope

The matrix covers all standardized parameter sets:

- ML-KEM-512, ML-KEM-768, and ML-KEM-1024
- ML-DSA-44, ML-DSA-65, and ML-DSA-87

For each parameter set, artifacts flow in both directions:

- Rust key material and signatures/ciphertexts consumed by OpenSSL
- OpenSSL key material and signatures/ciphertexts consumed by Rust

The expected total is 12 passing cases.

## Provider boundary

OpenSSL 3.5 and later natively implement ML-KEM and ML-DSA in the default provider. Current oqs-provider releases suppress duplicate standardized algorithms when loaded with OpenSSL 3.5 or later. Therefore this milestone validates interoperability through the OpenSSL provider API rather than assuming that oqsprovider owns the implementation.

## Requirements

- OpenSSL 3.5 or later, including development headers
- `pkg-config`
- a C compiler
- the existing Rust test harness

On Apple Silicon with Homebrew:

```bash
brew install openssl@3 pkg-config
export OPENSSL_PREFIX="$(brew --prefix openssl@3)"
```

## Validation

```bash
python3 scripts/validate-a2-4.py
cargo xtask interop-openssl --strict
```

Expected output:

```text
decision=pass
executed=12
passed=12
failed=0
```

The report is written to `target/interop-openssl/report.md`.

## Regression gates

```bash
cargo xtask interop --provider liboqs --suite liboqs-smoke --strict
cargo xtask interop-cross --strict
cargo xtask interop-openssl --strict
```

## Claim boundary

A passing report demonstrates byte-compatible ML-KEM exchange and ML-DSA cross-verification between this Rust implementation and the tested OpenSSL provider implementation. It does not by itself establish certification, broad protocol interoperability, or interoperability with every OpenSSL configuration.
