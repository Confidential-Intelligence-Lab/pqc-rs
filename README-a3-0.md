# A3.0 — Post-Quantum HPKE with ML-KEM

This milestone implements the RFC 9180 HPKE Base-mode key schedule using the pure post-quantum ML-KEM KEM identifiers defined by `draft-ietf-hpke-pq-05`:

- ML-KEM-512 (`0x0040`)
- ML-KEM-768 (`0x0041`)
- ML-KEM-1024 (`0x0042`)

The initial interoperable profile is:

- Mode: Base (`0x00`)
- KDF: HKDF-SHA256 (`0x0001`)
- AEAD: AES-128-GCM (`0x0001`)

The harness composes the existing Rust, liboqs, and OpenSSL ML-KEM providers with a shared RFC 9180 key schedule and verifies encryption, decryption, and exporter agreement in twelve cross-provider cases.

## Dependencies

```bash
python3 -m pip install cryptography
```

The existing liboqs and OpenSSL provider dependencies from A2.3/A2.4 must remain configured.

## Run

```bash
python3 scripts/validate-a3-0.py
cargo xtask interop-hpke --strict
```

Expected result:

```text
decision=pass
executed=12
passed=12
failed=0
```

## Scope

This stage supports Base mode. The ML-KEM HPKE bindings do not define `AuthEncap` or `AuthDecap`, so RFC 9180 Auth and AuthPSK modes are intentionally out of scope. PSK mode can be added independently in A3.1.
