# A3.1 — Native Rust HPKE Execution

A3.1 promotes `pqc-rs-hpke` from an existing library component to the authoritative HPKE execution path used by the interoperability campaign.

The milestone retains the A3.0 provider matrix for ML-KEM-512, ML-KEM-768, and ML-KEM-1024:

- native Rust → liboqs;
- liboqs → native Rust;
- native Rust → OpenSSL;
- OpenSSL → native Rust.

For each provider pairing, the resulting ML-KEM shared secret is consumed by the native Rust RFC 9180 Base-mode implementation. The harness independently computes the same transcript with the Python reference oracle and compares nine fields exactly:

1. AEAD key;
2. base nonce;
3. exporter secret;
4. key-schedule context;
5. ciphertext;
6. opened plaintext;
7. exported secret;
8. sender sequence number;
9. receiver sequence number.

The profile remains HKDF-SHA256 with AES-128-GCM and the ML-KEM identifiers from `draft-ietf-hpke-pq-05`.

## Apply and validate

Extract the archive from the `pqc-rfc9958-rs` repository root, then run:

```bash
python3 scripts/validate-a3-1.py
cargo fmt --all
cargo xtask interop-hpke --strict
```

Expected result:

```text
decision=pass
executed=12
passed=12
failed=0
```

The report is written to `target/interop-hpke/report.md`.

## Regression gate

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo xtask interop --provider liboqs --suite liboqs-smoke --strict
cargo xtask interop-cross --strict
cargo xtask interop-openssl --strict
cargo xtask interop-hpke --strict
```

## Claim boundary

A passing A3.1 report demonstrates exact Base-mode transcript agreement between the native Rust HPKE implementation and an independent reference oracle while the underlying ML-KEM exchange crosses Rust, liboqs, and OpenSSL provider boundaries. It does not claim support for HPKE Auth or AuthPSK modes.
