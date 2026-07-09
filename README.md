# pqc-rfc9958-rs

Rust workspace for implementing and validating the post-quantum cryptographic
algorithms and protocol engineering patterns discussed by RFC 9958.

## Stage 5B-8 status

Stage 5B-8 adds deterministic K-PKE decryption structure:

- CPA secret-key component decoding
- ciphertext component decoding
- structural `w = v - s^T u`
- message recovery
- malformed input rejection tests

## Validate

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## GitHub stage workflow

After tests pass:

```bash
git add .
git commit -m "Stage 5B-8: Add deterministic K-PKE decryption structure"
git push origin main
```
