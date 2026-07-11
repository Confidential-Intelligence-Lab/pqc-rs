# Stage 7B-2

Apply:

```bash
python3 scripts/patch-stage7b2-ml-kem-adapter.py
```

Validate:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

This stage implements pure ML-KEM adapters for the HPKE KEM interface.
Full HPKE context and AEAD integration remain pending.
