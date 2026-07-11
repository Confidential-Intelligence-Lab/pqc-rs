# Stage 7B-1

Apply:

```bash
python3 scripts/patch-stage7b1-hpke-foundation.py
```

Validate:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

This stage implements RFC 9180 labeled HKDF and key-schedule primitives
only. KEM and AEAD integration remain pending.
