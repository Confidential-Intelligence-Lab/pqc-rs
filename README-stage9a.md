# Stage 9A

Copy these files into the repository root, then run:

```bash
python3 scripts/patch-stage9a-mldsa-foundation.py

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Stage 9A adds only the ML-DSA foundation. It does not implement key generation,
signing, or verification and makes no conformance claim.
