# Stage 9C-4

Copy these files into the repository root, then run:

```bash
python3 scripts/patch-stage9c4-mldsa-rounding.py

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa
cargo test --workspace --all-features
```

Stage 9C-4 adds ML-DSA rounding and decomposition for both standardized
`gamma2` variants.
