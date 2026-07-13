# Stage 9C-3

Copy these files into the repository root, then run:

```bash
python3 scripts/patch-stage9c3-mldsa-challenge.py

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa
cargo test --workspace --all-features
```

Stage 9C-3 adds sparse challenge sampling for all three FIPS 204 parameter
sets.
