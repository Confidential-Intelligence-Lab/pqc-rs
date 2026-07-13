# Stage 9C-5

Copy these files into the repository root, then run:

```bash
python3 scripts/patch-stage9c5-mldsa-hints.py

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa
cargo test --workspace --all-features
```

Stage 9C-5 adds ML-DSA scalar and polynomial hint generation/application.
