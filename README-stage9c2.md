# Stage 9C-2

Copy these files into the repository root, then run:

```bash
python3 scripts/patch-stage9c2-mldsa-secret-sampling.py

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa
cargo test --workspace --all-features
```

Stage 9C-2 adds bounded secret-polynomial sampling for `eta = 2` and `eta = 4`.
