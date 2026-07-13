# Stage 9C-1

Copy these files into the repository root, then run:

```bash
python3 scripts/patch-stage9c1-mldsa-expanders.py
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa
cargo test --workspace --all-features
```
