# Stage 9D-3

Copy into the repository root, then run:

```bash
python3 scripts/patch-stage9d3-mldsa-keygen.py
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa
cargo test --workspace --all-features
```
