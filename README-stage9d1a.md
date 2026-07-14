# Stage 9D-1A

```bash
python3 scripts/patch-stage9d1a-mldsa-coefficient-encoding.py
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa
cargo test --workspace --all-features
```
