# Stage 9D-4A

```bash
python3 scripts/patch-stage9d4a-mldsa-signing-preparation.py
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa
cargo test --workspace --all-features
```
