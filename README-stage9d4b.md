# Stage 9D-4B

```bash
python3 scripts/patch-stage9d4b-mldsa-signing-core.py
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa
cargo test --workspace --all-features
```
