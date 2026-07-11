# Stage 6.6

```bash
python3 scripts/patch-stage6-6-key-check.py

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cargo run -p pqc-test-harness       --bin ml-kem-acvp-key-check       --release
```
