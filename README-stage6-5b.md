# Stage 6.5B

```bash
python3 scripts/patch-stage6-5b-encapsulation-module.py
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cargo run -p pqc-test-harness   --bin ml-kem-acvp-encapsulation   --release
```
