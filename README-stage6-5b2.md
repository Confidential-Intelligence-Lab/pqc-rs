# Stage 6.5B-2

```bash
python3 scripts/patch-stage6-5b2-cbd-eta3.py

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cargo run -p pqc-test-harness   --bin ml-kem-acvp-encapsulation   --release
```
