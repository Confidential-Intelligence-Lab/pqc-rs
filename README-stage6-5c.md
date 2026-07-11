# Stage 6.5C

```bash
python3 scripts/patch-stage6-5c-decapsulation.py

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cargo run -p pqc-test-harness       --bin ml-kem-acvp-decapsulation       --release
```
