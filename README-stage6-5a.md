# Stage 6.5A

NIST ACVP ML-KEM encapsulation/decapsulation parser and inventory runner.

```bash
python3 scripts/patch-stage6-5a-harness-module.py

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cargo run -p pqc-test-harness   --bin ml-kem-acvp-encap-decap-inventory   --release
```

Stage 6.5A parses and validates vectors only. It does not claim encapsulation or
decapsulation success.
