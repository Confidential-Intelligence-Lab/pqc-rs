# Stage 9B

Copy these files into the repository root, then run:

```bash
python3 scripts/patch-stage9b-mldsa-arithmetic.py

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa
cargo test --workspace --all-features
```

Stage 9B adds only the arithmetic substrate. Sampling, encoding, KeyGen,
signing, and verification remain for later Stage 9 increments.
