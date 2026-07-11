# Stage 7C

Apply:

```bash
python3 scripts/patch-stage7c-vector-harness.py
./scripts/fetch-hpke-pq-vectors.sh
```

Validate:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cargo run -p pqc-test-harness       --bin hpke-pq-base-vectors       --release
```
