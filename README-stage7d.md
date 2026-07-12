# Stage 7D

Apply:

```bash
python3 scripts/patch-stage7d-hybrid-hpke.py
```

Validate:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cargo run -p pqc-test-harness \
  --bin hpke-pq-hybrid-vectors \
  --release
```

The target is exactly three pinned Base-mode suites with zero vector failures.
