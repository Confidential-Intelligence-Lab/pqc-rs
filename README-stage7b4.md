# Stage 7B-4

This archive includes the missing Stage 7B-3 Base-mode setup layer and the Stage 7B-4 AEAD/context layer.

```bash
python3 scripts/patch-stage7b4-base-context-aead.py
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```
