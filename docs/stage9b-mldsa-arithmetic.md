# Stage 9B: ML-DSA Arithmetic

Stage 9B adds:

- field constants;
- Montgomery reduction;
- coefficient reduction and canonicalization;
- polynomial storage;
- forward NTT;
- inverse NTT with Montgomery scaling;
- pointwise Montgomery multiplication;
- arithmetic regression tests.

## Claim boundary

The transform constants and structure follow the ML-DSA reference ordering.
Stage 9B does not yet claim arithmetic conformance because independent
known-answer vectors and full conversion helpers are added in subsequent
increments.

## Acceptance criteria

```bash
python3 scripts/patch-stage9b-mldsa-arithmetic.py
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa
cargo test --workspace --all-features
```
