# Stage 9C-6: ML-DSA Primitive Stabilization

This stage adds no new cryptographic functionality. It adds broader regression,
edge-case, and fuzz coverage for sampling, challenge generation, rounding,
decomposition, and hints.

Run:

```bash
python3 scripts/patch-stage9c6-mldsa-fuzz.py
./scripts/run-stage9c6.sh
```

For a longer campaign:

```bash
cargo +nightly fuzz run --fuzz-dir fuzz mldsa_primitives -- \
  -max_total_time=3600 -max_len=256 -timeout=10
```
