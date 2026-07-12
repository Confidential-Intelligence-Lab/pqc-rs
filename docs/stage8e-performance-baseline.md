# Stage 8E: Performance and Size Baseline

Stage 8E records a reproducible baseline before optimization.

Benchmarks cover ML-KEM KeyGen, Encaps, and Decaps for all three parameter sets; pure-PQ HPKE Base sender/receiver setup, 1 KiB Seal/Open, and Export; and sender/receiver setup for all three hybrid HPKE suites.

Run:

```bash
python3 scripts/install-stage8e.py
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
./scripts/run-stage8e.sh
```

Reports are written under `target/stage8e/`; Criterion HTML reports are under `target/criterion/`.

Record CPU, OS, Rust/Cargo versions, build profile, median estimate, confidence interval, outliers, and object/binary sizes. Do not enforce timing thresholds yet. Investigate sustained changes above 10% and require explanation above 20% until dedicated benchmark hardware exists.

Criterion measurements are not evidence of constant-time execution.
