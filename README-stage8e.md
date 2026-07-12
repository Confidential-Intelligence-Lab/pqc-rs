# Stage 8E

```bash
python3 scripts/install-stage8e.py
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
./scripts/run-stage8e.sh
```

Outputs:

```text
target/stage8e/environment.txt
target/stage8e/sizes.md
target/stage8e/ml-kem-bench.txt
target/stage8e/hpke-bench.txt
target/stage8e/hybrid-hpke-bench.txt
target/stage8e/release-binaries.txt
target/criterion/
```
