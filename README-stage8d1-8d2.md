# Stage 8D-1 and 8D-2

Apply and validate Stage 8D-1 first:

```bash
python3 scripts/patch-stage8d1.py
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Commit that milestone.

Then apply Stage 8D-2:

```bash
python3 scripts/patch-stage8d2.py
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
./scripts/run-stage8d.sh
```

Stage 8D-1 removes printable secret aggregates and rewrites tests so they do
not require `Debug`. Stage 8D-2 migrates selected HPKE and hybrid secret
storage to zeroizing wrappers.
