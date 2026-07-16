# Stage 9F-4C

Install the machine-code tooling once:

```bash
cargo install cargo-binutils
rustup component add llvm-tools-preview
```

Then apply and run:

```bash
unzip -o pqc-rs-stage9f4c-machine-code-audit.zip
cp -R pqc-rs/. .
rm -rf pqc-rs

./scripts/run-stage9f4c-machine-code-audit.sh
```

Review `target/stage9f4c/audit-summary.md` first.
