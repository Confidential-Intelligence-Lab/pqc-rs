# Stage 7A

Apply the module and README claim-boundary update:

```bash
python3 scripts/patch-stage7a-standards-scope.py
```

Validate:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Stage 7A adds no protocol cryptography. It establishes standards
provenance, engineering traceability, and enforceable claim boundaries
before RFC 9180 HPKE implementation begins.
