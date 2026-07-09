# pqc-rfc9958-rs

Rust workspace for implementing and validating the post-quantum cryptographic
algorithms and protocol engineering patterns discussed by RFC 9958.

RFC 9958 is informational. This project treats it as a traceability and
engineering-guidance document, while normative algorithm behavior is drawn from
the underlying standards such as FIPS 203, FIPS 204, FIPS 205, and relevant
IETF protocol specifications.

## Stage 4 status

Stage 4 adds the ML-KEM K-PKE foundation:

- baseline NTT-domain module boundary
- polynomial-vector helpers
- K-PKE parameter-set API boundary
- K-PKE key, ciphertext, message, and randomness shapes
- K-PKE scaffold tests
- NTT round-trip and multiplication consistency tests
- documentation for the Stage 5 handoff

Important: Stage 4 is still **not production ML-KEM**. The NTT module is a
correctness-oriented baseline boundary, not yet the optimized FIPS 203 zeta
schedule. The high-level `keygen`, `encaps`, and `decaps` functions remain
scaffolds until the complete K-PKE flow and official KAT validation are added.

## Validate

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## GitHub stage workflow

After tests pass:

```bash
git add .
git commit -m "Stage 4: ML-KEM NTT and K-PKE foundation"
git push origin main
```
