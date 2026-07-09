# Stage 5B-2: FIPS NTT Schedule Assets

## Scope

Stage 5B-2 adds the constant-table and bit-reversal assets needed for the real
FIPS 203 NTT implementation.

## Added

- `zetas.rs`
- compact 128-entry zeta schedule
- `bit_reverse`
- generator/order tests
- canonical-value tests
- indexed `basemul` helper

## Design choice

The forward and inverse NTT transforms remain facade functions in this increment.
This keeps the repository green while validating the schedule assets separately.
Stage 5B-3 should replace the facade with the real butterfly implementation.

## Validation

Run:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```
