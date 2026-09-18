# SLH-DSA verification fuzz seeds

The tracked corpus contains deterministic bootstrap inputs for the two
structured paths in `slhdsa_verification`:

- `seed-decoder`: malformed-length / decoder robustness path.
- `seed-deep`: exact-length expansion / deep-verification path.

Coverage-derived SHA-named libFuzzer corpus entries are intentionally ignored
by the repository and are regenerated during fuzz campaigns.
