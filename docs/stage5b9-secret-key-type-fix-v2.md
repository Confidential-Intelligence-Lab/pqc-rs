# Stage 5B-9 Secret-Key Type Fix v2

The earlier patch did not replace the macro invocation types. This version
replaces `kpke_structural.rs` completely and explicitly uses:

- `StructuralKpke512SecretKey = SecretKeyBytes<768>`
- `StructuralKpke768SecretKey = SecretKeyBytes<1152>`
- `StructuralKpke1024SecretKey = SecretKeyBytes<1536>`

These are CPA/K-PKE secret-key component sizes, distinct from full ML-KEM
secret-key sizes.
