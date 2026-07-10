# Stage 5B-12: NTT-Backed K-PKE Arithmetic

Stage 5B-12 replaces schoolbook polynomial products in the structural K-PKE
path with the reference-compatible ML-KEM NTT multiplier from Stage 5B-11.

Added:

- `kpke_arithmetic.rs`
- NTT-backed polynomial multiplication
- NTT-backed polynomial-vector inner products
- NTT-backed matrix-vector multiplication
- keygen, encryption, and decryption integration
- direct equivalence tests against schoolbook arithmetic

Existing structural encodings remain unchanged. Exact FIPS 203 NTT-domain
intermediate representation and authoritative vectors remain pending.
