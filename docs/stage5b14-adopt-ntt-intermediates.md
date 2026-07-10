# Stage 5B-14: Adopt NTT-Domain K-PKE Intermediates

Stage 5B-14 adopts the explicit NTT-domain matrix and vector types introduced in
Stage 5B-13 in structural K-PKE key generation and encryption.

Changes:

- key generation transforms `A` and `s` before matrix-vector multiplication
- encryption transforms `A^T` and `r` before computing `u`
- encryption transforms `t` and `r` before computing the `v` inner product
- coefficient-domain error and message terms are added after inverse conversion
- decryption remains unchanged

The new paths are checked against the Stage 5B-12 NTT-backed coefficient-domain
wrappers. The repository remains pre-KAT.
