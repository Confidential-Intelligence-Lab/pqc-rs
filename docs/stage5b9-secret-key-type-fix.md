# Stage 5B-9 Secret-Key Type Fix

The initial Stage 5B-9 trait integration reused the full ML-KEM secret-key
aliases:

- ML-KEM-512: 1632 bytes
- ML-KEM-768: 2400 bytes
- ML-KEM-1024: 3168 bytes

However, the structural K-PKE backend currently produces only the CPA
secret-key component:

- K-PKE-512: 768 bytes
- K-PKE-768: 1152 bytes
- K-PKE-1024: 1536 bytes

This patch introduces dedicated structural K-PKE secret-key aliases and uses
them in the `Kpke` trait implementations.
