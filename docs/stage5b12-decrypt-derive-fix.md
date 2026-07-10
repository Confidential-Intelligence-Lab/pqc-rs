# Stage 5B-12 Decryption Derive Fix

Stage 5B-12 was assembled from the pre-fix Stage 5B-8 decryption source and
reintroduced `Eq` and `PartialEq` on `KpkeDecryptOutput`.

`KpkeDecryptOutput` contains `Message`, an alias for `SharedSecretBytes<32>`.
Secret-like wrappers intentionally avoid ordinary equality traits and use
constant-time equality when comparisons are required.

This patch removes `Eq` and `PartialEq` from the derive list.
