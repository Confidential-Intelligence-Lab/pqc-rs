# Stage 5B-8 Eq Derive Fix

`KpkeDecryptOutput` contained a `Message`, which is an alias for
`SharedSecretBytes<32>`. That type intentionally avoids ordinary `Eq` and
`PartialEq` derives because it represents secret-like material and should use
constant-time equality when comparisons are required.

This patch removes `Eq` and `PartialEq` from `KpkeDecryptOutput`.
