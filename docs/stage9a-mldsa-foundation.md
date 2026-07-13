# Stage 9A: ML-DSA Foundation

Stage 9A establishes the ML-DSA crate structure without implementing
cryptographic operations.

Acceptance criteria:

- all three FIPS 204 parameter sets are represented;
- public/private key and signature sizes are covered by tests;
- the API returns an explicit `NotImplemented` error;
- no algorithm or conformance claim is made;
- formatting, Clippy, and workspace tests remain clean.
