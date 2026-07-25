# ML-DSA public implementation boundary

The publication-facing API of `pqc-rs-ml-dsa` is the typed crate-root facade
and the documented `api`, `error`, and `params` modules.

The supported crate-root surface comprises:

- `MlDsa`;
- `MlDsaKeyGenSeed`;
- `MlDsaKeyPair`;
- `MlDsaPublicKey`;
- `MlDsaPrivateKey`;
- `MlDsaSignature`;
- `MlDsaParameterSet`;
- `MlDsaParameters`;
- `MlDsaError`;
- `PreHashAlgorithm`; and
- `ML_DSA_KEYGEN_SEED_BYTES`.

Arithmetic, polynomial, NTT, encoding, sampling, signing, verification, and
audit modules are implementation details. They are private in ordinary builds
and are not covered by the crate's SemVer compatibility commitment.

The non-default `internal-api` feature exposes those modules with hidden
documentation for repository assurance only. The workspace uses it for ACVP
runners, primitive regression tests, fuzz targets, timing screens,
generated-code review, and benchmarks. Downstream applications must not enable
or depend on this feature.

This boundary lets the project retain low-level validation without accidentally
promising stability for arithmetic internals. Any future expansion of the
publication-facing surface requires a separate API, security, documentation,
and SemVer review.
