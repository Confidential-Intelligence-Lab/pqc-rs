# RFC 9958 Traceability Matrix

RFC 9958 is informational. This project maps the document's engineering guidance
to concrete Rust crates, validation targets, and protocol harnesses.

| RFC 9958 Area | Workspace Target | Stage | Status |
|---|---|---:|---|
| KEM migration | `pqc-ml-kem`, `pqc-core::Kem` | 2-4 | API scaffold + arithmetic foundation |
| Signature migration | `pqc-ml-dsa`, `pqc-core::SignatureScheme` | 5 | Planned |
| Hash-based signatures | `pqc-slh-dsa` | 6 | Planned |
| PQ/T hybrid key agreement | `pqc-hybrid` | 7 | Planned |
| HPKE integration | `pqc-hpke` | 8 | Planned |
| Validation guidance | `pqc-test-harness`, `tests/*`, `fuzz/*` | Continuous | Started |
| Constrained implementations | `no_std`, `alloc`, stack profiling | Continuous | Started |
| Side-channel considerations | `subtle`, constant-time review, dudect plan | Continuous | Started |

## Stage 3 ML-KEM traceability

| ML-KEM item | Rust artifact | Status |
|---|---|---|
| Field arithmetic modulo q | `pqc_ml_kem::arithmetic` | implemented baseline |
| Polynomial representation | `pqc_ml_kem::poly::Poly` | implemented baseline |
| Polynomial encoding | `Poly::encode_12`, `Poly::decode_12` | implemented baseline |
| Compression/decompression | `arithmetic`, `Poly::compress`, `Poly::decompress` | implemented baseline |
| CBD sampling | `sampling::cbd_eta2`, `sampling::cbd_eta3` | implemented baseline |
| SHA3/SHAKE helpers | `symmetric` | implemented baseline |
| High-level KEM API | `MlKem512`, `MlKem768`, `MlKem1024` | scaffold |
