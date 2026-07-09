# RFC 9958 Traceability Matrix

RFC 9958 is informational. This project maps the document's engineering guidance
to concrete Rust crates, validation targets, and protocol harnesses.

| RFC 9958 Area | Workspace Target | Stage | Status |
|---|---|---:|---|
| KEM migration | `pqc-ml-kem`, `pqc-core::Kem` | 2-5 | API scaffold + arithmetic + K-PKE foundation |
| Signature migration | `pqc-ml-dsa`, `pqc-core::SignatureScheme` | 6 | Planned |
| Hash-based signatures | `pqc-slh-dsa` | 7 | Planned |
| PQ/T hybrid key agreement | `pqc-hybrid` | 8 | Planned |
| HPKE integration | `pqc-hpke` | 9 | Planned |
| Validation guidance | `pqc-test-harness`, `tests/*`, `fuzz/*` | Continuous | Started |
| Constrained implementations | `no_std`, `alloc`, stack profiling | Continuous | Started |
| Side-channel considerations | `subtle`, constant-time review, dudect plan | Continuous | Started |

## Stage 4 ML-KEM traceability

| ML-KEM item | Rust artifact | Status |
|---|---|---|
| Field arithmetic modulo q | `pqc_ml_kem::arithmetic` | implemented baseline |
| Polynomial representation | `pqc_ml_kem::poly::Poly` | implemented baseline |
| Polynomial vectors | `pqc_ml_kem::polyvec::PolyVec` | implemented baseline |
| NTT-domain boundary | `pqc_ml_kem::ntt` | baseline boundary |
| K-PKE API | `pqc_ml_kem::kpke` | scaffold boundary |
| High-level KEM API | `MlKem512`, `MlKem768`, `MlKem1024` | scaffold |
| KAT validation | `tests/kat` | pending official vectors |
