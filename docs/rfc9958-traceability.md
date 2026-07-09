# RFC 9958 Traceability Matrix

RFC 9958 is informational. This project maps the document's engineering guidance
to concrete Rust crates, validation targets, and protocol harnesses.

| RFC 9958 Area | Workspace Target | Stage | Status |
|---|---|---:|---|
| KEM migration | `pqc-ml-kem`, `pqc-core::Kem` | 2-6 | API scaffold + arithmetic + NTT schedule assets |
| Signature migration | `pqc-ml-dsa`, `pqc-core::SignatureScheme` | 7 | Planned |
| Hash-based signatures | `pqc-slh-dsa` | 8 | Planned |
| PQ/T hybrid key agreement | `pqc-hybrid` | 9 | Planned |
| HPKE integration | `pqc-hpke` | 10 | Planned |
| Validation guidance | `pqc-test-harness`, `tests/*`, `fuzz/*` | Continuous | Started |
| Constrained implementations | `no_std`, `alloc`, stack profiling | Continuous | Started |
| Side-channel considerations | `subtle`, constant-time review, dudect plan | Continuous | Started |

## Stage 5B-2 ML-KEM traceability

| ML-KEM item | Rust artifact | Status |
|---|---|---|
| Field arithmetic modulo q | `pqc_ml_kem::arithmetic` | implemented baseline + Montgomery helpers |
| Polynomial representation | `pqc_ml_kem::poly::Poly` | implemented baseline |
| Polynomial vectors | `pqc_ml_kem::polyvec::PolyVec` | implemented baseline |
| Zeta schedule assets | `pqc_ml_kem::zetas` | added |
| FIPS NTT facade | `pqc_ml_kem::fips_ntt` | facade with zeta-indexed basemul |
| Matrix expansion | `pqc_ml_kem::matrix::expand_matrix` | implemented structure |
| Rejection sampling | `pqc_ml_kem::matrix::sample_uniform_from_xof` | implemented scaffold |
| Message encoding | `pqc_ml_kem::encoding` | implemented baseline |
| K-PKE API | `pqc_ml_kem::kpke` | scaffold boundary |
| High-level KEM API | `MlKem512`, `MlKem768`, `MlKem1024` | scaffold |
| KAT validation | `tests/kat` | pending official vectors |
