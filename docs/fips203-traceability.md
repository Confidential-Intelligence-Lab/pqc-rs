# FIPS 203 Implementation Traceability

| Algorithmic item | Rust artifact | Current status |
|---|---|---|
| Parameter sets | `MlKemParameterSet` | Internally validated |
| Field arithmetic | `arithmetic.rs` | Internally validated |
| Polynomial encoding | `poly.rs`, `packing.rs` | Internally validated |
| Sampling | `sampling.rs`, `matrix.rs` | Structural |
| NTT | `fips_ntt.rs`, `zetas.rs` | Experimental |
| K-PKE.KeyGen | `kpke_keygen.rs` | Structural |
| K-PKE.Encrypt | `kpke_encrypt.rs` | Structural |
| K-PKE.Decrypt | `kpke_decrypt.rs` | Structural |
| K-PKE trait integration | `kpke_structural.rs` | Structural |
| ML-KEM.KeyGen | `lib.rs` scaffold | Pending |
| ML-KEM.Encaps | `lib.rs` scaffold | Pending |
| ML-KEM.Decaps | `lib.rs` scaffold | Pending |
| Official KAT runner | `pqc-test-harness` | Schema ready |
| Official KAT vectors | `tests/kat` | Pending |
