# Fuzz Target Register

> Generated from `compliance/fuzz-policy.toml` by `scripts/fuzz_audit.py`. Do not edit manually.

| ID | Target | Class | Status | Corpus | Dictionary |
|---|---|---|---|---|---|
| `FZ-MLKEM-KEY-CHECKS` | `ml_kem_key_checks` | `decoder` | `active` | `fuzz/corpus/ml_kem_key_checks` | — |
| `FZ-MLKEM-DECAPS` | `ml_kem_decapsulation` | `cryptographic-boundary` | `active` | `fuzz/corpus/ml_kem_decapsulation` | — |
| `FZ-HPKE-VECTOR-PARSER` | `hpke_vector_parser` | `parser` | `active` | `fuzz/corpus/hpke_vector_parser` | `fuzz/dictionaries/json.dict` |
| `FZ-HPKE-RECEIVER` | `hpke_receiver_open` | `state-machine` | `active` | `fuzz/corpus/hpke_receiver_open` | — |
| `FZ-HYBRID-KEM` | `hybrid_kem_inputs` | `cryptographic-boundary` | `active` | `fuzz/corpus/hybrid_kem_inputs` | — |
| `FZ-MLDSA-PRIMITIVES` | `mldsa_primitives` | `arithmetic-invariant` | `active` | `fuzz/corpus/mldsa_primitives` | — |
| `FZ-MLDSA-VERIFY` | `mldsa_verification` | `cryptographic-boundary` | `active` | `fuzz/corpus/mldsa_verification` | — |

## Gate findings

No policy, harness, corpus, manifest, or CI findings.
