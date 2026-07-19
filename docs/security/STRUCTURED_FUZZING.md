# Structured Fuzzing

> Generated from `compliance/fuzz-policy.toml` by `scripts/fuzz_audit.py`. Do not edit manually.

## Scope and claim

Milestone: **B1.3.4**.

Claim boundary: **structured robustness testing; not a proof of memory safety or cryptographic security**.

The fuzzing program targets malformed encodings, parser robustness, protocol state transitions, cryptographic API boundaries, and arithmetic invariants. Every active target must be declared in the cargo-fuzz manifest, included in bounded CI smoke execution, and associated with a persistent seed-corpus directory.

## Decision

**PASS** — 7 active targets; 0 blocking findings.

## Coverage summary

| Dimension | Count |
|---|---:|
| Active targets | 7 |
| CI smoke duration per target | 30 seconds |
| Recommended campaign duration per target | 3600 seconds |
| `arithmetic-invariant` targets | 1 |
| `cryptographic-boundary` targets | 3 |
| `decoder` targets | 1 |
| `parser` targets | 1 |
| `state-machine` targets | 1 |

## Execution profiles

### Pull-request smoke

```bash
cargo xtask fuzz-audit --check
FUZZ_SECONDS=30 ./scripts/run-fuzz-smoke.sh
```

### Focused campaign

```bash
FUZZ_SECONDS=3600 FUZZ_TARGETS=ml_kem_decapsulation ./scripts/run-fuzz-smoke.sh
```

Crashes and timeouts are written under `fuzz/artifacts/<target>/`. Every confirmed defect must receive a deterministic regression test before the artifact is removed. Useful non-crashing inputs should be promoted into the corresponding `fuzz/corpus/<target>/` directory.

## Target details

### FZ-MLKEM-KEY-CHECKS — `ml_kem_key_checks`

- Class: `decoder`
- Status: `active`
- Components: ML-KEM-512; ML-KEM-768; ML-KEM-1024
- Properties: arbitrary key bytes never panic; invalid lengths return structured results
- Seed corpus: `fuzz/corpus/ml_kem_key_checks`

### FZ-MLKEM-DECAPS — `ml_kem_decapsulation`

- Class: `cryptographic-boundary`
- Status: `active`
- Components: ML-KEM decapsulation; implicit rejection
- Properties: malformed keys and ciphertexts never panic; all parameter sets are exercised
- Seed corpus: `fuzz/corpus/ml_kem_decapsulation`

### FZ-HPKE-VECTOR-PARSER — `hpke_vector_parser`

- Class: `parser`
- Status: `active`
- Components: HPKE-PQ vector JSON
- Properties: malformed JSON is rejected without panic
- Seed corpus: `fuzz/corpus/hpke_vector_parser`
- Dictionary: `fuzz/dictionaries/json.dict`

### FZ-HPKE-RECEIVER — `hpke_receiver_open`

- Class: `state-machine`
- Status: `active`
- Components: HPKE receiver context; AEAD authentication failure
- Properties: failed open does not advance sequence; arbitrary AAD and ciphertext never panic
- Seed corpus: `fuzz/corpus/hpke_receiver_open`

### FZ-HYBRID-KEM — `hybrid_kem_inputs`

- Class: `cryptographic-boundary`
- Status: `active`
- Components: MLKEM768-P256; MLKEM768-X25519; MLKEM1024-P384
- Properties: arbitrary randomness lengths fail cleanly; arbitrary encapsulations fail cleanly
- Seed corpus: `fuzz/corpus/hybrid_kem_inputs`

### FZ-MLDSA-PRIMITIVES — `mldsa_primitives`

- Class: `arithmetic-invariant`
- Status: `active`
- Components: challenge sampling; eta sampling; rounding; hints
- Properties: sample bounds hold; challenge weight holds; rounding identities hold
- Seed corpus: `fuzz/corpus/mldsa_primitives`

### FZ-MLDSA-VERIFY — `mldsa_verification`

- Class: `cryptographic-boundary`
- Status: `active`
- Components: ML-DSA-44 verification; ML-DSA-65 verification; ML-DSA-87 verification
- Properties: arbitrary public keys and signatures never panic; malformed encodings return false or structured error
- Seed corpus: `fuzz/corpus/mldsa_verification`

## Limitations

- Coverage-guided fuzzing does not prove memory safety, correctness, standards conformance, constant-time behavior, or cryptographic security.
- Bounded CI runs are regression screens; meaningful assurance requires longer campaigns on supported release targets.
- Harness assertions are part of the security contract and require review when APIs or protocol state semantics change.
- Third-party dependencies retain their own fuzzing and assurance boundaries.

## Release maintenance

Run all targets for an extended campaign before a release candidate. Archive the toolchain, target triple, duration, corpus hash, and crash disposition in the release evidence bundle.
