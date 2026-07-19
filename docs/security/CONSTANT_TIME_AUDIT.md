# Constant-Time Audit

> Generated from `compliance/constant-time-policy.toml` by `scripts/constant_time_audit.py`. Do not edit manually.

## Scope and claim

Milestone: **B1.3.3**.

Claim boundary: **documented constant-time engineering posture; not a formal proof**.

This audit consolidates the repository's source review, timing screens, rejection-loop analysis, and generated-code evidence. It distinguishes fixed-schedule operations from public or algorithmically variable-time operations. A passing gate is not a mathematical proof and is not portable across unreviewed compilers or targets.

## Decision

**PASS** — 11 targets classified; 0 blocking findings.

## Summary

| Dimension | Count |
|---|---:|
| Class: `algorithmic-variable-time` | 3 |
| Class: `constant-time-required` | 7 |
| Class: `public-variable-time` | 1 |
| Status: `reviewed` | 5 |
| Status: `variable-time-accepted` | 3 |
| Status: `verified` | 3 |

## Target register

| ID | Component | Class | Status | Primary path |
|---|---|---|---|---|
| `CT-CORE-COMPARE` | pqc-core | `constant-time-required` | `verified` | `crates/pqc-core/src/ct/compare.rs` |
| `CT-CORE-SELECT` | pqc-core | `constant-time-required` | `verified` | `crates/pqc-core/src/ct/select.rs` |
| `CT-MLKEM-DECAPS` | pqc-ml-kem | `constant-time-required` | `reviewed` | `crates/pqc-ml-kem/src/ml_kem_decaps.rs` |
| `CT-HPKE-KDF` | pqc-hpke | `constant-time-required` | `reviewed` | `crates/pqc-hpke/src/key_schedule.rs` |
| `CT-HPKE-MLKEM` | pqc-hpke | `constant-time-required` | `reviewed` | `crates/pqc-hpke/src/ml_kem.rs` |
| `CT-HYBRID-DECAPS` | pqc-hpke | `constant-time-required` | `reviewed` | `crates/pqc-hpke/src/hybrid_kem.rs` |
| `CT-MLDSA-SAMPLING` | pqc-ml-dsa | `algorithmic-variable-time` | `variable-time-accepted` | `crates/pqc-ml-dsa/src/challenge.rs` |
| `CT-MLDSA-ETA-SAMPLING` | pqc-ml-dsa | `algorithmic-variable-time` | `variable-time-accepted` | `crates/pqc-ml-dsa/src/sample.rs` |
| `CT-MLDSA-SIGN` | pqc-ml-dsa | `algorithmic-variable-time` | `variable-time-accepted` | `crates/pqc-ml-dsa/src/signature.rs` |
| `CT-MLDSA-VERIFY` | pqc-ml-dsa | `public-variable-time` | `verified` | `crates/pqc-ml-dsa/src/verification.rs` |
| `CT-MACHINE-CODE-RELEASE` | release toolchain | `constant-time-required` | `reviewed` | `scripts/run-stage9f4c-machine-code-audit.sh` |

## Detailed review

### CT-CORE-COMPARE — pqc-core

- Classification: `constant-time-required`
- Status: `verified`
- Symbols: `ct_eq_bytes`; `ct_is_zero_bytes`; `ct_eq_slices`; `ct_is_zero_slice`
- Secret inputs: secret byte arrays and slices
- Public inputs: public lengths
- Requirements: no secret-dependent branch; no secret-indexed memory; full-length comparison
- Validation: source review; unit tests; generated-code review
- Evidence: `docs/security/STAGE10B2_CT_COMPARE.md`; `docs/security/CONSTANT_TIME_ENGINEERING.md`
- Notes: Length mismatch is public and may return early; equal-length contents are compared without early exit.

### CT-CORE-SELECT — pqc-core

- Classification: `constant-time-required`
- Status: `verified`
- Symbols: `ct_select_bytes`; `ct_assign_bytes`
- Secret inputs: selection mask; secret candidate bytes
- Public inputs: array length
- Requirements: branchless selection; fixed memory schedule
- Validation: source review; unit tests; generated-code review
- Evidence: `docs/security/STAGE10B11_CT_PRIMITIVES.md`; `docs/security/STAGE10B6B_CONDITIONAL_MIGRATION.md`

### CT-MLKEM-DECAPS — pqc-ml-kem

- Classification: `constant-time-required`
- Status: `reviewed`
- Symbols: `decaps_internal`
- Secret inputs: decapsulation key; implicit rejection value z; derived shared secrets
- Public inputs: ciphertext bytes; parameter set
- Requirements: implicit rejection without secret-dependent early return; constant-time ciphertext comparison; constant-time shared-secret selection
- Validation: ACVP tests; source review; conditional-assignment migration
- Evidence: `docs/stage6-5c-decapsulation.md`; `docs/security/CONSTANT_TIME_ENGINEERING.md`; `docs/security/STAGE10B6_MIGRATION.md`
- Notes: Malformed ciphertext behavior and parameter selection may vary only with public inputs.

### CT-HPKE-KDF — pqc-hpke

- Classification: `constant-time-required`
- Status: `reviewed`
- Symbols: `key_schedule`
- Secret inputs: KEM shared secret; PSK; exporter secret; AEAD key
- Public inputs: suite identifier; info; PSK identifier
- Requirements: no secret-dependent control flow; fixed HKDF operations for selected public suite; no secret-indexed memory
- Validation: source review; HPKE ciphersuite matrix; exporter agreement tests
- Evidence: `docs/stage7b1-rfc9180-kdf-key-schedule.md`; `docs/security/ZEROIZATION_AUDIT.md`

### CT-HPKE-MLKEM — pqc-hpke

- Classification: `constant-time-required`
- Status: `reviewed`
- Symbols: `decapsulate`
- Secret inputs: ML-KEM private key; decapsulated shared secret
- Public inputs: encapsulated key; suite identifier
- Requirements: delegate to reviewed ML-KEM decapsulation; no secret-dependent adapter branches
- Validation: source review; HPKE interoperability tests
- Evidence: `docs/stage7b2-ml-kem-hpke-adapter.md`; `docs/security/CONSTANT_TIME_ENGINEERING.md`

### CT-HYBRID-DECAPS — pqc-hpke

- Classification: `constant-time-required`
- Status: `reviewed`
- Symbols: `decapsulate`
- Secret inputs: component private keys; component shared secrets; combined secret
- Public inputs: hybrid encapsulated key; suite selection
- Requirements: no secret-dependent component selection; fixed combiner schedule; component failures follow documented public-input policy
- Validation: source review; hybrid HPKE tests
- Evidence: `docs/stage7d-hybrid-hpke.md`; `docs/security/CONSTANT_TIME_ENGINEERING.md`

### CT-MLDSA-SAMPLING — pqc-ml-dsa

- Classification: `algorithmic-variable-time`
- Status: `variable-time-accepted`
- Symbols: `sample_in_ball`; `sample_in_ball_bytes`
- Secret inputs: None recorded
- Public inputs: transcript-derived challenge seed; public tau parameter
- Requirements: variation depends on transcript-derived randomness, not secret key material; memory-access behavior reviewed
- Validation: timing decomposition; generated-code review; finding register
- Evidence: `docs/stage9c3-mldsa-challenge.md`; `docs/stage9f2a-challenge-decomposition.md`; `audit/stage9f4e/security-finding-register.md`
- Notes: Variable iteration is algorithmic and transcript-derived; this is not claimed to be fixed-time.

### CT-MLDSA-ETA-SAMPLING — pqc-ml-dsa

- Classification: `algorithmic-variable-time`
- Status: `variable-time-accepted`
- Symbols: `sample_eta_poly`; `sample_eta_polyvec`
- Secret inputs: secret-key generation seed material
- Public inputs: parameter set; nonce
- Requirements: sampling variation documented; no secret-indexed table access; generated-code findings classified
- Validation: primitive timing screen; generated-code review; finding register
- Evidence: `docs/stage9c2-mldsa-secret-sampling.md`; `docs/stage9f2-primitive-timing.md`; `audit/stage9f4e/security-finding-register.md`
- Notes: Sampling is variable-work by construction. Exposure is documented and must be reassessed for hardened deployment profiles.

### CT-MLDSA-SIGN — pqc-ml-dsa

- Classification: `algorithmic-variable-time`
- Status: `variable-time-accepted`
- Symbols: `sign_internal`; `sign_internal_message`; `sign_internal_mu`
- Secret inputs: signing key; secret polynomials; ephemeral masking values
- Public inputs: message; context; parameter set
- Requirements: rejection-loop variation explicitly characterized; fixed-work primitives reviewed separately; no unsupported constant-time claim
- Validation: fixed-varying timing screen; attempt-count conditioning; key-class analysis; generated-code review
- Evidence: `docs/stage9f1-timing-screen.md`; `docs/stage9f3-rejection-loop.md`; `docs/stage9f3a-key-class-analysis.md`; `docs/stage9f4b-secret-dependency-audit.md`
- Notes: ML-DSA signing is not represented as fixed-time because FIPS 204 signing uses rejection sampling.

### CT-MLDSA-VERIFY — pqc-ml-dsa

- Classification: `public-variable-time`
- Status: `verified`
- Symbols: `verify_internal`; `verify_internal_message`; `verify_internal_mu`
- Secret inputs: None recorded
- Public inputs: verification key; message; signature; verification result
- Requirements: branches depend only on public input or public result; malformed-input behavior does not consume secrets
- Validation: ACVP SigVer; source review; generated-code review
- Evidence: `docs/stage9d5-mldsa-verification.md`; `audit/stage9f4e/security-finding-register.md`

### CT-MACHINE-CODE-RELEASE — release toolchain

- Classification: `constant-time-required`
- Status: `reviewed`
- Symbols: `release audit wrappers`
- Secret inputs: all secret-bearing inputs reaching audited wrappers
- Public inputs: compiler version; target triple; optimization profile
- Requirements: conditional branches classified; indexed-memory candidates classified; compiler upgrade triggers re-review
- Validation: optimized assembly extraction; instruction classification; finding register
- Evidence: `docs/stage9f4c-machine-code-audit.md`; `docs/stage9f4d-data-dependency-audit.md`; `audit/stage9f4e/security-finding-register.md`
- Notes: Review is toolchain- and target-specific and must be repeated for release targets.

## Limitations

- Timing screens detect statistical differences; they do not prove absence of leakage.
- Generated-code conclusions apply only to the recorded compiler, optimization profile, and target architecture.
- ML-DSA signing and selected sampling routines retain documented algorithmic variable work.
- Third-party cryptographic dependencies remain within their own assurance boundaries.
- Formal verification and hardware leakage evaluation are outside B1.3.3.

## Required release maintenance

Re-run the source, timing, and generated-code reviews after cryptographic code changes, compiler upgrades, target changes, or changes to optimization flags. Any unresolved secret-dependent branch or memory access must be entered into the finding register and blocks a constant-time assurance claim.
