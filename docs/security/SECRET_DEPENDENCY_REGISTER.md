# Secret-Dependency Register

> Generated from `compliance/constant-time-policy.toml` by `scripts/constant_time_audit.py`. Do not edit manually.

This register records the security classification of control-flow and memory-access dependencies. `constant-time-required` means secret-dependent control flow and addressing are prohibited. `public-variable-time` permits variation based only on public values. `algorithmic-variable-time` records intentional variable work that requires explicit exposure analysis.

| Target | Secret-bearing data | Permitted dependency | Prohibited dependency | Disposition |
|---|---|---|---|---|
| `CT-CORE-COMPARE` | secret byte arrays and slices | Public parameters, fixed loop indices, implementation control | Secret-dependent branch, loop bound, error path, allocation, or address | `verified` |
| `CT-CORE-SELECT` | selection mask; secret candidate bytes | Public parameters, fixed loop indices, implementation control | Secret-dependent branch, loop bound, error path, allocation, or address | `verified` |
| `CT-MLKEM-DECAPS` | decapsulation key; implicit rejection value z; derived shared secrets | Public parameters, fixed loop indices, implementation control | Secret-dependent branch, loop bound, error path, allocation, or address | `reviewed` |
| `CT-HPKE-KDF` | KEM shared secret; PSK; exporter secret; AEAD key | Public parameters, fixed loop indices, implementation control | Secret-dependent branch, loop bound, error path, allocation, or address | `reviewed` |
| `CT-HPKE-MLKEM` | ML-KEM private key; decapsulated shared secret | Public parameters, fixed loop indices, implementation control | Secret-dependent branch, loop bound, error path, allocation, or address | `reviewed` |
| `CT-HYBRID-DECAPS` | component private keys; component shared secrets; combined secret | Public parameters, fixed loop indices, implementation control | Secret-dependent branch, loop bound, error path, allocation, or address | `reviewed` |
| `CT-MLDSA-SAMPLING` | None recorded | Documented transcript/randomness-driven algorithmic work | Secret-dependent branch, loop bound, error path, allocation, or address | `variable-time-accepted` |
| `CT-MLDSA-ETA-SAMPLING` | secret-key generation seed material | Documented transcript/randomness-driven algorithmic work | Secret-dependent branch, loop bound, error path, allocation, or address | `variable-time-accepted` |
| `CT-MLDSA-SIGN` | signing key; secret polynomials; ephemeral masking values | Documented transcript/randomness-driven algorithmic work | Secret-dependent branch, loop bound, error path, allocation, or address | `variable-time-accepted` |
| `CT-MLDSA-VERIFY` | None recorded | Public input and public result | Secret-dependent branch, loop bound, error path, allocation, or address | `verified` |
| `CT-MACHINE-CODE-RELEASE` | all secret-bearing inputs reaching audited wrappers | Public parameters, fixed loop indices, implementation control | Secret-dependent branch, loop bound, error path, allocation, or address | `reviewed` |

## Gate findings

No policy or evidence findings.

## Residual exposure

ML-DSA signing and selected sampling paths are explicitly classified as algorithmically variable-time. Their acceptance is limited to the documented FIPS 204 behavior and existing timing analyses; it is not a claim that execution time is independent of all secret-bearing state. Hardened deployment profiles may require additional mitigations, isolation, or alternative implementations.
