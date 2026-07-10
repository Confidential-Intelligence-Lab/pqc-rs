# Stage 6.5A: ACVP Encapsulation/Decapsulation Inventory

Stage 6.5A adds strict parsing, joining, decoding, and inventory reporting for
NIST's `ML-KEM-encapDecap-FIPS203` vector set.

Supported group functions:

- `encapsulation`
- `decapsulation`
- `encapsulationKeyCheck`
- `decapsulationKeyCheck`

Function-specific fields are enforced:

| Function | Prompt | Expected result |
|---|---|---|
| encapsulation | `ek`, `m` | `c`, `k` |
| decapsulation | `dk`, `c` | `k` |
| encapsulationKeyCheck | `ek` | `testPassed` |
| decapsulationKeyCheck | `dk` | `testPassed` |

The parser also validates parameter-specific key and ciphertext lengths.

This stage does not execute cryptographic operations. Its runner reports parsed
cases separately from executed or passed cases, preventing accidental
conformance claims.
