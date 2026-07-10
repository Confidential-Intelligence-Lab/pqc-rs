# Internal ML-KEM Golden Fixtures

These fixtures are generated from fixed inputs and are intended to detect
regressions in this repository.

They are **not** official FIPS 203 KATs.

Current fixture identifiers:

- `stage5b15-ml-kem-512`
- `stage5b15-ml-kem-768`
- `stage5b15-ml-kem-1024`

Captured fields:

- key-generation seed
- `rho`
- `sigma`
- message
- encryption randomness
- digest of matrix entry `A[0][0]`
- digest of secret polynomial `s[0]`
- digest of error polynomial `e[0]`
- packed public key
- packed CPA secret-key component
- packed ciphertext

The next conformance stage should import authoritative vectors and compare these
same checkpoints.
