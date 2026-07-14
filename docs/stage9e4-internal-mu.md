# Stage 9E-4: NIST ACVP ML-DSA Internal Interfaces

This stage adds and validates:

- `sign_internal_message`: module computes `mu = SHAKE256(tr || M', 64)`;
- `sign_internal_mu`: caller supplies the 64-byte `mu`;
- `verify_internal_message`;
- `verify_internal_mu`.

Both `externalMu=false` and `externalMu=true` ACVP groups are covered for
sigGen and sigVer. External pure and prehash groups are excluded.
