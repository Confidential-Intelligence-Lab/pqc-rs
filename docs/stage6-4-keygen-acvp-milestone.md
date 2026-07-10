# Stage 6.4 Milestone: ML-KEM KeyGen ACVP Validation

The implementation passed all 75 NIST ACVP FIPS 203 ML-KEM KeyGen cases across
ML-KEM-512, ML-KEM-768, and ML-KEM-1024.

Cleanup actions:

- align internal fixtures with parameter-aware seed expansion;
- rename fixtures for the Stage 6.4 milestone;
- verify that each serialized public key ends in its recorded `rho`;
- mark only `kpke-keygen` as `KatValidated`.

Full ML-KEM conformance remains unclaimed. Encapsulation, decapsulation,
invalid-ciphertext handling, and implicit rejection are still pending.
