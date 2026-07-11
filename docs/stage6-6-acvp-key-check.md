# Stage 6.6: NIST ACVP ML-KEM KeyCheck

Stage 6.6 implements the remaining 60 ACVP ML-KEM cases.

Encapsulation-key validation performs:

1. parameter-set-specific length checking;
2. canonicality checking of every 12-bit coefficient, requiring values below
   `q = 3329`.

Decapsulation-key validation performs:

1. parameter-set-specific length checking;
2. recomputation of `H(embedded_ek)`;
3. constant-time comparison with the hash stored in the key.

These checks implement FIPS 203 Sections 7.2 and 7.3. They do not alter the
already validated KeyGen, Encaps_internal, or Decaps_internal operations.
