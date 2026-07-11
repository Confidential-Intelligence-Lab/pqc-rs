# Stage 6.5B: NIST ACVP ML-KEM Encapsulation Execution

This stage adds deterministic `ML-KEM.Encaps_internal(ek, m)` execution and an
ACVP comparison runner for all 75 encapsulation cases.

It derives:

```text
(K, r) = G(m || H(ek))
c      = K-PKE.Encrypt(ek, m, r)
```

and compares both `c` and `K` against NIST expected results.

Decapsulation and key-check behavior remain unchanged.
