# Stage 6.5B-1: K-PKE Encryption Domain Corrections

This stage applies three narrowly scoped FIPS 203 corrections:

1. The decoded public-key vector is already `t_hat`; it must not be transformed
   again.
2. `ExpandA(rho, transpose=true)` returns sampled NTT-domain matrix entries;
   they must not be transformed again.
3. The ephemeral secret `r` uses `eta1`, while `e1` and `e2` use `eta2`.

For ML-KEM-512, this distinction is essential because `eta1 = 3` and
`eta2 = 2`.

The ACVP runner is also updated to report ciphertext and shared-secret results
independently.
