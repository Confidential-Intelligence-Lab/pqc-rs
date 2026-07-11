# Stage 6.5C: ML-KEM Decapsulation and Implicit Rejection

Stage 6.5C implements deterministic FIPS 203 decapsulation:

1. parse `dkPKE || ek || H(ek) || z`;
2. decrypt the ciphertext with K-PKE;
3. derive `(K', r') = G(m' || H(ek))`;
4. deterministically re-encrypt;
5. compute `Kbar = J(z || c)`;
6. compare ciphertexts in constant time;
7. select `K'` or `Kbar` without a secret-dependent branch.

It also corrects the K-PKE decryption representation boundary by treating
`s_hat` as already in the NTT domain and transforming only decoded `u`.

The acceptance criterion is all 30 official ACVP decapsulation cases.
