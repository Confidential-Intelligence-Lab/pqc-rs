# Stage 9D-3: Deterministic ML-DSA Key Generation

This stage implements the internal seed-based key-generation procedure from
FIPS 204 Algorithm 6.

Pipeline:

1. derive `rho`, `rho_prime`, and `K` from `xi || k || l`;
2. expand the public matrix `A`;
3. sample bounded secret vectors `s1` and `s2`;
4. transform `s1` to the NTT domain;
5. compute `t = A * s1 + s2`;
6. split `t` using `Power2Round`;
7. encode `pk = rho || t1`;
8. compute `tr = H(pk, 64)`;
9. encode `sk = rho || K || tr || s1 || s2 || t0`.

This increment exposes only deterministic internal key generation.
