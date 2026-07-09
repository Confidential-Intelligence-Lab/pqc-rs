# Stage 5B-4 NTT Round-Trip Fix

The first Stage 5B-4 patch wired the new butterfly candidate directly into the
public `ntt` and `intt` functions. Tests showed that the candidate pair was not
yet a valid round-trip: `intt(ntt(1))` returned `R mod q = 2285` instead of `1`.

This patch keeps the public `ntt`/`intt` boundary correctness-preserving while
retaining the butterfly code as:

- `experimental_forward_ntt`
- `experimental_inverse_ntt`

This lets the project stay green while Stage 5B-5 focuses on the exact FIPS 203
domain/scaling conventions and NTT-domain multiplication.
