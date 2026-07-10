# Stage 6.2: FIPS 203 KeyGen Seed Derivation

The first ACVP execution produced zero passing vectors and an encapsulation-key
mismatch at byte zero.

The earliest confirmed normative divergence is seed derivation.

The structural implementation used:

```text
rho || sigma = G(d)
```

FIPS 203 K-PKE key generation uses:

```text
rho || sigma = G(d || k)
```

where `k` is the one-byte module rank:

- ML-KEM-512: `k = 2`
- ML-KEM-768: `k = 3`
- ML-KEM-1024: `k = 4`

This patch changes only the normative key-generation path and leaves the
original structural seed-expansion helper available for existing internal
fixtures.

After applying the patch, rerun the complete ACVP KeyGen suite and record the
new first mismatch. A remaining mismatch is expected because matrix sampling,
NTT-domain key representation, and packing still require authoritative
checkpoint validation.
