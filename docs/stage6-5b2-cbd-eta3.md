# Stage 6.5B-2: Reference CBD Eta3 Sampling

The Stage 6.5B-1 ACVP result was 50/75, with the 25 failures confined to
ML-KEM-512. Because ML-KEM-512 is the only parameter set using eta1 = 3 for the
ephemeral secret, this stage replaces only `cbd_eta3`.

For each six-bit group:

```text
a = b0 + b1 + b2
b = b3 + b4 + b5
coefficient = a - b
```

The implementation processes 192 bytes into 256 coefficients using 64
little-endian 24-bit words.

The ACVP runner also reports results separately for each parameter set.
