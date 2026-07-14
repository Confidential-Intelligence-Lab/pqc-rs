# Stage 9D-2: ML-DSA ExpandA

Stage 9D-2 implements deterministic public-matrix expansion.

`ExpandA` uses SHAKE128 with the ML-DSA coordinate domain separator and
`RejNTTPoly` rejection sampling. Each candidate is decoded from three
little-endian bytes, masked to 23 bits, and accepted only when it is less than
`Q`.

The resulting coefficients are the NTT-domain representation specified by
FIPS 204; no additional forward NTT is applied.

Acceptance criteria:

- dimensions match `(k, l)` for ML-DSA-44, ML-DSA-65, and ML-DSA-87;
- all coefficients lie in `[0, Q)`;
- fixed seed and coordinates are deterministic;
- row/column coordinates are domain separated;
- different seeds produce different matrices;
- formatting, Clippy, and all workspace tests remain clean.
