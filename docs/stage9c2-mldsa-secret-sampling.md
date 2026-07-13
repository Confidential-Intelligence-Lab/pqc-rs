# Stage 9C-2: ML-DSA Bounded Secret Sampling

Stage 9C-2 implements the bounded-polynomial sampler used by `ExpandS`.

## Algorithm

The sampler consumes nibbles from the Stage 9C-1 SHAKE256 stream.

For `eta = 2`:

- nibble value 15 is rejected;
- accepted values are reduced modulo 5;
- the coefficient is `2 - reduced`.

For `eta = 4`:

- values 0 through 8 are accepted;
- values 9 through 15 are rejected;
- the coefficient is `4 - value`.

The resulting coefficients are uniformly distributed in `[-eta, eta]`.

## Added APIs

- `sample_eta_poly`
- `sample_eta_polyvec`
- `SamplingError`

## Acceptance criteria

- deterministic output for a fixed seed and nonce;
- different nonces produce different polynomials;
- every coefficient lies in `[-eta, eta]`;
- both FIPS 204 values `eta = 2` and `eta = 4` are supported;
- unsupported values are rejected;
- vector sampling uses consecutive nonces;
- formatting, Clippy, and all workspace tests remain clean.

## Claim boundary

This stage validates bounds, determinism, and nibble decoding. Independent
FIPS 204 known-answer vectors are still required before a conformance claim.
