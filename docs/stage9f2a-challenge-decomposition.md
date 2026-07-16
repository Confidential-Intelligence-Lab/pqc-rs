# Stage 9F-2A: Controlled Challenge-Multiplication Decomposition

Three experiments isolate the Stage 9F-2 signal:

1. **fixed-challenge**: identical challenge, fixed versus varying polynomial.
2. **varying-challenge**: fixed polynomial, fixed versus varying sparse support.
3. **matched-distribution**: both classes use independent but distribution-matched challenges and polynomials.

Interpretation:

- signal only in varying-challenge: public support/branch-predictor effect likely;
- signal in fixed-challenge: coefficient-dependent implementation behavior requires review;
- signal in matched-distribution: experimental or systemic bias likely.

No cryptographic implementation code is modified.
