# M1.E2 — Experimental Toeplitz privacy amplification

This module implements binary Toeplitz hashing with a public uniformly sampled seed, deterministic bit ordering, and strict shape checks. It is a **primitive correctness** demonstration, not an accepted QKD key-extraction policy.

- Inputs represent reconciled bits; no reconciliation transcript is consumed or verified here.
- No conditional min-entropy bound is computed; no subtraction of error-correction leakage, public verification leakage, or authentication costs occurs.
- An arbitrary requested output length is **not** certified to be secure. M1.E3 must enforce finite-key bounds and composable security parameters before secret-key acceptance.
- The basic implementation is quadratic-time and not constant-time; do not expose confidential raw input to untrusted processes or use this reference code in production.
- Seeds are public, but should be sampled independently of the raw string. Seed reuse across sessions is not supported by a QKD security claim here.
- Reconciled key material and extracted outputs must not be logged, placed in Git, or promoted to a production QKD PSK.
- The prior M1.C SHA-256 fixture path remains experimental and unchanged.

`QKD_M1E2_PRIVACY_AMPLIFICATION_STATUS=PASS` only means the stated tests and validations passed.

`QKD_M1E2_SECURITY_QUALIFIED=false` remains mandatory.
