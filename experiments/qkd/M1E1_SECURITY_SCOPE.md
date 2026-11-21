# M1.E1 — Experimental authenticated reconciliation (not secure QKD)

The implementation is an independently testable, **educational** one-error-per-block
reconciliation prototype. It does not replace the M1.C SHA-256 fixture producer,
does not export a cryptographic key, and does not change the HPKE library.

## Assumptions and boundaries

- Alice and Bob possess the same, separately provisioned secret MAC key. QKD
  itself does **not** solve initial authentication. The sample test MAC key is
  public and must never be used in a real protocol.
- HMAC-SHA256 authenticates sequenced, canonical JSON classical messages in a
  **local in-process simulation**, not a production transport. No persistent
  anti-replay mechanism, mutual identity establishment, or key rotation exists.
- The raw bitstrings are supplied as input. This stage does not implement
  channel-noise sampling or authenticated parameter estimation.
- One bit error per block can be located by binary search of publicly revealed
  parities. Multiple errors in a block can cause residual errors and rejection.
- The 128-bit confirmation digest is disclosed and conservatively counted as
  128 bits of information leakage. Each revealed parity is counted as one bit.
  The accounting is **not** an entropy or finite-key security proof.
- The confirmation digest has a nonzero collision probability. Matching it is
  only a correctness test in the stated non-malicious-party setting.
- There is no privacy amplification, leakage-based key-length selection, active
  adversary security proof, or qualified key export.

## Gates

`QKD_M1E1_RECONCILIATION_STATUS=PASS` only means the correctness and negative
regressions passed. `QKD_M1E1_SECURITY_QUALIFIED=false` remains mandatory.

Next: audited information reconciliation under a documented attack model,
parameter estimation, and privacy amplification, followed by finite-key analysis.
