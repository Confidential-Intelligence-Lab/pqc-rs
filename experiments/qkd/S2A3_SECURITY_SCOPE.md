# S2.A3: syndrome reconciliation in authenticated QKD distillation

- Replaces the M1.E1 educational parity-search call in M2.A with S2.A2 authenticated 128-bit-block syndrome decoding and S2.A1 independent-seed Toeplitz confirmation.
- Accounts separately for 32 disclosed syndrome bits per block and the configured confirmation tag length; carries `epsilon_correctness_bound` in the public report.
- Acceptance uses authenticated syndrome/confirmation only; the simulator's private Alice-versus-Bob equality comparison is not an acceptance criterion.
- Raw X keys shorter than 128 bits abort explicitly. No implicit padding or legacy fallback.
- Reconciliation still uses simulator-provisioned HMAC keys, not a qualified authentication provisioning service; syndrome decoder is bounded-distance reference, not a production LDPC implementation.
- No theorem-qualified min-entropy evidence exists. All M2.A finite-key, secret export and production HPKE authorization remain fail-closed.
- The existing M1.E1 implementation remains available solely for historical regression tests, and is no longer called by M2.A.
