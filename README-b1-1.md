# B1.1 — HPKE PSK Mode and Context Safety

This milestone hardens the native Rust HPKE layer with RFC 9180 PSK mode and explicit terminal context state.

## Added

- Deterministic `SetupPSKS` and `SetupPSKR` APIs for all ML-KEM parameter sets.
- Strict RFC 9180 validation of `psk` and `psk_id` presence.
- Sender/receiver exporter agreement in PSK mode.
- Explicit `is_exhausted()` context state.
- Safe one-time use of the final representable sequence number.
- Permanent rejection of message operations after sequence exhaustion.
- Negative tests for incorrect PSKs, incorrect PSK identities, and malformed PSK inputs.
- Exporter tests for zero-length, maximum HKDF output, and excessive output requests.

Pure ML-KEM supports HPKE Base and PSK modes. Auth and AuthPSK require an authenticated KEM construction and are intentionally deferred to hybrid HPKE work.
