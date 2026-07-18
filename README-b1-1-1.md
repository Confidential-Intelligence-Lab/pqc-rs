# B1.1.1 — Restore A3.1 shared-secret setup helpers

This narrow compatibility repair restores the A3.1 public helpers:

- `setup_base_sender_from_shared_secret`
- `setup_base_receiver_from_shared_secret`

B1.1 inadvertently replaced `crates/pqc-hpke/src/setup.rs` without retaining
these functions. The HPKE transcript harness imports them to construct native
Base-mode contexts from shared secrets established by external KEM providers.

The repair does not alter PSK mode, sequence exhaustion, exporter behavior, or
cryptographic primitives.
