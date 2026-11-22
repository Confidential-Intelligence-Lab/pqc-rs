# S3.A — Experimental authentication-key lifecycle

This additive module accepts a caller-provided pre-shared secret and derives domain-separated keys for an authenticated classical transcript. It **does not** generate QKD entropy, attest where the pre-shared key came from, provision a key through an HSM, or confer HPKE export authority.

## Mechanism and boundaries

- The caller must independently provision the same secret and public key identifier at each endpoint. The demo generates a local random fixture for tests only. No source attestation is performed.
- Per-session subkeys use HKDF-style HMAC-SHA256 extraction and expansion under versioned context. Sender and protocol-stage-specific HMAC-SHA256 tags cover canonical frames, roles, session IDs, key identifiers, sequence numbers, previous transcript hashes, and public payload bytes.
- Each endpoint keeps a volatile local set of consumed session IDs. Replay is rejected within the same live session and session IDs cannot be reopened on that live store. **No crash-persistent replay protection** exists, and sessions recreated from new stores may reuse IDs unless an external monotonic registry prevents it.
- Session closure and root destruction overwrite local Python bytearrays, but Python copies, garbage collection, allocator behavior and OS memory prevent a zeroization guarantee. Production secure memory requires separate engineering.
- A valid MAC authenticates the chosen key's holder; it does not establish that provisioning was independent, secure, or authenticated. No concrete composable authentication-failure bound is certified by this module.
- This is an *additive* experimental layer. Existing H2, S2.A2 and M2.A still create local authentication secrets internally and are **not** rewired to the provisioned-key interface by S3.A. That is S3.B's mandatory integration task.
- API messages are public classical discussion only. The `hpke_handoff` stage is unsupported; raw secret keys must never be passed as payloads.

## Explicit security states

`provisioning_origin_verified=false`, `replay_tracking_persistent=false`, `quantum_min_entropy_certified=false`, `security_model_validated=false`, `security_qualified=false`, `hpke_export_authorized=false`.

## Next mandatory closure work

S3.B integrates independently provisioned authenticated channels into every actual BB84 discussion stage without a generated-secret fallback, adds durable anti-replay/one-time use across restarts, and proves the channel authentication budget under an explicit provisioning model. A separate quantum sampling/source proof and cryptographic review are needed before any conditional QKD security authorization.
