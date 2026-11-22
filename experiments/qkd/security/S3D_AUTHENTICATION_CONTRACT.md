# S3.D — Explicit authentication provisioning and local root-use contract

**Research status:** EXPERIMENTAL / UNQUALIFIED. Baseline `cedfce69b5c275d61bbe27d51fc43140eda2c7ee`.

This increment is a strict **optional** entry point atop S4.F. It does not change existing S3.B/S3.C/S4.E behavior. Callers must supply an explicit `AssumedProvisionedCredential`, an `AuthenticationBudget`, and a private pre-existing single-host registry.

## Trust and threat model

- A root of at least 32 bytes is supplied *externally* and is **assumed** independently provisioned to Alice/Bob, secret, authentic, unique to the public `key_id`, and uncompromised. The code cannot verify these properties or detect low-entropy 32-byte inputs.
- Alice/Bob frame MACs use computational HMAC-SHA256. The source does **not** establish an information-theoretic authentication guarantee.
- A reserved root-use marker is created with the existing S3.B durable O_EXCL+fsync mechanism before precommitment/acquisition. Same `key_id` is single-use on the same uncompromised, durable, non-rolled-back host and registry. Privileged rollback, multi-host registry partitioning and key-ID aliasing are outside the contract. The marker consumes the root even on abort.
- The root remains as Python `bytes` during execution; representation redaction is not secure-memory erasure.

## Explicit wire-frame budget

For S4.E+S3.C `h2-ec-pa-v1` and `n_key >= 128`, the *conservative normal-path* outer authenticated wire-frame count is:

`F_outer = 2 (proof) + 9 (H2) + ceil(n_key/128) (syndrome) + 3 (EC confirm/ack/commit) + 3 (PA) = 17 + ceil(n_key/128)`.

Quota-abort paths are shorter. The policy rejects a session when `F_outer > max_outer_frames` or `max_root_sessions != 1`. This is a **resource cap**, not a computational MAC advantage or epsilon bound. Inner MACs in H2/EC, the authentication-key derivation, message lengths and adversarial verification-query counts require an end-to-end reduction; they are not covered by this simple frame count. In particular there is **no justified conversion** `epsilon_auth = F / 2^256`.

## Completion limitations and next security reduction

This implementation closes the optional **local provisioning and one-root-use engineering contract**, not the full S3.D cryptographic proof. A formal S3.D closure still needs (1) bootstrap credential trust evidence or explicit axiomatization accepted by the theorem, (2) a session-wide/multi-user HMAC security bound for the actual derived-key construction and all inner/outer MACs, (3) cross-host and rollback assumptions in the end-to-end model, (4) authenticated policy agreement between independently deployed peers rather than a single-process simulation. Keep QST-AUTH-02 open until then.

No output has `security_model_validated`, `security_qualified`, `hpke_export_authorized` or `qkd_psk_available` true. No quantum min-entropy and no QKD-based HPKE PSK is established.

## Evidence

`test_s3d_authentication_contract.py` contains resource-limit, replay/burn, failure/abort, profile-mismatch, unqualified-result, and redacted-repr tests. Full `test_*.py` regression must be run on EdgeExpert before commit.
