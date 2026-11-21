# S3.B: strict credential forwarding and persistent session reservation

Experimental idealized BB84 simulation only. No cryptographic security or hardware
source is certified; HPKE key export remains prohibited.

The strict wrapper requires an external 32-byte-or-longer authentication root,
public key ID, explicit session ID, and an existing private 0700 local registry.
A marker is atomically created with O_EXCL and fsynced before the acquisition
starts; any error burns the session. The registry provides single-host,
crash-persistent session reuse detection only under durable, non-rolled-back
storage assumptions. Filesystem snapshots, privileged tampering, directory
replacement, multiple hosts, and provisioning authenticity remain unresolved.

M2.A now accepts explicit credentials for H2 and S2.A2. Distinct MAC keys are
HKDF-extract/expand-style domain-separated from the supplied root and session
ID. The strict wrapper bans deterministic selection inputs and hypothetical
entropy. The old implicit-random-key invocation is retained **only as an
experimental diagnostic** for regression compatibility, not the strict path.

This increment does NOT yet migrate all H2/S2.A2 frames to the S3.A
AuthSession stage-machine API. Root authenticity and authentication security
budgets are not attested or proven, and storage persistence alone is not a
cryptographic security proof. It cannot certify simulation-generated QKD PSKs.

`security_model_validated=false`, `security_qualified=false`, and
`hpke_export_authorized=false` are mandatory.
