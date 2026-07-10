# ML-KEM Known-Answer Tests

This directory contains KAT manifests and vector records.

Current status:

- Structural vector schema: available
- Intermediate-value schema: available
- Official FIPS 203 vectors: not yet imported
- FIPS 203 conformance claim: none

A vector record should contain:

```text
id
parameter_set
keygen_seed
rho
sigma
message
encryption_randomness
public_key
secret_key
ciphertext
shared_secret
```

Official vectors must identify their authoritative source and version.
