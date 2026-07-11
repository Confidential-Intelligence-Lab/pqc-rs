# Stage 7C: Pure ML-KEM HPKE Vector Execution

Stage 7C executes the three pure ML-KEM Base-mode suites published with
`draft-ietf-hpke-pq-05`:

- ML-KEM-512 / HKDF-SHA256 / AES-128-GCM
- ML-KEM-768 / HKDF-SHA256 / AES-128-GCM
- ML-KEM-1024 / HKDF-SHA384 / AES-256-GCM

The harness validates:

- recipient private-key derivation;
- recipient public-key derivation;
- deterministic KEM encapsulation;
- KEM shared secret;
- Base-mode sender and receiver setup;
- every listed ciphertext;
- receiver plaintext recovery;
- every listed sender exporter output;
- every listed receiver exporter output.

Hybrid KEM suites and the draft's SHA-3/TurboSHAKE KDF suites remain
outside this stage.
