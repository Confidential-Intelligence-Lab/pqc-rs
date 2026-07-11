# Stage 7B-1: RFC 9180 Labeled HKDF and Key Schedule

This stage implements the RFC 9180 protocol foundation:

- two-byte KEM, KDF, and AEAD identifiers;
- HPKE and KEM suite identifiers;
- `LabeledExtract`;
- `LabeledExpand`;
- Base, PSK, Auth, and AuthPSK mode values;
- `VerifyPSKInputs`;
- key-schedule context construction;
- derivation of `key`, `base_nonce`, and `exporter_secret`;
- initial sequence number zero.

Supported RFC 9180 KDFs:

- HKDF-SHA256;
- HKDF-SHA384;
- HKDF-SHA512.

Stage 7B-1 intentionally does not implement:

- ML-KEM as an HPKE KEM;
- sender or receiver setup;
- AEAD encryption or decryption;
- secret export APIs;
- RFC 9180 full ciphersuite vectors.

The included known-answer test independently fixes the exact output of one
Base-mode HKDF-SHA256 key schedule. Stage 7B-5 will add authoritative HPKE
protocol vectors.
