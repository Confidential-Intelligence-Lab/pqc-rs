# S5.D-5: single-use bounded authenticated peer confirmation

Research-only S3.C session extension `s5d5-cascade-v1`. Preserves original fixed schedules and S5.D-4 default behavior. Authenticates Bob's fresh independent public confirmation seed and Alice's resulting universal Toeplitz confirmation tag as two extra S3.C frames after bounded interactive parity correction and before commit. Bob recomputes the tag from its corrected local state. Mismatch aborts before a public acceptance report.

- 4800 parity comparisons; 9600 parity frames; profile/finish/ack/commit (5) plus confirmation (2): **9607 authenticated outer frames** maximum.
- Maximum parity disclosure 9600 bits. Two separate 64-bit confirmation tags are deliberately charged for the numerical candidate (legacy local confirmation and the new peer confirmation): **9728 bits** charged against `leak_EC`, yielding a numerical candidate about 329 bits. This deliberately double-charges potential overlapping proof terms rather than making a theorem claim.
- Assumes an externally provisioned shared root. Single-host registry burns a root marker **before** any protocol exchange. Neither distributed anti-rollback nor external provisioning is demonstrated.
- The local Cascade reference engine still owns Bob's error-correction state; endpoints are independently authenticated *states* but not independently deployed processes. Confirmation is peer-mediated and checked, yet the original local confirmation remains. Full quantum theorem correspondence, adaptive leakage reduction, source/device attestation, operational authentication reduction, and quantum-secret export remain **unproven**.
- HMAC-SHA256 messages are counted, not assigned a proven epsilon_auth. The 1e-12 nominal authentication target is not certified.
- Strictly no key material is returned and `security_qualified`, `conditional_security_supported`, `qkd_psk_available`, `hpke_export_authorized` remain false.

Next step is S5.E: documented standards-aligned research-security assessment. Do not claim conditional security unless published theorem instantiation and the computational authentication assumption are independently justified.
