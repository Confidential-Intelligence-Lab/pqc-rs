# M1.D experimental robustness scope

This milestone expands protocol-integration regression coverage. It **does not**
certify physical QKD security or transform a SHA-256-compressed fixture into a
secure QKD key. The simulator still lacks authenticated public discussion,
information reconciliation, security-parameterized privacy amplification,
finite-key entropy bounds, optical channel and detector models, and secure
network key-manager interfaces. A deterministic Python PRNG is used for
reproducible diagnostic experiments, **not cryptographic key generation**.

The BB84 intercept-and-resend model has expected sifted QBER `p/4`, where
`p` is the intercepted fraction. The sweep uses a 5-sigma statistical tolerance
with an absolute floor of 0.035 for demonstration reliability; this is **not**
a security threshold. The integration tests exercise fail-closed behavior for
malformed fixture records, wrong HPKE PSK identity, wrong PSK, wrong HPKE
context, ciphertext/AAD tampering, and provider key reuse and authorization.

Execution uses the existing M1.C CLI and `05_qkd_cudaq_secure_messaging`
example. Secret-bearing fixture contents must never be committed or logged.
The robustness runner uses private temporary files and deletes them on exit.

Future work: formal QKD postprocessing, security-qualified key eligibility,
authenticated KME provisioning, channel noise/loss models, and explicit
policy-driven acceptance/rejection. Failures in this test suite do not by
themselves quantify real-world QKD security.
