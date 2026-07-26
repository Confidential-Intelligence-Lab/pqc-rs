# OpenSSL ML-DSA interoperability

Stage 15A-7 makes bidirectional OpenSSL interoperability a blocking
publication-assurance gate for Pure ML-DSA.

## Required matrix

The gate covers ML-DSA-44, ML-DSA-65, and ML-DSA-87 in both directions:

- PQC-rs signs and OpenSSL verifies; and
- OpenSSL signs and PQC-rs verifies.

Every direction verifies the authentic signature and rejects the same
signature under a modified message, modified context, and single-bit signature
mutation. The complete matrix contains 24 required verification outcomes.

The provider adapter requires OpenSSL 3.5 or later, where ML-DSA key management
and one-shot signing are available. The report records the provider version,
parameter set, producer, consumer, mutation, expected result, and observed
result without recording private keys or signatures.

## Execution

```bash
scripts/check-ml-dsa-openssl-interop.sh
```

The machine-readable and Markdown reports are written under
`target/stage15a7-openssl-mldsa/`.

## Claim boundary

A pass demonstrates byte-compatible Pure ML-DSA signature cross-verification
between the tested PQC-rs revision and recorded OpenSSL provider for the named
parameter sets and cases. It also demonstrates the tested negative-verification
behavior.

OpenSSL 3.5 does not expose a native HashML-DSA operation. This gate therefore
does not claim HashML-DSA interoperability, formal proof, FIPS validation,
Common Criteria certification, or independent security audit.
