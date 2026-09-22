# Standards Support

| Standard or specification | Scope | Status |
|---|---|---|
| FIPS 203 | ML-KEM-512, ML-KEM-768, ML-KEM-1024 | Implemented and repository-verified |
| FIPS 204 | ML-DSA-44, ML-DSA-65, ML-DSA-87; Pure/Hash; deterministic/hedged signing | Implemented and repository-verified |
| FIPS 205 | All twelve standardized SLH-DSA parameter sets; Pure/Hash | Implemented and repository-verified |
| RFC 9180 | HPKE Base and PSK modes | Implemented and repository-verified |
| RFC 9958 | Post-quantum engineering guidance | Mapped; informational guidance, not an implementation target |
| `draft-ietf-hpke-pq-05` | Pure-PQ and PQ/traditional hybrid HPKE integration | Revision-pinned experimental support |

Detailed traceability is maintained under [`docs/standards/`](standards/), with
machine-readable evidence under [`compliance/`](../compliance/).

`verified` denotes repository validation evidence; it does not mean NIST
validation, certification, formal verification, or independent security audit.
