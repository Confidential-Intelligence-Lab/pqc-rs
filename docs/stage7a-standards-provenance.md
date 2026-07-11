# Stage 7A: Standards Provenance and Claim Boundaries

Stage 7A establishes the scope for protocol integration.

## Authoritative documents

- RFC 9958: informational engineering guidance for PQC migration.
- RFC 9180: HPKE construction and protocol behavior.
- FIPS 203: ML-KEM algorithm specification.
- draft-ietf-hpke-pq-05: pinned work-in-progress target for pure PQ and
  PQ/traditional hybrid HPKE KEMs.

## Repository status after Stage 7A

```text
FIPS 203 ML-KEM        vector validated
RFC 9958               engineering guidance traced
RFC 9180 HPKE          implementation pending
draft-ietf-hpke-pq-05 pinned experimental target
```

Compile-time and integration tests enforce these claim boundaries.
