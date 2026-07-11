# RFC 9958 Engineering Traceability

RFC 9958 is an informational engineering guide. This matrix maps its
migration concerns to concrete repository evidence without treating the
RFC as an executable protocol specification.

| Engineering concern | Repository evidence | Status | Next evidence |
|---|---|---|---|
| Inventory algorithms and dependencies | Workspace crates separate ML-KEM, ML-DSA, SLH-DSA, HPKE, and hybrid workstreams | Partial | Generate a machine-readable crypto inventory |
| Replace quantum-vulnerable public-key mechanisms | FIPS 203 ML-KEM implementation passes all imported ACVP categories | Strong | Add protocol interoperability evidence |
| Plan for larger keys and ciphertexts | Parameter-size constants, exact-length checks, ACVP key checks | Strong | Add transport and memory-overhead benchmarks |
| Validate malformed public inputs | Encapsulation-key canonicality and decapsulation-key integrity checks | Strong | Add fuzzing and parser resource limits |
| Preserve algorithm agility | Parameter-set enums and crate boundaries | Partial | Introduce protocol suite identifiers and negotiation policy |
| Address harvest-now-decrypt-later risk | ML-KEM and planned PQ HPKE integration | Partial | Implement and validate HPKE with pure PQ and PQ/T suites |
| Consider hybrid migration | `pqc-hybrid` crate reserved; PQ/T HPKE draft pinned | Planned | Implement MLKEM768-X25519 first |
| Avoid downgrade and negotiation failures | No protocol negotiation layer yet | Pending | Add explicit downgrade-resistant suite selection |
| Account for performance and message expansion | Primitive lengths are tested | Partial | Add end-to-end HPKE size, latency, and memory measurements |
| Review side-channel exposure | Constant-time selection used in implicit rejection | Partial | Perform whole-crate constant-time and zeroization audit |
| Coordinate deployment and interoperability | ACVP evidence exists for ML-KEM | Partial | Add RFC 9180 and pinned-draft vector harnesses |
| Maintain standards provenance | `standards-scope.toml` and compile-time claim-boundary tests | Complete for Stage 7A | Update whenever a draft revision changes |

## Claim boundary

The repository may state:

- FIPS 203 ML-KEM is validated against the imported NIST ACVP corpus.
- RFC 9958 engineering concerns are traced to repository evidence.
- RFC 9180 HPKE implementation is pending.
- `draft-ietf-hpke-pq-05` is a pinned experimental target.

The repository must not state:

- that RFC 9958 defines ML-KEM, HPKE, or PQ/T hybrid algorithms;
- that passing ACVP vectors constitutes CMVP module validation;
- that an Internet-Draft is a final RFC;
- that HPKE conformance exists before RFC 9180 and pinned-draft vectors pass.
