# PQC-rs Roadmap

> Last reviewed: 2026-09-21

PQC-rs develops an open-source, standards-driven Rust stack in which
post-quantum cryptography is implemented, assured, interoperable across
independent providers, and changeable across real applications with
quantitatively low change propagation and overhead.

The roadmap emphasizes the joint combination of standards fidelity, assurance,
interoperability, crypto-agility, application transparency, and measured
efficiency. It does not aim to maximize algorithm count or provider count.

## Current foundation

The principal standardized cryptographic foundation is implemented:

- **ML-KEM / FIPS 203** — ML-KEM-512, ML-KEM-768, and ML-KEM-1024;
- **ML-DSA / FIPS 204** — ML-DSA-44, ML-DSA-65, and ML-DSA-87, including
  Pure ML-DSA, HashML-DSA, deterministic signing, and hedged signing;
- **SLH-DSA / FIPS 205** — all twelve standardized parameter sets, including
  Pure SLH-DSA and HashSLH-DSA;
- **HPKE / RFC 9180** — Base and PSK modes with post-quantum KEM integration;
- **hybrid composition** — revision-pinned post-quantum/traditional HPKE
  integration.

The repository also includes independent-provider interoperability,
standards traceability, ACVP/vector validation, negative testing, fuzzing,
Miri and sanitizer analysis, secret-lifetime and zeroization review,
constant-time engineering, side-channel screening, reproducibility, and
release certification.

PQC-Forge builds above this foundation with capability negotiation, policy,
resolution, protocol binding, activation, and provider boundaries. Current
application realizations include secure channels and challenge-response
authentication.

## Definition of completion

A cryptographic capability is not considered complete merely because its
algorithm is implemented. Where applicable, completion requires:

1. implementation;
2. standards traceability;
3. conformance and adversarial testing;
4. independent interoperability;
5. assurance coverage;
6. concise user documentation; and
7. reproducible release evidence.

Claims remain bounded by the evidence available for each capability.

## R0 — Foundation consolidation

**Objective:** maintain a concise and accurate description of the foundation
already present on `main`.

Current work:

- reconcile canonical documentation with released capabilities;
- close remaining documentation/evidence gaps for ML-DSA and SLH-DSA;
- keep generated implementation and standards matrices current;
- separate current documentation from historical development provenance.

Exit condition: canonical documentation describes the current implementation,
validation, interoperability, assurance, and release state without completed
capabilities remaining listed as future work.

## R1 — Bouncy Castle interoperability

**Objective:** extend independent interoperability to Bouncy Castle Rust using
the existing provider-interoperability framework.

Planned order:

1. ML-KEM;
2. ML-DSA;
3. SLH-DSA where overlapping Bouncy Castle interfaces are available.

Evidence will distinguish byte-exact deterministic comparisons from semantic
interoperability when provider APIs expose different controls.

Provider additions are motivated by independent implementation diversity and
useful external validation, not provider count alone.

## R2 — Compiled-code constant-time assurance

**Objective:** strengthen assurance that source-level constant-time intent
survives compilation.

Investigate compiled-code secret-dependency testing with Bouncy Castle and
other collaborators, including dynamic taint-style approaches and
architecture-specific generated-code analysis.

This complements rather than replaces existing timing, secret-dependency,
machine-code, and cross-architecture assurance.

## R3 — Hybrid HPKE

**Objective:** mature post-quantum/traditional HPKE composition into a
well-defined transition mechanism.

Work includes:

- construction and revision audit;
- public API and failure semantics;
- deterministic validation evidence;
- interoperability where independent support exists;
- negative and downgrade-oriented testing;
- assurance integration; and
- application-level demonstration through PQC-Forge.

Experimental constructions remain explicitly revision-pinned until their
specifications are sufficiently stable.

## R4 — Unified assurance

**Objective:** make assurance reusable across cryptographic capabilities rather
than accumulating algorithm-specific campaigns.

Consolidate:

- standards and conformance evidence;
- secret inventory and zeroization;
- constant-time and secret-dependency analysis;
- fuzzing and adversarial testing;
- Miri and sanitizer analysis;
- cross-architecture testing;
- performance and resource characterization; and
- reproducible release certification.

## R5 — PQC-Forge migration lifecycle

**Objective:** make cryptographic migration and replacement explicit system
operations.

Develop the lifecycle:

```text
inventory
   -> capability
   -> policy
   -> resolution
   -> binding
   -> activation
   -> measurement
   -> deprecation
```

Applications should depend on stable protocol and integration boundaries while
algorithms, providers, policies, and execution substrates remain replaceable
behind them.

## R6 — Quantitative crypto-agility

**Objective:** measure the cost and localization of cryptographic change.

Evaluation will characterize:

- change propagation;
- negotiation and resolution overhead;
- provider substitution;
- algorithm and policy transitions;
- software-to-hardware provider substitution;
- performance and resource overhead; and
- reproducibility across supported environments.

The goal is to turn crypto-agility from an architectural claim into a
measurable system property.

## R7 — Application expansion

**Objective:** demonstrate migration and agility across distinct security
mechanisms.

Priority applications are:

1. secure software and artifact update;
2. identity, credentials, and PKI;
3. additional secure-channel and authentication deployments.

New applications should exercise the common PQC-Forge lifecycle rather than
introduce application-specific algorithm-selection machinery.

## R8 — Deployment providers

**Objective:** extend provider agility where concrete deployment requirements
justify additional execution substrates.

Candidate environments include:

- embedded systems;
- HSM and accelerator interfaces;
- FPGA and other hardware providers; and
- GPU acceleration where workloads justify it.

Hardware work is driven by application and migration requirements rather than
accelerator count.

## Long-term direction

PQC migration is the immediate use case. The longer-term objective is
continuous cryptographic resilience: systems in which cryptography can be
discovered, selected, negotiated, replaced, accelerated, and deprecated
without redesigning the application.

PQC-rs provides the cryptographic and assurance foundation. PQC-Forge provides
the migration and agility architecture.
