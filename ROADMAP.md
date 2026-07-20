# Roadmap

> Last reviewed: 2026-07-19

This roadmap communicates project direction and release gates rather than a
binding delivery schedule. PQC-rs advances a crate only when its normative
source, validation evidence, interoperability, security review, packaging, and
maintenance ownership are sufficiently mature for the claim being made.

## Current baseline — v0.4.0-rc.1

The first release candidate establishes a standards-driven Rust foundation for
post-quantum key establishment and HPKE.

| Area | Current status |
|---|---|
| Published crates | `pqc-rs-core`, `pqc-rs-ml-kem`, and `pqc-rs-hpke` are available from crates.io at `0.4.0-rc.1` |
| ML-KEM | FIPS 203 ML-KEM-512, ML-KEM-768, and ML-KEM-1024 are implemented and ACVP-oriented vector validated |
| ML-DSA | FIPS 204 ML-DSA-44, ML-DSA-65, ML-DSA-87, and HashML-DSA are implemented and repository validated; the crate remains unpublished |
| HPKE | RFC 9180 Base and PSK modes are implemented across the maintained ciphersuite matrix |
| PQ HPKE | Pure post-quantum and post-quantum/traditional hybrid profiles are pinned to `draft-ietf-hpke-pq-05` and remain experimental |
| Interoperability | Bidirectional ML-KEM and ML-DSA checks with Open Quantum Safe `liboqs`; ML-KEM exchange checks with OpenSSL; native HPKE transcript comparison with an independent RFC 9180 oracle |
| Assurance | Formatting, warning-free linting, tests, rustdoc, ACVP-oriented validation, fuzzing, Miri, secret and zeroization review, timing and generated-code screening, SBOM generation, signed source artifacts, and signed Stage 13 evidence |

The release remains intended for research, evaluation, integration testing,
and external scrutiny. Repository-local evidence is not a formal proof, FIPS or
CMVP validation, Common Criteria certification, independent security audit, or
authorization to protect production secrets without an application-specific
risk assessment.

## Engineering principles

1. **Normative sources before implementation claims.** Finalized standards,
   Internet-Drafts, regional selections, and research candidates have distinct
   maturity labels and compatibility promises.
2. **Correctness before optimization.** Conformance, malformed-input handling,
   interoperability, and side-channel review precede architecture-specific
   tuning.
3. **Stable and experimental APIs remain separated.** Revision-pinned drafts
   and pre-standard algorithms do not silently enter stable interfaces.
4. **Each crate earns publication independently.** A passing workspace does
   not substitute for crate-specific packaging, reconstruction, documentation,
   and assurance gates.
5. **Security claims remain conservative.** Testing and empirical screening
   are described as evidence, not proof or certification.

## Foundation release track

### v0.4 final — public stabilization

Primary outcome: convert the signed release candidate into a broadly reviewed
public foundation without changing the meaning of the tagged
`v0.4.0-rc.1` release.

Planned work:

- make the repository and signed prerelease broadly accessible before fall
  2026, or establish a public mirror if the UCI GitHub Enterprise instance
  requires authentication;
- verify anonymous repository and release-asset access;
- open public issue and discussion channels for standards questions,
  interoperability failures, API feedback, and security reports;
- correct the Stage 13 interactive Minisign integration and ensure the
  artifact-authenticity claim is evaluated only after signature verification;
- complete the deferred Stage 10B-5 generated-code and timing comparison on
  Apple ARM64, Linux x86-64, and Linux ARM64;
- add installation examples, an interoperability quick start, supported-target
  documentation, and a release-candidate migration guide;
- complete at least one public review cycle and resolve all critical and high
  findings.

Crates.io action: publish final `0.4.0` releases of `pqc-rs-core`,
`pqc-rs-ml-kem`, and `pqc-rs-hpke` only after these gates pass.

### v0.5 — FIPS 204 ML-DSA publication

Primary outcome: productize the existing verified ML-DSA implementation as an
independently consumable crate.

Planned work:

- remove the temporary placeholder surface and complete the public API and
  feature-flag review;
- preserve coverage for ML-DSA-44, ML-DSA-65, ML-DSA-87, and HashML-DSA;
- maintain ACVP-oriented and intermediate-value evidence;
- complete malformed-input, fuzzing, timing, generated-code, secret-lifetime,
  and zeroization review for the publishable surface;
- preserve bidirectional signature interoperability with `liboqs` and add
  equivalent OpenSSL cross-verification coverage;
- rebuild the packaged crate from its crates.io dependency graph and verify
  docs.rs-compatible documentation.

Crates.io action: first publication of `pqc-rs-ml-dsa`, initially as a release
candidate and then as `0.5.0` after external review.

### v0.6 — FIPS 205 SLH-DSA

Primary outcome: replace the `pqc-rs-slh-dsa` placeholder with a complete,
standards-traced implementation.

Planned work:

- implement all twelve SHA2 and SHAKE parameter sets in FIPS 205;
- add authoritative known-answer and intermediate-value evidence;
- define bounded stack, heap, signature-size, and performance profiles;
- add malformed-input tests, structured fuzzing, differential testing, and
  secret-lifetime review;
- establish interoperability with `liboqs` and OpenSSL;
- track NIST SP 800-230 additional limited-use parameter sets, but keep them
  outside the stable API until that specification is final.

Crates.io action: first publication of `pqc-rs-slh-dsa` after all FIPS 205
parameter sets and publication gates pass.

### v0.7 — hybrid composition and evolving HPKE specifications

Primary outcome: move reusable hybrid construction beyond HPKE-local profiles
while preserving explicit draft compatibility boundaries.

Planned work:

- replace the `pqc-rs-hybrid` placeholder with a specification-bound combiner
  API;
- document component ordering, domain separation, failure behavior, downgrade
  resistance, identifiers, and serialization;
- track `draft-ietf-hpke-pq-05` and later revisions through explicit
  compatibility releases rather than silently changing wire behavior;
- track `draft-ietf-hpke-hpke-04`, which would obsolete RFC 9180 if approved;
- decide Auth and AuthPSK support against the successor HPKE specification
  rather than expanding an API that may immediately change;
- extend cross-provider and negative interoperability coverage for every
  supported hybrid profile.

Crates.io action: first publication of `pqc-rs-hybrid` and a corresponding
compatibility release of `pqc-rs-hpke`.

### v1.0 — stable NIST foundation

Version 1.0 stabilizes the common traits and the NIST-centered production API;
it is not blocked on every future regional or diversity algorithm.

Required gates:

- stable APIs for core, ML-KEM, ML-DSA, SLH-DSA, HPKE, and hybrid composition;
- a documented SemVer and deprecation contract;
- supported-platform CI and generated-code/timing evidence for the maintained
  architecture matrix;
- independent cryptographic and API review with no unresolved critical or high
  findings;
- complete installation, migration, interoperability, threat-model, and
  operational-limitation documentation;
- reproducible package reconstruction, SBOMs, checksums, signed artifacts, and
  release provenance;
- evidence of sustained external use and feedback across at least one complete
  public release-candidate cycle.

Crates.io action: stable `1.0.0` releases of the six foundation crates. A small
umbrella `pqc-rs` crate may then provide curated feature groups without making
every algorithm a mandatory dependency.

## Standards and algorithm expansion

New algorithms are developed as independently gated crates. Their maturity does
not delay security fixes or API stability for the foundation crates.

### ISO/IEC, European, and NIST diversity track

This track covers algorithm diversity standardized through ISO/IEC or selected
by NIST, together with the migration and hybrid-deployment requirements being
developed by European bodies. Europe does not currently define a single,
separate algorithm portfolio for this project to copy: the EU coordination
roadmap, ANSSI guidance, and ETSI work are treated as deployment and protocol
requirements, while new primitive crates remain tied to their normative
algorithm standards.

| Algorithm | External status | Planned crate | Entry condition |
|---|---|---|---|
| Classic McEliece | Included in ISO/IEC 18033-2:2006/Amd 2:2026 material | `pqc-rs-classic-mceliece` | Confirm exact normative profile, authoritative vectors, large-key API design, licensing, and constant-time reference behavior |
| FrodoKEM | Included in ISO/IEC 18033-2:2006/Amd 2:2026 material | `pqc-rs-frodokem` | Confirm exact normative profile, authoritative vectors, memory/performance bounds, and reference interoperability |
| FN-DSA | Selected by NIST; FIPS 206 remains in development | `pqc-rs-fn-dsa` | Stable public draft, authoritative vectors, floating-point/integer implementation policy, and side-channel plan |
| HQC | Selected by NIST as a non-lattice backup KEM; standard remains in development | `pqc-rs-hqc` | Normative public draft, authoritative vectors, decoding-failure analysis, and reference interoperability |

These crates begin at independent `0.x` versions after the foundation reaches a
stable release. They graduate according to their own standards and assurance
evidence.

### Korean KpqC track

The KpqC competition selected two KEMs and two signature schemes. Work remains
standards-track until the applicable Korean Standard texts and associated
artifacts are final.

| Algorithm | Class | Planned crate |
|---|---|---|
| SMAUG-T | KEM | `pqc-rs-smaug-t` |
| NTRU+ | KEM | `pqc-rs-ntru-plus` |
| HAETAE | Digital signature | `pqc-rs-haetae` |
| AIMer | Digital signature | `pqc-rs-aimer` |

Entry gates for every KpqC crate:

- final Korean Standard or another authoritative normative specification;
- stable parameter sets and identifiers;
- authoritative vectors and accessible reference code;
- intellectual-property and licensing review;
- bidirectional interoperability with a Korean reference implementation;
- a named maintainer and the same fuzzing, side-channel, packaging, and signed
  release-evidence requirements used by the foundation crates.

## Crate publication policy

| Crate group | Versioning policy | Publication status |
|---|---|---|
| Existing foundation crates | Synchronized through `1.0.0` | Three published; ML-DSA, SLH-DSA, and hybrid follow the gated sequence above |
| ISO/European/NIST diversity crates | Independent `0.x` versions after the foundation stabilizes | Not yet created |
| KpqC crates | Independent `0.x` versions after normative and licensing gates pass | Not yet created |
| `pqc-rs` umbrella | Versioned with the stable foundation and composed from optional feature groups | Candidate after `1.0.0` APIs stabilize |
| `pqc-rs-test-harness` | Workspace-internal only | Permanently `publish = false` |

For every public crate, publication requires:

1. an authoritative specification and explicit claim boundary;
2. deterministic conformance and malformed-input evidence;
3. independent interoperability where an external implementation exists;
4. secret-dependency, constant-time, zeroization, fuzzing, and memory-safety
   review appropriate to the algorithm;
5. API, SemVer, feature-flag, `no_std`/`alloc`/`std`, and rustdoc review;
6. `cargo package --list` and `cargo publish --dry-run` from a clean Git state;
7. verification against already published dependency versions;
8. SBOM, checksums, signed artifacts, and a reproducible evidence bundle;
9. a clean release commit, annotated tag, and remote verification.

## Interoperability roadmap

The current provider framework covers native Rust, Open Quantum Safe `liboqs`,
OpenSSL, and an independent RFC 9180 transcript oracle. Planned extensions are:

- OpenSSL bidirectional ML-DSA signature generation and verification;
- SLH-DSA cross-provider vectors for every published parameter set;
- negative and malformed-input cross-provider corpora;
- version-captured provider matrices in signed release evidence;
- independent reference implementations for Classic McEliece, FrodoKEM,
  FN-DSA, HQC, and the KpqC algorithms before their stable publication;
- future protocol adapters only when their IETF specifications and wire formats
  are sufficiently stable.

An interoperability pass applies only to the named provider versions,
parameter sets, operations, and vectors recorded in the evidence. It is not a
general certification of either implementation.

## Public adoption and teaching

The public project should support three mutually reinforcing uses:

- **Open-source engineering:** invite implementation review, cryptanalysis,
  interoperability reports, integrations, and additional maintainers.
- **Migration prototyping:** provide standards-based components and evidence
  for teams evaluating cryptographic agility, hybrid deployment, and system
  impacts without overstating production readiness.
- **Advanced education:** turn the standards matrix, deterministic vectors,
  provider framework, fuzzing targets, side-channel screens, and release gates
  into UCI laboratories covering KEMs, signatures, HPKE, interoperability,
  crypto agility, and secure software engineering.

Teaching material should use deterministic fixtures and explicit
release-candidate warnings; it must never normalize unsafe key handling or
present repository-local testing as certification.

## Deferred but retained — high-performance engineering

Architecture-specific optimization remains a planned workstream:

- vectorized NTT and polynomial arithmetic;
- NEON, AVX2, AVX-512, and SVE2 backends;
- cache-aware and memory-footprint engineering;
- performance-regression CI across supported targets;
- compiler-diversity and generated-code comparison;
- future hardware acceleration and co-design interfaces.

This work follows stable reference implementations and API boundaries.
Optimization must preserve conformance, interoperability, constant-time review,
and portable fallback paths.

## Standards watch links

- [NIST Post-Quantum Cryptography project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST HQC selection](https://csrc.nist.gov/News/2025/hqc-announced-as-a-4th-round-selection)
- [IETF `draft-ietf-hpke-pq`](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/)
- [IETF `draft-ietf-hpke-hpke`](https://datatracker.ietf.org/doc/draft-ietf-hpke-hpke/)
- [ISO/IEC 18033-2:2006/Amd 2:2026](https://www.iso.org/standard/86890.html)
- [EU coordinated PQC implementation roadmap](https://cyber.gouv.fr/en/publications/jointly-led-international-publications/roadmap-for-the-transition-to-pqc/)
- [ANSSI position on the PQC transition](https://cyber.gouv.fr/en/technological-and-cybersecurity-challenges/post-quantum-cryptography/)
- [ETSI ESI PQC Working Group](https://portal.etsi.org/TB-SiteMap/ESI/ESI-PQC-WG-ToR)
- [Open Quantum Safe `liboqs`](https://openquantumsafe.org/liboqs/)
- [OpenSSL ML-KEM documentation](https://docs.openssl.org/3.5/man7/EVP_KEM-ML-KEM/)
- [KpqC final algorithm specifications](https://www.kpqc.or.kr/contents/03_exhibit/sub_03.html)
