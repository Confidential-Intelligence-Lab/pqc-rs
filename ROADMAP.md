# Roadmap

> Last reviewed: 2026-07-21

This roadmap communicates project direction and release gates rather than a
binding delivery schedule. PQC-rs advances a crate only when its normative
source, validation evidence, interoperability, security review, packaging, and
maintenance ownership are sufficiently mature for the claim being made.

## Milestone 0 — public foundation and hardening (complete)

The first release candidate established a standards-driven Rust foundation for
post-quantum key establishment and HPKE. The public GitHub repository is now
the project's external source of record.

| Area | Completed checkpoint |
|---|---|
| Published crates | `pqc-rs-core`, `pqc-rs-ml-kem`, and `pqc-rs-hpke` are available from crates.io at `0.4.0-rc.1` |
| Public release | The immutable `v0.4.0-rc.1` tag, signed source archive, and signed assurance evidence are publicly available |
| ML-KEM | FIPS 203 ML-KEM-512, ML-KEM-768, and ML-KEM-1024 are implemented and ACVP-oriented vector validated |
| ML-DSA | FIPS 204 ML-DSA-44, ML-DSA-65, ML-DSA-87, and HashML-DSA are implemented and repository validated; the crate remains unpublished |
| HPKE | RFC 9180 Base and PSK modes are implemented across the maintained ciphersuite matrix |
| PQ HPKE | Pure post-quantum and post-quantum/traditional hybrid profiles are pinned to `draft-ietf-hpke-pq-05` and remain experimental |
| Interoperability | Bidirectional ML-KEM and ML-DSA checks with Open Quantum Safe `liboqs`; ML-KEM exchange checks with OpenSSL; native HPKE transcript comparison with an independent RFC 9180 oracle |
| Assurance | Formatting, warning-free linting, tests, rustdoc, ACVP-oriented validation, fuzzing, Miri, secret and zeroization review, timing and generated-code screening, SBOM generation, signed source artifacts, and signed Stage 13 evidence |
| Public CI | All public workflows pass; external actions are pinned to immutable commit SHAs and repository-level SHA enforcement is active |
| Main protection | Changes require a pull request and the `quality`, `audit`, `dependency-policy`, `constant-time-audit`, and `zeroization-audit` checks; deletion and force-push are blocked |

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

## Release and branch policy

Three project decisions govern the next stages:

1. The public repository at
   `https://github.com/Confidential-Intelligence-Lab/pqc-rs` is the external
   source of record for code, issues, pull requests, releases, and public
   review outcomes.
2. The foundation crates retain synchronized ecosystem versions through
   `1.0.0`. Independently gated diversity crates may use their own `0.x`
   versions.
3. The `v0.4.0` candidate receives a 21-day public review. The clock starts
   only when the exact tag, commit, signed evidence, reviewer packet, feedback
   channels, and closing date are public.

Milestones 1 and 2 intentionally overlap after the `v0.4.0` candidate freezes:

- `release/0.4` accepts only stabilization and review-driven fixes;
- ML-DSA work proceeds through feature branches and pull requests into `main`;
- fixes made on `release/0.4` are forward-ported to `main`;
- ML-DSA changes never flow backward into `release/0.4`; and
- `v0.5.0-rc.1` is not published until final `v0.4.0` packages are published.

A change restarts the review clock when it materially changes a published API,
cryptographic behavior, serialization or wire behavior, normative claim, or a
release-gating assurance result. Editorial corrections, CI-only repairs, and
clearly non-semantic documentation changes are recorded in the review log and
do not automatically restart the full window.

## Milestone 1 — v0.4.0 final stabilization

Primary outcome: freeze, externally review, and publish the stable foundation
without expanding its algorithm or API scope.

### Candidate-defining work

1. Reinstate Stage 10B-5 on public GitHub-hosted runners:

   - Linux x86-64 (`ubuntu-24.04`);
   - Linux ARM64 (`ubuntu-24.04-arm`); and
   - Apple ARM64 (`macos-14` or another explicitly pinned ARM64 image).

   Functional, generated-code, secret-dependency, and artifact-integrity checks
   are release gates. Hosted-runner timing measurements initially produce
   architecture-specific evidence and regression screens; absolute performance
   is not compared across unlike machines.

2. Complete the user-facing release documentation:

   - installation and minimal working examples;
   - ML-KEM and HPKE quick starts;
   - interoperability quick start;
   - supported-target matrix;
   - release-candidate-to-`v0.4.0` migration notes;
   - threat model, limitations, and non-certification language; and
   - Minisign verification instructions.

3. Complete public-project governance:

   - focused issue forms for bugs, interoperability, API feedback, and
     standards questions;
   - verified private vulnerability reporting;
   - a public discussion channel for non-sensitive questions; and
   - protection for release tags matching `v*`.

4. Freeze the exact review candidate. If anything reviewers are asked to
   evaluate differs from `v0.4.0-rc.1`, publish a matching new candidate tag
   and packages rather than moving the review target implicitly.

### External review and outreach

The 21-day review is an active workstream:

- contact the authors of RFC 9958 with a focused request about engineering
  interpretation and migration guidance;
- invite selected cryptographers, Rust engineers, implementers, and deployment
  experts to review areas aligned with their expertise;
- announce the review to the PQUIP mailing list (`pqc@ietf.org`);
- send a separate HPKE-focused notice to `hpke@ietf.org`; and
- publish a disposition record covering every non-sensitive comment and its
  release impact.

RFC 9958 is Informational engineering guidance, not an algorithm or protocol
specification. The project must not describe itself as an “RFC 9958
implementation.” Normative claims remain tied to FIPS 203, RFC 9180, and the
explicitly pinned HPKE Internet-Draft revision.

The review closes only when:

- at least 21 full calendar days have elapsed against the fixed candidate;
- every report has been acknowledged and classified;
- no critical or high-severity security or correctness finding remains open;
- no unresolved release-blocking conformance or interoperability defect
  remains open; and
- every release-critical fix has passed the complete applicable assurance
  profile.

Crates.io action: publish final `0.4.0` releases of `pqc-rs-core`,
`pqc-rs-ml-kem`, and `pqc-rs-hpke` only after these gates pass.

## Milestone 2 — v0.5.0 FIPS 204 ML-DSA publication

Primary outcome: productize the existing verified ML-DSA implementation as an
independently consumable crate. Engineering may begin as soon as the Milestone
1 candidate freezes; publication follows final `v0.4.0`.

### Public API contract

The first ML-DSA stage is an API and ownership-boundary review. It defines:

- typed public keys, private keys, key-generation seeds, and signatures;
- ML-DSA-44, ML-DSA-65, and ML-DSA-87;
- pure ML-DSA and HashML-DSA;
- context handling and pre-hash selection;
- deterministic and randomized signing;
- explicit verification and malformed-signature behavior;
- seed-form versus expanded private-key ownership and zeroization;
- `no_std`, `alloc`, and `std` feature boundaries; and
- a private implementation boundary for arithmetic internals.

NIST recognizes a key-generation seed as an acceptable alternative private-key
format for FIPS 204. PQC-rs will therefore make the seed-versus-expanded-key
choice explicit in the supported API and documentation rather than leaving it
as an incidental storage detail.

### Implementation and publication assurance

- remove the temporary placeholder type and route validated internals through
  the supported public surface;
- keep arithmetic and primitive-only modules private unless a separately
  reviewed use case requires exposure;
- preserve coverage for ML-DSA-44, ML-DSA-65, ML-DSA-87, and HashML-DSA;
- maintain ACVP-oriented and intermediate-value evidence;
- complete malformed-input, negative-verification, fuzzing, Miri, timing,
  generated-code, secret-lifetime, and zeroization review;
- preserve bidirectional signature interoperability with `liboqs` and add
  OpenSSL signature cross-verification;
- add complete rustdoc examples and feature-matrix tests; and
- rebuild the packaged crate from its crates.io dependency graph and verify
  docs.rs-compatible documentation.

Release sequence: `v0.5.0-rc.1`, a bounded external review, then `v0.5.0`.

## Milestone 3 — v0.6.0 FIPS 205 SLH-DSA

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

## Milestone 4 — v0.7.0 hybrid composition and HPKE evolution

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

## Milestone 5 — v1.0 stable NIST foundation

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
- [NIST PQC FAQ](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/faqs)
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST HQC selection](https://csrc.nist.gov/News/2025/hqc-announced-as-a-4th-round-selection)
- [RFC 9958](https://www.rfc-editor.org/info/rfc9958/)
- [IETF PQUIP working group](https://datatracker.ietf.org/wg/pquip/about/)
- [IETF HPKE working group](https://datatracker.ietf.org/wg/hpke/about/)
- [IETF `draft-ietf-hpke-pq`](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/)
- [IETF `draft-ietf-hpke-hpke`](https://datatracker.ietf.org/doc/draft-ietf-hpke-hpke/)
- [ISO/IEC 18033-2:2006/Amd 2:2026](https://www.iso.org/standard/86890.html)
- [EU coordinated PQC implementation roadmap](https://cyber.gouv.fr/en/publications/jointly-led-international-publications/roadmap-for-the-transition-to-pqc/)
- [ANSSI position on the PQC transition](https://cyber.gouv.fr/en/technological-and-cybersecurity-challenges/post-quantum-cryptography/)
- [ETSI ESI PQC Working Group](https://portal.etsi.org/TB-SiteMap/ESI/ESI-PQC-WG-ToR)
- [Open Quantum Safe `liboqs`](https://openquantumsafe.org/liboqs/)
- [OpenSSL ML-KEM documentation](https://docs.openssl.org/3.5/man7/EVP_KEM-ML-KEM/)
- [KpqC final algorithm specifications](https://www.kpqc.or.kr/contents/03_exhibit/sub_03.html)
- [GitHub-hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
