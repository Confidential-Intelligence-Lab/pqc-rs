# PQC-rs

**Standards-driven post-quantum cryptography and crypto-agility in Rust**

PQC-rs is an open-source Rust stack for trustworthy and crypto-agile
post-quantum systems. It connects FIPS-standardized post-quantum cryptography
to validation evidence, independent-provider interoperability, protocol
composition, and applications—while keeping cryptographic implementations and
execution providers replaceable behind stable boundaries.

> **Status:** PQC-rs is pre-1.0 and has not been independently audited.
> It is intended for research, evaluation, interoperability work, and
> integration testing. Security-critical deployment requires independent
> review and application-specific risk assessment.

## Why PQC-rs?

Deploying post-quantum cryptography requires more than implementing new
algorithms. Implementations must track standards, produce reproducible
validation evidence, interoperate with independent providers, compose into
protocols, and remain changeable as algorithms, policies, and execution
platforms evolve.

PQC-rs develops these properties together:

| | Focus | Evidence in the repository |
|---|---|---|
| **Standards** | FIPS 203, FIPS 204, FIPS 205, RFC 9180, RFC 9958 | normative traceability, ACVP/vector validation, protocol transcripts |
| **Cryptography** | ML-KEM, ML-DSA, SLH-DSA | typed Rust APIs, deterministic and randomized interfaces, negative testing |
| **Interoperability** | independent providers | PQC-rs, OpenSSL, wolfSSL, liboqs, and AWS-LC integration/evaluation |
| **Assurance** | implementation and release evidence | secret-lifetime review, timing analysis, Miri, sanitizers, fuzzing, SBOM and reproducibility |
| **Agility** | algorithm, provider, policy, and execution substitution | PQC-Forge negotiation, resolution, binding, activation, and provider boundaries |
| **Applications** | usable cryptographic composition | HPKE, hybrid composition, secure channels, and authentication |

The goal is not merely to expose post-quantum primitives. It is to make the
path from **standard → implementation → evidence → interoperability → protocol
→ application** explicit and testable.

## Architecture

The repository has two complementary layers.

### PQC-rs — cryptographic foundation

PQC-rs implements the cryptographic mechanisms and composition primitives:

- **ML-KEM** — FIPS 203;
- **ML-DSA** — FIPS 204;
- **SLH-DSA** — FIPS 205;
- **HPKE** — RFC 9180 composition with post-quantum KEM integration;
- **hybrid cryptography** — post-quantum and traditional composition.

Standards are treated as engineering inputs rather than labels: normative
requirements are connected to implementation paths, tests, interoperability
evidence, and generated compliance reports.

### PQC-Forge — crypto-agility and integration

PQC-Forge builds above the primitive layer so cryptographic change does not
have to propagate throughout an application. It provides:

- capability negotiation and policy validation;
- validated negotiation evidence;
- local cryptographic profile resolution;
- protocol-context binding;
- cryptographic activation behind explicit integration boundaries.

Current realizations include negotiated post-quantum/hybrid HPKE secure
channels and ML-DSA challenge-response authentication.

The architectural objective is straightforward: applications consume stable
protocol and integration boundaries while algorithms, implementations,
providers, policies, and—where supported—execution substrates can change
behind them.

### Validation, interoperability, and assurance

The repository includes shared infrastructure for conformance testing,
independent-provider interoperability, vector processing, malformed-input
testing, fuzzing, timing analysis, memory-safety analysis, reproducibility,
and release assurance.

These mechanisms are used to preserve evidence alongside implementation
changes. They provide engineering assurance; they do **not** constitute formal
verification, FIPS validation, certification, or an independent security
audit.

## Runtime architecture

PQC-Forge separates negotiation and policy from the cryptographic operation
selected after negotiation:

```text
Application
    |
    v
pqc-rs-protocol
    |
    +-- capability negotiation
    +-- policy validation
    +-- validated negotiation evidence
    +-- established protocol context
    |
    +-------------------------------+
    |                               |
    v                               v
pqc-rs-secure-channel          pqc-rs-authentication
    |                               |
    +-- HPKE profile resolution     +-- ML-DSA profile resolution
    +-- context binding             +-- challenge binding
    +-- channel activation          +-- proof generation / verification
    |                               |
    v                               v
protected application          authenticated possession
traffic                        of the configured public key
```
Capability identifiers remain opaque at the common protocol boundary.
Application-specific integration layers resolve validated capabilities locally
into closed cryptographic profiles, bind operations to established protocol
context, and activate the selected mechanism.

This separation allows different cryptographic applications to share
negotiation, policy, and protocol-state machinery without embedding
algorithm-selection logic throughout the application or depending on one
another.

## Get started

All project crates are published on crates.io. APIs remain pre-1.0 and may
change before version 1.0.

| Crate | Layer | Purpose | Version |
|---|---|---|---|
| [`pqc-rs-core`](https://crates.io/crates/pqc-rs-core) | PQC-rs | Core traits, byte types, errors, and secret containers | `0.4.0` |
| [`pqc-rs-ml-kem`](https://crates.io/crates/pqc-rs-ml-kem) | PQC-rs | ML-KEM (FIPS 203) | `0.4.1` |
| [`pqc-rs-ml-dsa`](https://crates.io/crates/pqc-rs-ml-dsa) | PQC-rs | ML-DSA (FIPS 204) | `0.4.0` |
| [`pqc-rs-slh-dsa`](https://crates.io/crates/pqc-rs-slh-dsa) | PQC-rs | SLH-DSA (FIPS 205) | `0.4.0` |
| [`pqc-rs-hybrid`](https://crates.io/crates/pqc-rs-hybrid) | PQC-rs | PQ/traditional hybrid composition | `0.4.0` |
| [`pqc-rs-hpke`](https://crates.io/crates/pqc-rs-hpke) | PQC-rs | HPKE with post-quantum and hybrid KEM integration | `0.4.1` |
| [`pqc-rs-protocol`](https://crates.io/crates/pqc-rs-protocol) | PQC-Forge | Negotiation, policy binding, and protocol state | `0.4.1` |
| [`pqc-rs-secure-channel`](https://crates.io/crates/pqc-rs-secure-channel) | PQC-Forge | HPKE secure-channel resolution and activation | `0.4.0` |
| [`pqc-rs-authentication`](https://crates.io/crates/pqc-rs-authentication) | PQC-Forge | ML-DSA challenge-response authentication | `0.4.0` |
| [`pqc-rs-test-harness`](https://crates.io/crates/pqc-rs-test-harness) | Assurance | Conformance, interoperability, and validation infrastructure | `0.4.0` |

Add only the crates required by your application. For example:

```toml
[dependencies]
pqc-rs-ml-kem = "0.4.1"
pqc-rs-ml-dsa = "0.4.0"
pqc-rs-slh-dsa = "0.4.0"
pqc-rs-hpke = "0.4.1"
```
### Try the crypto-agile secure channel

Run the negotiated client/server realization over loopback TCP:

```bash
cargo run -p pqc-rs-secure-channel --example negotiated_tcp
```

The example negotiates a capability under local policy, resolves it to an HPKE
profile, binds it to established protocol context, activates sender and
receiver channels, and exchanges authenticated encrypted application data.

Focused primitive and composition examples are also available:

| Example | Demonstrates |
|---|---|
| [`01_mlkem_secure_channel.rs`](crates/pqc-ml-kem/examples/01_mlkem_secure_channel.rs) | ML-KEM-768 channel composition and tamper detection |
| [`02_mldsa_document_signing.rs`](crates/pqc-ml-dsa/examples/02_mldsa_document_signing.rs) | ML-DSA signing and verification |
| [`hashslh_signing.rs`](crates/pqc-slh-dsa/examples/hashslh_signing.rs) | HashSLH-DSA signing with a standardized prehash |
| [`03_hpke_secure_messaging.rs`](crates/pqc-hpke/examples/03_hpke_secure_messaging.rs) | Post-quantum HPKE secure messaging |
| [`04_hpke_crypto_agility.rs`](crates/pqc-hpke/examples/04_hpke_crypto_agility.rs) | Policy-driven HPKE crypto-agility |

## Standards and interoperability

PQC-rs treats standards conformance and independent-provider interoperability
as separate evidence dimensions.

The canonical standards matrix is maintained in
[`compliance/matrix.toml`](compliance/matrix.toml). Generated reports connect
standards topics and requirements to implementation paths, tests, CI gates,
and assurance evidence.

Current standards work includes:

- **FIPS 203** — ML-KEM;
- **FIPS 204** — ML-DSA;
- **FIPS 205** — SLH-DSA, including Pure SLH-DSA and HashSLH-DSA;
- **RFC 9180** — HPKE composition and transcript validation;
- **RFC 9958** — post-quantum cryptography engineering and integration guidance.

Validation includes NIST ACVP/vector evidence, deterministic/reference checks,
negative testing, and protocol transcript validation where applicable.

Independent-provider evaluation spans **PQC-rs, OpenSSL, wolfSSL, liboqs, and
AWS-LC** across the algorithms and interfaces supported by each provider.
Evidence distinguishes byte-exact deterministic comparisons from semantic
cross-provider interoperability when public APIs do not expose equivalent
deterministic controls.

See:

- [standards documentation](docs/standards/README.md);
- [standards traceability policy](docs/standards/TRACEABILITY.md);
- [interoperability documentation](docs/interoperability/README.md);
- [implementation matrix](docs/IMPLEMENTATION_MATRIX.md).

## Assurance

PQC-rs preserves implementation evidence alongside the code rather than
treating assurance as a release-time afterthought. The repository includes
infrastructure for:

- ACVP, known-answer, malformed-input, and adversarial testing;
- secret-lifetime and zeroization review;
- constant-time engineering analysis and timing-leakage screening;
- Miri and AddressSanitizer campaigns;
- fuzzing and bounded memory-behavior analysis;
- stack and heap characterization;
- reproducible performance baselines;
- SBOM generation, evidence checksums, and release-signing support.

Assurance claims are deliberately bounded. These activities provide
engineering evidence; they do **not** constitute formal verification, FIPS
validation, Common Criteria certification, or an independent security audit.

See [SECURITY.md](SECURITY.md) for the disclosure and supported-version policy.

## Crypto-agility and evaluation

PQC-Forge makes cryptographic change an explicit systems concern. Negotiation,
policy, resolution, binding, and activation are separated so applications do
not need to scatter algorithm or provider choices throughout their code.

The evaluation infrastructure exercises:

- pure post-quantum and hybrid HPKE composition;
- negotiated secure-channel workflows;
- negative and mismatch behavior;
- real loopback TCP and partial byte-stream progress;
- deterministic retryable transport schedules;
- cryptographic change-localization;
- software-provider interoperability;

Reproducibility artifacts and methodology are maintained under
[`paper/evaluation/`](paper/evaluation/).

## Portability

PQC-rs does not make a workspace-wide `no_std` claim. Runtime requirements are
crate-specific: lower-level crates expose `std` and/or `alloc` feature paths,
while current application integrations such as `pqc-rs-secure-channel` are
`std`-oriented.

Users targeting embedded or restricted environments should evaluate the
feature and allocation requirements of the specific crate and API they intend
to use.

## Build and validate

The standard workspace checks are:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo xtask compliance --strict
```

Additional conformance, interoperability, dynamic-analysis, fuzzing, and
release-assurance workflows are documented in the repository and CI
configuration.

## Project

- [Documentation index](docs/README.md)
- [Roadmap](ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Governance](GOVERNANCE.md)
- [Support](SUPPORT.md)
- [Release process](RELEASE.md)
- [Changelog](CHANGELOG.md)
- [Citation metadata](CITATION.cff)

Cryptographic changes require specification references, deterministic and
negative tests where applicable, conformance evidence, and review of
secret-dependent control flow, indexing, formatting, and zeroization.

PQC-rs is licensed under the [MIT License](LICENSE).
