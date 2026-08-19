# PQC-rs

**Post-quantum cryptography and cryptographic agility in Rust**

PQC-rs is an open-source Rust implementation and research platform for
standards-based post-quantum cryptography.

The repository is organized into two project layers plus shared validation
and assurance infrastructure.

## Project architecture

### PQC-rs: cryptographic foundation

PQC-rs provides the cryptographic mechanisms used by the project:

- ML-KEM (FIPS 203);
- ML-DSA (FIPS 204);
- SLH-DSA (FIPS 205);
- HPKE with post-quantum KEM integration;
- post-quantum / traditional hybrid composition.

### PQC-Forge: cryptographic agility

PQC-Forge builds on PQC-rs to provide a common cryptographic-agility
architecture:

- capability negotiation;
- policy validation;
- validated negotiation evidence;
- local cryptographic profile resolution;
- binding of cryptographic operations to established protocol context;
- application-specific cryptographic realization.

The common protocol machinery is implemented by `pqc-rs-protocol`. Validated
protocol evidence is then consumed by application-specific integration layers.

Two concrete realizations are currently implemented:

- `pqc-rs-secure-channel` resolves negotiated capabilities into pure
  post-quantum or hybrid HPKE secure channels;
- `pqc-rs-authentication` resolves negotiated authentication capabilities into
  ML-DSA-65 challenge-response authentication.

These realizations share negotiation, policy, and protocol-state machinery
without requiring the authentication layer to depend on the secure-channel,
HPKE, or ML-KEM implementations.

### Validation and assurance

The repository also includes shared infrastructure for conformance testing,
interoperability, vector processing, fuzzing, timing analysis, reproducibility,
and release assurance.

> **Status:** PQC-rs is pre-1.0 and has not been independently audited.
> The project is intended for research, evaluation, interoperability work,
> and integration testing. Production use requires independent security
> review and application-specific risk assessment.

## Repository structure

    PQC-rs repository
    |
    +-- PQC-rs -- cryptographic foundation
    |   +-- pqc-rs-core
    |   +-- pqc-rs-ml-kem
    |   +-- pqc-rs-ml-dsa
    |   +-- pqc-rs-slh-dsa
    |   +-- pqc-rs-hybrid
    |   `-- pqc-rs-hpke
    |
    +-- PQC-Forge -- cryptographic-agility architecture
    |   +-- pqc-rs-protocol
    |   +-- pqc-rs-secure-channel
    |   `-- pqc-rs-authentication
    |
    `-- Validation and assurance
        `-- pqc-rs-test-harness

## Runtime architecture

PQC-Forge separates common negotiation and policy machinery from the
cryptographic operation performed after negotiation:

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
    protected application          authenticated possession of
    traffic                        the configured public key

The separation is intentional:

- **PQC-rs owns cryptographic mechanisms.**
- **PQC-Forge owns negotiation, policy, protocol-state establishment, and
  application-specific cryptographic integration.**
- **The common protocol layer does not resolve peer-controlled identifiers
  directly into arbitrary cryptographic parameters.**
- **Validated capabilities are resolved locally by the integration layer that
  consumes them.**
- **Different cryptographic applications can share protocol machinery without
  depending on one another.**

At the PQC-Forge protocol boundary, capability identifiers are opaque.
Validated capabilities are resolved locally into a closed set of
implementation-defined cryptographic profiles.

The secure-channel realization maps validated capabilities to HPKE profiles,
binds them to the established protocol context, activates sender and receiver
state, and protects application traffic.

The authentication realization maps a validated authentication capability to
ML-DSA-65, binds a verifier-issued challenge and application context to the
established protocol context, and verifies proof of possession of the public
key configured by the verifier. Pending challenges are single-use within the
verifier workflow.

Together, the two realizations demonstrate that cryptographic capabilities can
evolve behind common negotiation and policy boundaries without embedding
algorithm-selection logic throughout an application or coupling distinct
cryptographic applications to one another.

## Crates

| Crate | Layer | Purpose | Version |
|---|---|---|---|
| [`pqc-rs-core`](https://crates.io/crates/pqc-rs-core) | PQC-rs | Core traits, byte types, errors, and secret containers | `0.4.0` |
| [`pqc-rs-ml-kem`](https://crates.io/crates/pqc-rs-ml-kem) | PQC-rs | ML-KEM (FIPS 203) | `0.4.1` |
| [`pqc-rs-ml-dsa`](https://crates.io/crates/pqc-rs-ml-dsa) | PQC-rs | ML-DSA (FIPS 204) | `0.4.0` |
| [`pqc-rs-slh-dsa`](https://crates.io/crates/pqc-rs-slh-dsa) | PQC-rs | SLH-DSA (FIPS 205) | `0.4.0` |
| [`pqc-rs-hybrid`](https://crates.io/crates/pqc-rs-hybrid) | PQC-rs | PQ/traditional hybrid composition | `0.4.0` |
| [`pqc-rs-hpke`](https://crates.io/crates/pqc-rs-hpke) | PQC-rs | HPKE with post-quantum and hybrid KEM integration | `0.4.1` |
| [`pqc-rs-protocol`](https://crates.io/crates/pqc-rs-protocol) | PQC-Forge | Framing, negotiation, policy binding, and protocol state | `0.4.1` |
| [`pqc-rs-secure-channel`](https://crates.io/crates/pqc-rs-secure-channel) | PQC-Forge | Profile resolution, binding, and HPKE secure-channel activation | `0.4.0` |
| [`pqc-rs-authentication`](https://crates.io/crates/pqc-rs-authentication) | PQC-Forge | ML-DSA authentication-profile resolution and challenge-response proof workflow | `0.4.0` |
| [`pqc-rs-test-harness`](https://crates.io/crates/pqc-rs-test-harness) | Assurance | Conformance, interoperability, vector, and validation infrastructure | `0.4.0` |

All listed crates are published on crates.io. APIs remain pre-1.0 and may
change before version 1.0.

## Installation

Add only the crates required by your application.

PQC-rs cryptographic foundation:

    [dependencies]
    pqc-rs-core = "0.4.0"
    pqc-rs-ml-kem = "0.4.1"
    pqc-rs-ml-dsa = "0.4.0"
    pqc-rs-slh-dsa = "0.4.0"
    pqc-rs-hybrid = "0.4.0"
    pqc-rs-hpke = "0.4.1"

PQC-Forge:

    [dependencies]
    pqc-rs-protocol = "0.4.1"
    pqc-rs-secure-channel = "0.4.0"
    pqc-rs-authentication = "0.4.0"

Validation and assurance:

    [dev-dependencies]
    pqc-rs-test-harness = "0.4.0"

The Rust library names use underscores, for example `pqc_ml_kem`,
`pqc_hpke`, `pqc_protocol`, `pqc_secure_channel`, and
`pqc_authentication`.

## Quick start

### PQC-Forge secure-channel example

Run the negotiated client/server secure-channel realization:

    cargo run -p pqc-rs-secure-channel --example negotiated_tcp

It runs separate client and server roles over a real loopback TCP socket,
negotiates a cryptographic capability under local policy, resolves the
validated capability to an HPKE profile, activates secure channels, and
exchanges authenticated encrypted application data.

A successful run reports:

    negotiated secure channel over loopback TCP: pass
    selected capability: 0x0101
    request authenticated and decrypted: pass
    response authenticated and decrypted: pass

TCP is used by this example as a readable transport demonstration; transport
is separate from cryptographic profile resolution.

### PQC-Forge authentication example

Run the ML-DSA-65 challenge-response realization:

    cargo run -p pqc-rs-authentication --example challenge_response

The example negotiates the registered authentication capability, establishes
validated protocol context, resolves the capability to ML-DSA-65, issues a
fresh verifier challenge, generates a context-bound authentication proof, and
consumes the challenge during successful verification.

A successful run includes:

    negotiated capability: 0x0201
    resolved authentication profile: MlDsa65
    verifier issued fresh challenge
    prover generated ML-DSA-65 authentication proof
    authentication succeeded

The result demonstrates proof of possession of the public key configured by
the verifier. Mapping that key to a user, device, service, certificate, or
other identity is application policy and is outside this example.

### Cryptographic examples

The repository also includes focused examples for the PQC-rs cryptographic
foundation:

| Example | Purpose |
|---|---|
| [`01_mlkem_secure_channel.rs`](crates/pqc-ml-kem/examples/01_mlkem_secure_channel.rs) | ML-KEM-768 with symmetric channel composition and tamper detection |
| [`02_mldsa_document_signing.rs`](crates/pqc-ml-dsa/examples/02_mldsa_document_signing.rs) | ML-DSA document signing and verification |
| [`03_hpke_secure_messaging.rs`](crates/pqc-hpke/examples/03_hpke_secure_messaging.rs) | Post-quantum HPKE secure messaging |
| [`04_hpke_crypto_agility.rs`](crates/pqc-hpke/examples/04_hpke_crypto_agility.rs) | Policy-driven HPKE cryptographic agility |

Run them from the workspace root:

    cargo run -p pqc-rs-ml-kem --example 01_mlkem_secure_channel --all-features
    cargo run -p pqc-rs-ml-dsa --example 02_mldsa_document_signing --all-features
    cargo run -p pqc-rs-hpke --example 03_hpke_secure_messaging --all-features
    cargo run -p pqc-rs-hpke --example 04_hpke_crypto_agility --all-features

The evaluation suite goes beyond these teaching examples and exercises framed
transport, partial byte-stream progress, real loopback TCP, and deterministic
retryable `Pending` and `Interrupted` schedules.

## PQC-Forge secure-channel profiles

The current PQC-Forge secure-channel resolver includes complete profiles based
on:

- ML-KEM-768;
- ML-KEM-1024;
- ML-KEM-768 with ChaCha20-Poly1305;
- ML-KEM-768 + X25519 hybrid KEM.

The protocol layer negotiates capability identifiers. The secure-channel layer
maps validated identifiers to the concrete cryptographic suites.

## PQC-Forge authentication profiles

The current authentication resolver includes:

- ML-DSA-65 challenge-response authentication (`AUTH_ML_DSA_65`).

The authentication proof binds the established protocol context, negotiated
policy and capability, verifier-issued challenge, and application context into
a canonical transcript before ML-DSA signing.

Verifier-side pending challenges are consumed by a verification attempt. The
current workflow therefore provides a single-use challenge lifecycle within
one verifier instance without claiming a distributed replay database or
identity-management system.

## Runtime model: `std`, `alloc`, and portability

PQC-rs does not currently make one workspace-wide `no_std` claim.

Support is crate-specific:

- lower-level crates expose feature combinations involving `std` and/or
  `alloc`;
- `pqc-rs-core` provides allocation-gated types;
- `pqc-rs-ml-kem` exposes `std` and `alloc` feature paths;
- `pqc-rs-hybrid` and `pqc-rs-protocol` also expose `std`/`alloc` feature
  controls;
- the current `pqc-rs-secure-channel` integration is `std`-oriented.

Users targeting embedded or restricted environments should evaluate the
feature and allocation requirements of the individual crate/API they intend
to use.

## Evaluation and reproducibility

The PQC-Forge secure-channel evaluation covers:

- negotiated reference workflows;
- negative and mismatch behavior;
- controlled performance measurements;
- pure-PQ versus hybrid HPKE composition costs;
- real loopback TCP transport;
- deterministic partial-transfer behavior;
- retryable `Pending` and `Interrupted` transport schedules;
- reproducibility of the functional evaluation;
- deterministic derivation of paper-facing results;
- controlled cryptographic change-localization analysis.

The final evaluated implementation revision is:

    218f3a3165cc5355ce084b63ac69082cac1afa26

The canonical evaluation artifact inventory and SHA-256 digests are recorded
in:

    paper/evaluation/FINAL_EVALUATION_FREEZE.txt

The evaluation methodology is documented in:

    paper/evaluation/SECURE_CHANNEL_EVALUATION.md

The frozen artifact can be verified with:

    /bin/zsh paper/evaluation/scripts/freeze_evaluation_artifacts.zsh

The reproducible secure-channel demonstration can be run with:

    /bin/zsh paper/evaluation/scripts/reproduce_secure_channel_demo.zsh

Paper-facing E2/E3 tables and the HPKE-composition figure are derived from
frozen inputs using:

    python3 paper/evaluation/scripts/generate_paper_results.py

## Engineering principles

1. **Standards before claims** — map normative requirements to code, tests, and evidence.
2. **Correctness before optimization** — establish conformance and interoperability before architecture-specific tuning.
3. **Explicit secret handling** — minimize accidental copying, formatting, and disclosure.
4. **Reproducible assurance** — preserve machine-readable test, timing, compiler, and release evidence.
5. **Conservative security language** — distinguish testing and empirical evidence from formal proof, certification, and independent audit.

## Build and test

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Generate and validate the standards traceability report:

```bash
./scripts/install-a1-1.sh
python3 scripts/validate-a1-1.py
cargo xtask compliance --strict
```

Run the portable assurance campaign:

```bash
python3 scripts/validate-stage13.py
./scripts/run-stage13.sh portable
```

Generated evidence is written below `target/` and is not committed unless a release procedure explicitly requires it.

## Standards and compliance

The canonical standards matrix is maintained in `compliance/matrix.toml`. Generated reports link standards topics and requirements to implementation paths, tests, CI gates, and assurance evidence.

- [Standards documentation](docs/standards/README.md)
- [Traceability policy](docs/standards/TRACEABILITY.md)
- [RFC 9958 topic mapping](docs/standards/RFC9958.md)

The current traceability framework is intentionally conservative: a requirement is promoted from `mapped` to `implemented` or `verified` only when the corresponding machine-checkable evidence is present.

## Security and assurance

The project includes layered assurance infrastructure for:

- ACVP and known-answer validation;
- malformed-input and negative testing;
- fuzzing and interpreter/sanitizer-based checks;
- secret-lifetime and zeroization review;
- timing-leakage characterization and regression screening;
- generated-code inspection and compiler-diversity checks;
- SBOM generation, evidence checksums, and release-signing support.

These activities provide engineering evidence. They do **not** constitute a formal proof, FIPS validation, Common Criteria certification, or independent security audit.

See [SECURITY.md](SECURITY.md) for the disclosure policy and supported-version policy.

## Project documentation

- [Implementation matrix](docs/IMPLEMENTATION_MATRIX.md)
- [Documentation index](docs/README.md)
- [Roadmap](ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Governance](GOVERNANCE.md)
- [Support](SUPPORT.md)
- [Release process](RELEASE.md)
- [Changelog](CHANGELOG.md)
- [Citation metadata](CITATION.cff)

## Roadmap

The foundation track publishes ML-DSA, SLH-DSA, and reusable hybrid
composition before stabilizing the NIST-centered APIs at version 1.0.

Independent diversity tracks cover Classic McEliece and FrodoKEM under the
ISO/IEC and European-aligned roadmap, NIST's forthcoming FN-DSA and HQC
standards, and the Korean KpqC algorithms SMAUG-T, NTRU+, HAETAE, and AIMer.
Each future crate remains gated on a suitable normative specification,
authoritative vectors, interoperability, licensing review, and the project's
security and release-assurance requirements.

Architecture-specific high-performance engineering remains an explicit future workstream. It is deferred until the API and algorithm portfolio are sufficiently stable to avoid premature optimization and rework.

See [ROADMAP.md](ROADMAP.md) for the maintained plan.

## Contributing

Cryptographic changes require a specification reference, deterministic tests, malformed-input tests where applicable, conformance evidence, and review of secret-dependent control flow, indexing, formatting, and zeroization.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under the [MIT License](LICENSE).
