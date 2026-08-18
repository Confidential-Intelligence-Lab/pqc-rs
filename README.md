# PQC-rs

**Standards-driven post-quantum cryptography in Rust**

PQC-rs is a Rust workspace for post-quantum cryptography and post-quantum key establishment. The project emphasizes standards traceability, interoperability, explicit secret handling, reproducible validation, and production-oriented engineering.

> **Project status:** pre-1.0 and not independently audited. The current code
> and validation evidence are suitable for research, evaluation, and integration
> testing. Do not rely on this project to protect production secrets without an
> independent security review and an application-specific risk assessment.

## Scope

The workspace implements the three finalized NIST post-quantum cryptography
standards together with protocol-composition and validation infrastructure:

- ML-KEM (FIPS 203);
- ML-DSA (FIPS 204);
- SLH-DSA (FIPS 205);
- HPKE with post-quantum KEM integration;
- post-quantum/traditional hybrid key establishment;
- ACVP-oriented validation, interoperability, fuzzing, side-channel regression
  testing, and release assurance.

RFC 9958 is used as an informational engineering guide. Normative conformance claims are traced separately to the applicable FIPS, RFC, and future ISO/IEC specifications.

## Workspace

PQC-rs provides the cryptographic foundation. PQC-Forge builds on that
foundation to provide cryptographic-agility and negotiated secure-channel
infrastructure.

| Package | Purpose | Publication status |
|---|---|---|
| [`pqc-rs-core`](https://crates.io/crates/pqc-rs-core) | Common traits, byte wrappers, errors, and secret containers | Published (`0.4.0`) |
| [`pqc-rs-ml-kem`](https://crates.io/crates/pqc-rs-ml-kem) | FIPS 203 ML-KEM implementation | Published (`0.4.1`) |
| [`pqc-rs-ml-dsa`](https://crates.io/crates/pqc-rs-ml-dsa) | FIPS 204 ML-DSA implementation | Published (`0.4.0`) |
| [`pqc-rs-slh-dsa`](https://crates.io/crates/pqc-rs-slh-dsa) | FIPS 205 SLH-DSA implementation | Published (`0.4.0`) |
| [`pqc-rs-hpke`](https://crates.io/crates/pqc-rs-hpke) | HPKE with post-quantum and hybrid KEM integration | Published (`0.4.0`) |
| `pqc-rs-hybrid` | Support for PQ/traditional hybrid cryptographic composition | Publication-ready; not yet published |
| `pqc-rs-protocol` | Transport-independent protocol roles, framing, capability negotiation, policy binding, and session machinery | Publication-ready; not yet published |
| `pqc-rs-secure-channel` | PQC-Forge integration from validated negotiation evidence to bound HPKE secure channels | Publication-ready; not yet published |
| `pqc-rs-test-harness` | Conformance, vector, interoperability, and assurance support infrastructure | Publication-ready; not yet published |

The pre-1.0 APIs and publication boundaries may change before version 1.0.

## PQC-rs and PQC-Forge

**PQC-rs** is the cryptographic substrate: standardized post-quantum
algorithms, HPKE integration, hybrid composition support, secret-handling
types, validation tooling, and assurance infrastructure.

**PQC-Forge** is the cryptographic-agility architecture layered above those
primitives. It separates:

- capability advertisement and negotiation;
- local policy validation;
- negotiated evidence;
- cryptographic profile resolution;
- protocol-context binding;
- secure-channel activation;
- transport and application processing.

The intent is to keep protocol behavior independent of concrete cryptographic
implementations wherever possible.

The secure-channel path is:

    capability offer
        ->
    capability negotiation
        ->
    validated negotiation evidence
        ->
    cryptographic profile resolution
        ->
    secure-channel binding
        ->
    sender / receiver activation
        ->
    protected application traffic

Capability identifiers are opaque at the protocol layer. Concrete KEM, KDF,
and AEAD choices are resolved locally from closed implementation-defined
profiles rather than being accepted directly from the peer.

## Installation

Add only the crates required by your application.

Published cryptographic crates:

    [dependencies]
    pqc-rs-core = "0.4.0"
    pqc-rs-ml-kem = "0.4.1"
    pqc-rs-ml-dsa = "0.4.0"
    pqc-rs-slh-dsa = "0.4.0"
    pqc-rs-hpke = "0.4.0"

The corresponding Rust library names are `pqc_core`, `pqc_ml_kem`,
`pqc_ml_dsa`, `pqc_slh_dsa`, and `pqc_hpke`.

The protocol, hybrid, secure-channel, and test-harness crates are currently
prepared for publication but are not yet available from crates.io.

## Reference applications

The repository includes examples ranging from primitive composition to
negotiated networked secure channels.

| # | Application | Purpose |
|---|---|---|
| 01 | [01_mlkem_secure_channel.rs](crates/pqc-ml-kem/examples/01_mlkem_secure_channel.rs) | Educational composition of ML-KEM-768, HKDF-SHA-256, and ChaCha20-Poly1305 with associated-data binding and tamper detection. |
| 02 | [02_mldsa_document_signing.rs](crates/pqc-ml-dsa/examples/02_mldsa_document_signing.rs) | ML-DSA detached document authentication with context binding and rejection of modified documents and signatures. |
| 03 | [03_hpke_secure_messaging.rs](crates/pqc-hpke/examples/03_hpke_secure_messaging.rs) | ML-KEM HPKE Base-mode setup, ordered authenticated messaging, tamper rejection, and receiver-state preservation. |
| 04 | [04_hpke_crypto_agility.rs](crates/pqc-hpke/examples/04_hpke_crypto_agility.rs) | Policy-driven KEM/KDF/AEAD selection while reusing one messaging workflow. |
| 05 | [negotiated_tcp.rs](crates/pqc-secure-channel/examples/negotiated_tcp.rs) | PQC-Forge client/server capability negotiation, secure-channel activation, and protected request/response traffic over real loopback TCP. |

### Run the examples

Run these commands from the workspace root:

    cargo run -p pqc-rs-ml-kem --example 01_mlkem_secure_channel --all-features
    cargo run -p pqc-rs-ml-dsa --example 02_mldsa_document_signing --all-features
    cargo run -p pqc-rs-hpke --example 03_hpke_secure_messaging --all-features
    cargo run -p pqc-rs-hpke --example 04_hpke_crypto_agility --all-features
    cargo run -p pqc-rs-secure-channel --example negotiated_tcp

The first four examples execute locally within one process and focus on
cryptographic API composition.

The PQC-Forge `negotiated_tcp` example is different: client and server roles
execute in separate threads and communicate through a real loopback TCP
socket. They exchange serialized capability-handshake frames, establish
negotiated protocol state, activate HPKE contexts in both directions, and
exchange authenticated encrypted application data.

Conceptually:

    Client                                      Server
    ------                                      ------

    capability offer -------------------------->

                               validate offer against local policy
                               select registered capability

                        <---------------- capability selection

    establish context                           establish context
            |                                           |
            +----------- HPKE activation ---------------+
            |                                           |
    encrypted request -------------------------->

                        <--------------- encrypted response

The public example deliberately uses simple length-prefixed TCP records to
keep the workflow readable.

The evaluation suite goes further: it exercises the protocol framing and
transport abstractions over real loopback TCP, enforces small partial
transfers, and injects deterministic retryable `Pending` and `Interrupted`
events. These transport tests are distinct from the higher-level teaching
example.

## Registered secure-channel profiles

The current PQC-Forge secure-channel resolver includes complete profiles based
on:

- ML-KEM-768;
- ML-KEM-1024;
- ML-KEM-768 with ChaCha20-Poly1305;
- ML-KEM-768 + X25519 hybrid KEM.

The protocol layer negotiates capability identifiers. The secure-channel layer
maps validated identifiers to the concrete cryptographic suites.

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
