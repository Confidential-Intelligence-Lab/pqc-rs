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

| Package | Purpose | Publication status |
|---|---|---|
| [`pqc-rs-core`](https://crates.io/crates/pqc-rs-core) | Common traits, byte wrappers, errors, and secret containers | Published (`0.4.0`) |
| [`pqc-rs-ml-kem`](https://crates.io/crates/pqc-rs-ml-kem) | ML-KEM implementation | Published (`0.4.0`) |
| [`pqc-rs-ml-dsa`](https://crates.io/crates/pqc-rs-ml-dsa) | ML-DSA implementation | Published (`0.4.0`) |
| [`pqc-rs-slh-dsa`](https://crates.io/crates/pqc-rs-slh-dsa) | FIPS 205 SLH-DSA implementation | Published (`0.4.0`) |
| [`pqc-rs-hpke`](https://crates.io/crates/pqc-rs-hpke) | HPKE and post-quantum KEM integration | Published (`0.4.0`) |
| `pqc-rs-hybrid` | Experimental hybrid composition support | Experimental; not published |
| `pqc-rs-test-harness` | ACVP, protocol-vector, and validation tooling | Internal; not published |

The pre-1.0 APIs and publication boundaries may change before version 1.0.

## Installation

Add only the crates required by your application:

```toml
[dependencies]
pqc-rs-core = "0.4.0"
pqc-rs-ml-kem = "0.4.0"
pqc-rs-ml-dsa = "0.4.0"
pqc-rs-slh-dsa = "0.4.0"
pqc-rs-hpke = "0.4.0"
```

The corresponding Rust library names are `pqc_core`, `pqc_ml_kem`,
`pqc_ml_dsa`, `pqc_slh_dsa`, and `pqc_hpke`. These are pre-1.0 packages and should be
evaluated under the security limitations stated above.

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
