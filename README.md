# PQC-rs

**Standards-focused post-quantum cryptography in Rust**

PQC-rs is a Rust workspace for post-quantum cryptography and post-quantum key establishment, with an emphasis on correctness, interoperability, explicit secret handling, reproducible validation, and production-oriented engineering.

> **Security status:** experimental, pre-audit software. Do not use this release to protect production secrets without an independent security review and an application-specific risk assessment.

## Current scope

| Component | Status |
|---|---|
| ML-KEM-512 | Implemented and ACVP-vector tested |
| ML-KEM-768 | Implemented and ACVP-vector tested |
| ML-KEM-1024 | Implemented and ACVP-vector tested |
| RFC 9180 HPKE foundation | Implemented |
| Pure ML-KEM HPKE Base mode | Pinned vector suite passing |
| PQ/traditional hybrid HPKE Base mode | Pinned vector suite passing |
| ML-DSA | Planned |
| SLH-DSA | Planned |
| HPKE PSK/Auth/AuthPSK modes | Planned |
| JOSE/COSE, TLS, X.509, PKCS/CMS | Planned |

## Design principles

1. **Standards first** — implement against NIST and IETF specifications.
2. **Correctness before optimization** — establish conformance before tuning.
3. **Explicit secret handling** — minimize accidental copying, formatting, and disclosure.
4. **Reproducible validation** — preserve deterministic test and benchmark evidence.
5. **Production-oriented engineering** — fuzzing, sanitizers, dependency policy, and release gates.

## Workspace

| Package | Purpose | Release status |
|---|---|---|
| `pqc-rs-core` | Common traits, byte wrappers, errors, and zeroizing secret containers | Release candidate |
| `pqc-rs-ml-kem` | ML-KEM implementation | Release candidate |
| `pqc-rs-hpke` | HPKE with pure-PQ and hybrid ML-KEM adapters | Release candidate |
| `pqc-rs-hybrid` | Experimental hybrid composition support | Not published |
| `pqc-rs-test-harness` | ACVP and protocol-vector tooling | Not published |
| `pqc-rs-ml-dsa` | ML-DSA work area | Not published |
| `pqc-rs-slh-dsa` | SLH-DSA work area | Not published |

The source directories retain their original names, while published package names use the `pqc-rs-*` namespace.

## Validation status

### ML-KEM ACVP

| Test | Result |
|---|---:|
| Key generation | 75 / 75 |
| Encapsulation | 75 / 75 |
| Decapsulation | 30 / 30 |
| Encapsulation and decapsulation key checks | 60 / 60 |

### HPKE

| Test suite | Result |
|---|---:|
| Pure ML-KEM Base mode | 105 / 105 |
| PQ/traditional hybrid Base mode | 102 / 102 |

The workspace also includes:

- negative HPKE protocol tests;
- structured libFuzzer targets;
- Miri checks;
- AddressSanitizer checks;
- Linux UndefinedBehaviorSanitizer checks;
- `cargo audit`;
- `cargo deny`;
- secret-lifetime and zeroization review;
- reproducible Criterion performance baselines;
- cryptographic object-size and release-binary-size reports.

These results provide implementation evidence. They are not a certification, formal proof, or independent security audit.

## Build and test

```bash
cargo fmt --all -- --check

cargo clippy \
  --workspace \
  --all-targets \
  --all-features \
  -- \
  -D warnings

cargo test --workspace --all-features
```

Dependency and advisory checks:

```bash
cargo deny check
cargo audit
```

## Conformance harnesses

```bash
cargo run -p pqc-rs-test-harness --bin ml-kem-acvp-keygen --release
cargo run -p pqc-rs-test-harness --bin ml-kem-acvp-encapsulation --release
cargo run -p pqc-rs-test-harness --bin ml-kem-acvp-decapsulation --release
cargo run -p pqc-rs-test-harness --bin ml-kem-acvp-key-check --release
cargo run -p pqc-rs-test-harness --bin hpke-pq-base-vectors --release
cargo run -p pqc-rs-test-harness --bin hpke-pq-hybrid-vectors --release
```

## Hardening and release gates

```bash
./scripts/run-security-baseline.sh
./scripts/run-fuzz-smoke.sh
./scripts/run-stage8c.sh
./scripts/run-stage8d.sh
./scripts/run-stage8e.sh
./scripts/run-stage8-release-gate.sh
```

## Performance baseline

Stage 8E records:

- ML-KEM KeyGen, Encaps, and Decaps;
- pure-PQ HPKE sender and receiver setup;
- 1 KiB `Seal` and `Open`;
- HPKE exporter performance;
- hybrid HPKE sender and receiver setup;
- object sizes;
- release executable sizes;
- toolchain and platform metadata.

Results are written under:

```text
target/stage8e/
target/criterion/
```

Performance data is platform-specific and must be reported together with the CPU, operating system, compiler, and build profile.

## Release status

The first public release candidate is:

```text
0.4.0-rc.1
```

Intended publication order:

1. `pqc-rs-core`
2. `pqc-rs-ml-kem`
3. `pqc-rs-hpke`

The test harness and incomplete algorithm crates remain unpublished.

## Roadmap

- ML-DSA / FIPS 204
- HPKE PSK, Auth, and AuthPSK modes
- SLH-DSA / FIPS 205
- DER, PEM, PKCS #8, and SubjectPublicKeyInfo
- X.509 and CMS
- JOSE and COSE
- TLS integration

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

Cryptographic changes must include:

- a specification reference;
- deterministic tests;
- malformed-input tests where applicable;
- conformance evidence;
- secret-dependent branch and indexing analysis;
- zeroization and formatting review.

## Security

See [SECURITY.md](SECURITY.md) for the security policy and responsible disclosure process.

## License

Licensed under either:

- Apache License, Version 2.0
- MIT License

at your option.
