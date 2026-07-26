# pqc-rs-ml-dsa 0.4.0

`pqc-rs-ml-dsa` `0.4.0` is the first independently published ML-DSA crate in
the PQC-rs workspace. It was published after the original three-crate
`v0.4.0` workspace promotion and therefore has its own immutable source
provenance and crate-specific tag.

## Registry and source provenance

| Field | Value |
| --- | --- |
| Package | `pqc-rs-ml-dsa` |
| Version | `0.4.0` |
| Publication date | 2026-07-25 |
| Source commit | `98140a3422fbc212bd43d96992028d29c548714d` |
| Source tag | `pqc-rs-ml-dsa-v0.4.0` |
| Crates.io SHA-256 | `d7e2b207710f11adf90a4e4a5046e1c6f20ef0996463f034007d7e890ba752d3` |
| Archive size | 49,209 bytes |
| Packaged files | 50 |
| Yanked | No, when independently verified on 2026-07-25 |

The clean-source candidate was reconstructed independently twice. Its bytes
matched the downloaded crates.io archive and the checksum reported by the
registry. The registry-served package metadata and all-feature tests passed.

The crate-specific tag must always peel to the source commit above. Repository
documentation committed after publication does not alter or move that tag.

## Standards and functionality

The crate implements the FIPS 204 ML-DSA-44, ML-DSA-65, and ML-DSA-87
parameter sets. It supports Pure ML-DSA and HashML-DSA, deterministic and
hedged signing, contexts of up to 255 bytes, strict encoded-object decoding,
and the prehash algorithms approved by FIPS 204.

## Validation scope

Release evidence includes NIST ACVP coverage, negative and malformed-input
tests, structured fuzzing, secret-lifetime checks, timing characterization,
and bidirectional interoperability with liboqs for all three parameter sets.
It also includes Pure ML-DSA cross-verification and negative-verification
cases with a recorded OpenSSL 3.5-or-later provider.

These results are engineering evidence. They do not constitute a formal
proof, FIPS validation, Common Criteria certification, independent security
audit, or a universal constant-time claim.

## Installation

```toml
[dependencies]
pqc-rs-ml-dsa = "0.4.0"
rand_core = { version = "0.6", features = ["getrandom"] }
```

The Rust library name is `pqc_ml_dsa`. Version `0.4.0` is pre-1.0 and requires
the Rust standard library.

## Documentation correction

The immutable `0.4.0` archive contains a stale README statement saying that
crates.io publication is disabled and recommending only a path dependency.
That statement is incorrect; it does not affect the implementation or
registry provenance. The repository documentation corrects the installation
instructions. A separately validated documentation-only patch release may
correct the README displayed from a registry package without yanking or
replacing `0.4.0`.
