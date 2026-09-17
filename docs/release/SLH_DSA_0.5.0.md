# pqc-rs-slh-dsa 0.5.0 release candidate

`pqc-rs-slh-dsa` `0.5.0` is the hardened FIPS 205 SLH-DSA release line for
PQC-rs.

The release advances beyond the previously published `0.4.0` line with a
completed public API, HashSLH-DSA support, expanded validation and
interoperability evidence, assurance closure, and reproducible performance
characterization.

## Version boundary

Version `0.5.0` establishes a new pre-1.0 API boundary.

The published `0.4.0` API exposed `SlhDsaError::NotImplemented`. The hardened
implementation removes that public enum variant because the supported
operations are now implemented. Downstream exhaustive matches may therefore
require source changes.

## Standards and functionality

The crate implements all twelve FIPS 205 SLH-DSA parameter sets:

- SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f;
- SLH-DSA-SHA2-192s and SLH-DSA-SHA2-192f;
- SLH-DSA-SHA2-256s and SLH-DSA-SHA2-256f;
- SLH-DSA-SHAKE-128s and SLH-DSA-SHAKE-128f;
- SLH-DSA-SHAKE-192s and SLH-DSA-SHAKE-192f;
- SLH-DSA-SHAKE-256s and SLH-DSA-SHAKE-256f.

The public API supports:

- random and deterministic key generation;
- deterministic and hedged Pure SLH-DSA signing;
- Pure SLH-DSA verification;
- deterministic and hedged HashSLH-DSA signing;
- HashSLH-DSA verification;
- all twelve standardized HashSLH prehash choices;
- parameter-bound key, seed, and signature types;
- the common PQC-rs `SignatureScheme` interface.

## Validation evidence

The release-candidate evidence includes NIST ACVP FIPS 205 validation across
the supported operation families and parameter sets.

Recorded evidence includes:

- HashSLH-DSA SigGen: 288/288 cases passed, including 144 deterministic and
  144 hedged cases;
- HashSLH-DSA SigVer: 168/168 cases matched, including valid and invalid
  signatures;
- all-set adversarial and malformed-input validation;
- deterministic/reference checks and parameter-set mismatch coverage.

See `compliance/standards/fips205.toml` for the normative mapping and recorded
validation evidence.

## Interoperability

Independent-provider evidence includes PQC-rs/liboqs interoperability:

- Pure SLH-DSA: 24/24 directed cases across all twelve FIPS 205 parameter
  sets;
- representative HashSLH-DSA: 24/24 directed cases.

The interoperability evidence distinguishes exact deterministic comparisons
from semantic cross-provider validation where provider APIs expose different
controls.

## Assurance scope

The SLH-DSA assurance work package includes:

- secret-lifetime and zeroization review;
- source and machine-code secret-dependency review;
- timing-leakage screening;
- bounded Miri and AddressSanitizer campaigns;
- structured verification fuzzing;
- stack and heap characterization;
- bounded memory-behavior analysis;
- reproducible performance baselines.

Representative recorded results include:

- maximum observed timing statistic |t| = 1.4629, below the documented
  investigation threshold;
- 20,886 fuzz executions in the recorded bounded campaign with zero crashes;
- 85 selected Miri tests passing;
- measured peak live heap up to 99,864 bytes for Pure deterministic signing
  and 99,879 bytes for HashSLH deterministic signing;
- 60 Criterion measurements covering twelve parameter sets and five public
  operation classes.

The evidence is recorded under `audit/slh-dsa-s6/` and
`audit/slh-dsa-s7/`.

UBSan was not executed for this work package and is not claimed as release
evidence.

These activities provide engineering assurance. They do not constitute formal
verification, FIPS validation, Common Criteria certification, an independent
security audit, or a universal constant-time guarantee.

## Installation

```toml
[dependencies]
pqc-rs-slh-dsa = "0.5.0"
rand_core = { version = "0.6", features = ["getrandom"] }
The Rust library name is pqc_slh_dsa.

Release provenance

This document describes the release candidate before registry publication.

Source commit, crate-specific tag, crates.io checksum, archive size, publication
date, and yank status must be recorded only after the final release candidate
passes all release gates and the registry publication is independently
verified.
