# pqc-rs-slh-dsa

A Rust implementation of the NIST Stateless Hash-Based Digital Signature
Standard, **SLH-DSA**, specified in
[NIST FIPS 205](https://doi.org/10.6028/NIST.FIPS.205).

The crate is part of the
[`pqc-rs`](https://github.com/Confidential-Intelligence-Lab/pqc-rs)
workspace.

## Status

The crate implements all twelve SLH-DSA parameter sets standardized by
FIPS 205:

| SHA-2 | SHAKE |
|---|---|
| SLH-DSA-SHA2-128s | SLH-DSA-SHAKE-128s |
| SLH-DSA-SHA2-128f | SLH-DSA-SHAKE-128f |
| SLH-DSA-SHA2-192s | SLH-DSA-SHAKE-192s |
| SLH-DSA-SHA2-192f | SLH-DSA-SHAKE-192f |
| SLH-DSA-SHA2-256s | SLH-DSA-SHAKE-256s |
| SLH-DSA-SHA2-256f | SLH-DSA-SHAKE-256f |

Implemented operations include:

- cryptographic key generation;
- deterministic key generation from a caller-supplied FIPS 205 seed;
- deterministic Pure SLH-DSA signing;
- hedged Pure SLH-DSA signing;
- Pure SLH-DSA signature verification;
- typed import and export of keys and signatures;
- feature-gated internal interfaces for validation tooling.

## Example

```rust
use pqc_slh_dsa::{SlhDsa, SlhDsaParameterSet};
use rand_core::OsRng;

let slh_dsa = SlhDsa::new(SlhDsaParameterSet::Shake128f);
let key_pair = slh_dsa.keygen(&mut OsRng)?;

let message = b"post-quantum signatures";
let context = b"pqc-rs example";

let signature = slh_dsa.sign_hedged(
    key_pair.private_key(),
    message,
    context,
    &mut OsRng,
)?;

assert!(slh_dsa.verify(
    key_pair.public_key(),
    message,
    context,
    &signature,
)?);

# Ok::<(), pqc_slh_dsa::SlhDsaError>(())
```

For reproducible provising or validation, use
`SlhDsaKeyGenSeed::from_bytes` together with `SlhDsa::keygen_from_seed`.

## API design

The public API uses parameter-bound objects:

- `SlhDsaKeyGenSeed`
- `SlhDsaPublicKey`
- `SlhDsaPrivateKey`
- `SlhDsaSignature`
- `SlhDsaKeyPair`

Each object records its SLH-DSA parameter set. Operations reject objects
bound to a different parameter set, reducing accidental cross-parameter
misuse.

Private keys and key-generation seeds use protected ownership through the
shared `pqc-rs-core` secret container.

## Features

The crate has no default features.

| Feature | Purpose |
|---|---|
| `acvp` | Enables shared ACVP-related support in `pqc-rs-core`. |
| `bench` | Enables benchmark-related support. |
| `internal-api` | Exposes low-level and internal validation interfaces. This feature is unstable and is not part of the supported application-facing API. |

Ordinary applications should not enable `internal-api`.

## Validation

The implementation has been tested against pinned NIST ACVP sample vectors:

| Operation | Result |
|---|---:|
| KeyGen | 120 / 120 |
| External Pure SigGen | 168 / 168 |
| External Pure SigVer | 168 / 168 |

The crate also contains unit tests covering address encoding, hash
instantiation, WOTS+, XMSS, FORS, hypertree composition, key generation,
deterministic and hedged signing, verification, malformed inputs, and
interface separation.

These results are implementation-validation evidence. They do not constitute
CMVP validation, FIPS 140 validation, certification, or an independent
security audit.

## Security status

This crate is intended for research, evaluation, interoperability testing,
and continued engineering toward production use.

Before deploying it in a security-critical environment, users should perform
an independent review appropriate to their threat model and deployment
requirements.

The crate forbids unsafe Rust.

## Minimum supported Rust version

Rust 1.80 or later.

## License

MIT.
