# SLH-DSA Publication Audit

## Candidate

- Package: `pqc-rs-slh-dsa`
- Version: `0.4.0`
- Standard: NIST FIPS 205
- MSRV: Rust 1.80
- License: MIT

## Implementation status

- All 12 FIPS 205 parameter sets
- Key generation
- Deterministic Pure SLH-DSA signing
- Hedged Pure SLH-DSA signing
- Pure SLH-DSA verification
- Feature-gated internal validation interface
- No unsafe code

## Validation status

- Crate tests: 292 passed
- NIST ACVP sample KeyGen: 120/120
- NIST ACVP sample external Pure SigGen: 168/168
- NIST ACVP sample external Pure SigVer: 168/168
- Rustdoc with warnings denied: passed
- Cargo package inventory: passed

## Publication blockers

1. `publish = false`
2. Missing crate README
3. Missing `readme` and `documentation` package metadata
4. Stale crate-level documentation
5. Missing user-facing examples
6. Workspace documentation still describes SLH-DSA as planned/private
7. Release assurance language requires explicit certification boundaries

## Assurance boundary

The ACVP results are implementation-validation evidence against pinned
NIST sample vectors. They are not CMVP validation, FIPS 140 validation,
certification, or an independent security audit.
