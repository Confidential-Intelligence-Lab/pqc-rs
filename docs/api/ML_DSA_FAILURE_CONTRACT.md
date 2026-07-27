# ML-DSA failure and misuse contract

The publication-facing `pqc-rs-ml-dsa` API rejects malformed or inconsistent
inputs through `MlDsaError`. Invalid caller-controlled data must not terminate
the process through a panic.

## Typed failure behavior

- Wrong-length or non-canonical public keys return `InvalidPublicKey`.
- Wrong-length or non-canonical private keys return `InvalidPrivateKey`.
- Wrong-length or non-canonical signatures return `InvalidSignature`.
- Contexts longer than the FIPS 204 limit of 255 bytes return
  `ContextTooLong`.
- Keys or signatures bound to a different parameter set return
  `ParameterSetMismatch`.
- Failure of caller-supplied randomness returns `RandomnessFailure`.
- Exhaustion of the bounded signing rejection loop returns
  `RejectionLimitExceeded`.
- Failures of implementation invariants return `InternalError`.

A well-formed signature that does not authenticate the supplied message,
context, key, or prehash returns `Ok(false)`.

## Panic-free implementation rule

Non-test ML-DSA source must not use `panic!`, `unwrap`, `expect`, `todo!`,
`unimplemented!`, or `unreachable!`. Fallible arithmetic, conversions, nonce
allocation, decoding, randomness, and rejection limits must propagate an
explicit error.

Assertions and convenience unwrapping remain permitted in tests and rustdoc
examples, where a failure is itself test evidence rather than a
caller-triggerable process termination.

## Enforcement

`scripts/check-ml-dsa-failure-contract.sh` statically checks the production
source and runs the dedicated downstream misuse suite. The suite covers every
parameter set, malformed object lengths, oversized contexts, parameter-set
mismatches, and failing random-number generators. The ordinary API, internal
assurance, package, fuzzing, and workspace regression gates remain required.
