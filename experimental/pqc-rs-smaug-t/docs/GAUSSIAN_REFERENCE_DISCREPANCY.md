# SMAUG-T 1.1.1 Gaussian Reference Discrepancy

## Status

**Confirmed implementation discrepancy; specification conformity pending.**

The pinned SMAUG-T 1.1.1 C reference exhibits a destination-indexing
defect in the discrete Gaussian sampler's bit-plane loading function.

The experimental PQC-rs Rust implementation preserves all four
64-coefficient groups. It agrees exactly with an experimentally
corrected C implementation across the tested inputs.

This does not establish an exploitable vulnerability or independent
conformity with the normative SMAUG-T specification.

## Reference provenance

- Project: SMAUG-T
- Reference version: 1.1.1
- Pinned upstream commit:
  `bbc463cd788eae36c6d155cef667ac9dbd9054cd`
- Affected source: `reference_implementation/src/dg.c`
- Affected function: `load64_littleendian`
- Calling function: `d_gaussian_poly`
- Rust implementation: `src/gaussian.rs`

## Observed indexing defect

The reference expands a 33-byte seed using SHAKE256 into 320 bytes.

These bytes represent 40 interleaved 64-bit words: ten bit planes
for each of four groups of 64 polynomial coefficients.

Within `load64_littleendian`, the outer loop advances the input
position by 80 bytes, but the output destination uses only the
inner-loop counter.

Original destination:

    out[j] = /* little-endian word */;

Experimentally corrected destination:

    out[i * 10 + j] = /* little-endian word */;

The original implementation repeatedly overwrites the first ten
words. After four iterations, those words contain the last input
group, while the remaining 30 words retain their initial zeros.

The Gaussian Boolean circuit subsequently consumes all 40 words.

## Observed effect

For the tested inputs and configurations, the pinned C reference
produces Gaussian polynomials whose coefficients 64 through 255
are zero. Only coefficients 0 through 63 can be nonzero.

This changes the output distribution relative to the corrected
four-group interpretation.

The security consequences have not been quantified. No claim of
a practical attack or exploitable vulnerability is made.

## Differential validation

The validation harness maintains two separate contracts:

1. **Original reference:** Build the unmodified pinned C source
   and verify the observed overwrite behavior.
2. **Corrected-reference experiment:** Create a temporary copy
   of `dg.c`, correct exactly one destination-index expression,
   and compare its output with the Rust implementation.

The corrected C source is generated in a temporary build directory.
The pinned upstream source is never modified.

### Tested configurations

- `SMAUGT_MODE1`
- `SMAUGT_MODE3`
- `SMAUGT_MODE5`
- `SMAUGT_MODET`

### Tested seed patterns

- All-zero bytes
- All-0xFF bytes
- Incrementing bytes

### Validation results

| Validation | Result |
| --- | --- |
| Original-reference overwrite regression | PASS |
| Corrected polynomial differential parity | 3,072 / 3,072 |
| Corrected vector differential parity | 8,448 / 8,448 |
| Total corrected-reference comparisons | 11,520 / 11,520 |
| Rust unit tests | 29 passed |
| Full reference validation | PASS |
| Formatting, Clippy, documentation tests | PASS |

The original-reference regression is intentionally ignored during
the general corrected-reference test invocation and executed
separately against the unmodified reference oracle.

## Reproduction

From the PQC-rs repository root, with the pinned reference available:

    REF="$HOME/Documents/uci_research/Prelim/smaug-t-reference/extracted/SMAUG-T-1.1.1/reference_implementation"

    bash experimental/pqc-rs-smaug-t/scripts/validate-reference.sh "$REF"

Expected final marker:

    SMAUGT_REFERENCE_VALIDATION=PASS

The harness builds 28 reference oracles, including original and
experimentally corrected Gaussian variants.

## Interpretation and limitations

The 11,520 matching coefficients establish exact differential
agreement for the tested inputs. They do not constitute exhaustive
verification.

The corrected C implementation is an experimental diagnostic oracle,
not an independently certified or authoritative reference.

The Rust implementation has not completed constant-time assurance.

The normative specification must be checked independently before
declaring the corrected interpretation specification-conformant.

## Remaining assurance gates

- [ ] Verify the Gaussian algorithm against the normative SMAUG-T specification.
- [ ] Check whether upstream has corrected or documented the discrepancy.
- [ ] Review the Rust sampler for secret-dependent control flow and memory access.
- [ ] Complete constant-time hardening and associated validation.
- [ ] Expand deterministic and randomized differential coverage.
- [ ] Assess cryptographic implications of the original output distribution.
- [ ] Complete integration-level validation before production use.

## Engineering decision

Preserve the Rust four-group implementation while pursuing
independent specification evidence.

Retain the original-reference regression as a permanent record
of the observed discrepancy.

Do not introduce the pinned C reference's overwrite behavior
into the Rust sampler.
