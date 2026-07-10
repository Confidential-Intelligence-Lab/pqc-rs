# Stage 5B-10: FIPS 203 Conformance Gate

## Purpose

Stage 5B-10 establishes a formal distinction between:

- structural validation,
- internal deterministic validation,
- official known-answer-test validation,
- full FIPS 203 conformance.

The repository does not currently claim FIPS 203 conformance.

## Added

- `pqc_ml_kem::conformance`
- component maturity manifest
- parameter-set conformance status
- KAT and intermediate-value record types
- deterministic validation result model
- negative tests for parameter-set length mismatches
- structural KAT schema and example manifest

## Current status

| Component | Status |
|---|---|
| Field arithmetic | Internally validated |
| FIPS NTT | Experimental |
| Matrix expansion | Structural |
| K-PKE keygen | Structural |
| K-PKE encrypt | Structural |
| K-PKE decrypt | Structural |
| ML-KEM CCA transform | Structural |
| Official KATs | Pending |

## Exit criteria

A parameter set may be marked `KatValidated` only after:

1. authoritative vectors are imported,
2. key generation matches,
3. encryption matches,
4. decryption matches,
5. encapsulation matches,
6. decapsulation matches,
7. malformed-input behavior is validated,
8. source and vector versions are documented.
