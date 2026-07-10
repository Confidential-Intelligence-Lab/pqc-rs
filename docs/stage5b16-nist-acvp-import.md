# Stage 5B-16: NIST ACVP Vector Import

## Purpose

Stage 5B-16 establishes a reproducible path from the repository to NIST's
authoritative FIPS 203 ML-KEM ACVP files.

## Added

- pinned NIST ACVP-Server provenance
- reproducible fetch script
- SHA-256 checksum generation
- strongly typed ML-KEM keyGen prompt parser
- strongly typed keyGen expected-results parser
- prompt/expected result joining by `tgId` and `tcId`
- metadata mismatch detection
- missing expected-result detection
- decoded `z`, `d`, `ek`, and `dk` byte records

## Pinned source

```text
https://github.com/usnistgov/ACVP-Server.git
RELEASE/v1.1.0.42
```

## Conformance boundary

The terms have distinct meanings:

1. **Imported**: authoritative files were fetched with recorded provenance.
2. **Parsed**: the repository accepted the ACVP schema.
3. **Executed**: the implementation ran the corresponding operation.
4. **Passed**: produced bytes matched NIST expected results.
5. **Conformant**: all required validation and process criteria were satisfied.

Stage 5B-16 reaches the import and parser levels only. It does not mark any
parameter set as KAT-validated.

## Next stage

Stage 5B-17 should adapt deterministic ML-KEM key generation to the ACVP `d` and
`z` inputs, execute the official keyGen cases, and report the first exact byte
mismatch without weakening the conformance gate.
