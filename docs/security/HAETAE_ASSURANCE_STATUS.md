# HAETAE 1.2.0 — Assurance Status

## Scope

Experimental Rust HAETAE implementation supporting parameter sets
HAETAE-2, HAETAE-3, and HAETAE-5.

This document records implementation validation and known assurance
limitations. It is not an independent security certification.

## Validated implementation properties

- Native key generation, signing, and verification exercised.
- Authenticated C-reference parity exercised across all parameter sets.
- Signing rejection/retry behavior exercised against reference evidence.
- Malformed inputs and signature mutations tested.
- Secret-lifecycle cleanup tests exercised for relevant structures.
- Rust formatting and strict Clippy checks passed.

## Regression evidence

On 2026-11-02, the authenticated regression completed with:

- 214 library tests passing.
- 38 integration tests passing.
- Zero failed tests.
- Strict Clippy, formatting, and diff-integrity checks passing.

The complete regression is available through:

    bash scripts/run-haetae-regression.sh

Reference fixture directories must be supplied separately.
The default fixture base is:

    $HOME/Documents/uci_research/Prelim

Override it using HAETAE_FIXTURE_BASE.

## Secret-memory handling

The implementation applies source-level zeroization and
lifetime-based cleanup to selected secret-bearing structures,
including signing seeds, decoded signing secrets, and secret-derived
intermediate polynomial/vector state.

Public verification matrices, signatures, and challenges do not
require secret zeroization.

## Outstanding assurance limitations

1. SHAKE/Keccak internal-state erasure has not been established.
2. Constant-time execution has not been established through a
   complete side-channel assessment.
3. Source-level zeroization does not prove physical memory erasure
   under every compiler and execution configuration.
4. The implementation has not undergone an independent security audit.
5. Authenticated reference parity does not by itself establish
   resistance to side-channel attacks.

## Integration decision

Functional regression: PASS.

Source-level secret-lifecycle hardening: implemented and regression-tested.

Independent security assurance: OPEN.

Production certification: NOT CLAIMED.
