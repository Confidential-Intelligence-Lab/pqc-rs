# SLH-DSA S6 runtime and memory-safety audit

## Scope

This audit records the S6.3 runtime and memory-safety assurance evidence for
`pqc-rs-slh-dsa`.

The evidence is intentionally layered and bounded. It combines Rust's
unsafe-code prohibition with Miri, AddressSanitizer, and structured fuzzing.
These mechanisms are complementary and do not constitute a formal proof of
memory safety, cryptographic security, constant-time behavior, or absence of
side channels.

## Unsafe-code boundary

The SLH-DSA crate declares `#![forbid(unsafe_code)]`.

The implementation therefore permits no Rust `unsafe` blocks or functions
within the crate's compilation boundary. This is a source-language
restriction, not by itself a claim about dependencies or native code outside
the crate.

## Bounded Miri campaign

The dedicated runner is:

`scripts/run-slhdsa-s6-miri.sh`

The campaign uses strict-provenance and symbolic-alignment checking and
exercises 85 selected tests spanning:

- address representation and encoding;
- integer and byte conversions;
- message-digest parsing;
- WOTS structural, bounds, and malformed-input paths;
- FORS indexing, bounds, and malformed-input paths;
- XMSS tree arithmetic, bounds, and malformed-input paths;
- hypertree layer arithmetic, signature slicing, bounds, and validation.

The dedicated public CI job completed without Miri findings.

Computationally expensive full signing campaigns are intentionally outside
this bounded Miri claim.

Result: **PASS within the documented bounded Miri scope.**

## AddressSanitizer campaign

The dedicated runner is:

`scripts/run-slhdsa-s6-asan.sh`

The runner applies AddressSanitizer with frame pointers, leak detection,
halt-on-error behavior, and strict string checking to the bounded SLH-DSA
structural and malformed-input campaign.

The dedicated public CI job completed without AddressSanitizer findings.

A separate repository-wide AddressSanitizer job has exceeded its current
45-minute CI execution budget. That timeout is neither an SLH-DSA sanitizer
finding nor evidence that the complete workspace passed under ASan.

Result: **PASS within the dedicated bounded SLH-DSA ASan scope.**

## Structured fuzzing

The active target is:

`fuzz/fuzz_targets/slhdsa_verification.rs`

It exercises all twelve FIPS 205 parameter sets through two structured paths:

1. malformed-length and decoder robustness;
2. exact-length expansion reaching deep Pure SLH-DSA verification.

The initial local 60-second campaign executed 20,886 inputs with zero crashes
and zero panics.

A deterministic tracked bootstrap corpus covers both paths. SHA-named
coverage-derived libFuzzer inputs remain intentionally untracked.

Public Fuzz smoke run 35133540037 completed successfully after the
reproducible seed corpus was committed, validating both the fuzz-policy gate
and bounded fuzz execution.

HashSLH-DSA fuzzing, longer campaigns, and additional architectures remain
follow-on assurance opportunities outside this closure claim.

Result: **PASS within the documented structured-fuzzing scope.**

## UndefinedBehaviorSanitizer

Rust nightly does not expose LLVM UndefinedBehaviorSanitizer through the
repository's `-Zsanitizer` mechanism.

The compatibility workflow records this limitation but does not execute
UBSan. A successful workflow job must therefore not be interpreted as
successful UBSan analysis.

Result: **UNSUPPORTED / NOT EXECUTED.**

Miri remains the repository's executable undefined-behavior analysis gate.

## S6.3 closure

| Assurance layer | SLH-DSA scope | Result |
| --- | --- | --- |
| Rust unsafe-code boundary | crate source | `forbid(unsafe_code)` |
| Miri | 85 selected structural/bounds/malformed-input tests | PASS |
| AddressSanitizer | dedicated bounded SLH-DSA campaign | PASS |
| Structured fuzzing | all 12 sets; decoder + deep Pure verification | PASS |
| UBSan | unavailable through current Rust sanitizer interface | UNSUPPORTED |

S6.3 is closed as **PASS within the documented bounded claim**.

This closure does not claim that every SLH-DSA execution path has been
explored by every dynamic-analysis mechanism. It records reproducible,
independent runtime and memory-safety evidence with explicit tool and coverage
boundaries.
