# SMAUG-T 1.1.1 Experimental Assurance Evidence

## 1. Scope

This ledger records implementation, differential-validation,
adversarial-testing, and fuzzing evidence for the experimental native
Rust SMAUG-T 1.1.1 KEM in `pqc-rs-smaug-t`.

It is an evidence inventory, not a security certification or a claim
of production readiness.

## 2. Reference provenance

- Algorithm: SMAUG-T 1.1.1
- Upstream reference commit:
  `bbc463cd788eae36c6d155cef667ac9dbd9054cd`
- Evaluated modes: `SMAUG_T128`, `SMAUG_T192`,
  `SMAUG_T256`, and `TIMER`
- Gaussian discrepancy:
  [GAUSSIAN_REFERENCE_DISCREPANCY.md](GAUSSIAN_REFERENCE_DISCREPANCY.md)
- Gaussian assurance:
  [GAUSSIAN_ASSURANCE.md](GAUSSIAN_ASSURANCE.md)

The corrected C oracle is distinct from the original pinned
upstream reference. Differential agreement with the corrected oracle
must not be described as proof of normative specification conformity.

## 3. Evidence matrix

| ID | Assurance dimension | Status | Evidence |
| --- | --- | --- | --- |
| E01 | Rust unit tests | Previously observed PASS | 72 tests passing |
| E02 | C-reference differential validation | Previously observed PASS | 28 oracle binaries across four modes |
| E03 | Secret-key corruption testing | Previously observed PASS | 37,632 cases |
| E04 | Single-bit ciphertext mutation testing | Previously observed PASS | 29,184 cases |
| E05 | KEM structured fuzzing | PASS | Four paired campaigns, 10,000 executions each |
| E06 | Gaussian reference discrepancy | Documented | Dedicated discrepancy and assurance records |
| E07 | Formatting and lint checks | Previously observed PASS | Nightly formatting and Clippy checks |
| E08 | Complete validation-script rerun | PASS | End-to-end validation completed; `SMAUGT_REFERENCE_VALIDATION=PASS` |
| E09 | Normative SMAUG-T conformity | Open | Independent specification-level verification required |
| E10 | Full constant-time assurance | Open | Compiled-code and side-channel validation required |
| E11 | Production security review | Not performed | Experimental implementation |

Statuses distinguish observed evidence from unverified or outstanding
assurance obligations.

## 4. Structured fuzzing methodology

The KEM harnesses support three configurations:

- Default: existing raw and structured inputs.
- `structured-only`: normalized ten-byte `SMTF` descriptor.
- `structured-fields`: six-byte mutation-field representation.

The two experimental structured features are mutually exclusive.

### Matched-corpus experiment

The starting corpora contained:

| Target | Matched semantic seeds |
| --- | ---: |
| KEM decapsulation | 393 |
| KEM encapsulation | 386 |

Each mode used the same semantic starting descriptors, seed
`20261024`, and 10,000 executions per target.

| Target | Configuration | Executions/s | Coverage counter | Feature counter | Peak RSS |
| --- | --- | ---: | ---: | ---: | ---: |
| Decapsulation | Normalized | 114 | 4920 | 11063 | 414 MB |
| Decapsulation | Six-byte fields | 93 | 4917 | 11060 | 425 MB |
| Encapsulation | Normalized | 117 | 4795 | 9456 | 420 MB |
| Encapsulation | Six-byte fields | 102 | 4792 | 9453 | 426 MB |

All four campaigns completed without reported crashes or assertion
failures.

Coverage and feature counters from separately instrumented binaries
are not strictly equivalent measures of cryptographic code coverage.
The throughput differences are observations from one paired experiment,
not a statistically established performance ranking.

Decision: retain `structured-only` as the preferred structured
fuzzing configuration. Preserve `structured-fields` for experimental
reproducibility, without promoting it to the default.

### Evidence locations

- Matched seed corpora:
  `/tmp/smaugt_s5_5b_4f_matched/`
- Working experiment corpora:
  `/tmp/smaugt_s5_5b_4f_experiment/`
- Campaign logs:
  `/tmp/smaugt_s5_5b_4f_<mode>_<target>.log`
- Earlier post-fuzzing corpus snapshot:
  `/tmp/smaugt_structured_snapshot/`

These paths are local, temporary evidence locations. They are not
durable repository artifacts and may not exist on another machine.

## 5. Outstanding assurance obligations

1. Preserve the completed end-to-end reference-validation evidence
   and rerun `scripts/validate-reference.sh` after subsequent
   implementation changes.
2. Verify algorithmic conformity independently against the normative
   SMAUG-T specification, especially the Gaussian sampler.
3. Audit secret-dependent control flow, memory access, and optimized
   machine code.
4. Review secret handling, zeroization, error semantics, and API
   misuse resistance.
5. Reconcile the assurance evidence with the final experimental
   integration and release decision.

## 6. Security interpretation

The available evidence supports substantial functional correctness,
reference parity, and adversarial robustness.

It does not establish complete constant-time execution, resistance
to physical side channels, formal security, or production readiness.
