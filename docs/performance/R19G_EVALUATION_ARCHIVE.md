# R19G Evaluation Archive

## Evaluated source

Commit: `53422e126552f352acd0d6d61ec588a7bde8cc51`

The evaluation source is frozen at this revision. This archival
commit introduces documentation only.

## Evaluation coverage

| Family | Cases | Runs | Timing samples |
|---|---:|---:|---:|
| ML-KEM | 36 | 216 | 21,600 |
| ML-DSA | 36 | 216 | 21,600 |
| SLH-DSA | 108 | 648 | 64,800 |
| Total | 180 | 1,080 | 108,000 |

Six independent runs per case, with 100 timing samples per run.

## Evidence archive

Archive filename: `r19g-evaluation-evidence.tar.gz`

SHA-256: `f359d130af291d1c4bb2d492729842691cff738b4c29152f0c6d25a2a0acf781`

The archive is maintained separately from the source repository.
Its filename and digest identify the evaluated evidence artifact.

## Validation

- Archive gzip integrity: PASS
- Campaign matrix reconciliation: PASS
- Expected cases: 180
- Observed cases: 180
- Missing cases: 0
- Unexpected cases: 0
- Incomplete cases: 0
- Measurement JSON files: 1,080
- Timing samples: 108,000
- Internal checksum entries verified: 507
- Missing checksum targets: 0
- Checksum mismatches: 0
- Measurement contract source revision: matches evaluated source

## Metadata qualification

The archived `database/campaign_summary.json` retains its
initialization state (`completed_cases: 0`, `status: initialized`).

The finalized evaluation coverage is established independently
through case-level reconciliation of the campaign matrix and
measurement files.

The original evidence archive has not been modified.

## Measurement considerations

Measurement boundaries B1-P and B1-A must remain distinct.

Provider comparisons must preserve algorithm, parameter set,
operation, measurement boundary, and relevant execution settings.

## R20 baseline

R20 optimization experiments use the evaluated source revision
above as the frozen baseline.

Optimization results must be compared under equivalent measurement
conditions and validated for correctness, conformance, portability,
and security properties.
