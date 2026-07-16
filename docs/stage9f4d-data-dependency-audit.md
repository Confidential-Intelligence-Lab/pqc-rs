# Stage 9F-4D: Source-to-Assembly Data-Dependency Audit

This stage converts Stage 9F-4C machine-code findings into a version-controlled
instruction classification ledger.

Run:

```bash
./scripts/run-stage9f4d-classification.sh
```

The authoritative record is:

```text
audit/stage9f4d/instruction-classification.csv
```

For every instruction, complete:

- source file and source line;
- dependency class;
- classification;
- rationale;
- reviewer;
- status.

Validate with:

```bash
./scripts/validate-stage9f4d-classification.sh
```

Exit codes:

- 0: all records accepted or closed;
- 1: ordinary open/provisional records remain;
- 2: unresolved secret-dependent branch findings remain.

The initializer applies only conservative provisional defaults:
challenge-support branches are marked transcript-derived, rounding `csel`
instructions are marked secret-coefficient constant-time selects, and all
other findings remain open for manual review.
