# Stage 10B-6A: Constant-Time Byte-Comparison Migration

Stage 10B-6 begins with a conservative migration of validation-oriented byte
comparisons in ML-KEM and ML-DSA.

## Safety model

The stage does not rewrite:

- public length comparisons;
- parameter-set selection;
- loop counters;
- structural dimension checks;
- ambiguous equality expressions.

It inventories all candidate comparison sites, classifies obvious public
structural checks, and rewrites only validation-shaped comparisons whose names
indicate ciphertext, challenge, commitment, signature, expected/computed
values, or authentication tags.

## Outputs

```text
audit/stage10b6/byte-comparison-inventory.csv
audit/stage10b6/applied-byte-comparison-migrations.csv
```

## Run

```bash
./scripts/run-stage10b6a-byte-comparison-migration.sh
```

The functional regression suite is the hard gate. Remaining open inventory
records are reviewed in subsequent Stage 10B-6 increments.
