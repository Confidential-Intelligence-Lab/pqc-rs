# Stage 9E-2A

Apply and run:

```bash
python3 scripts/patch-stage9e2-mldsa-siggen.py
./scripts/run-stage9e2-mldsa-siggen.sh
```

Success requires zero mismatches for every ACVP group whose interface is
`external` and whose `preHash` value is `pure`. Other group families are
reported as skipped rather than silently reinterpreted.
