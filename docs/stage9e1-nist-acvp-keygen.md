# Stage 9E-1: NIST ACVP ML-DSA keyGen

This stage performs an exact byte-for-byte differential comparison against the
sample ML-DSA keyGen vectors in the official NIST ACVP-Server repository.
The fetch script pins the repository commit in `SOURCE.txt`.

Run:

```bash
python3 scripts/patch-stage9e1-mldsa-keygen.py
./scripts/run-stage9e1-mldsa-keygen.sh
```

Expected result: 75 generated cases, 75 exact matches, 0 mismatches.
Passing these sample vectors is external interoperability evidence, not a formal
ACVP certificate.
