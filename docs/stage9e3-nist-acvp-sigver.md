# Stage 9E-3: NIST ACVP ML-DSA sigVer — External Pure

This stage validates groups with:

- `testType = AFT`
- `signatureInterface = external`
- `preHash = pure`

Each case provides `pk`, `message`, `signature`, and `context`. The harness
returns `testPassed` and compares that boolean directly with NIST
`expectedResults.json`.

Malformed keys or signatures are mapped to `testPassed = false`; they are not
treated as harness errors.

Internal and prehash groups are counted and skipped explicitly.

Run:

```bash
python3 scripts/patch-stage9e3-mldsa-sigver.py
./scripts/run-stage9e3-mldsa-sigver.sh
```
