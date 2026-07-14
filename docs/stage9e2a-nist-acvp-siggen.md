# Stage 9E-2A: NIST ACVP ML-DSA sigGen — External Pure Interface

The NIST sigGen vector set covers multiple interfaces:

- internal interface with module-computed `mu`;
- internal interface with externally supplied `mu`;
- external pure ML-DSA;
- external prehash ML-DSA.

The current PQC-rs API directly implements the final FIPS 204 external pure
interface. This stage therefore validates only groups with:

```text
signatureInterface = external
preHash = pure
testType = AFT
```

Both deterministic and nondeterministic groups are supported. Deterministic
groups use an all-zero 32-byte randomness value; nondeterministic groups use
the ACVP-provided `rnd`.

Unsupported groups are counted and skipped explicitly. They are not converted,
approximated, or silently treated as pure-signature tests.

## Run

```bash
python3 scripts/patch-stage9e2-mldsa-siggen.py
./scripts/run-stage9e2-mldsa-siggen.sh
```

The runner compares decoded signature bytes, so hexadecimal capitalization does
not affect the result.

## Next increment

Stage 9E-2B should add an explicit internal-`mu` signing entry point and then
cover the two internal-interface ACVP group families. External prehash support
should remain separate because it requires the HashML-DSA message construction
and hash-algorithm identifiers.
