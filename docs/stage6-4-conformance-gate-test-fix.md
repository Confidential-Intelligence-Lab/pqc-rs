# Stage 6.4 Conformance-Gate Integration Test Fix

The component manifest now marks `kpke-keygen` as `KatValidated` after passing
all 75 NIST ACVP KeyGen cases.

The integration test still asserted that no component could be KAT-validated.
This patch updates the assertion to require exactly one validated component:

```text
kpke-keygen
```

Aggregate parameter-set status remains non-conformant and
`official_kats_passed` remains false until encapsulation and decapsulation also
pass.
