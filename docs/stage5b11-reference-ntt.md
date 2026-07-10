# Stage 5B-11: Reference-Compatible ML-KEM NTT

## Scope

Stage 5B-11 replaces the experimental NTT facade with a
reference-compatible ML-KEM NTT arithmetic layer.

## Added

- centered Montgomery-domain zeta schedule
- forward NTT
- `invntt_tomont`
- convenience inverse transform that removes the Montgomery factor
- degree-one `basemul`
- complete 128-pair NTT-domain polynomial multiplication
- equivalence tests against schoolbook negacyclic multiplication

## Important domain convention

`invntt_tomont(ntt(a))` equals `a * R mod q`, not `a`.

The convenience `intt` function removes `R`, so `intt(ntt(a)) == a`.

For polynomial multiplication, the reference-compatible flow is:

```text
invntt_tomont(basemul_polynomials(ntt(a), ntt(b)))
```

which returns the standard coefficient-domain product.

## Validation status

This stage validates internal equivalence against the repository's
schoolbook negacyclic multiplier. Official FIPS 203 intermediate vectors and
KATs remain pending.
