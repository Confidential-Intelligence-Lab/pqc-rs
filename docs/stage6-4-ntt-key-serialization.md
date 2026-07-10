# Stage 6.4: NTT-Domain K-PKE Key Serialization

This patch corrects the FIPS 203 KeyGen representation boundary.

The previous implementation computed mathematically equivalent coefficient-domain
values and serialized those values. FIPS 203 instead serializes the NTT-domain
vectors directly:

```text
s_hat = NTT(s)
e_hat = NTT(e)
t_hat = A_hat o s_hat + e_hat

ekPKE = ByteEncode12(t_hat) || rho
dkPKE = ByteEncode12(s_hat)
```

The patch also treats matrix entries returned by `SampleNTT` as already being in
the NTT domain; it does not apply a second forward transform to them.

After applying the patch, rerun the unit tests and all 75 ACVP KeyGen cases. A
remaining mismatch should be used to identify the next normative divergence,
most likely matrix-XOF streaming/indexing or exact arithmetic normalization.
