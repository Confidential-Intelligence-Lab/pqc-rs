# Stage 6.4 KeyGen Serialization Repair

The original Stage 6.4 patcher relied on an exact text match for the
`keygen_from_seed` implementation. The repository's accumulated formatting and
prior stage changes caused that match to fail after the patcher had already
updated `kpke_ntt_domain.rs` and `packing.rs`.

This repair is intentionally narrow and idempotent:

- it modifies only `kpke_keygen.rs`;
- it detects `keygen_from_seed` by its signature and balanced braces;
- it preserves the length-validation and return-value sections;
- it replaces only the algorithm and serialization body;
- it installs the required NTT-domain imports and packing functions;
- it adds a regression test proving that the CPA secret key serializes `s_hat`.

The resulting KeyGen path serializes:

```text
ekPKE = ByteEncode12(t_hat) || rho
dkPKE = ByteEncode12(s_hat)
```

and treats the expanded matrix as already sampled in the NTT domain.
