# A2.4 — OpenSSL provider interoperability

A2.4 connects the provider-neutral interoperability framework to OpenSSL 3.5
or later. The shared bridge supports ML-KEM key exchange and Pure ML-DSA
signature operations through OpenSSL's provider APIs.

Run the complete OpenSSL provider matrix with:

```bash
cargo xtask interop-openssl --strict
```

Stage 15A-7 adds the publication-focused ML-DSA gate:

```bash
scripts/check-ml-dsa-openssl-interop.sh
```

That gate requires bidirectional signing and verification for ML-DSA-44,
ML-DSA-65, and ML-DSA-87. It also requires rejection under a modified message,
modified context, and single-bit signature mutation. Reports record the tested
provider version and outcomes without retaining private keys or signatures.

These checks are independent interoperability evidence for the named provider
versions and cases. They are not a formal proof, FIPS validation, Common
Criteria certification, or independent security audit.
