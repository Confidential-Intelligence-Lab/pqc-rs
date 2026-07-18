# Milestone A2.2 — liboqs Interoperability Adapter

A2.2 adds the first independent cryptographic provider to the A2 interoperability framework.

## Install

```bash
python3 scripts/install-a2-2.py
python3 scripts/validate-a2-2.py
python3 scripts/configure-liboqs-interop.py auto
```

If liboqs is available and enabled:

```bash
cargo xtask interop --provider liboqs --suite liboqs-smoke --strict
```

## Coverage

- ML-KEM-512, ML-KEM-768, ML-KEM-1024;
- ML-DSA-44, ML-DSA-65, ML-DSA-87;
- provider version and shared-library provenance;
- KEM key generation, encapsulation, decapsulation, and shared-secret agreement;
- signature key generation, signing, and verification;
- deterministic ML-KEM entry points for later exact cross-provider vectors;
- ML-DSA verification and external-key signing entry points for later cross-generated vectors.

The provider is disabled by default to preserve clean builds on systems without liboqs. The configuration script enables it only after successful capability negotiation.
