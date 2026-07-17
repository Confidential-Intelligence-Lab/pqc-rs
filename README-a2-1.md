# Milestone A2.1 — Interoperability Framework

This overlay introduces a provider-neutral, deterministic interoperability harness without adding mandatory native dependencies.

## Install and validate

```bash
python3 scripts/install-a2-1.py
python3 scripts/validate-a2-1.py
cargo xtask interop --strict
```

The initial enabled provider is a protocol self-test. `liboqs` and `botan` are registered but intentionally disabled until their production adapters are implemented in A2.2 and A2.3.

## Design invariants

- JSON protocol and report formats are versioned.
- Vector IDs and provider IDs are unique.
- Hexadecimal cryptographic values are normalized before comparison.
- Enabled required providers fail closed.
- Disabled providers never create false interoperability claims.
- A strict run must execute at least one case.
- Reports retain a clear claim boundary.
