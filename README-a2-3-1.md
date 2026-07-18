# A2.3.1 — Legacy smoke-suite compatibility

This patch makes the liboqs provider simultaneously support:

- the A2.2 manifest-driven interoperability protocol, including `roundtrip` vectors and top-level `capabilities`; and
- the A2.3 primitive provider protocol used by `interop-cross`.

It does not change the cryptographic algorithms or the cross-provider claim boundary.

## Validate

```bash
python3 scripts/validate-a2-3-1.py
export OQS_LIBOQS_PATH=/opt/homebrew/lib/liboqs.dylib
export OQS_PREFIX=/opt/homebrew
python3 scripts/configure-liboqs-interop.py auto
cargo xtask interop --provider liboqs --suite liboqs-smoke --strict
cargo xtask interop-cross --strict
```

Expected results:

```text
decision=pass
providers=1
executed=6
```

and:

```text
decision=pass
executed=12
passed=12
failed=0
```
