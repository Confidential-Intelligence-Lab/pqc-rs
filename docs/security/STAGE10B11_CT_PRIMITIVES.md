# Stage 10B-1.1: Production-Quality Constant-Time Primitives

This refinement adds complete public API documentation, `#[must_use]`,
`#[inline(always)]`, standard bitwise operator traits, canonical-mask checks,
and a stable generated-code audit wrapper.

`From<bool>` is intentionally omitted because converting secret conditions to
or from Rust `bool` can encourage secret-dependent control flow. Public callers
should construct `CtMask*::TRUE` or `CtMask*::FALSE` explicitly.

Run:

```bash
python3 scripts/patch-stage10b11-enable-ct.py
./scripts/run-stage10b11-ct-primitives.sh
```
