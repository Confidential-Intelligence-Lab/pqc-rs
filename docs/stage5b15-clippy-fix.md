# Stage 5B-15 Clippy Fix

This patch resolves two `-D warnings` failures:

- removes the unused `PolyVec` import
- moves `assert_fixture_shape` into the `#[cfg(test)]` module

The helper is test-only and should not be compiled into the library build.
