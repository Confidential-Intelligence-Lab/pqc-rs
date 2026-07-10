# Stage 5B-11 Import Fix

`to_montgomery` is only used by the test module. This patch removes it from the
library-level import list and imports it inside `#[cfg(test)] mod tests`.
