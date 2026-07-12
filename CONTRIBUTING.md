# Contributing

Before submitting changes, run formatting, Clippy, tests, `cargo deny check`, and `cargo audit`. Changes touching secrets must also run Stage 8C and 8D checks. Cryptographic changes require specification references, deterministic tests, malformed-input tests, conformance reruns, and a side-channel/zeroization assessment. Unsafe code requires an explicit safety invariant and dedicated review.
