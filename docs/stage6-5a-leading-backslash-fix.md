# Stage 6.5A Leading Backslash Fix

The generated Stage 6.5A archive included a literal backslash as the first
character of three Rust files. Rust therefore failed to parse each file before
`cargo fmt` could run.

This repair removes only that leading character from:

- `crates/pqc-test-harness/src/acvp_encap_decap.rs`
- `crates/pqc-test-harness/src/bin/ml-kem-acvp-encap-decap-inventory.rs`
- `crates/pqc-test-harness/tests/acvp_encap_decap.rs`
