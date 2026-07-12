# Security Policy

PQC-rs is experimental, pre-audit cryptographic software. Passing vectors, fuzzing, sanitizers, Miri, and internal review do not guarantee absence of side channels, logic flaws, or integration errors.

Report suspected vulnerabilities privately to the maintainers. Include the affected crate/version, platform, toolchain, reproducer, expected and observed behavior, and possible secret exposure.

Current claims are limited to documented vector-tested interoperability, structured negative testing, dynamic-analysis coverage, explicit secret wrappers, and no known unsafe code in cryptographic workspace crates. The project does not claim formal verification, FIPS 140 validation, Common Criteria certification, or a universal constant-time guarantee.
