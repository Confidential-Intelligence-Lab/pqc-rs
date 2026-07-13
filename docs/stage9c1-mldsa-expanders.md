# Stage 9C-1: ML-DSA SHAKE Expanders

This increment adds deterministic, domain-separated SHAKE streams for `ExpandA`,
`ExpandS`, and `ExpandMask`.

Acceptance criteria:

- identical seed and domain inputs produce identical output;
- changing coordinates or nonces changes output;
- streaming and one-shot expansion match;
- formatting, Clippy, and workspace tests remain clean.

This stage does not yet perform coefficient rejection sampling.
