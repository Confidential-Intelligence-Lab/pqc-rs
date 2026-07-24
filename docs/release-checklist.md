# v0.4.0 Stable-Promotion Checklist

- [x] Confirm `v0.4.0-rc.1` at commit `e02731b6` as the promotion baseline
- [x] Create isolated `release/v0.4.0` worktree from the RC tag
- [x] Confirm stable `0.4.0` is absent locally, remotely, and on crates.io
- [x] Keep ML-DSA, SLH-DSA, hybrid, and test-harness crates unpublished
- [x] Update active workspace and dependency versions to `0.4.0`
- [x] Preserve historical RC notes, stage helpers, tag, and artifacts
- [x] Add stable-promotion changelog and release notes
- [ ] Run the complete workspace-assurance gate
- [ ] Package and inspect the three public crates
- [ ] Publish and verify `pqc-rs-core` `0.4.0`
- [ ] After indexing, publish and verify `pqc-rs-ml-kem` `0.4.0`
- [ ] After indexing, publish and verify `pqc-rs-hpke` `0.4.0`
- [ ] Verify docs.rs builds for all three published crates
- [ ] Create and push annotated tag `v0.4.0`
- [ ] Create the GitHub Enterprise release and attach verified artifacts
