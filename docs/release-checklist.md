# v0.4.0-rc.1 Release Checklist

- [x] Resolve authors and repository placeholders
- [x] Add crate descriptions, README paths, keywords, and categories
- [x] Keep test harness and incomplete signature crates unpublished
- [x] Run formatting, Clippy, tests, rustdoc, audit, deny, fuzz smoke, Miri, ASan, UBSan
- [x] Confirm KeyGen 75/75, Encaps 75/75, Decaps 30/30, key checks 60/60
- [x] Confirm pure-PQ HPKE 105/105 and hybrid HPKE 102/102
- [x] Review `cargo package --list` for each release crate
- [x] Run package builds and publish dry-runs in dependency order
- [x] Publish and verify `pqc-rs-core`, `pqc-rs-ml-kem`, and `pqc-rs-hpke`
- [x] Verify docs.rs builds for all three published crates
- [ ] Tag `v0.4.0-rc.1` and open external review window
- [ ] Create the GitHub release from the reviewed release notes
