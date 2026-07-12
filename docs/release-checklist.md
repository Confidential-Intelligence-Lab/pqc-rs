# v0.4.0-rc.1 Release Checklist

- [ ] Resolve authors and repository placeholders
- [ ] Add crate descriptions, README paths, keywords, and categories
- [ ] Keep test harness and incomplete signature crates unpublished
- [ ] Run formatting, Clippy, tests, rustdoc, audit, deny, fuzz smoke, Miri, ASan, UBSan
- [ ] Confirm KeyGen 75/75, Encaps 75/75, Decaps 30/30, key checks 60/60
- [ ] Confirm pure-PQ HPKE 105/105 and hybrid HPKE 102/102
- [ ] Review `cargo package --list` for each release crate
- [ ] Run package builds and publish dry-runs in dependency order
- [ ] Tag `v0.4.0-rc.1` and open external review window
