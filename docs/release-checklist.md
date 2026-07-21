# v0.4.0 Release Checklist

## Completed v0.4.0-rc.1 checkpoint

- [x] Resolve authors and repository placeholders.
- [x] Add crate descriptions, README paths, keywords, and categories.
- [x] Keep the test harness and incomplete signature crates unpublished.
- [x] Run formatting, Clippy, tests, rustdoc, audit, deny, fuzz smoke, Miri,
      ASan, and UBSan.
- [x] Confirm KeyGen 75/75, Encaps 75/75, Decaps 30/30, and key checks 60/60.
- [x] Confirm pure-PQ HPKE 105/105 and hybrid HPKE 102/102.
- [x] Review `cargo package --list` for each release crate.
- [x] Run package builds and publish dry-runs in dependency order.
- [x] Publish and verify `pqc-rs-core`, `pqc-rs-ml-kem`, and `pqc-rs-hpke`.
- [x] Create immutable tag `v0.4.0-rc.1`.
- [x] Create the public GitHub prerelease and attach signed source and assurance
      evidence.
- [x] Establish the public GitHub repository as the external source of record.
- [x] Run all public workflows successfully.
- [x] Pin external Actions to full commit SHAs and enable repository-level SHA
      enforcement.
- [x] Protect `main` with pull requests and required release-critical checks.

## Candidate-defining work

- [ ] Verify the live docs.rs pages for all three published crates.
- [ ] Complete Stage 10B-5 on Linux x86-64, Linux ARM64, and Apple ARM64.
- [ ] Complete installation, quick-start, interoperability, supported-target,
      migration, limitations, and Minisign-verification documentation.
- [ ] Add focused issue forms, confirm private vulnerability reporting, open a
      public discussion channel, and protect `v*` tags.
- [ ] Decide whether the review target differs sufficiently from
      `v0.4.0-rc.1` to require matching `v0.4.0-rc.2` packages and a new tag.
- [ ] Freeze the exact candidate tag and full commit.
- [ ] Run the complete assurance profile and all public workflows against the
      frozen candidate.
- [ ] Publish and verify signed source and assurance artifacts.

## Twenty-one-day external review

- [ ] Complete every placeholder in
      [`docs/release/V0.4.0_EXTERNAL_REVIEW.md`](release/V0.4.0_EXTERNAL_REVIEW.md).
- [ ] Open a public tracking issue for non-sensitive findings.
- [ ] Verify the candidate, packet, release assets, evidence, issue, and private
      reporting channel from an anonymous session.
- [ ] Announce the fixed target to RFC 9958 authors, selected colleagues,
      PQUIP, and HPKE reviewers.
- [ ] Record the opening and closing timestamps in UTC.
- [ ] Acknowledge and classify every report.
- [ ] Resolve all critical, high-severity, conformance-blocking, and
      interoperability-blocking findings.
- [ ] Restart the review clock if a material candidate change requires it.
- [ ] Publish a non-sensitive review disposition.

## Final v0.4.0 release

- [ ] Re-run the complete applicable assurance profile from the final clean
      commit.
- [ ] Review package contents and run `cargo publish --dry-run` in dependency
      order.
- [ ] Publish `pqc-rs-core`, `pqc-rs-ml-kem`, and `pqc-rs-hpke` at `0.4.0`.
- [ ] Create and verify the annotated `v0.4.0` tag and signed release assets.
- [ ] Forward-port every `release/0.4` fix to `main`.
