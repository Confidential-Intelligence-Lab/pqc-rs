# Release Records and Open Assurance Work

This file is the maintained index for completed release checkpoints and
remaining assurance work. Historical checklists describe the state at their
respective publication boundaries; they are not retroactively rewritten when a
later crate is published independently.

## v0.4.0-rc.1 checkpoint

- Immutable tag: `v0.4.0-rc.1`
- Source commit: `e02731b6d13c5b4d8f8bc3fb86193a748074d38d`
- Published crates: `pqc-rs-core`, `pqc-rs-ml-kem`, and `pqc-rs-hpke`
- Published version: `0.4.0-rc.1`
- Scope note: ML-DSA remained unpublished at this checkpoint.

## v0.4.0 stable foundation

- Immutable tag: `v0.4.0`
- Original stable-publication scope: `pqc-rs-core`, `pqc-rs-ml-kem`, and
  `pqc-rs-hpke`
- Published version: `0.4.0`
- Release record: [`docs/release/V0.4.0.md`](release/V0.4.0.md)
- Scope note: the original decision to keep ML-DSA unpublished was superseded
  by the later independent ML-DSA publication below.

## pqc-rs-ml-dsa 0.4.0

- Immutable annotated tag: `pqc-rs-ml-dsa-v0.4.0`
- Publication source: `98140a3422fbc212bd43d96992028d29c548714d`
- Published crate: `pqc-rs-ml-dsa`
- Published version: `0.4.0`
- Release record:
  [`docs/release/ML_DSA_0.4.0.md`](release/ML_DSA_0.4.0.md)
- Closeout status: publication audited and closed.

## pqc-rs-slh-dsa 0.5.0

- Immutable annotated tag: `pqc-rs-slh-dsa-v0.5.0`
- Publication source: `c446714f9ae5a9210b1fb7959d8e640c03a15d39`
- Published crate: `pqc-rs-slh-dsa`
- Published version: `0.5.0`
- Release record:
  [`docs/release/SLH_DSA_0.5.0.md`](release/SLH_DSA_0.5.0.md)
- Registry archive verified byte-for-byte against the local release archive.
- Closeout status: FIPS 205 implementation, validation, interoperability,
  assurance, performance/footprint characterization, and publication audited
  and closed.

## PQC-rs 1.0.0-rc.1 candidate

- Candidate cryptographic crates: `pqc-rs-core`, `pqc-rs-ml-kem`,
  `pqc-rs-ml-dsa`, `pqc-rs-slh-dsa`, and `pqc-rs-hpke`.
- Candidate version: `1.0.0-rc.1`.
- Compatibility contract:
  [`docs/api/PQC_RS_1_0_SEMVER_CONTRACT.md`](api/PQC_RS_1_0_SEMVER_CONTRACT.md).
- Release record:
  [`docs/release/V1.0.0_RC1.md`](release/V1.0.0_RC1.md).
- Publication status: pending final candidate validation and registry
  publication.
- PQC-Forge/application crates remain separately versioned.
- Standalone `pqc-rs-hybrid` remains deferred beyond the 1.0 boundary.

## Current published baseline

The current independently published cryptographic crates are:

- `pqc-rs-core` `0.5.0`;
- `pqc-rs-ml-kem` `0.4.1`;
- `pqc-rs-ml-dsa` `0.4.0`;
- `pqc-rs-slh-dsa` `0.5.0`; and
- `pqc-rs-hpke` `0.4.1`.

These independent pre-1.0 versions record each crate's publication history.
They are the baseline from which the coordinated PQC-rs 1.0 cryptographic
release line is prepared.

`pqc-rs-hybrid` and `pqc-rs-test-harness` remain unpublished. PQC-Forge and
application-layer workspace crates are outside the PQC-rs 1.0 cryptographic
compatibility boundary and are released separately.

## Open assurance and maintenance work

- [ ] Complete Stage 10B-5 cross-architecture generated-code and timing
      validation for Linux x86-64, Linux ARM64, and Apple ARM64 when the
      required environments are available.
- [ ] Continue post-publication external review and record non-sensitive
      findings and dispositions.
- [ ] Run the complete applicable assurance profile before any corrective or
      compatibility release.
- [ ] Preserve immutable tags, registry identities, release records, signed
      evidence, and publication closeout records.

For new publication work, follow [`RELEASE.md`](../RELEASE.md), the applicable
crate-specific release record, and the current roadmap rather than treating an
older historical checklist as an active release plan.
