# Public Access Readiness

> Last reviewed: 2026-07-19

This checklist governs public access to the PQC-rs source repository and its
signed `v0.4.0-rc.1` prerelease. It is separate from algorithm and package
release readiness: the three release-candidate crates are already public on
crates.io, while the source repository remains private on UCI GitHub
Enterprise.

Changing repository visibility is an owner-authorized external action. No
automation or release script may make that change implicitly.

## Preserved release state

- Tag: `v0.4.0-rc.1`
- Tagged commit: `e02731b6d13c5b4d8f8bc3fb86193a748074d38d`
- Published crates: `pqc-rs-core`, `pqc-rs-ml-kem`, and `pqc-rs-hpke`
- GitHub release: published as a prerelease with signed source and Stage 13
  evidence, checksums, the public Minisign key, and a build record
- Public-access changes after the tag are documentation and hosting changes;
  they do not move the tag or modify signed artifacts

## Hosting decision

The canonical public source is:

`https://github.com/Confidential-Intelligence-Lab/pqc-rs`

The UCI GitHub Enterprise repository remains the internal development origin.
The public GitHub organization provides anonymous access, CI/CD, public issue
tracking, security reporting, and release distribution. The mirror must
preserve the complete Git history, annotated tags, and signed release assets.

Do not maintain two repositories that both appear canonical. Identify the
authoritative issue tracker, security channel, release page, and contribution
path in the README.

## Required pre-publication gates

- [x] Select and record the canonical public host and repository URL.
- [ ] Scan the complete Git history, tags, and current tree for credentials,
      private keys, tokens, confidential data, and unintended large artifacts.
- [ ] Confirm that committed test vectors and external materials have
      compatible redistribution terms and preserved provenance.
- [ ] Verify that `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`,
      `CODE_OF_CONDUCT.md`, `GOVERNANCE.md`, `SUPPORT.md`, and `CITATION.cff`
      render correctly on the selected host.
- [ ] Enable and test a private vulnerability-reporting path before inviting
      public security scrutiny.
- [ ] Enable CI for the maintained platform matrix, or document which gates
      must run on a controlled release machine until hosted CI is available.
- [ ] Configure branch protection, required review, and tag/release
      permissions appropriate to a cryptography project.
- [ ] Verify repository description, topics, license detection, default
      branch, release page, and crates.io links.
- [ ] Perform a fresh anonymous clone and run the documented build, test,
      compliance, and package-reconstruction commands.
- [ ] Download every release asset anonymously; verify `SHA256SUMS` and all
      Minisign signatures using the published key.
- [ ] Confirm that the security limitations and release-candidate status are
      visible before installation instructions.
- [ ] Complete owner approval for the visibility change or mirror launch.

## Post-publication verification

From a machine and browser session without UCI or hosting-provider
authentication:

1. clone the canonical repository and verify the annotated tag resolves to the
   recorded release commit;
2. open the README, roadmap, security policy, contribution guide, release
   notes, and license;
3. download and verify all signed release assets;
4. open a non-security test issue or discussion and confirm the public support
   path is usable;
5. confirm private vulnerability reporting is visible but does not disclose
   report contents;
6. confirm CI starts from a harmless documentation pull request or equivalent
   protected test branch;
7. verify the three crates.io pages link to the canonical repository.

Record the public URL, launch date, anonymous verification results, and any
accepted limitations in the next release-readiness evidence bundle.
