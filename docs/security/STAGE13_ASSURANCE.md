# Stage 13 — Formal Assurance and Release Evidence

Stage 13 converts the Stage 12 regression campaign into an explicit assurance case. It links versioned claims to reproducible evidence and records limitations that remain open for formal verification or external review.

## Profiles

`portable` runs the Stage 12 hosted-CI profile, the complete workspace test suite, focused differential tests, secret-lifetime inventory, and SBOM generation. Statistical timing results are retained as evidence but do not hard-gate shared hosted runners; deterministic and generated-code checks remain gating.

`review` additionally requires a clean Git tree, Stage 12 full validation, Miri, and code-generation comparison across installed Rust toolchains.

`release` uses the Stage 12 soak profile and requires an authenticated evidence bundle. Set `MINISIGN_SECRET_KEY` to a local secret-key path; the key is never stored in the repository or evidence archive.

Every Stage 13 archive embeds the nested Stage 12 evidence bundle so a failed
side-channel subcheck can be diagnosed after the runner has been destroyed.

## Interpretation

Property tests, differential tests, Miri, compiler comparisons, and timing experiments increase assurance but do not prove whole-library correctness or constant-time behavior. Stage 13 therefore labels each claim by evidence strength and carries explicit non-claims in every report.
