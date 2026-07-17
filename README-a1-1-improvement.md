# Milestone A1.1.1 — Live Standards Traceability

This overlay upgrades the initial standards matrix into a live engineering control.

## Added capabilities

- richer requirement metadata: owner, CI gates, references, tags, evidence paths, verification dates, review intervals, and optional coverage;
- glob-aware repository path resolution;
- structured findings with stable finding codes;
- stale-verification detection;
- strict status-dependent evidence rules;
- evidence-readiness coverage in Markdown, JSON, and HTML reports;
- `findings.json` for CI ingestion;
- query support for standards, statuses, and missing evidence dimensions.

## Commands

```bash
./scripts/install-a1-1.sh
python3 scripts/validate-a1-1.py
cargo xtask compliance --strict
cargo xtask query --standard RFC9958 --status mapped
cargo xtask query --missing tests
cargo xtask query --missing evidence
```

## Promotion policy

- `mapped`: a standard topic is associated with likely implementation areas; unresolved references are warnings.
- `implemented`: implementation references must resolve and a CI gate should be identified.
- `verified`: implementation and test references must resolve, evidence must be named, and `last_verified` must be present and current.
- `not-applicable`: a rationale is mandatory.

Narrative evidence labels document why a claim is credible. `evidence_paths` identify machine-checkable evidence artifacts when those artifacts are versioned in the repository.
