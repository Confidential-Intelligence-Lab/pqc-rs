# Milestone A5 — Public Project Identity

This overlay creates a commit-ready public-project identity layer for PQC-rs.

Before committing, replace `OWNER` in `CITATION.cff` with the current GitHub account or organization. Review the release date and version metadata if the commit is not associated with a release.

Validate with:

```bash
python3 scripts/validate-a5-public-identity.py
```

Recommended commit:

```bash
git add README.md CONTRIBUTING.md SECURITY.md CODE_OF_CONDUCT.md \
  GOVERNANCE.md SUPPORT.md ROADMAP.md RELEASE.md CHANGELOG.md \
  CITATION.cff docs/README.md scripts/validate-a5-public-identity.py \
  README-a5.md
git commit -m "Milestone A5: establish public project identity"
```
