#!/usr/bin/env python3
from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parents[1]
required = [
    "README.md", "CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md",
    "GOVERNANCE.md", "SUPPORT.md", "ROADMAP.md", "RELEASE.md",
    "CHANGELOG.md", "CITATION.cff", "docs/README.md",
]
errors = []
for rel in required:
    path = root / rel
    if not path.is_file() or not path.read_text(encoding="utf-8").strip():
        errors.append(f"missing-or-empty:{rel}")

readme = (root / "README.md").read_text(encoding="utf-8")
for link in re.findall(r"\[[^\]]+\]\(([^)]+)\)", readme):
    if "://" not in link and not (root / link.split("#", 1)[0]).exists():
        errors.append(f"broken-readme-link:{link}")

for rel in required:
    text = (root / rel).read_text(encoding="utf-8")
    if "formal proof" in text.lower() and "not" not in text.lower():
        errors.append(f"unsafe-proof-claim:{rel}")

citation = (root / "CITATION.cff").read_text(encoding="utf-8")
canonical_repository = (
    'repository-code: '
    '"https://github.com/Confidential-Intelligence-Lab/pqc-rs"'
)
if re.search(r"\b(?:OWNER|TODO|CHANGEME)\b", citation, re.IGNORECASE):
    errors.append("unresolved-citation-repository-placeholder")
if canonical_repository not in citation:
    errors.append("noncanonical-citation-repository-code")

if errors:
    print("decision=fail")
    for item in errors:
        print(f"finding={item}")
    sys.exit(1)
print("decision=pass")
print(f"files={len(required)}")
print("A5 public identity validation passed.")
