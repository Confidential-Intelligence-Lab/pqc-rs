#!/usr/bin/env python3
from pathlib import Path
import json, sys, tomllib

root = Path(__file__).resolve().parents[1]
module = root / "compliance" / "standards" / "fips204.toml"
required = [module, root / "docs" / "standards" / "FIPS204.md", root / "scripts" / "install-a1-3.py"]
missing = [str(p.relative_to(root)) for p in required if not p.exists()]
if missing:
    print("decision=fail")
    print("missing=" + ",".join(missing))
    sys.exit(1)
with module.open("rb") as f:
    data = tomllib.load(f)
reqs = data.get("requirement", [])
ids = [r.get("id") for r in reqs]
findings = []
if data.get("standard") != "FIPS204": findings.append("standard must be FIPS204")
if data.get("classification") != "normative": findings.append("classification must be normative")
if len(reqs) < 30: findings.append("expected at least 30 requirements")
if len(ids) != len(set(ids)): findings.append("duplicate requirement ids")
for i, r in enumerate(reqs, 1):
    for key in ("id", "section", "class", "status", "title", "owner"):
        if not r.get(key): findings.append(f"requirement {i} missing {key}")
    if r.get("status") not in {"mapped", "implemented", "verified", "not-applicable"}:
        findings.append(f"{r.get('id')} invalid status")
report_dir = root / "target" / "a1-3-validation"
report_dir.mkdir(parents=True, exist_ok=True)
(report_dir / "report.json").write_text(json.dumps({"decision":"pass" if not findings else "fail","requirements":len(reqs),"findings":findings}, indent=2)+"\n")
(report_dir / "report.md").write_text("# A1.3 Validation\n\n- Decision: **%s**\n- Requirements: %d\n- Findings: %d\n" % ("pass" if not findings else "fail", len(reqs), len(findings)))
print("decision=" + ("pass" if not findings else "fail"))
print(f"requirements={len(reqs)}")
print(f"report={report_dir / 'report.md'}")
if findings:
    for f in findings: print("finding=" + f)
    sys.exit(1)
print("A1.3 overlay validation passed.")
