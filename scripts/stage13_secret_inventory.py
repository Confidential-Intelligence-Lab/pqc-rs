#!/usr/bin/env python3
"""Create a conservative inventory of secret-bearing Rust code and lifecycle controls."""
from __future__ import annotations
import argparse, json, re
from pathlib import Path

PATTERNS = {
    "secret_type": re.compile(r"\b(?:Secret|Private|Decapsulation|Signing)\w*\b"),
    "zeroization": re.compile(r"\b(?:Zeroize|zeroize|clear|Drop)\b"),
    "constant_time": re.compile(r"\b(?:Choice|CtOption|ConstantTimeEq|ct_eq|conditional_(?:assign|select|swap))\b"),
    "debug_surface": re.compile(r"\b(?:derive\s*\([^)]*Debug|impl\s+Debug)\b"),
    "clone_surface": re.compile(r"\bderive\s*\([^)]*Clone\b"),
}

def main() -> int:
    ap=argparse.ArgumentParser(); ap.add_argument("--output",type=Path,required=True); args=ap.parse_args()
    root=Path("crates"); findings=[]
    if root.exists():
        for path in sorted(root.rglob("*.rs")):
            text=path.read_text(encoding="utf-8",errors="replace")
            for number,line in enumerate(text.splitlines(),1):
                kinds=[name for name,rx in PATTERNS.items() if rx.search(line)]
                if kinds:
                    findings.append({"path":str(path),"line":number,"kinds":kinds,"text":line.strip()[:300]})
    counts={name:sum(name in f["kinds"] for f in findings) for name in PATTERNS}
    args.output.mkdir(parents=True,exist_ok=True)
    report={"schema_version":1,"files_scanned":len({f['path'] for f in findings}),"counts":counts,"findings":findings,
            "interpretation":"Inventory candidates require human review; matches are not automatically vulnerabilities."}
    (args.output/"inventory.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# Stage 13 Secret-Lifetime Inventory","",f"Candidate-bearing files: **{report['files_scanned']}**","", "| Category | Matches |","|---|---:|"]
    lines += [f"| `{k}` | {v} |" for k,v in counts.items()]
    lines += ["", "This is a conservative review inventory, not a vulnerability finding."]
    (args.output/"inventory.md").write_text("\n".join(lines)+"\n")
    return 0
if __name__=="__main__": raise SystemExit(main())
