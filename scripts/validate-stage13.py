#!/usr/bin/env python3
from __future__ import annotations
import json, py_compile, sys
from pathlib import Path
REQUIRED=[
 "assurance/stage13/profiles.json","assurance/stage13/claims.json","scripts/stage13_assurance.py",
 "scripts/stage13_secret_inventory.py","scripts/stage13_sbom.py","scripts/stage13_codegen_matrix.py",
 "scripts/run-stage13.sh","docs/security/STAGE13_ASSURANCE.md",".github/workflows/stage13-assurance.yml"
]
def main()->int:
 missing=[x for x in REQUIRED if not Path(x).is_file()]
 if missing: print("missing:",*missing,sep="\n"); return 1
 for x in ["assurance/stage13/profiles.json","assurance/stage13/claims.json"]: json.loads(Path(x).read_text())
 for x in Path("scripts").glob("stage13_*.py"): py_compile.compile(str(x),doraise=True)
 print("Stage 13 overlay validation passed."); return 0
if __name__=="__main__": raise SystemExit(main())
