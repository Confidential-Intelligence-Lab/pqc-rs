#!/usr/bin/env python3
from __future__ import annotations
import json, py_compile
from pathlib import Path
required=[
 "scripts/stage12_capabilities.py","scripts/stage12_compiler_matrix.py",
 "scripts/stage12_perf_probe.py","scripts/stage12_campaign.py",
 "scripts/run-stage12.sh","sidechannel/stage12/profiles.json",
 "docs/security/STAGE12_COMPREHENSIVE_SIDECHANNEL_VALIDATION.md"
]
for name in required:
 p=Path(name)
 if not p.is_file(): raise SystemExit(f"missing {name}")
for name in required:
 if name.endswith(".py"): py_compile.compile(name,doraise=True)
json.loads(Path("sidechannel/stage12/profiles.json").read_text())
print("Stage 12 overlay validation passed.")
