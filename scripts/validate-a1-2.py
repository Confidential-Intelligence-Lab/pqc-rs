#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, py_compile, subprocess, sys, tomllib
root=pathlib.Path(__file__).resolve().parents[1]
required=['compliance/catalog.toml','compliance/standards/fips203.toml','scripts/standards_engine.py','docs/standards/FIPS203.md']
missing=[x for x in required if not (root/x).exists()]
if missing: print('missing='+','.join(missing)); raise SystemExit(1)
for p in ['compliance/catalog.toml','compliance/standards/fips203.toml']:
    with (root/p).open('rb') as f: tomllib.load(f)
py_compile.compile(str(root/'scripts/standards_engine.py'),doraise=True)
r=subprocess.run([sys.executable,str(root/'scripts/standards_engine.py'),'validate','--strict','--structural-only','--output','target/a1-2-validation'],cwd=root)
if r.returncode: raise SystemExit(r.returncode)
print('A1.2 standards engine validation passed.')
