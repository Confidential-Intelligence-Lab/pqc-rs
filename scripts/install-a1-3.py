#!/usr/bin/env python3
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
catalog = root / "compliance" / "catalog.toml"
if not catalog.exists():
    raise SystemExit("missing compliance/catalog.toml; apply A1.2 first")
text = catalog.read_text()
if re.search(r'(?m)^id\s*=\s*"FIPS204"\s*$', text):
    print("FIPS204 already registered")
    raise SystemExit(0)
entry = '''\n[[document]]
id = "FIPS204"
title = "Module-Lattice-Based Digital Signature Standard"
classification = "normative"
source = "https://doi.org/10.6028/NIST.FIPS.204"
data = "compliance/standards/fips204.toml"
documentation = "docs/standards/FIPS204.md"
'''
catalog.write_text(text.rstrip() + "\n" + entry)
print("registered FIPS204 in compliance/catalog.toml")
