#!/usr/bin/env python3
from __future__ import annotations

import ast
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[1]
provider = root / "scripts/interop/providers/liboqs_provider.py"
source = provider.read_text()
ast.parse(source, filename=str(provider))
required = [
    '"capabilities": capabilities()',
    '"roundtrip", "kem-keygen", "kem-encaps", "kem-decaps"',
    '"roundtrip", "dsa-keygen", "dsa-sign", "dsa-verify"',
    'elif "case" in request:',
    'execute_primitive(request)',
]
missing = [item for item in required if item not in source]
if missing:
    print("missing compatibility elements:", *missing, sep="\n- ", file=sys.stderr)
    raise SystemExit(1)
print("A2.3.1 compatibility provider structure: pass")
