#!/usr/bin/env python3
from pathlib import Path
import py_compile, sys
files=[Path('scripts/hpke/hpke_core.py'),Path('scripts/hpke_interop.py')]
for p in files:
    if not p.is_file(): raise SystemExit(f'missing {p}')
    py_compile.compile(str(p), doraise=True)
text=Path('scripts/hpke/hpke_core.py').read_text()
for token in ['0x0040','0x0041','0x0042','HPKE-v1','psk_id_hash','base_nonce']:
    if token not in text: raise SystemExit(f'missing HPKE token {token}')
print('A3.0 static validation: pass')
