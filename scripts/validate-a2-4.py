#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

required = [
    "scripts/interop/providers/openssl_bridge.c",
    "scripts/interop/providers/openssl_provider.py",
    "scripts/openssl_provider_interop.py",
    "xtask/src/main.rs",
    ".github/workflows/a2-openssl-provider.yml",
]
missing = [path for path in required if not Path(path).is_file()]
if missing:
    print("missing A2.4 files:")
    for path in missing:
        print(f"- {path}")
    raise SystemExit(1)
for path in ("scripts/interop/providers/openssl_provider.py", "scripts/openssl_provider_interop.py"):
    subprocess.run([sys.executable, "-m", "py_compile", path], check=True)
text = Path("xtask/src/main.rs").read_text()
if 'Some("interop-openssl")' not in text or "fn interop_openssl" not in text:
    raise SystemExit("xtask OpenSSL command is not installed")
print("A2.4 static validation: pass")
