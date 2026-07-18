#!/usr/bin/env python3
import pathlib, py_compile, sys
root=pathlib.Path(__file__).resolve().parents[1]
required=[
"crates/pqc-test-harness/src/bin/pqc-interop-rust.rs",
"scripts/interop/providers/rust_provider.py",
"scripts/interop/providers/liboqs_provider.py",
"scripts/interop/providers/liboqs_bridge.c",
"scripts/cross_provider_interop.py",
"README-a2-3.md",
".github/workflows/a2-cross-provider.yml",
]
missing=[p for p in required if not (root/p).exists()]
if missing: raise SystemExit("missing: "+", ".join(missing))
for p in ["scripts/interop/providers/rust_provider.py","scripts/interop/providers/liboqs_provider.py","scripts/cross_provider_interop.py"]:
 py_compile.compile(str(root/p),doraise=True)
text=(root/"xtask/src/main.rs").read_text()
assert 'Some("interop-cross")' in text and 'fn interop_cross' in text
print("A2.3 static validation passed")
print("Run cargo xtask interop-cross --strict with liboqs installed for cryptographic validation.")
