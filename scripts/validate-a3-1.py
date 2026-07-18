#!/usr/bin/env python3
from __future__ import annotations
import pathlib, py_compile, sys

root = pathlib.Path(__file__).resolve().parent.parent
required = [
    root / "crates/pqc-test-harness/src/bin/hpke-native-transcript.rs",
    root / "crates/pqc-hpke/src/setup.rs",
    root / "scripts/hpke/hpke_core.py",
    root / "scripts/hpke_interop.py",
    root / "README-a3-1.md",
]
missing = [str(path.relative_to(root)) for path in required if not path.exists()]
if missing:
    print("A3.1 static validation: fail")
    for path in missing:
        print(f"missing: {path}")
    raise SystemExit(1)

for path in [root / "scripts/hpke/hpke_core.py", root / "scripts/hpke_interop.py"]:
    py_compile.compile(str(path), doraise=True)

setup = (root / "crates/pqc-hpke/src/setup.rs").read_text()
binary = (root / "crates/pqc-test-harness/src/bin/hpke-native-transcript.rs").read_text()
runner = (root / "scripts/hpke_interop.py").read_text()
core = (root / "scripts/hpke/hpke_core.py").read_text()
checks = {
    "sender shared-secret setup": "setup_base_sender_from_shared_secret" in setup,
    "receiver shared-secret setup": "setup_base_receiver_from_shared_secret" in setup,
    "native transcript binary": "hpke-native-transcript" in runner,
    "exact transcript comparison": '"key_schedule_context"' in runner and '"exported_secret"' in runner,
    "full suite-id exporter domain": "self.suite_id" in core,
    "native RFC 9180 context use": "setup_base_sender_from_shared_secret" in binary,
}
failed = [name for name, passed in checks.items() if not passed]
if failed:
    print("A3.1 static validation: fail")
    for name in failed:
        print(f"failed: {name}")
    raise SystemExit(1)

print("A3.1 static validation: pass")
