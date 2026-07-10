#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/pqc-ml-kem/src/conformance.rs")
if not path.exists():
    raise SystemExit(f"{path} not found; run from repository root")

text = path.read_text(encoding="utf-8")

start = text.find('    ComponentStatus {\n        id: "kpke-keygen",')
if start < 0:
    raise SystemExit("Could not locate kpke-keygen conformance entry")

end = text.find("    },", start)
if end < 0:
    raise SystemExit("Could not locate end of kpke-keygen conformance entry")
end += len("    },")

replacement = '''    ComponentStatus {
        id: "kpke-keygen",
        level: ConformanceLevel::KatValidated,
        note: "Passed all 75 NIST ACVP FIPS 203 ML-KEM KeyGen cases across ML-KEM-512, ML-KEM-768, and ML-KEM-1024.",
    },'''

text = text[:start] + replacement + text[end:]
path.write_text(text, encoding="utf-8")
print(f"Updated {path}")
