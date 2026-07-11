#!/usr/bin/env python3
from pathlib import Path

lib_path = Path("crates/pqc-test-harness/src/lib.rs")
readme_path = Path("README.md")

if not lib_path.exists():
    raise SystemExit(f"{lib_path} not found; run from repository root")

text = lib_path.read_text(encoding="utf-8")
declaration = "pub mod standards_scope;\n"

if declaration not in text:
    marker = "pub mod acvp_encap_decap;\n"
    if marker not in text:
        marker = "pub mod acvp;\n"
    if marker not in text:
        raise SystemExit("Could not locate harness module insertion point")
    text = text.replace(marker, marker + declaration, 1)
    lib_path.write_text(text, encoding="utf-8")
    print(f"Updated {lib_path}")
else:
    print("Standards-scope module already declared.")

if readme_path.exists():
    readme = readme_path.read_text(encoding="utf-8")
    begin = "<!-- STANDARDS-STATUS:BEGIN -->"
    end = "<!-- STANDARDS-STATUS:END -->"
    block = '''<!-- STANDARDS-STATUS:BEGIN -->
## Standards status

- **FIPS 203 ML-KEM:** validated against the imported NIST ACVP corpus.
- **RFC 9958:** engineering guidance traced; it is not treated as an
  executable protocol or conformance specification.
- **RFC 9180 HPKE:** implementation and vector validation pending.
- **draft-ietf-hpke-pq-05:** pinned experimental integration target;
  Internet-Draft status is preserved explicitly.

Passing ACVP vectors is not a claim of CMVP module validation.
<!-- STANDARDS-STATUS:END -->'''

    if begin in readme and end in readme:
        prefix = readme.split(begin, 1)[0]
        suffix = readme.split(end, 1)[1]
        readme = prefix + block + suffix
    else:
        readme = readme.rstrip() + "\n\n" + block + "\n"

    readme_path.write_text(readme, encoding="utf-8")
    print(f"Updated {readme_path}")
