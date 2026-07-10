\
#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/pqc-ml-kem/src/intermediate_values.rs")
if not path.exists():
    raise SystemExit(f"{path} not found; run this script from the repository root")

text = path.read_text(encoding="utf-8")

old = (
    "        let seed_material = "
    "kpke_keygen::expand_keygen_seed(&keygen_seed);\n"
)
new = (
    "        let seed_material = "
    "kpke_keygen::expand_keygen_seed_for_parameter_set(\n"
    "            parameter_set,\n"
    "            &keygen_seed,\n"
    "        );\n"
)

if new in text:
    print("Fixture seed expansion is already parameter-set aware.")
elif old in text:
    text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8")
    print(f"Patched {path}")
else:
    raise SystemExit(
        "Could not locate the fixture seed-expansion call in intermediate_values.rs"
    )
