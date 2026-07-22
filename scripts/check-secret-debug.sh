#!/usr/bin/env bash
set -euo pipefail

mkdir -p target

python3 - <<'PY'
from pathlib import Path
import re
import sys

derive_debug = re.compile(
    r"#\s*\[\s*derive\s*\((?P<traits>[^)]*)\)\s*\]"
)

declaration = re.compile(
    r"\b(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:struct|enum)\s+([A-Za-z_][A-Za-z0-9_]*)"
)

secret_name = re.compile(
    r"(secret|private|decapsulation|keypair|key_pair|"
    r"encapsulationoutput|encapsulation_output|seedmaterial|seed_material|"
    r"keygen(?:prompt|expected)?case|encapdecappromptcase|"
    r"hpkeexportvector|kpkedecryptoutput)",
    re.IGNORECASE,
)

secret_field = re.compile(
    r"\b(secret|private_key|private_seed|decapsulation_key|"
    r"shared_secret|expanded_private_key|traditional_private_key|"
    r"secret_key|sigma)\b",
    re.IGNORECASE,
)

block_comment = re.compile(r"/\*.*?\*/", re.DOTALL)

safe_error_type = re.compile(r"Error$")

findings = []

for path in Path("crates").rglob("*.rs"):
    lines = path.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines()

    index = 0

    while index < len(lines):
        match = derive_debug.search(lines[index])

        if not match or "Debug" not in match.group("traits"):
            index += 1
            continue

        derive_line = index
        probe = index + 1

        while probe < len(lines):
            stripped = lines[probe].strip()

            if not stripped or stripped.startswith("///") or stripped.startswith("#["):
                probe += 1
                continue

            decl = declaration.search(lines[probe])

            if not decl:
                break

            type_name = decl.group(1)

            if safe_error_type.search(type_name):
                break

            block_lines = [lines[probe]]
            brace_depth = lines[probe].count("{") - lines[probe].count("}")
            cursor = probe + 1

            while cursor < len(lines) and brace_depth > 0:
                block_lines.append(lines[cursor])
                brace_depth += lines[cursor].count("{")
                brace_depth -= lines[cursor].count("}")
                cursor += 1

            block = "\n".join(block_lines)
            code_only = block_comment.sub("", block)
            code_only = "\n".join(
                line.split("//", 1)[0] for line in code_only.splitlines()
            )

            if secret_name.search(type_name) or secret_field.search(code_only):
                context_start = max(0, derive_line - 2)
                context_end = min(len(lines), cursor)

                findings.append(
                    f"{path}:{derive_line + 1}: "
                    f"{type_name} derives Debug and appears secret-bearing\n"
                    + "\n".join(lines[context_start:context_end])
                    + "\n"
                )

            break

        index += 1

report = Path("target/stage8d-debug-findings.txt")
report.write_text("\n".join(findings), encoding="utf-8")

if findings:
    print(report.read_text(encoding="utf-8"))
    print(
        "Review required: remove Debug or add an explicitly redacted "
        "Debug implementation.",
        file=sys.stderr,
    )
    sys.exit(1)

print("No secret-bearing types derive Debug.")
PY
