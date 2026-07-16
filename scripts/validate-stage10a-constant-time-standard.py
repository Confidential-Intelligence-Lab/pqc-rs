#!/usr/bin/env python3
"""Validate that Stage 10A constant-time governance files are present."""

from pathlib import Path

REQUIRED = [
    Path("docs/security/CONSTANT_TIME_ENGINEERING.md"),
    Path("docs/security/CONSTANT_TIME_REVIEW_CHECKLIST.md"),
    Path("docs/security/SECURITY_CRITICAL_REVIEW_POLICY.md"),
    Path(".github/PULL_REQUEST_TEMPLATE_SECURITY.md"),
]

def main() -> None:
    missing = [str(path) for path in REQUIRED if not path.is_file()]

    for path in REQUIRED:
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            if len(text.strip()) < 200:
                missing.append(f"{path} is unexpectedly short")

    if missing:
        print("Stage 10A validation failed:")
        for item in missing:
            print(f"  {item}")
        raise SystemExit(1)

    print("Stage 10A constant-time engineering standard validation passed.")
    for path in REQUIRED:
        print(f"  {path}")

if __name__ == "__main__":
    main()
