#!/usr/bin/env python3
"""Enable, disable, or auto-configure the liboqs interoperability provider."""
from __future__ import annotations
import argparse
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[1]
manifest = root / "interop/manifest.toml"
provider = root / "scripts/interop/providers/liboqs_provider.py"


def available() -> tuple[bool, str]:
    completed = subprocess.run(
        [sys.executable, str(provider)],
        cwd=root,
        input=json.dumps({"protocol_version": 1, "action": "capabilities"}),
        text=True,
        capture_output=True,
        check=False,
    )
    try:
        response = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return False, completed.stderr.strip() or completed.stdout.strip()
    if not response.get("ok"):
        return False, str(response.get("error", "provider unavailable"))
    return True, f"liboqs {response.get('provider_version', 'unknown')} at {response.get('library', 'unknown')}"


def replace_enabled(text: str, value: bool) -> str:
    marker = 'id = "liboqs"'
    start = text.find(marker)
    if start < 0:
        raise SystemExit("liboqs provider block not found in interop/manifest.toml")
    end = text.find("\n[[", start + len(marker))
    if end < 0:
        end = len(text)
    block = text[start:end]
    if "enabled = true" in block:
        updated = block.replace("enabled = true", f"enabled = {str(value).lower()}", 1)
    elif "enabled = false" in block:
        updated = block.replace("enabled = false", f"enabled = {str(value).lower()}", 1)
    else:
        raise SystemExit("liboqs provider block has no enabled field")
    return text[:start] + updated + text[end:]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["auto", "enable", "disable"], nargs="?", default="auto")
    args = parser.parse_args()
    ok, detail = available()
    if args.mode == "enable" and not ok:
        print(f"cannot enable liboqs: {detail}", file=sys.stderr)
        return 1
    enable = ok if args.mode == "auto" else args.mode == "enable"
    manifest.write_text(replace_enabled(manifest.read_text(), enable))
    print(f"liboqs provider enabled={str(enable).lower()}: {detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
