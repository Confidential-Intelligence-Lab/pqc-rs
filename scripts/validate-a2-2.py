#!/usr/bin/env python3
"""Structural and executable validation for A2.2.

The validator exercises the current C bridge against a real shared liboqs
installation. Set OQS_PREFIX or OQS_LIBOQS_PATH when liboqs is not installed
under /usr/local or Homebrew's default prefix.
"""
from __future__ import annotations
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import tomllib

root = pathlib.Path(__file__).resolve().parents[1]
required = [
    "scripts/interop/providers/liboqs_provider.py",
    "scripts/interop/providers/liboqs_bridge.c",
    "scripts/configure-liboqs-interop.py",
    "scripts/install-a2-2.py",
    "docs/interoperability/liboqs.md",
    ".github/workflows/a2-liboqs.yml",
]
required.extend(f"interop/vectors/liboqs/{name}-roundtrip.json" for name in [
    "ml-kem-512", "ml-kem-768", "ml-kem-1024", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87"
])
missing = [p for p in required if not (root / p).exists()]
if missing:
    print("missing files:", *missing, sep="\n- ", file=sys.stderr)
    raise SystemExit(1)

with (root / "interop/manifest.toml").open("rb") as handle:
    manifest = tomllib.load(handle)
assert any(p.get("id") == "liboqs" for p in manifest.get("provider", []))
assert any(s.get("id") == "liboqs-smoke" for s in manifest.get("suite", []))

vectors = []
for path in sorted((root / "interop/vectors/liboqs").glob("*.json")):
    value = json.loads(path.read_text())
    assert value["suite"] == "liboqs-smoke"
    vectors.append(value)
assert len(vectors) == 6
assert len({v["vector_id"] for v in vectors}) == 6

with tempfile.TemporaryDirectory(prefix="a22-") as tmp:
    tmpdir = pathlib.Path(tmp)
    env = os.environ.copy()
    request = json.dumps({"protocol_version": 1, "action": "capabilities"})
    completed = subprocess.run(
        [sys.executable, "scripts/interop/providers/liboqs_provider.py"], cwd=root,
        input=request, text=True, capture_output=True, env=env, check=False,
    )
    if completed.returncode != 0:
        print(completed.stdout, file=sys.stderr)
        print(completed.stderr, file=sys.stderr)
        raise SystemExit(completed.returncode)
    response = json.loads(completed.stdout)
    assert response["ok"] is True
    assert response["provider"] == "liboqs"
    capabilities = response["capabilities"]
    assert {item["algorithm"] for item in capabilities} == {"ML-KEM", "ML-DSA"}

    temp_manifest = root / "target/a2-2-validation-manifest.toml"
    temp_manifest.parent.mkdir(parents=True, exist_ok=True)
    text = (root / "interop/manifest.toml").read_text()
    marker = 'id = "liboqs"'
    start = text.index(marker)
    end = text.find("\n[[", start + len(marker))
    if end < 0:
        end = len(text)
    block = text[start:end]
    if "enabled = false" in block:
        block = block.replace("enabled = false", "enabled = true", 1)
    elif "enabled = true" not in block:
        raise SystemExit("liboqs provider block has no enabled field")
    text = text[:start] + block + text[end:]
    temp_manifest.write_text(text)
    completed = subprocess.run(
        [sys.executable, "scripts/interop_engine.py", "report", "--manifest", str(temp_manifest),
         "--output", str(tmpdir / "report"), "--provider", "liboqs", "--suite", "liboqs-smoke", "--strict"],
        cwd=root, text=True, capture_output=True, env=env, check=False,
    )
    print(completed.stdout, end="")
    if completed.returncode != 0:
        print(completed.stderr, file=sys.stderr)
        raise SystemExit(completed.returncode)
    report = json.loads((tmpdir / "report/report.json").read_text())
    assert report["decision"] == "pass"
    assert report["summary"]["executed"] == 6
    assert report["summary"]["passed"] == 6
    assert report["summary"]["failed"] == 0
    temp_manifest.unlink(missing_ok=True)

print("A2.2 validation: pass")
