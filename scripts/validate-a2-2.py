#!/usr/bin/env python3
"""Structural and executable validation for A2.2.

A small ABI-compatible mock library exercises the ctypes boundary without
claiming cryptographic interoperability. Real liboqs execution occurs in the
A2.2 CI workflow and on developer machines with a shared liboqs installation.
"""
from __future__ import annotations
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile
import tomllib

root = pathlib.Path(__file__).resolve().parents[1]
required = [
    "scripts/interop/providers/liboqs_provider.py",
    "scripts/configure-liboqs-interop.py",
    "scripts/install-a2-2.py",
    "scripts/interop/testing_mock_liboqs.c",
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

compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
if not compiler:
    raise SystemExit("a C compiler is required to validate the liboqs ABI adapter")
with tempfile.TemporaryDirectory(prefix="a22-") as tmp:
    tmpdir = pathlib.Path(tmp)
    suffix = ".dylib" if platform.system() == "Darwin" else ".so"
    library = tmpdir / f"liboqs{suffix}"
    command = [compiler]
    if platform.system() == "Darwin":
        command += ["-dynamiclib"]
    else:
        command += ["-shared", "-fPIC"]
    command += [str(root / "scripts/interop/testing_mock_liboqs.c"), "-o", str(library)]
    subprocess.run(command, check=True)

    env = {**os.environ, "OQS_LIBOQS_PATH": str(library)}
    request = json.dumps({"protocol_version": 1, "action": "capabilities"})
    completed = subprocess.run(
        [sys.executable, "scripts/interop/providers/liboqs_provider.py"], cwd=root,
        input=request, text=True, capture_output=True, env=env, check=False,
    )
    if completed.returncode != 0:
        print(completed.stderr, file=sys.stderr)
        raise SystemExit(completed.returncode)
    response = json.loads(completed.stdout)
    assert response["ok"] is True
    assert response["provider_version"] == "a2.2-mock"

    temp_manifest = root / "target/a2-2-validation-manifest.toml"
    temp_manifest.parent.mkdir(parents=True, exist_ok=True)
    text = (root / "interop/manifest.toml").read_text()
    marker = 'id = "liboqs"'
    start = text.index(marker)
    end = text.find("\n[[", start + len(marker))
    block = text[start:end]
    block = block.replace("enabled = false", "enabled = true", 1)
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
