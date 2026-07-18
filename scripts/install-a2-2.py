#!/usr/bin/env python3
"""Idempotently register the A2.2 liboqs provider suite."""
from __future__ import annotations
import pathlib

root = pathlib.Path(__file__).resolve().parents[1]
manifest = root / "interop/manifest.toml"
if not manifest.exists():
    raise SystemExit("interop/manifest.toml not found; install A2.1 first")
text = manifest.read_text()
if 'id = "liboqs"' not in text:
    raise SystemExit("A2.1 liboqs provider registration not found")
old_note = 'notes = "Adapter reserved for A2.2; enable only after liboqs and the adapter are installed."'
new_note = 'notes = "A2.2 ctypes adapter. Run python3 scripts/configure-liboqs-interop.py auto after installing a shared liboqs build."'
if old_note in text:
    text = text.replace(old_note, new_note, 1)
if 'id = "liboqs-smoke"' not in text:
    text = text.rstrip() + '''

[[suite]]
id = "liboqs-smoke"
title = "liboqs ML-KEM and ML-DSA adapter smoke interoperability"
vectors = ["interop/vectors/liboqs/*.json"]
providers = ["liboqs"]
required = false
comparison = "semantic"
'''
manifest.write_text(text)
print("A2.2 installed: liboqs adapter and smoke suite registered.")
