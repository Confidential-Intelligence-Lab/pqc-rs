#!/usr/bin/env python3
"""Idempotent A1.3.1 installer and catalog normalizer."""
from __future__ import annotations
import pathlib
import re

root = pathlib.Path(__file__).resolve().parents[1]
catalog = root / "compliance/catalog.toml"
if catalog.exists():
    text = catalog.read_text()
    # Normalize the transient A1.3 FIPS204 catalog shape while preserving all
    # other entries. The v2 engine accepts it either way, but canonical output
    # avoids future confusion.
    pattern = re.compile(
        r'\[\[document\]\]\nid = "FIPS204"\n(?P<body>.*?)(?=\n\[\[document\]\]|\Z)',
        re.DOTALL,
    )
    match = pattern.search(text)
    if match:
        canonical = '''[[document]]
id = "FIPS204"
title = "Module-Lattice-Based Digital Signature Standard"
kind = "normative"
source = "compliance/standards/fips204.toml"
status = "active"
published = "2024-08-13"
issuer = "NIST"
'''
        text = text[:match.start()] + canonical + text[match.end():]
        catalog.write_text(text.rstrip() + "\n")
print("A1.3.1 installed; catalog normalized when present.")
