#!/usr/bin/env python3
"""Reserved liboqs adapter entry point for A2.2."""
import json, sys
json.load(sys.stdin)
print(json.dumps({"ok": False, "error": "liboqs adapter is not implemented; keep provider disabled"}))
