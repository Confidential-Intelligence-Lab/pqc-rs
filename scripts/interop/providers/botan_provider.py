#!/usr/bin/env python3
"""Reserved Botan adapter entry point for A2.3."""
import json, sys
json.load(sys.stdin)
print(json.dumps({"ok": False, "error": "Botan adapter is not implemented; keep provider disabled"}))
