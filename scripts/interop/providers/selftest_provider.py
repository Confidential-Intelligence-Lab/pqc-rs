#!/usr/bin/env python3
"""Reference provider for validating the A2.1 JSON protocol itself."""
from __future__ import annotations
import hashlib
import json
import sys

PROTOCOL_VERSION = 1


def emit(value: dict) -> None:
    print(json.dumps(value, sort_keys=True), flush=True)


def main() -> int:
    try:
        request = json.load(sys.stdin)
        if request.get("protocol_version") != PROTOCOL_VERSION:
            emit({"ok": False, "error": "unsupported protocol version"})
            return 0
        action = request.get("action")
        if action == "capabilities":
            emit({
                "ok": True,
                "protocol_version": PROTOCOL_VERSION,
                "provider": "selftest",
                "capabilities": [
                    {"algorithm": "framework.echo", "parameter_sets": ["sha256"], "operations": ["digest"]}
                ],
            })
            return 0
        if action != "execute":
            emit({"ok": False, "error": f"unsupported action: {action}"})
            return 0
        case = request.get("case", {})
        if (case.get("algorithm"), case.get("parameter_set"), case.get("operation")) != (
            "framework.echo", "sha256", "digest"
        ):
            emit({"ok": False, "error": "unsupported case"})
            return 0
        message = bytes.fromhex(case["inputs"]["message"])
        emit({"ok": True, "outputs": {"digest": hashlib.sha256(message).hexdigest().upper()}})
        return 0
    except Exception as exc:  # protocol boundary must return structured failure
        emit({"ok": False, "error": f"provider exception: {exc}"})
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
