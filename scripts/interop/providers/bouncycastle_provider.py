#!/usr/bin/env python3
"""Bouncy Castle Java provider for PQC-rs interoperability."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[3]
BRIDGE_DIR = pathlib.Path(__file__).with_name("bouncycastle")

KEM_PARAMETER_SETS = [
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
]

DSA_PARAMETER_SETS = [
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
]

SLH_PARAMETER_SETS = [
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s",
    "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s",
    "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s",
    "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-256s",
    "SLH-DSA-SHAKE-256f",
]


def capabilities() -> list[dict[str, Any]]:
    return [
        {
            "algorithm": "ML-KEM",
            "parameter_sets": KEM_PARAMETER_SETS,
            "operations": [
                "kem-keygen",
                "kem-encaps",
                "kem-decaps",
            ],
            "properties": {
                "deterministic_keygen": "supported",
                "deterministic_encaps": "supported",
            },
        },
        {
            "algorithm": "ML-DSA",
            "parameter_sets": DSA_PARAMETER_SETS,
            "operations": [
                "dsa-keygen",
                "dsa-sign",
                "dsa-verify",
            ],
            "properties": {
                "seeded_keygen": "supported",
                "explicit_signing_randomness": "supported",
                "cross_verification": "supported",
            },
        },
        {
            "algorithm": "SLH-DSA",
            "parameter_sets": SLH_PARAMETER_SETS,
            "operations": [
                "slh-keygen",
                "slh-sign",
                "slh-verify",
                "slh-hash-sign",
                "slh-hash-verify",
            ],
            "properties": {
                "seeded_keygen": "supported",
                "explicit_signing_randomness": "supported",
                "context": "supported",
                "cross_verification": "supported",
            },
        },
    ]


def execute_primitive(request: dict[str, Any]) -> dict[str, Any]:
    raise RuntimeError(
        "Bouncy Castle primitive execution is not enabled in BC2.1"
    )


def main() -> int:
    try:
        request = json.load(sys.stdin)

        if request.get("protocol_version") != 1:
            raise ValueError("unsupported interoperability protocol version")

        action = request.get("action")

        if action == "capabilities":
            response = {
                "ok": True,
                "provider": "bouncycastle",
                "capabilities": capabilities(),
                "outputs": {
                    "provider": "bouncycastle",
                    "implementation": "Bouncy Castle Java",
                    "bridge": str(BRIDGE_DIR.relative_to(ROOT)),
                },
            }
        elif action == "execute":
            response = {
                "ok": True,
                "outputs": execute_primitive(request),
            }
        else:
            raise ValueError(f"unsupported action {action}")

        print(json.dumps(response, sort_keys=True))
        return 0

    except Exception as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": str(exc),
                },
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
