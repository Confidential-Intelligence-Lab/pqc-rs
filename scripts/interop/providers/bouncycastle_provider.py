#!/usr/bin/env python3
"""Bouncy Castle Java provider for PQC-rs interoperability."""

from __future__ import annotations

import json
import os
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
            ],
            "properties": {
                "seeded_keygen": "supported",
                "explicit_signing_randomness": "supported",
                "context": "supported",
                "cross_verification": "supported",
            },
        },
    ]


def bc_jar() -> pathlib.Path:
    override = os.environ.get("BC_JAVA_JAR")
    if override:
        jar = pathlib.Path(override).expanduser().resolve()
    else:
        jar = pathlib.Path(
            "/tmp/pqc-rs-bc-audit/bc-java/prov/build/libs/"
            "bcprov-jdk18on-1.87-SNAPSHOT.jar"
        )

    if not jar.is_file():
        raise RuntimeError(
            "Bouncy Castle provider jar not found; "
            "set BC_JAVA_JAR to bcprov-jdk18on"
        )

    return jar


def bridge_classes() -> pathlib.Path:
    return ROOT / "target" / "interop" / "bouncycastle-classes"


def bridge_source() -> pathlib.Path:
    return BRIDGE_DIR / "BouncyCastleInterop.java"


def ensure_bridge() -> tuple[pathlib.Path, pathlib.Path]:
    jar = bc_jar()
    classes = bridge_classes()
    source = bridge_source()
    class_file = classes / "BouncyCastleInterop.class"

    classes.mkdir(parents=True, exist_ok=True)

    rebuild = (
        not class_file.is_file()
        or class_file.stat().st_mtime < source.stat().st_mtime
    )

    if rebuild:
        completed = subprocess.run(
            [
                "javac",
                "-cp",
                str(jar),
                "-d",
                str(classes),
                str(source),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                completed.stderr.strip()
                or "failed to compile Bouncy Castle bridge"
            )

    return jar, classes


def run_bridge(
    operation: str,
    parameter_set: str,
    inputs: dict[str, Any],
) -> dict[str, Any]:
    jar, classes = ensure_bridge()

    arguments = [
        "java",
        "-cp",
        f"{jar}:{classes}",
        "BouncyCastleInterop",
        operation,
        parameter_set,
    ]

    if operation == "kem-keygen":
        arguments.extend([
            str(inputs["d"]),
            str(inputs["z"]),
        ])
    elif operation == "kem-encaps":
        arguments.extend([
            str(inputs["public_key"]),
            str(inputs["m"]),
        ])
    elif operation == "kem-decaps":
        arguments.extend([
            str(inputs["secret_key"]),
            str(inputs["ciphertext"]),
        ])
    elif operation == "slh-keygen":
        arguments.extend([
            str(inputs["seed"]),
        ])
    elif operation == "slh-sign":
        arguments.extend([
            str(inputs["secret_key"]),
            str(inputs["message"]),
            str(inputs["context"]),
        ])
    elif operation == "slh-verify":
        arguments.extend([
            str(inputs["public_key"]),
            str(inputs["message"]),
            str(inputs["context"]),
            str(inputs["signature"]),
        ])
    elif operation == "dsa-keygen":
        arguments.extend([
            str(inputs["xi"]),
        ])
    elif operation == "dsa-sign":
        arguments.extend([
            str(inputs["secret_key"]),
            str(inputs["message"]),
            str(inputs["context"]),
            str(inputs["randomness"]),
        ])
    elif operation == "dsa-verify":
        arguments.extend([
            str(inputs["public_key"]),
            str(inputs["message"]),
            str(inputs["context"]),
            str(inputs["signature"]),
        ])
    else:
        raise ValueError(
            f"unsupported Bouncy Castle operation {operation}"
        )

    completed = subprocess.run(
        arguments,
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    if completed.returncode != 0:
        raise RuntimeError(
            completed.stderr.strip()
            or completed.stdout.strip()
            or f"Bouncy Castle bridge exited with {completed.returncode}"
        )

    value = completed.stdout.strip()

    if operation == "kem-keygen":
        public_key, secret_key = value.split(":", 1)
        return {
            "public_key": public_key,
            "secret_key": secret_key,
        }

    if operation == "kem-encaps":
        ciphertext, shared_secret = value.split(":", 1)
        return {
            "ciphertext": ciphertext,
            "shared_secret": shared_secret,
        }

    if operation == "kem-decaps":
        return {
            "shared_secret": value,
        }

    if operation == "dsa-keygen":
        public_key, secret_key = value.split(":", 1)
        return {
            "public_key": public_key,
            "secret_key": secret_key,
        }

    if operation == "dsa-sign":
        return {
            "signature": value,
        }

    if operation == "dsa-verify":
        return {
            "valid": value.lower() == "true",
        }

    if operation == "slh-keygen":
        public_key, secret_key = value.split(":", 1)
        return {
            "public_key": public_key,
            "secret_key": secret_key,
        }

    if operation == "slh-sign":
        return {
            "signature": value,
        }

    if operation == "slh-verify":
        return {
            "valid": value.lower() == "true",
        }

    raise AssertionError("unreachable")


def execute_primitive(request: dict[str, Any]) -> dict[str, Any]:
    return run_bridge(
        str(request["operation"]),
        str(request["parameter_set"]),
        dict(request.get("inputs", {})),
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
