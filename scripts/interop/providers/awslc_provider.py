#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC = pathlib.Path(__file__).with_name("awslc_bridge.c")
BIN = ROOT / "target" / "interop" / "awslc_bridge"

KEM_PARAMETER_SETS = [
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
]

OPERATIONS = [
    "kem-keygen",
    "kem-encaps",
    "kem-decaps",
]


def source_root() -> pathlib.Path:
    configured = os.environ.get("AWSLC_SRC")
    if configured:
        return pathlib.Path(configured)

    return ROOT / "target" / "interop" / "aws-lc-src"


def prefix() -> pathlib.Path:
    configured = os.environ.get("AWSLC_PREFIX")
    if configured:
        return pathlib.Path(configured)

    return ROOT / "target" / "interop" / "aws-lc-install"


def ensure_bridge() -> pathlib.Path:
    aws_src = source_root()
    install_prefix = prefix()

    kem_header = (
        aws_src
        / "crypto"
        / "fipsmodule"
        / "ml_kem"
        / "ml_kem.h"
    )
    library = install_prefix / "lib" / "libcrypto.a"

    if not kem_header.exists():
        raise RuntimeError(
            f"AWS-LC ML-KEM header not found: {kem_header}"
        )

    if not library.exists():
        raise RuntimeError(
            f"AWS-LC static library not found: {library}"
        )

    BIN.parent.mkdir(parents=True, exist_ok=True)

    rebuild = (
        not BIN.exists()
        or BIN.stat().st_mtime < SRC.stat().st_mtime
        or BIN.stat().st_mtime < kem_header.stat().st_mtime
        or BIN.stat().st_mtime < library.stat().st_mtime
    )

    if rebuild:
        compiler = os.environ.get("CC", "cc")

        command = [
            compiler,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(aws_src),
            "-I",
            str(install_prefix / "include"),
            str(SRC),
            str(library),
            "-lpthread",
        ]

        if sys.platform == "darwin":
            command.extend(
                [
                    "-framework",
                    "Security",
                    "-framework",
                    "CoreFoundation",
                ]
            )
        else:
            command.append("-ldl")

        command.extend(["-o", str(BIN)])

        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
        )

        if completed.returncode != 0:
            raise RuntimeError(
                completed.stderr.strip()
                or "failed to compile AWS-LC bridge"
            )

    return BIN


def run_bridge(
    operation: str,
    parameter_set: str,
    inputs: dict[str, Any],
) -> dict[str, Any]:
    if parameter_set not in KEM_PARAMETER_SETS:
        raise ValueError(
            f"unsupported parameter set {parameter_set}"
        )

    arguments = [
        str(ensure_bridge()),
        operation,
        parameter_set,
    ]

    if operation == "kem-keygen":
        arguments.extend(
            [
                str(inputs["d"]),
                str(inputs["z"]),
            ]
        )
    elif operation == "kem-encaps":
        arguments.extend(
            [
                str(inputs["public_key"]),
                str(inputs["m"]),
            ]
        )
    elif operation == "kem-decaps":
        arguments.extend(
            [
                str(inputs["secret_key"]),
                str(inputs["ciphertext"]),
            ]
        )
    else:
        raise ValueError(
            f"unsupported operation {operation}"
        )

    completed = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
    )

    if completed.returncode != 0:
        raise RuntimeError(
            completed.stderr.strip()
            or f"AWS-LC bridge exited with {completed.returncode}"
        )

    outputs: dict[str, Any] = {}

    for line in completed.stdout.splitlines():
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        outputs[key] = value

    return outputs


def capabilities() -> list[dict[str, Any]]:
    ensure_bridge()

    return [
        {
            "algorithm": "ML-KEM",
            "parameter_sets": KEM_PARAMETER_SETS,
            "operations": OPERATIONS,
        }
    ]


def execute_primitive(
    request: dict[str, Any],
) -> dict[str, Any]:
    return run_bridge(
        str(request["operation"]),
        str(request["parameter_set"]),
        dict(request.get("inputs", {})),
    )


def main() -> int:
    try:
        request = json.load(sys.stdin)
        action = request.get("action")

        if action == "capabilities":
            response = {
                "ok": True,
                "provider": "awslc",
                "capabilities": capabilities(),
                "outputs": {
                    "provider": "awslc",
                    "operations": OPERATIONS,
                },
            }
        else:
            response = {
                "ok": True,
                "outputs": execute_primitive(request),
            }

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
