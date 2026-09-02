#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[3]

SRC = pathlib.Path(__file__).with_name(
    "openssl_bridge.c"
)

BIN = (
    ROOT
    / "target"
    / "interop-openssl"
    / "openssl_bridge"
)

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

OPERATIONS = [
    "kem-keygen",
    "kem-encaps",
    "kem-decaps",
    "dsa-keygen",
    "dsa-sign",
    "dsa-verify",
]


def openssl_prefix() -> pathlib.Path | None:

    configured = os.environ.get(
        "OPENSSL_PREFIX"
    )

    if configured:
        return pathlib.Path(configured)

    brew = shutil.which("brew")

    if brew:
        result = subprocess.run(
            [brew, "--prefix", "openssl@3"],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            return pathlib.Path(
                result.stdout.strip()
            )

    for candidate in (
        pathlib.Path(
            "/opt/homebrew/opt/openssl@3"
        ),
        pathlib.Path(
            "/usr/local/opt/openssl@3"
        ),
    ):
        if (
            candidate
            / "include"
            / "openssl"
            / "evp.h"
        ).exists():
            return candidate

    return None


def compile_flags() -> list[str]:

    prefix = openssl_prefix()

    if prefix is not None:
        flags = [
            "-I",
            str(prefix / "include"),
            "-L",
            str(prefix / "lib"),
            f"-Wl,-rpath,{prefix / 'lib'}",
            "-lcrypto",
        ]

        return flags

    pkg_config = shutil.which(
        "pkg-config"
    )

    if pkg_config:
        result = subprocess.run(
            [
                pkg_config,
                "--cflags",
                "--libs",
                "openssl",
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            return shlex.split(
                result.stdout
            )

    return ["-lcrypto"]


def ensure_bridge() -> pathlib.Path:

    BIN.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    rebuild = (
        not BIN.exists()
        or BIN.stat().st_mtime
        < SRC.stat().st_mtime
    )

    if rebuild:

        command = [
            os.environ.get("CC", "cc"),
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(SRC),
        ]

        command.extend(
            compile_flags()
        )

        command.extend(
            [
                "-o",
                str(BIN),
            ]
        )

        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
        )

        if completed.returncode != 0:
            raise RuntimeError(
                completed.stderr.strip()
                or "failed to compile OpenSSL bridge"
            )

    return BIN


def run_bridge(
    operation: str,
    parameter_set: str,
    inputs: dict[str, Any],
) -> dict[str, Any]:

    if parameter_set not in (
        KEM_PARAMETER_SETS
        + DSA_PARAMETER_SETS
        + ["OpenSSL"]
    ):
        raise ValueError(
            f"unsupported parameter set "
            f"{parameter_set}"
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

    elif operation == "dsa-keygen":
        arguments.append(
            str(inputs["xi"])
        )

    elif operation == "dsa-sign":
        arguments.extend(
            [
                str(inputs["secret_key"]),
                str(inputs["message"]),
                str(inputs.get("context", "")),
                str(inputs["randomness"]),
            ]
        )

    elif operation == "dsa-verify":
        arguments.extend(
            [
                str(inputs["public_key"]),
                str(inputs["message"]),
                str(inputs.get("context", "")),
                str(inputs["signature"]),
            ]
        )

    completed = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
    )

    if completed.returncode != 0:
        raise RuntimeError(
            completed.stderr.strip()
            or (
                "OpenSSL bridge exited with "
                f"{completed.returncode}"
            )
        )

    outputs: dict[str, Any] = {}

    for line in completed.stdout.splitlines():

        if "=" not in line:
            continue

        key, value = line.split(
            "=",
            1,
        )

        outputs[key] = (
            value == "true"
            if key == "valid"
            else value
        )

    return outputs


def capabilities() -> list[dict[str, Any]]:

    ensure_bridge()

    return [
        {
            "algorithm": "ML-KEM",
            "parameter_sets": KEM_PARAMETER_SETS,
            "operations": [
                "kem-keygen",
                "kem-encaps",
                "kem-decaps",
            ],
        },
        {
            "algorithm": "ML-DSA",
            "parameter_sets": DSA_PARAMETER_SETS,
            "operations": [
                "dsa-keygen",
                "dsa-sign",
                "dsa-verify",
            ],
        },
    ]


def main() -> int:

    try:

        request = json.load(
            sys.stdin
        )

        if (
            request.get("action")
            == "capabilities"
        ):
            version = run_bridge(
                "version",
                "OpenSSL",
                {},
            ).get(
                "version",
                "unknown",
            )

            response = {
                "ok": True,
                "provider": "openssl",
                "capabilities": capabilities(),
                "outputs": {
                    "provider": "openssl",
                    "version": version,
                    "operations": OPERATIONS,
                },
            }

        else:
            response = {
                "ok": True,
                "outputs": run_bridge(
                    str(
                        request[
                            "operation"
                        ]
                    ),
                    str(
                        request[
                            "parameter_set"
                        ]
                    ),
                    dict(
                        request.get(
                            "inputs",
                            {},
                        )
                    ),
                ),
            }

        print(
            json.dumps(
                response,
                sort_keys=True,
            )
        )

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
