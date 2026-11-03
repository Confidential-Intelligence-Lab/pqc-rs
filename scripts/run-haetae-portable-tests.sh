#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

python3 - <<'PYTHON'
import os
import subprocess

toolchain = os.environ.get("HAETAE_CARGO_TOOLCHAIN", "").strip()
target = os.environ.get("HAETAE_CARGO_TARGET", "").strip()

cargo = ["cargo"]
if toolchain:
    cargo.append("+" + toolchain)

target_args = ["--target", target] if target else []

prefixes = (
    "api::api_regression_tests::",
    "arithmetic::tests::",
    "keygen_arithmetic::tests::",
    "decompose::tests::",
    "fixed_fft::tests::",
    "montgomery::tests::",
    "ntt::tests::",
)

result = subprocess.run(
    [
        *cargo, "test", "--locked", *target_args,
        "-p", "pqc-rs-haetae",
        "--lib", "--", "--list",
    ],
    check=True,
    capture_output=True,
    text=True,
)

names = []
for line in result.stdout.splitlines():
    if not line.endswith(": test"):
        continue
    name = line[:-len(": test")]
    if any(name.startswith(prefix) for prefix in prefixes):
        names.append(name)

if len(names) != 29:
    raise SystemExit(
        f"HAETAE_PORTABLE_TEST_COUNT_MISMATCH={len(names)} EXPECTED=29"
    )

for name in names:
    subprocess.run(
        [
            *cargo, "test", "--locked", *target_args,
            "-p", "pqc-rs-haetae",
            "--lib", name, "--", "--exact", "--quiet",
        ],
        check=True,
    )

print(f"HAETAE_PORTABLE_TESTS={len(names)}")
print("HAETAE_PORTABLE_TEST_STATUS=PASS")
PYTHON
