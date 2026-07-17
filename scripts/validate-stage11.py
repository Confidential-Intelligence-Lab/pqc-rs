#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

runner = Path("scripts/stage11_sidechannel.py")
example = Path("sidechannel/experiments/example.json")

assert runner.is_file()
assert example.is_file()
manifest = json.loads(example.read_text(encoding="utf-8"))
assert manifest["schema_version"] == 1
assert manifest["enabled"] is False

with tempfile.TemporaryDirectory() as temporary:
    temp = Path(temporary)
    experiments = temp / "experiments"
    experiments.mkdir()
    command = [
        sys.executable,
        "-c",
        "print('welch_t=1.25')",
    ]
    synthetic = {
        "schema_version": 1,
        "id": "synthetic-self-test",
        "description": "Runner self-test",
        "command": command,
        "working_directory": ".",
        "repetitions": 2,
        "timeout_seconds": 10,
        "parser": {
            "type": "regex",
            "pattern": "welch_t=(-?[0-9]+(?:\\.[0-9]+)?)",
            "metric": "welch_t",
            "absolute": True,
        },
        "policy": {
            "maximum": 4.5,
            "minimum_successful_repetitions": 2,
        },
        "tags": ["self-test"],
        "enabled": True,
    }
    (experiments / "synthetic.json").write_text(
        json.dumps(synthetic), encoding="utf-8"
    )
    output = temp / "output"
    proc = subprocess.run(
        [
            sys.executable,
            str(runner),
            "--experiments",
            str(experiments),
            "--output",
            str(output),
        ],
        check=False,
    )
    assert proc.returncode == 0
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    summary = report["experiments"][0]["summary"]
    assert summary["decision"] == "pass"
    assert summary["maximum"] == 1.25

print("Stage 11 framework self-validation passed.")
