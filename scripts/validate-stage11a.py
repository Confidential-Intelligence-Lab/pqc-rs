#!/usr/bin/env python3
from __future__ import annotations
import json, subprocess, sys, tempfile
from pathlib import Path

runner=Path("scripts/stage11_sidechannel.py")
adapter=Path("scripts/stage11_legacy_adapter.py")
manifest_dir=Path("sidechannel/experiments")
assert runner.is_file() and adapter.is_file()
expected={"stage9f-2a-fixed","stage9f-2a-matched","stage9f-2a-varying",
          "stage9f-3a-residual","stage9f-3a-within-attempt","stage10b2-ct-compare",
          "stage9f-4-machine-code","stage10b4-zeroization"}
loaded={}
for path in manifest_dir.glob("*.json"):
    data=json.loads(path.read_text())
    if data.get("enabled"): loaded[data["id"]]=data
assert expected <= loaded.keys(), expected-loaded.keys()

with tempfile.TemporaryDirectory() as td:
    temp=Path(td); ex=temp/"experiments"; ex.mkdir(); out=temp/"out"
    passing={"schema_version":1,"id":"synthetic-max","description":"self test",
      "command":[sys.executable,"-c","print('stage11_metric=1.25')"],
      "working_directory":".","repetitions":2,"timeout_seconds":10,
      "parser":{"type":"regex","pattern":"stage11_metric=(-?[0-9]+(?:\\.[0-9]+)?)","absolute":True},
      "policy":{"maximum":4.5,"minimum_successful_repetitions":2},"enabled":True}
    positive={**passing,"id":"synthetic-min","policy":{"minimum":4.5,"minimum_successful_repetitions":2},
              "command":[sys.executable,"-c","print('stage11_metric=8.0')"]}
    skipped={**passing,"id":"synthetic-skip","command":[sys.executable,"-c","print('STAGE11_SKIP: fixture')"],
             "parser":{**passing["parser"],"skip_pattern":"^STAGE11_SKIP:"}}
    for item in [passing,positive,skipped]:
        (ex/f"{item['id']}.json").write_text(json.dumps(item))
    proc=subprocess.run([sys.executable,str(runner),"--experiments",str(ex),"--output",str(out)])
    assert proc.returncode==2
    report=json.loads((out/"report.json").read_text())
    decisions={x["id"]:x["summary"]["decision"] for x in report["experiments"]}
    assert decisions=={"synthetic-max":"pass","synthetic-min":"pass","synthetic-skip":"inconclusive"}
print("Stage 11A manifest wiring self-validation passed.")
