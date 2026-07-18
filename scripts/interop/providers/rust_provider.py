#!/usr/bin/env python3
import json, pathlib, subprocess, sys
root=pathlib.Path(__file__).resolve().parents[3]
req=json.load(sys.stdin)
cmd=["cargo","run","--quiet","-p","pqc-rs-test-harness","--bin","pqc-interop-rust"]
p=subprocess.run(cmd,cwd=root,input=json.dumps(req),text=True,capture_output=True)
if p.returncode:
 print(json.dumps({"ok":False,"error":p.stderr.strip() or p.stdout.strip()}));sys.exit(1)
print(p.stdout.strip())
