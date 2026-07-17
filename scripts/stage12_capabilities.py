#!/usr/bin/env python3
"""Capture Stage 12 host capabilities without installing or downloading tools."""
from __future__ import annotations
import json, os, platform, shutil, subprocess, sys
from pathlib import Path

def output(command: list[str]) -> str | None:
    try:
        p=subprocess.run(command,capture_output=True,text=True,timeout=15)
        return (p.stdout or p.stderr).strip() if p.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None

def main() -> int:
    target=Path(sys.argv[1] if len(sys.argv)>1 else "target/stage12/capabilities.json")
    installed=[]
    rustup=shutil.which("rustup")
    if rustup:
        text=output([rustup,"toolchain","list"]) or ""
        installed=[line.split()[0] for line in text.splitlines() if line.strip()]
    perf=shutil.which("perf")
    valgrind=shutil.which("valgrind")
    record={
      "schema_version":1,
      "platform":platform.platform(),"system":platform.system(),
      "machine":platform.machine(),"processor":platform.processor(),
      "logical_cpus":os.cpu_count(),
      "tools":{
        "cargo":shutil.which("cargo"),"rustc":shutil.which("rustc"),
        "rustup":rustup,"perf":perf,"valgrind":valgrind,
        "llvm_objdump":shutil.which("llvm-objdump") or shutil.which("objdump")
      },
      "rust_toolchains":installed,
      "perf_available": bool(perf and platform.system()=="Linux"),
      "ctgrind_available": bool(valgrind and platform.system()=="Linux"),
      "notes":[
        "Tool absence is recorded as unsupported, never as a passing security result.",
        "Apple ARM64 does not provide Linux perf events; portable timing and machine-code gates still apply."
      ]
    }
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(record,indent=2)+"\n",encoding="utf-8")
    print(target)
    return 0
if __name__=="__main__": raise SystemExit(main())
