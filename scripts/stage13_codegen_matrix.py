#!/usr/bin/env python3
"""Capture reproducible hashes of selected release binaries across installed Rust toolchains."""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, subprocess
from pathlib import Path

def sha(path:Path)->str: return hashlib.sha256(path.read_bytes()).hexdigest()
def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--output",type=Path,required=True); args=ap.parse_args(); args.output.mkdir(parents=True,exist_ok=True)
    rustup=shutil.which("rustup"); toolchains=[None]
    if rustup:
        names=[]
        for line in subprocess.run([rustup,"toolchain","list"],capture_output=True,text=True).stdout.splitlines():
            name=line.split()[0]
            if name.startswith(("stable","beta","nightly")): names.append(name)
        toolchains=names or [None]
    records=[]; failures=0
    for tc in toolchains:
        target=args.output/(tc or "default")/"target"; env=os.environ.copy(); env["CARGO_TARGET_DIR"]=str(target)
        cmd=(["rustup","run",tc] if tc else [])+["cargo","build","--release","--workspace","--bins","--locked"]
        p=subprocess.run(cmd,capture_output=True,text=True,env=env)
        log=args.output/(tc or "default")/"build.log"; log.parent.mkdir(parents=True,exist_ok=True); log.write_text(p.stdout+"\n"+p.stderr)
        bins=[]
        if p.returncode==0:
            release=target/"release"
            for path in sorted(release.iterdir() if release.exists() else []):
                if path.is_file() and os.access(path,os.X_OK) and "." not in path.name: bins.append({"name":path.name,"sha256":sha(path),"size":path.stat().st_size})
        else: failures+=1
        records.append({"toolchain":tc or "default","return_code":p.returncode,"binaries":bins})
    (args.output/"matrix.json").write_text(json.dumps({"schema_version":1,"records":records},indent=2)+"\n")
    lines=["# Compiler Codegen Matrix","","Binary hashes are change detectors, not proofs of constant-time behavior.",""]
    for r in records: lines += [f"## {r['toolchain']}","",f"Return code: `{r['return_code']}`",f"Captured binaries: `{len(r['binaries'])}`",""]
    (args.output/"matrix.md").write_text("\n".join(lines)+"\n")
    return 1 if failures else 0
if __name__=="__main__": raise SystemExit(main())
