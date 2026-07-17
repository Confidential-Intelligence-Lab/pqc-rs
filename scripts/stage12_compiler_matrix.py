#!/usr/bin/env python3
"""Run no-network compiler-diversity checks using only installed Rust toolchains."""
from __future__ import annotations
import argparse, json, shutil, subprocess
from pathlib import Path

def run(cmd:list[str],timeout:int=1800)->dict:
    try:
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout)
        return {"command":cmd,"return_code":p.returncode,"stdout":p.stdout,"stderr":p.stderr,
                "status":"pass" if p.returncode==0 else "fail"}
    except subprocess.TimeoutExpired as e:
        return {"command":cmd,"status":"timeout","error":str(e)}
    except OSError as e:
        return {"command":cmd,"status":"launch-failed","error":str(e)}

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--output",type=Path,required=True)
    ap.add_argument("--toolchains",nargs="+",default=["stable","beta","nightly"])
    args=ap.parse_args(); args.output.mkdir(parents=True,exist_ok=True)
    rustup=shutil.which("rustup"); installed=set()
    if rustup:
        p=subprocess.run([rustup,"toolchain","list"],capture_output=True,text=True)
        installed={line.split()[0].split("-")[0] for line in p.stdout.splitlines() if line.strip()}
    rows=[]
    for tc in args.toolchains:
        if not rustup or tc not in installed:
            rows.append({"toolchain":tc,"status":"unsupported","reason":"toolchain not installed; no network installation attempted"})
            continue
        checks=[]
        checks.append(run(["cargo",f"+{tc}","check","--workspace","--all-targets","--all-features","--locked"]))
        if tc=="stable":
            checks.append(run(["cargo",f"+{tc}","test","--workspace","--all-features","--locked"]))
            checks.append(run(["cargo",f"+{tc}","clippy","--workspace","--all-targets","--all-features","--locked","--","-D","warnings"]))
        status="pass" if all(c["status"]=="pass" for c in checks) else "fail"
        rows.append({"toolchain":tc,"status":status,"checks":checks})
    report={"schema_version":1,"toolchains":rows,
            "decision":"pass" if any(r["toolchain"]=="stable" and r["status"]=="pass" for r in rows) else "fail"}
    (args.output/"compiler-matrix.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    lines=["# Stage 12 Compiler Matrix","","| Toolchain | Status |","|---|---:|"]
    lines += [f"| `{r['toolchain']}` | **{r['status']}** |" for r in rows]
    (args.output/"compiler-matrix.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    return 0 if report["decision"]=="pass" else 1
if __name__=="__main__": raise SystemExit(main())
