#!/usr/bin/env python3
"""Optional Linux perf probe. Produces evidence but does not invent thresholds."""
from __future__ import annotations
import argparse, csv, json, platform, shutil, subprocess
from pathlib import Path

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--output",type=Path,required=True)
    ap.add_argument("--runs",type=int,default=3); ap.add_argument("command",nargs=argparse.REMAINDER)
    args=ap.parse_args(); args.output.mkdir(parents=True,exist_ok=True)
    perf=shutil.which("perf")
    report={"schema_version":1,"supported":False,"runs":[],"classification":"informational"}
    if platform.system()!="Linux" or not perf:
        report["reason"]="Linux perf is unavailable on this host"
    elif not args.command:
        report["reason"]="no probe command supplied"
    else:
        report["supported"]=True
        events="cycles,instructions,branches,branch-misses,cache-references,cache-misses"
        for i in range(1,args.runs+1):
            cmd=[perf,"stat","-x,","-e",events,"--",*args.command]
            p=subprocess.run(cmd,capture_output=True,text=True)
            parsed={}
            for row in csv.reader(p.stderr.splitlines()):
                if len(row)>=3 and row[0].strip().replace(".","",1).isdigit():
                    parsed[row[2].strip()]=float(row[0])
            report["runs"].append({"repetition":i,"return_code":p.returncode,"events":parsed,
                                   "stdout":p.stdout,"stderr":p.stderr})
        report["decision"]="collected" if all(r["return_code"]==0 for r in report["runs"]) else "probe-failed"
    path=args.output/"perf-probe.json"; path.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(path)
    return 0
if __name__=="__main__": raise SystemExit(main())
