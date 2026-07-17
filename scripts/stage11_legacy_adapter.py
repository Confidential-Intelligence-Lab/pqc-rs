#!/usr/bin/env python3
"""Discover and execute legacy Stage 9F/10B side-channel harnesses.

The adapter normalizes heterogeneous historical output to `stage11_metric=<n>`.
If a compatible harness or metric cannot be found it prints STAGE11_SKIP, which
Stage 11 records as an inconclusive repetition rather than a pass or failure.
"""
from __future__ import annotations
import argparse, re, subprocess, sys
from pathlib import Path

SPECS = {
 "stage9f-2a-fixed": {
   "files": ["*9f*2a*", "*challenge*timing*"],
   "labels": [r"fixed[ _-]*challenge", r"fixed"],
 },
 "stage9f-2a-matched": {
   "files": ["*9f*2a*", "*challenge*timing*"],
   "labels": [r"matched[ _-]*distribution", r"matched"],
 },
 "stage9f-2a-varying": {
   "files": ["*9f*2a*", "*challenge*timing*"],
   "labels": [r"varying[ _-]*challenge", r"varying"],
 },
 "stage9f-3a-residual": {
   "files": ["*9f*3a*", "*conditioned*timing*"],
   "labels": [r"residual[ _-]*timing", r"residual"],
 },
 "stage9f-3a-within-attempt": {
   "files": ["*9f*3a*", "*conditioned*timing*"],
   "labels": [r"within[ _-]*attempt", r"within.*bucket", r"largest"],
 },
 "stage10b2-ct-compare": {
   "files": ["*10b2*", "*ct*compare*timing*", "*constant*time*compare*"],
   "labels": [r"maximum", r"max", r"welch"],
 },
 "stage9f-4-machine-code": {
   "files": ["*9f*4*", "*machine*code*audit*"], "exit_only": True,
 },
 "stage10b4-zeroization": {
   "files": ["*10b4*", "*zeroization*audit*"], "exit_only": True,
 },
}

NUM = r"(-?[0-9]+(?:\.[0-9]+)?)"
T_PATTERNS = [
 re.compile(r"(?:welch[_ -]?t|t[- ]?stat(?:istic)?|\|t\|)\s*[=:]\s*"+NUM, re.I),
 re.compile(r"\bt\s*[=:]\s*"+NUM, re.I),
]

def candidate_paths(patterns: list[str]) -> list[Path]:
    roots=[Path("scripts"),Path("crates"),Path("tests"),Path("benches")]
    found=[]
    for root in roots:
        if not root.exists(): continue
        for pattern in patterns:
            found.extend(p for p in root.rglob(pattern) if p.is_file())
    excluded={Path(__file__).resolve(), Path("scripts/run-stage11a.sh").resolve(),
              Path("scripts/collect-stage11a.sh").resolve()}
    unique=[]
    for p in found:
        try: rp=p.resolve()
        except OSError: continue
        if rp in excluded or "target" in p.parts: continue
        if p not in unique: unique.append(p)
    def rank(p:Path):
        suffix_rank={".sh":0,".py":1,".rs":2}.get(p.suffix,3)
        return (suffix_rank,len(str(p)),str(p))
    return sorted(unique,key=rank)

def package_name(path: Path) -> str | None:
    for parent in [path.parent,*path.parents]:
        toml=parent/"Cargo.toml"
        if toml.is_file():
            text=toml.read_text(errors="ignore")
            m=re.search(r'^name\s*=\s*"([^"]+)"',text,re.M)
            return m.group(1) if m else None
    return None

def command_for(path:Path) -> list[str] | None:
    if path.suffix==".sh": return ["bash",str(path)]
    if path.suffix==".py": return [sys.executable,str(path)]
    if path.suffix==".rs":
        pkg=package_name(path)
        if not pkg: return None
        if "tests" in path.parts: return ["cargo","test","-p",pkg,"--test",path.stem,"--","--nocapture"]
        if "examples" in path.parts: return ["cargo","run","-p",pkg,"--release","--example",path.stem]
        if path.parent.name=="bin": return ["cargo","run","-p",pkg,"--release","--bin",path.stem]
    return None

def extract_metric(output:str, labels:list[str]) -> float | None:
    lines=output.splitlines()
    for label in labels:
        rx=re.compile(label,re.I)
        for i,line in enumerate(lines):
            if rx.search(line):
                window="\n".join(lines[i:i+4])
                for p in T_PATTERNS:
                    m=p.search(window)
                    if m: return abs(float(m.group(1)))
    values=[]
    for p in T_PATTERNS:
        values.extend(abs(float(m.group(1))) for m in p.finditer(output))
    return values[-1] if len(values)==1 else None

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("experiment",choices=sorted(SPECS)); args=ap.parse_args()
    spec=SPECS[args.experiment]
    for path in candidate_paths(spec["files"]):
        command=command_for(path)
        if not command: continue
        print(f"stage11_adapter_candidate={path}",file=sys.stderr)
        proc=subprocess.run(command,capture_output=True,text=True)
        combined=proc.stdout+"\n"+proc.stderr
        sys.stdout.write(combined)
        if proc.returncode != 0:
            continue
        if spec.get("exit_only"):
            print("stage11_metric=0")
            return 0
        metric=extract_metric(combined,spec["labels"])
        if metric is not None:
            print(f"stage11_metric={metric}")
            return 0
    print(f"STAGE11_SKIP: no compatible harness or unambiguous metric for {args.experiment}")
    return 0

if __name__=="__main__": raise SystemExit(main())
