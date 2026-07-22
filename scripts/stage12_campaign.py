#!/usr/bin/env python3
"""Orchestrate Stage 12 comprehensive side-channel validation."""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, os, shutil, subprocess, tarfile
from pathlib import Path

def run(cmd:list[str],log:Path,env=None)->int:
    p=subprocess.run(cmd,capture_output=True,text=True,env=env)
    log.parent.mkdir(parents=True,exist_ok=True)
    log.write_text("$ "+" ".join(cmd)+"\n\nSTDOUT\n"+p.stdout+"\nSTDERR\n"+p.stderr,encoding="utf-8")
    return p.returncode

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--profile",choices=["ci","portable","full","soak"],default="portable")
    ap.add_argument("--output",type=Path,default=Path("target/stage12")); args=ap.parse_args()
    cfg=json.loads(Path("sidechannel/stage12/profiles.json").read_text())["profiles"][args.profile]
    out=args.output; out.mkdir(parents=True,exist_ok=True); logs=out/"logs"; generated=out/"generated-manifests"
    run(["python3","scripts/stage12_capabilities.py",str(out/"capabilities.json")],logs/"capabilities.log")
    dirty=subprocess.run(["git","status","--porcelain"],capture_output=True,text=True).stdout.strip()
    preflight={"profile":args.profile,"captured_at_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
               "git_dirty":bool(dirty),"require_clean_git":cfg["require_clean_git"]}
    (out/"preflight.json").write_text(json.dumps(preflight,indent=2)+"\n")
    if cfg["require_clean_git"] and dirty:
        (out/"release-decision.txt").write_text("FAIL: full/soak profiles require a clean Git tree.\n")
        return 1
    if generated.exists(): shutil.rmtree(generated)
    generated.mkdir(parents=True)
    for src in sorted(Path("sidechannel/experiments").glob("*.json")):
        data=json.loads(src.read_text())
        if data.get("enabled"):
            data["repetitions"]=cfg["repetitions"] if data["parser"]["type"]=="regex" else 1
            data["policy"]["minimum_successful_repetitions"]=data["repetitions"]
            (generated/src.name).write_text(json.dumps(data,indent=2)+"\n")
    observed_core_rc=run(["python3","scripts/stage11_sidechannel.py","--experiments",str(generated),"--output",str(out/"core")],logs/"core.log")
    core_rc=observed_core_rc
    informational_statistical_findings=[]
    if not cfg.get("statistical_gating",True):
        report_path=out/"core"/"report.json"
        if report_path.is_file():
            report=json.loads(report_path.read_text())
            deterministic_failures=[]
            for experiment in report.get("experiments",[]):
                decision=experiment.get("summary",{}).get("decision","inconclusive")
                if "timing" in experiment.get("tags",[]):
                    if decision!="pass":
                        informational_statistical_findings.append({"id":experiment.get("id"),"decision":decision})
                elif decision!="pass":
                    deterministic_failures.append({"id":experiment.get("id"),"decision":decision})
            core_rc=0 if not deterministic_failures else 1
    compiler_rc=0
    if cfg["run_compiler_matrix"]:
        compiler_rc=run(["python3","scripts/stage12_compiler_matrix.py","--output",str(out/"compiler")],logs/"compiler.log")
    if cfg["run_microarchitectural_probes"]:
        run(["python3","scripts/stage12_perf_probe.py","--output",str(out/"microarchitectural"),"--runs",str(max(3,cfg["repetitions"])),
             "python3","scripts/stage11_legacy_adapter.py","stage10b2-ct-compare"],logs/"perf.log")
    decision="pass" if core_rc==0 and compiler_rc==0 else "fail"
    summary={"schema_version":1,"profile":args.profile,"decision":decision,"core_return_code":core_rc,
             "core_observed_return_code":observed_core_rc,"statistical_gating":cfg.get("statistical_gating",True),
             "informational_statistical_findings":informational_statistical_findings,
             "compiler_return_code":compiler_rc,"microarchitectural_gating":False,
             "statement":"Statistical and generated-code evidence is regression evidence, not a proof of constant-time execution."}
    (out/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
    (out/"summary.md").write_text(f"# Stage 12 Comprehensive Side-Channel Validation\n\n"
      f"- Profile: `{args.profile}`\n- Decision: **{decision}**\n- Core gate: `{core_rc}`\n"
      f"- Core observed return code: `{observed_core_rc}`\n- Statistical gating: `{cfg.get('statistical_gating',True)}`\n"
      f"- Compiler gate: `{compiler_rc}`\n\n"
      "Microarchitectural probes are informational until architecture-specific baselines and confidence intervals are established.\n",encoding="utf-8")
    hashes=[]
    for path in sorted(p for p in out.rglob("*") if p.is_file() and p.name!="SHA256SUMS"):
        hashes.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(out)}")
    (out/"SHA256SUMS").write_text("\n".join(hashes)+"\n")
    bundle=out.parent/f"stage12-{args.profile}-evidence.tar.gz"
    with tarfile.open(bundle,"w:gz") as tar: tar.add(out,arcname=f"stage12-{args.profile}")
    print(f"decision={decision}"); print(f"evidence={bundle}")
    return 0 if decision=="pass" else 1
if __name__=="__main__": raise SystemExit(main())
