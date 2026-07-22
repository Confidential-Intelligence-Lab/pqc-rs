#!/usr/bin/env python3
"""Orchestrate Stage 13 formal-assurance preparation and release evidence."""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, os, shutil, subprocess, tarfile
from pathlib import Path

def run(name:str,cmd:list[str],out:Path,required:bool=True,env=None)->dict:
    p=subprocess.run(cmd,capture_output=True,text=True,env=env)
    log=out/"logs"/f"{name}.log"; log.parent.mkdir(parents=True,exist_ok=True)
    log.write_text("$ "+" ".join(cmd)+"\n\nSTDOUT\n"+p.stdout+"\nSTDERR\n"+p.stderr,encoding="utf-8")
    return {"id":name,"command":cmd,"return_code":p.returncode,"required":required,"status":"pass" if p.returncode==0 else ("fail" if required else "informational-failure")}

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--profile",choices=["portable","review","release"],default="portable"); ap.add_argument("--output",type=Path,required=True); args=ap.parse_args()
    cfg=json.loads(Path("assurance/stage13/profiles.json").read_text())["profiles"][args.profile]
    claims=json.loads(Path("assurance/stage13/claims.json").read_text())
    out=args.output; out.mkdir(parents=True,exist_ok=True)
    dirty=subprocess.run(["git","status","--porcelain"],capture_output=True,text=True).stdout.strip()
    preflight={"schema_version":1,"profile":args.profile,"captured_at_utc":dt.datetime.now(dt.timezone.utc).isoformat(),"git_dirty":bool(dirty),"require_clean_git":cfg["require_clean_git"]}
    (out/"preflight.json").write_text(json.dumps(preflight,indent=2)+"\n")
    if cfg["require_clean_git"] and dirty:
        (out/"summary.md").write_text("# Stage 13 Assurance\n\nDecision: **fail** — this profile requires a clean Git tree.\n")
        return 1
    checks=[]
    if cfg["run_stage12"]:
        stage12_profile=cfg["stage12_profile"]
        stage12_bundle=Path("target/stage12")/f"stage12-{stage12_profile}-evidence.tar.gz"
        nested_dir=out/"nested-evidence"
        stage12_bundle.unlink(missing_ok=True)
        if nested_dir.exists(): shutil.rmtree(nested_dir)
        nested_dir.mkdir(parents=True,exist_ok=True)
        stage12_check=run("stage12",["bash","scripts/run-stage12.sh",stage12_profile],out)
        if stage12_bundle.is_file():
            nested_bundle=nested_dir/stage12_bundle.name
            shutil.copy2(stage12_bundle,nested_bundle)
            stage12_check["evidence_bundle"]=str(nested_bundle)
        else:
            stage12_check["evidence_bundle_status"]="missing"
        checks.append(stage12_check)
    if cfg["run_property_tests"]:
        checks.append(run("property-tests",["cargo","test","--workspace","--all-features","--locked"],out))
    if cfg["run_differential_tests"]:
        # Existing schoolbook/NTT, deterministic fixture, and round-trip tests serve as differential checks.
        checks.append(run("differential-tests",["cargo","test","--workspace","--all-features","--locked","ntt_","--","--nocapture"],out))
    if cfg["run_secret_inventory"]:
        checks.append(run("secret-inventory",["python3","scripts/stage13_secret_inventory.py","--output",str(out/"secret-inventory")],out))
    if cfg["run_miri"]:
        available=subprocess.run(["cargo","miri","--version"],capture_output=True,text=True).returncode==0
        checks.append(run("miri",["cargo","miri","test","-p","pqc-rs-core","--lib"],out,required=True) if available else {"id":"miri","return_code":77,"required":True,"status":"fail","reason":"cargo-miri not installed"})
    if cfg["run_codegen_matrix"]:
        checks.append(run("codegen-matrix",["python3","scripts/stage13_codegen_matrix.py","--output",str(out/"codegen")],out))
    if cfg["require_sbom"]:
        checks.append(run("sbom",["python3","scripts/stage13_sbom.py","--output",str(out/"sbom")],out))
    failed=[c for c in checks if c.get("required") and c["status"]!="pass"]
    evidence_status={c["id"]:c["status"] for c in checks}
    evaluated=[]
    for claim in claims["claims"]:
        if args.profile not in claim["required_profiles"]: continue
        missing=[e for e in claim["evidence"] if e not in evidence_status and e not in ("checksums","signature")]
        statuses=[evidence_status.get(e,"pending") for e in claim["evidence"]]
        status="pass" if not missing and all(s=="pass" for s in statuses if s!="pending") else "open"
        evaluated.append({**claim,"status":status,"missing":missing})
    summary={"schema_version":1,"profile":args.profile,"decision":"fail" if failed else "pass","checks":checks,"claims":evaluated,"non_claims":claims["non_claims"]}
    (out/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
    lines=["# Stage 13 Formal Assurance and Release Evidence","",f"- Profile: `{args.profile}`",f"- Decision: **{summary['decision']}**",f"- Required check failures: `{len(failed)}`","","## Checks","","| Check | Required | Status |","|---|---:|---:|"]
    lines += [f"| `{c['id']}` | {'yes' if c.get('required') else 'no'} | **{c['status']}** |" for c in checks]
    lines += ["","## Assurance claims","","| Claim | Strength | Status |","|---|---|---:|"]
    lines += [f"| `{c['id']}` — {c['title']} | {c['strength']} | **{c['status']}** |" for c in evaluated]
    lines += ["","## Explicit limitations",""]+[f"- {x}" for x in claims["non_claims"]]
    (out/"summary.md").write_text("\n".join(lines)+"\n")
    hashes=[]
    for path in sorted(p for p in out.rglob("*") if p.is_file() and p.name!="SHA256SUMS"):
        hashes.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(out)}")
    (out/"SHA256SUMS").write_text("\n".join(hashes)+"\n")
    bundle=out.parent/f"stage13-{args.profile}-evidence.tar.gz"
    with tarfile.open(bundle,"w:gz") as tar: tar.add(out,arcname=f"stage13-{args.profile}")
    signature_status="not-required"
    if cfg["require_signature"]:
        key=os.environ.get("MINISIGN_SECRET_KEY")
        if key and shutil.which("minisign"):
            p=subprocess.run(["minisign","-S","-s",key,"-m",str(bundle)],capture_output=True,text=True)
            signature_status="pass" if p.returncode==0 else "fail"
        else: signature_status="fail"
        (out/"signature-status.txt").write_text(signature_status+"\n")
        if signature_status!="pass": return 1
    print(f"decision={summary['decision']}"); print(f"evidence={bundle}"); print(f"signature={signature_status}")
    for check in failed:
        print(f"failed_check={check['id']} return_code={check.get('return_code','unknown')}")
    return 1 if failed else 0
if __name__=="__main__": raise SystemExit(main())
