#!/usr/bin/env python3
import argparse,json,subprocess,sys,tomllib
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; POLICY=ROOT/'compliance/release-policy.toml'; REPORT=ROOT/'docs/release/RELEASE_READINESS.md'; JSON=ROOT/'target/release-audit.json'
def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--check',action='store_true'); a=ap.parse_args()
 with POLICY.open('rb') as f: data=tomllib.load(f)
 results=[]
 for c in data['check']:
  p=subprocess.run(c['command'],cwd=ROOT,text=True,capture_output=True)
  results.append({'id':c['id'],'pass':p.returncode==0,'command':c['command'],'output':(p.stdout+p.stderr)[-4000:]})
 ready=all(r['pass'] or not c.get('required',True) for c,r in zip(data['check'],results))
 lines=['# Release Readiness','', '> Generated from `compliance/release-policy.toml`. Do not edit manually.','',f"Milestone: **{data['metadata']['milestone']}**",'','| Check | Required | Status |','|---|---:|---|']
 for c,r in zip(data['check'],results): lines.append(f"| `{c['id']}` | {str(c.get('required',True)).lower()} | **{'PASS' if r['pass'] else 'FAIL'}** |")
 lines += ['','## Overall status','',f"**{'RELEASE READY' if ready else 'NOT RELEASE READY'}**",'']
 body='\n'.join(lines)
 if a.check:
  drift=not REPORT.is_file() or REPORT.read_text()!=body
  if drift: print('drift: docs/release/RELEASE_READINESS.md',file=sys.stderr)
  return 1 if drift or not ready else 0
 REPORT.parent.mkdir(parents=True,exist_ok=True); REPORT.write_text(body); JSON.parent.mkdir(parents=True,exist_ok=True); JSON.write_text(json.dumps({'schema_version':1,'generated_at':datetime.now(timezone.utc).isoformat(),'release_ready':ready,'checks':results},indent=2)+'\n'); print(body); return 0 if ready else 1
if __name__=='__main__': raise SystemExit(main())
