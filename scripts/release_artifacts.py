#!/usr/bin/env python3
import argparse, subprocess, sys, tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
MAP={
 'validation':('compliance/validation-policy.toml','docs/release/VALIDATION_CERTIFICATION.md','check','category','Validation Certification'),
 'security':('compliance/security-certification-policy.toml','docs/security/SECURITY_CERTIFICATION.md','check','area','Security Certification'),
 'standards':('compliance/standards-certification-policy.toml','docs/release/STANDARDS_CERTIFICATION.md','standard','scope','Standards Certification'),
 'architecture':('compliance/architecture-policy.toml','docs/architecture/ARCHITECTURE.md','layer','responsibility','Architecture Snapshot'),
 'manifest':('compliance/release-manifest.toml','RELEASE_MANIFEST.md','capability','status','Release Manifest'),
}
def write_or_check(path, text, check):
 p=ROOT/path; text=text.rstrip()+'\n'
 if check:
  if not p.is_file() or p.read_text()!=text:
   print(f'drift: {path}',file=sys.stderr); return False
  return True
 p.parent.mkdir(parents=True,exist_ok=True); p.write_text(text); return True
def main():
 ap=argparse.ArgumentParser(); ap.add_argument('artifact',choices=MAP); ap.add_argument('--check',action='store_true'); a=ap.parse_args()
 policy,out,key,desc,title=MAP[a.artifact]
 with (ROOT/policy).open('rb') as f: data=tomllib.load(f)
 rows=[]; ok=True
 for item in data[key]:
  evidence=item.get('evidence',item.get('paths',[])); passed=all((ROOT/x).exists() for x in evidence); ok &= passed
  name=item.get('id',item.get('name',str(item.get('order',''))))
  rows.append((name,item.get(desc,''),'PASS' if passed else 'FAIL','<br>'.join(f'`{x}`' for x in evidence)))
 lines=[f'# {title}','',f'> Generated from `{policy}`. Do not edit manually.','','This report consolidates repository-local engineering evidence. It is not third-party certification.','','| Item | Scope | Status | Evidence |','|---|---|---|---|']
 lines += [f'| `{n}` | {d} | **{s}** | {e} |' for n,d,s,e in rows]
 lines += ['','## Decision','',f"**{'PASS' if ok else 'FAIL'}**",'']
 drift_ok=write_or_check(out,'\n'.join(lines),a.check)
 print(f'{a.artifact}: '+('pass' if ok and drift_ok else 'fail'))
 return 0 if ok and drift_ok else 1
if __name__=='__main__': raise SystemExit(main())
