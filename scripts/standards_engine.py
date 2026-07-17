#!/usr/bin/env python3
from __future__ import annotations
import argparse, datetime as dt, glob, json, pathlib, sys, tomllib

RANK={"planned":0,"mapped":1,"implemented":2,"verified":3,"not-applicable":4}

def load(path):
    with path.open('rb') as f:return tomllib.load(f)

def matches(root, pattern):
    p=root/pattern
    if any(c in pattern for c in '*?['):
        return sorted(str(pathlib.Path(x).relative_to(root)) for x in glob.glob(str(p),recursive=True))
    return [pattern] if p.exists() else []

def validate_document(root,path,strict,structural_only=False):
    data=load(path); meta=data.get('metadata',{}); reqs=data.get('requirement',[]); findings=[]; ids=set(); rows=[]
    for r in reqs:
        rid=r.get('id','')
        if not rid or rid in ids: findings.append({"severity":"error","code":"DUPLICATE_OR_EMPTY_ID","requirement":rid})
        ids.add(rid)
        status=r.get('status','')
        if status not in RANK: findings.append({"severity":"error","code":"INVALID_STATUS","requirement":rid})
        impl={p:matches(root,p) for p in r.get('implementation',[])}
        tests={p:matches(root,p) for p in r.get('tests',[])}
        if (not structural_only) and RANK.get(status,0)>=2 and (not impl or any(not v for v in impl.values())):
            findings.append({"severity":"error","code":"IMPLEMENTATION_UNRESOLVED","requirement":rid})
        if (not structural_only) and status=='verified' and (not tests or any(not v for v in tests.values())):
            findings.append({"severity":"error","code":"TEST_UNRESOLVED","requirement":rid})
        if status=='verified' and not r.get('evidence') and not r.get('evidence_paths'):
            findings.append({"severity":"error","code":"MISSING_EVIDENCE","requirement":rid})
        if status=='verified' and not r.get('last_verified'):
            findings.append({"severity":"error","code":"MISSING_VERIFICATION_DATE","requirement":rid})
        rows.append({**r,"implementation_matches":impl,"test_matches":tests})
    errors=sum(f['severity']=='error' for f in findings); warnings=sum(f['severity']=='warning' for f in findings)
    decision='fail' if errors or (strict and warnings) else 'pass'
    return {"document":meta.get('generated_from',path.stem),"kind":meta.get('source_kind','unknown'),"decision":decision,"requirements":rows,"findings":findings,"counts":{"total":len(rows),"mapped_or_better":sum(RANK.get(r.get('status',''),0)>=1 for r in rows),"implemented_or_better":sum(RANK.get(r.get('status',''),0)>=2 and r.get('status')!='not-applicable' for r in rows),"verified":sum(r.get('status')=='verified' for r in rows),"errors":errors,"warnings":warnings}}

def md_report(result):
    c=result['counts']; out=[f"# {result['document']} Traceability Report","",f"- Classification: `{result['kind']}`",f"- Decision: **{result['decision']}**",f"- Requirements: {c['total']}",f"- Implemented or better: {c['implemented_or_better']}",f"- Verified: {c['verified']}","","## Requirements","","| ID | Section | Class | Status | Title | Tests | Evidence |","|---|---|---|---|---|---|---|"]
    for r in result['requirements']:
        tests='<br>'.join(f'`{x}`' for x in r.get('tests',[])) or '—'; ev='<br>'.join(r.get('evidence',[])) or '—'
        out.append(f"| `{r.get('id','')}` | {r.get('section','')} | {r.get('class','')} | **{r.get('status','')}** | {r.get('title','').replace('|','\\|')} | {tests} | {ev} |")
    out += ["","## Findings",""]
    out += ["No findings."] if not result['findings'] else [f"- **{f['severity']}** `{f['code']}` `{f.get('requirement','')}`" for f in result['findings']]
    return '\n'.join(out)+'\n'

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('command',choices=['validate','report']); ap.add_argument('--catalog',default='compliance/catalog.toml'); ap.add_argument('--output',default='target/standards'); ap.add_argument('--strict',action='store_true'); ap.add_argument('--structural-only',action='store_true'); a=ap.parse_args()
    root=pathlib.Path.cwd(); cat=load(root/a.catalog); output=root/a.output; output.mkdir(parents=True,exist_ok=True)
    all_results=[]; seen=set(); catalog_findings=[]
    for d in cat.get('document',[]):
        did=d['id']; src=root/d['source']
        if did in seen: catalog_findings.append({"severity":"error","code":"DUPLICATE_DOCUMENT","document":did})
        seen.add(did)
        if not src.exists(): catalog_findings.append({"severity":"error","code":"MISSING_DOCUMENT_SOURCE","document":did}); continue
        result=validate_document(root,src,a.strict,a.structural_only); result['id']=did; result['title']=d.get('title',did); result['source']=d['source']; all_results.append(result)
        docdir=output/did.lower(); docdir.mkdir(parents=True,exist_ok=True)
        (docdir/'report.json').write_text(json.dumps(result,indent=2)+'\n')
        (docdir/'report.md').write_text(md_report(result))
    errors=sum(r['counts']['errors'] for r in all_results)+sum(f['severity']=='error' for f in catalog_findings)
    warnings=sum(r['counts']['warnings'] for r in all_results)+sum(f['severity']=='warning' for f in catalog_findings)
    decision='fail' if errors or (a.strict and warnings) else 'pass'
    summary={"schema_version":1,"generated_at":dt.datetime.now(dt.timezone.utc).isoformat(),"decision":decision,"strict":a.strict,"documents":[{"id":r['id'],"title":r['title'],"kind":r['kind'],"decision":r['decision'],**r['counts']} for r in all_results],"findings":catalog_findings,"errors":errors,"warnings":warnings}
    (output/'report.json').write_text(json.dumps(summary,indent=2)+'\n')
    lines=["# Standards Engine Report","",f"- Decision: **{decision}**",f"- Strict mode: `{a.strict}`","","| Document | Classification | Requirements | Implemented+ | Verified | Decision |","|---|---|---:|---:|---:|---|"]
    for r in summary['documents']: lines.append(f"| {r['id']} | {r['kind']} | {r['total']} | {r['implemented_or_better']} | {r['verified']} | **{r['decision']}** |")
    lines += ["","## Claim boundary","","Passing this report means the traceability data and referenced local evidence are internally consistent. It is not a NIST CAVP, CMVP, or FIPS 140-3 validation certificate.",""]
    (output/'report.md').write_text('\n'.join(lines))
    print(f"decision={decision}"); print(f"documents={len(all_results)}"); print(f"report={output/'report.md'}")
    return 0 if decision=='pass' else 1
if __name__=='__main__': raise SystemExit(main())
