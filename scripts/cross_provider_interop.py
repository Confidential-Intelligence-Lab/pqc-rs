#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, pathlib, subprocess, sys, datetime as dt

PARAMS_KEM=["ML-KEM-512","ML-KEM-768","ML-KEM-1024"]
PARAMS_DSA=["ML-DSA-44","ML-DSA-65","ML-DSA-87"]
PARAMS_SLH=[
 "SLH-DSA-SHA2-128s","SLH-DSA-SHA2-128f",
 "SLH-DSA-SHA2-192s","SLH-DSA-SHA2-192f",
 "SLH-DSA-SHA2-256s","SLH-DSA-SHA2-256f",
 "SLH-DSA-SHAKE-128s","SLH-DSA-SHAKE-128f",
 "SLH-DSA-SHAKE-192s","SLH-DSA-SHAKE-192f",
 "SLH-DSA-SHAKE-256s","SLH-DSA-SHAKE-256f",
]
HASH_SLH_CASES=[
 ("SLH-DSA-SHA2-128s","SHA2-224"),
 ("SLH-DSA-SHA2-128f","SHA2-256"),
 ("SLH-DSA-SHA2-192s","SHA2-384"),
 ("SLH-DSA-SHA2-192f","SHA2-512"),
 ("SLH-DSA-SHA2-256s","SHA2-512/224"),
 ("SLH-DSA-SHA2-256f","SHA2-512/256"),
 ("SLH-DSA-SHAKE-128s","SHA3-224"),
 ("SLH-DSA-SHAKE-128f","SHA3-256"),
 ("SLH-DSA-SHAKE-192s","SHA3-384"),
 ("SLH-DSA-SHAKE-192f","SHA3-512"),
 ("SLH-DSA-SHAKE-256s","SHAKE-128"),
 ("SLH-DSA-SHAKE-256f","SHAKE-256"),
]
PROVIDERS={
 "rust":["python3","scripts/interop/providers/rust_provider.py"],
 "liboqs":["python3","scripts/interop/providers/liboqs_provider.py"],
}
def call(root: pathlib.Path, provider: str, operation: str, parameter_set: str, inputs: dict)->dict:
 req={"protocol_version":1,"action":"execute","operation":operation,"parameter_set":parameter_set,"inputs":inputs}
 p=subprocess.run(PROVIDERS[provider],cwd=root,input=json.dumps(req),text=True,capture_output=True,env=os.environ.copy())
 if p.returncode: raise RuntimeError(p.stderr.strip() or p.stdout.strip())
 r=json.loads(p.stdout)
 if not r.get("ok"): raise RuntimeError(str(r.get("error")))
 return r["outputs"]
def seed(tag:str)->str:
 import hashlib
 return hashlib.sha256(tag.encode()).hexdigest()

def seed_bytes(tag:str, length:int)->str:
 import hashlib
 return hashlib.shake_256(tag.encode()).hexdigest(length)
def run_case(root, alg, ps, producer, consumer):
 if alg=="ML-KEM" and producer=="rust":
  kg=call(root,"rust","kem-keygen",ps,{"d":seed(ps+"-d"),"z":seed(ps+"-z")})
  enc=call(root,"liboqs","kem-encaps",ps,{"public_key":kg["public_key"]})
  dec=call(root,"rust","kem-decaps",ps,{"secret_key":kg["secret_key"],"ciphertext":enc["ciphertext"]})
  return enc["shared_secret"]==dec["shared_secret"],{"artifact":"ciphertext","bytes":len(enc["ciphertext"])//2}
 if alg=="ML-KEM":
  kg=call(root,"liboqs","kem-keygen",ps,{})
  enc=call(root,"rust","kem-encaps",ps,{"public_key":kg["public_key"],"m":seed(ps+"-m")})
  dec=call(root,"liboqs","kem-decaps",ps,{"secret_key":kg["secret_key"],"ciphertext":enc["ciphertext"]})
  return enc["shared_secret"]==dec["shared_secret"],{"artifact":"ciphertext","bytes":len(enc["ciphertext"])//2}
 msg=seed(ps+"-message");ctx="41322e33"

 if alg=="ML-DSA":
  if producer=="rust":
   kg=call(root,"rust","dsa-keygen",ps,{"xi":seed(ps+"-xi")})
   sig=call(root,"rust","dsa-sign",ps,{"secret_key":kg["secret_key"],"message":msg,"context":ctx,"randomness":"00"*32})
   ver=call(root,"liboqs","dsa-verify",ps,{"public_key":kg["public_key"],"message":msg,"context":ctx,"signature":sig["signature"]})
  else:
   kg=call(root,"liboqs","dsa-keygen",ps,{})
   sig=call(root,"liboqs","dsa-sign",ps,{"secret_key":kg["secret_key"],"message":msg,"context":ctx})
   ver=call(root,"rust","dsa-verify",ps,{"public_key":kg["public_key"],"message":msg,"context":ctx,"signature":sig["signature"]})
  return bool(ver["valid"]),{"artifact":"signature","bytes":len(sig["signature"])//2}

 if alg=="SLH-DSA":
  if producer=="rust":
   n={"128":16,"192":24,"256":32}[next(x for x in ("128","192","256") if x in ps)]
   kg=call(root,"rust","slh-keygen",ps,{"seed":seed_bytes(ps+"-seed",3*n)})
   sig=call(root,"rust","slh-sign",ps,{"secret_key":kg["secret_key"],"message":msg,"context":ctx})
   ver=call(root,"liboqs","slh-verify",ps,{"public_key":kg["public_key"],"message":msg,"context":ctx,"signature":sig["signature"]})
  else:
   kg=call(root,"liboqs","slh-keygen",ps,{})
   sig=call(root,"liboqs","slh-sign",ps,{"secret_key":kg["secret_key"],"message":msg,"context":ctx})
   ver=call(root,"rust","slh-verify",ps,{"public_key":kg["public_key"],"message":msg,"context":ctx,"signature":sig["signature"]})
  return bool(ver["valid"]),{"artifact":"signature","bytes":len(sig["signature"])//2}

 if alg=="HashSLH-DSA":
  prehash=consumer
  direction=producer
  if direction=="rust->liboqs":
   n={"128":16,"192":24,"256":32}[next(x for x in ("128","192","256") if x in ps)]
   kg=call(root,"rust","slh-keygen",ps,{"seed":seed_bytes(ps+"-"+prehash+"-seed",3*n)})
   sig=call(root,"rust","slh-hash-sign",ps,{"secret_key":kg["secret_key"],"message":msg,"context":ctx,"prehash":prehash})
   ver=call(root,"liboqs","slh-hash-verify",ps,{"public_key":kg["public_key"],"message":msg,"context":ctx,"signature":sig["signature"],"prehash":prehash})
  else:
   kg=call(root,"liboqs","slh-keygen",ps,{})
   sig=call(root,"liboqs","slh-hash-sign",ps,{"secret_key":kg["secret_key"],"message":msg,"context":ctx,"prehash":prehash})
   ver=call(root,"rust","slh-hash-verify",ps,{"public_key":kg["public_key"],"message":msg,"context":ctx,"signature":sig["signature"],"prehash":prehash})
  return bool(ver["valid"]),{"artifact":"signature","bytes":len(sig["signature"])//2,"prehash":prehash,"direction":direction}

 raise RuntimeError(f"unsupported algorithm {alg}")
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--root",default=".");ap.add_argument("--output",default="target/interop-cross");ap.add_argument("--strict",action="store_true");a=ap.parse_args()
 root=pathlib.Path(a.root).resolve();results=[];findings=[]
 cases=[]
 for ps in PARAMS_KEM:
  cases += [("ML-KEM",ps,"rust","liboqs"),("ML-KEM",ps,"liboqs","rust")]
 for ps in PARAMS_DSA:
  cases += [("ML-DSA",ps,"rust","liboqs"),("ML-DSA",ps,"liboqs","rust")]
 for ps in PARAMS_SLH:
  cases += [("SLH-DSA",ps,"rust","liboqs"),("SLH-DSA",ps,"liboqs","rust")]
 for ps,prehash in HASH_SLH_CASES:
  cases += [
   ("HashSLH-DSA",ps,"rust->liboqs",prehash),
   ("HashSLH-DSA",ps,"liboqs->rust",prehash),
  ]
 for index,(alg,ps,p,c) in enumerate(cases, start=1):
  ident=f"{ps}:{p}->{c}" if alg!="HashSLH-DSA" else f"{ps}:{c}:{p}"
  print(f"[{index}/{len(cases)}] {alg} {ps} {p} -> {c} ...", flush=True)
  try:
   ok,meta=run_case(root,alg,ps,p,c);decision="pass" if ok else "fail"
   print(f"  {decision.upper()}", flush=True)
   if not ok:findings.append({"severity":"error","code":"CROSS_PROVIDER_MISMATCH","message":ident})
   results.append({"case":ident,"algorithm":alg,"parameter_set":ps,"producer":p,"consumer":c,"decision":decision,**meta})
  except Exception as e:
   print(f"  FAIL: {e}", flush=True)
   results.append({"case":ident,"algorithm":alg,"parameter_set":ps,"producer":p,"consumer":c,"decision":"fail","reason":str(e)})
   findings.append({"severity":"error","code":"CROSS_PROVIDER_EXECUTION_FAILED","message":f"{ident}: {e}"})
 passed=sum(r["decision"]=="pass" for r in results);failed=len(results)-passed;decision="pass" if failed==0 else "fail"
 report={"schema_version":1,"generated_at":dt.datetime.now(dt.timezone.utc).isoformat(),"decision":decision,"strict":a.strict,"summary":{"executed":len(results),"passed":passed,"failed":failed},"results":results,"findings":findings,"claim_boundary":"A pass demonstrates byte-compatible ML-KEM exchange and cross-verification interoperability for ML-DSA, Pure SLH-DSA, and the listed representative HashSLH-DSA parameter-set/prehash pairs between this Rust implementation and the tested liboqs build. HashSLH coverage is representative across all 12 parameter sets and all 12 FIPS 205 prehash algorithms, not the full Cartesian product."}
 out=root/a.output;out.mkdir(parents=True,exist_ok=True);(out/"report.json").write_text(json.dumps(report,indent=2)+"\n")
 lines=["# Cross-provider Interoperability Report","",f"- Decision: **{decision}**",f"- Executed: {len(results)}",f"- Passed: {passed}",f"- Failed: {failed}","","| Algorithm | Parameter set | Producer | Consumer | Decision |","|---|---|---|---|---|"]
 for r in results:lines.append(f"| {r['algorithm']} | `{r['parameter_set']}` | `{r['producer']}` | `{r['consumer']}` | **{r['decision']}** |")
 lines += ["","## Findings",""] + ([f"- **{f['code']}**: {f['message']}" for f in findings] if findings else ["No findings."])
 lines += ["","## Claim boundary","",report["claim_boundary"],""]
 (out/"report.md").write_text("\n".join(lines));print(f"decision={decision}\nexecuted={len(results)}\npassed={passed}\nfailed={failed}\nreport={out/'report.md'}")
 return 0 if decision=="pass" else 1
if __name__=="__main__":raise SystemExit(main())
