#!/usr/bin/env python3
"""Generate a dependency SBOM using Cargo metadata without external dependencies."""
from __future__ import annotations
import argparse, datetime as dt, json, subprocess
from pathlib import Path

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--output",type=Path,required=True); args=ap.parse_args()
    args.output.mkdir(parents=True,exist_ok=True)
    p=subprocess.run(["cargo","metadata","--format-version","1","--locked"],capture_output=True,text=True)
    (args.output/"cargo-metadata.stderr.txt").write_text(p.stderr)
    if p.returncode: return p.returncode
    metadata=json.loads(p.stdout)
    packages=[]
    for pkg in metadata.get("packages",[]):
        packages.append({"name":pkg["name"],"version":pkg["version"],"source":pkg.get("source"),
                         "license":pkg.get("license"),"manifest_path":pkg.get("manifest_path")})
    sbom={"bomFormat":"PQC-RS-CARGO-METADATA","specVersion":"1.0","generated_at_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
          "workspace_root":metadata.get("workspace_root"),"components":sorted(packages,key=lambda x:(x["name"],x["version"]))}
    (args.output/"sbom.json").write_text(json.dumps(sbom,indent=2)+"\n")
    lines=["# Dependency Inventory","",f"Components: **{len(packages)}**","","| Package | Version | License | Source |","|---|---:|---|---|"]
    for x in sbom["components"]:
        lines.append(f"| `{x['name']}` | `{x['version']}` | {x['license'] or 'unknown'} | {x['source'] or 'workspace'} |")
    (args.output/"sbom.md").write_text("\n".join(lines)+"\n")
    return 0
if __name__=="__main__": raise SystemExit(main())
