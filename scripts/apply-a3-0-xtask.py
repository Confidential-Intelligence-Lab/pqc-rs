#!/usr/bin/env python3
from pathlib import Path
p=Path('xtask/src/main.rs'); s=p.read_text()
if 'interop-hpke' not in s:
    s=s.replace('Some("interop-openssl") => interop_openssl(args.collect()),','Some("interop-openssl") => interop_openssl(args.collect()),\n        Some("interop-hpke") => interop_hpke(args.collect()),')
    s=s.replace('println!("cargo xtask interop-openssl [--strict]");','println!("cargo xtask interop-openssl [--strict]");\n    println!("cargo xtask interop-hpke [--strict]");')
    s += '''\nfn interop_hpke(args: Vec<String>) -> Result<(), String> {\n    let mut command = Command::new("python3");\n    command.arg("scripts/hpke_interop.py");\n    for arg in args {\n        match arg.as_str() {\n            "--strict" => { command.arg(arg); }\n            "--help" | "-h" => { println!("cargo xtask interop-hpke [--strict]"); return Ok(()); }\n            other => return Err(format!("unknown interop-hpke argument: {other}")),\n        }\n    }\n    let status = command.status().map_err(|e| format!("failed to run HPKE interoperability harness: {e}"))?;\n    if status.success() { Ok(()) } else { Err(format!("HPKE interoperability harness exited with {status}")) }\n}\n'''
    p.write_text(s)
    print('Added cargo xtask interop-hpke')
else:
    print('cargo xtask interop-hpke already present')
