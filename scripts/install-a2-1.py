#!/usr/bin/env python3
"""Idempotently add `cargo xtask interop` to the existing xtask dispatcher."""
from __future__ import annotations
import pathlib

root = pathlib.Path(__file__).resolve().parents[1]
main = root / "xtask/src/main.rs"
if not main.exists():
    raise SystemExit("xtask/src/main.rs not found; apply A2.1 to the project root")
text = main.read_text()
if 'Some("interop") => interop(args.collect()),' not in text:
    marker = '        Some("standards") => standards(args.collect()),\n'
    if marker not in text:
        raise SystemExit("cannot locate standards dispatcher in xtask/src/main.rs")
    text = text.replace(marker, marker + '        Some("interop") => interop(args.collect()),\n', 1)
if 'cargo xtask interop [--manifest PATH]' not in text:
    marker = '    println!("cargo xtask standards [--catalog PATH] [--output DIR] [--strict]");\n'
    if marker not in text:
        raise SystemExit("cannot locate xtask help block")
    text = text.replace(marker, marker + '    println!("cargo xtask interop [--manifest PATH] [--output DIR] [--provider ID] [--suite ID] [--strict]");\n', 1)
if 'fn interop(args: Vec<String>)' not in text:
    anchor = 'fn standards(args: Vec<String>) -> Result<(), String> {'
    if anchor not in text:
        raise SystemExit("cannot locate standards function")
    function = r'''
fn interop(args: Vec<String>) -> Result<(), String> {
    let mut command = Command::new("python3");
    command.arg("scripts/interop_engine.py").arg("report");
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--manifest" | "--output" | "--provider" | "--suite" => {
                let value = iter.next().ok_or_else(|| format!("{arg} requires a value"))?;
                command.arg(arg).arg(value);
            }
            "--strict" => { command.arg(arg); }
            "--help" | "-h" => {
                println!("cargo xtask interop [--manifest PATH] [--output DIR] [--provider ID] [--suite ID] [--strict]");
                return Ok(());
            }
            other => return Err(format!("unknown interop argument: {other}")),
        }
    }
    let status = command.status().map_err(|e| format!("failed to run interoperability engine: {e}"))?;
    if status.success() { Ok(()) } else { Err(format!("interoperability engine exited with {status}")) }
}
'''
    text = text.replace(anchor, function + anchor, 1)
main.write_text(text)
print("A2.1 installed: cargo xtask interop is available.")
