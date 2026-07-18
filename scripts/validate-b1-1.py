#!/usr/bin/env python3
from pathlib import Path

required = {
    "crates/pqc-hpke/src/setup.rs": ["setup_psk_sender_deterministic", "setup_psk_receiver", "HpkeMode::Psk"],
    "crates/pqc-hpke/src/context.rs": ["is_exhausted", "exhausted: bool", "u64::MAX"],
    "crates/pqc-hpke/tests/psk_mode_context.rs": ["psk_mode_round_trips", "maximum_hkdf_sha256_lengths"],
    "README-b1-1.md": ["B1.1"],
}
errors=[]
for name, needles in required.items():
    p=Path(name)
    if not p.is_file():
        errors.append(f"missing {name}")
        continue
    text=p.read_text()
    for n in needles:
        if n not in text:
            errors.append(f"{name}: missing {n}")
if errors:
    print("B1.1 static validation: fail")
    for e in errors: print(f"- {e}")
    raise SystemExit(1)
print("B1.1 static validation: pass")
