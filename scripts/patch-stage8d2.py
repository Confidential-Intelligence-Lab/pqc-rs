#!/usr/bin/env python3
from pathlib import Path

def ensure_use(text, line):
    if line in text:
        return text
    i = text.find("use ")
    return text[:i] + line + "\n" + text[i:] if i >= 0 else line + "\n" + text

# Ensure pqc-core dependency.
p = Path("crates/pqc-hpke/Cargo.toml")
t = p.read_text()
if "pqc-core =" not in t:
    marker = "[dependencies]"
    i = t.find(marker)
    j = t.find("\n[", i + len(marker))
    if j < 0: j = len(t)
    t = t[:j].rstrip() + '\npqc-core = { path = "../pqc-core", version = "0.4.0" }\n\n' + t[j:].lstrip("\n")
p.write_text(t)

# KeyScheduleOutput.
p = Path("crates/pqc-hpke/src/key_schedule.rs")
t = ensure_use(p.read_text(), "use pqc_core::secret::SecretVec;")
t = t.replace("pub key: Vec<u8>,", "pub key: SecretVec,")
t = t.replace("pub exporter_secret: Vec<u8>,", "pub exporter_secret: SecretVec,")
t = t.replace("pub secret: Vec<u8>,", "pub secret: SecretVec,")
t = t.replace("        key,\n        base_nonce,", "        key: SecretVec::new(key),\n        base_nonce,")
t = t.replace("        exporter_secret,\n        key_schedule_context,\n        secret,",
              "        exporter_secret: SecretVec::new(exporter_secret),\n        key_schedule_context,\n        secret: SecretVec::new(secret),")
t = t.replace("hex::encode(output.secret)", "hex::encode(output.secret.as_bytes())")
t = t.replace("hex::encode(output.exporter_secret)", "hex::encode(output.exporter_secret.as_bytes())")
p.write_text(t)

# Context conversion.
p = Path("crates/pqc-hpke/src/context.rs")
t = p.read_text()
t = t.replace("key: schedule.key,", "key: schedule.key.as_bytes().to_vec(),")
t = t.replace("exporter_secret: schedule.exporter_secret,",
              "exporter_secret: schedule.exporter_secret.as_bytes().to_vec(),")
p.write_text(t)

# ML-KEM HPKE aggregates.
p = Path("crates/pqc-hpke/src/ml_kem.rs")
t = ensure_use(p.read_text(), "use pqc_core::secret::{SecretBytes, SecretVec};")
t = t.replace("pub private_key_seed: [u8; 64],", "pub private_key_seed: SecretBytes<64>,")
t = t.replace("pub expanded_private_key: Vec<u8>,", "pub expanded_private_key: SecretVec,")
t = t.replace("pub shared_secret: Vec<u8>,", "pub shared_secret: SecretVec,")
t = t.replace("            private_key_seed,\n            public_key,\n            expanded_private_key,",
              "            private_key_seed: SecretBytes::new(private_key_seed),\n            public_key,\n            expanded_private_key: SecretVec::new(expanded_private_key),")
t = t.replace("shared_secret: output.shared_secret.as_bytes().to_vec(),",
              "shared_secret: SecretVec::new(output.shared_secret.as_bytes().to_vec()),")
t = t.replace("&key_pair.expanded_private_key", "key_pair.expanded_private_key.as_bytes()")
t = t.replace("&key_pair.private_key_seed", "key_pair.private_key_seed.as_bytes()")
t = t.replace("hex::encode(key_pair.private_key_seed)", "hex::encode(key_pair.private_key_seed.as_bytes())")
p.write_text(t)

# Hybrid aggregates.
p = Path("crates/pqc-hpke/src/hybrid_kem.rs")
t = ensure_use(p.read_text(), "use pqc_core::secret::{SecretBytes, SecretVec};")
t = t.replace("pub private_seed: [u8; 32],", "pub private_seed: SecretBytes<32>,")
t = t.replace("expanded_pq_private_key: Vec<u8>,", "expanded_pq_private_key: SecretVec,")
t = t.replace("traditional_private_key: Vec<u8>,", "traditional_private_key: SecretVec,")
t = t.replace("pub shared_secret: Vec<u8>,", "pub shared_secret: SecretVec,")
t = t.replace("            private_seed,\n            public_key,\n            expanded_pq_private_key: pq_private,\n            traditional_private_key,",
              "            private_seed: SecretBytes::new(private_seed),\n            public_key,\n            expanded_pq_private_key: SecretVec::new(pq_private),\n            traditional_private_key: SecretVec::new(traditional_private_key),")
t = t.replace("            shared_secret,\n        }",
              "            shared_secret: SecretVec::new(shared_secret),\n        }")
t = t.replace("&key_pair.expanded_pq_private_key", "key_pair.expanded_pq_private_key.as_bytes()")
t = t.replace("&key_pair.traditional_private_key", "key_pair.traditional_private_key.as_bytes()")
t = t.replace("&key_pair.private_seed", "key_pair.private_seed.as_bytes()")
p.write_text(t)

for name in ["setup.rs", "hybrid_setup.rs"]:
    p = Path("crates/pqc-hpke/src") / name
    t = p.read_text()
    t = t.replace("shared_secret: &encapsulation.shared_secret,",
                  "shared_secret: encapsulation.shared_secret.as_bytes(),")
    p.write_text(t)

print("Stage 8D-2 applied.")
