#!/usr/bin/env python3
from pathlib import Path

lib = Path("crates/pqc-ml-dsa/src/lib.rs")
challenge = Path("crates/pqc-ml-dsa/src/challenge.rs")

for path in (lib, challenge):
    if not path.exists():
        raise SystemExit(f"Missing {path}; run after Stage 9D-4A")

text = lib.read_text(encoding="utf-8")
if "pub mod signing_core;\n" not in text:
    text = text.rstrip() + "\npub mod signing_core;\n"
lib.write_text(text.rstrip() + "\n", encoding="utf-8")

text = challenge.read_text(encoding="utf-8")

old_signature = '''pub fn sample_in_ball(
    seed: &[u8; CHALLENGE_SEED_BYTES],
    tau: usize,
) -> Result<Poly, ChallengeError> {'''

new_signature = '''pub fn sample_in_ball(
    seed: &[u8; CHALLENGE_SEED_BYTES],
    tau: usize,
) -> Result<Poly, ChallengeError> {
    sample_in_ball_bytes(seed, tau)
}

/// Sample a sparse challenge from a parameter-sized challenge seed.
pub fn sample_in_ball_bytes(
    seed: &[u8],
    tau: usize,
) -> Result<Poly, ChallengeError> {'''

if "pub fn sample_in_ball_bytes(" not in text:
    if old_signature not in text:
        raise SystemExit("Could not locate sample_in_ball insertion point")
    text = text.replace(old_signature, new_signature, 1)

challenge.write_text(text.rstrip() + "\n", encoding="utf-8")
print("Applied Stage 9D-4B signing core and variable challenge seeds.")
