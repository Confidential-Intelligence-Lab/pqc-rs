#!/usr/bin/env python3
from pathlib import Path

lib_path = Path("crates/pqc-ml-kem/src/lib.rs")
decrypt_path = Path("crates/pqc-ml-kem/src/kpke_decrypt.rs")
symmetric_path = Path("crates/pqc-ml-kem/src/symmetric.rs")

for path in [lib_path, decrypt_path, symmetric_path]:
    if not path.exists():
        raise SystemExit(f"{path} not found; run from repository root")

# Expose the decapsulation module.
text = lib_path.read_text(encoding="utf-8")
declaration = "pub mod ml_kem_decaps;\n"
if declaration not in text:
    marker = "pub mod ml_kem_encaps;\n"
    if marker not in text:
        raise SystemExit("Could not locate ml_kem_encaps module declaration")
    text = text.replace(marker, marker + declaration, 1)
    lib_path.write_text(text, encoding="utf-8")
    print(f"Updated {lib_path}")

# Add J = SHAKE256-32.
text = symmetric_path.read_text(encoding="utf-8")
if "pub fn j(input: &[u8]) -> [u8; 32]" not in text:
    marker = "/// SHAKE128 XOF expansion with two domain bytes.\n"
    function = '''/// SHAKE256-based implicit-rejection hash.
pub fn j(input: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; 32];
    reader.read(&mut output);
    output
}

'''
    if marker not in text:
        raise SystemExit("Could not locate symmetric insertion point")
    text = text.replace(marker, function + marker, 1)
    symmetric_path.write_text(text, encoding="utf-8")
    print(f"Updated {symmetric_path}")

# Correct K-PKE decryption domain handling.
text = decrypt_path.read_text(encoding="utf-8")

if "use crate::kpke_ntt_domain::NttPolyVec;" not in text:
    marker = "use crate::kpke_arithmetic;\n"
    if marker in text:
        text = text.replace(
            marker,
            "use crate::kpke_ntt_domain::NttPolyVec;\n",
            1,
        )
    else:
        marker = "use crate::kpke::Message;\n"
        text = text.replace(
            marker,
            marker + "use crate::kpke_ntt_domain::NttPolyVec;\n",
            1,
        )

signature = "pub fn compute_message_poly("
start = text.find(signature)
if start < 0:
    raise SystemExit("Could not locate compute_message_poly")
brace = text.find("{", start)
depth = 0
end = None
for index in range(brace, len(text)):
    if text[index] == "{":
        depth += 1
    elif text[index] == "}":
        depth -= 1
        if depth == 0:
            end = index + 1
            break
if end is None:
    raise SystemExit("Could not locate compute_message_poly end")

replacement = '''pub fn compute_message_poly(
    s_hat: &PolyVec,
    u: &PolyVec,
    v: &Poly,
) -> Poly {
    assert_eq!(s_hat.rank(), u.rank());

    let secret_hat = NttPolyVec::from_sampled_ntt_polyvec(s_hat);
    let u_hat = NttPolyVec::from_polyvec(u);
    let product =
        crate::kpke_ntt_domain::dot_to_poly(&secret_hat, &u_hat);
    v.sub(&product)
}'''

text = text[:start] + replacement + text[end:]
decrypt_path.write_text(text, encoding="utf-8")
print(f"Updated {decrypt_path}")
