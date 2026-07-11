#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/pqc-ml-kem/src/kpke_encrypt.rs")
if not path.exists():
    raise SystemExit(f"{path} not found; run from repository root")

text = path.read_text(encoding="utf-8")

# Ensure sample_eta3_poly is imported.
if "sample_eta3_poly" not in text:
    if "sample_eta2_poly" not in text:
        raise SystemExit("Could not locate sample_eta2_poly import")
    text = text.replace(
        "sample_eta2_poly",
        "sample_eta2_poly, sample_eta3_poly",
        1,
    )

eta1_function = '''/// Sample an eta1 polynomial vector for K-PKE encryption.
pub fn sample_eta1_vector(
    parameter_set: MlKemParameterSet,
    sigma: &[u8; 32],
    nonce_start: u8,
) -> PolyVec {
    let rank = parameter_set.k();
    let mut polys = [Poly::zero(), Poly::zero(), Poly::zero(), Poly::zero()];

    let mut index = 0usize;
    while index < rank {
        let nonce = nonce_start.wrapping_add(index as u8);
        polys[index] = match parameter_set {
            MlKemParameterSet::MlKem512 => sample_eta3_poly(sigma, nonce),
            MlKemParameterSet::MlKem768 | MlKemParameterSet::MlKem1024 => {
                sample_eta2_poly(sigma, nonce)
            }
        };
        index += 1;
    }

    PolyVec::from_slice(&polys[..rank])
}

'''

if "pub fn sample_eta1_vector" not in text:
    marker = "pub fn sample_eta2_vector("
    index = text.find(marker)
    if index < 0:
        raise SystemExit("Could not locate pub fn sample_eta2_vector")
    text = text[:index] + eta1_function + text[index:]

# Repair the regression test seed type.
text = text.replace(
    "let randomness = EncryptionRandomness::new([0x33u8; 32]);",
    "let randomness = [0x33u8; 32];",
)
text = text.replace(
    "randomness.as_bytes(),",
    "&randomness,",
)

path.write_text(text, encoding="utf-8")
print(f"Repaired {path}")
