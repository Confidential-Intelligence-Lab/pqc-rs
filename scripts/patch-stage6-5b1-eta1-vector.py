#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/pqc-ml-kem/src/kpke_encrypt.rs")
if not path.exists():
    raise SystemExit(f"{path} not found; run from repository root")

text = path.read_text(encoding="utf-8")

# Ensure both eta2 and eta3 polynomial samplers are imported.
if "sample_eta3_poly" not in text:
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
    marker = "/// Sample an eta2 polynomial vector for K-PKE encryption.\n"
    if marker not in text:
        raise SystemExit("Could not locate eta2 vector helper insertion point")
    text = text.replace(marker, eta1_function + marker, 1)

# Fix the regression test to pass a &[u8; 32] directly.
old_test = '''        let randomness = EncryptionRandomness::new([0x33u8; 32]);
        let eta1 = sample_eta1_vector(
            MlKemParameterSet::MlKem512,
            randomness.as_bytes(),
            0,
        );
        let eta2 = sample_eta2_vector(
            MlKemParameterSet::MlKem512,
            randomness.as_bytes(),
            0,
        );
'''

new_test = '''        let randomness = [0x33u8; 32];
        let eta1 =
            sample_eta1_vector(MlKemParameterSet::MlKem512, &randomness, 0);
        let eta2 =
            sample_eta2_vector(MlKemParameterSet::MlKem512, &randomness, 0);
'''

if old_test in text:
    text = text.replace(old_test, new_test, 1)
else:
    # Handle the rustfmt-collapsed form shown by the compiler.
    text = text.replace(
        "        let randomness = EncryptionRandomness::new([0x33u8; 32]);\n",
        "        let randomness = [0x33u8; 32];\n",
        1,
    )
    text = text.replace(
        "sample_eta1_vector(MlKemParameterSet::MlKem512, randomness.as_bytes(), 0)",
        "sample_eta1_vector(MlKemParameterSet::MlKem512, &randomness, 0)",
        1,
    )
    text = text.replace(
        "sample_eta2_vector(MlKemParameterSet::MlKem512, randomness.as_bytes(), 0)",
        "sample_eta2_vector(MlKemParameterSet::MlKem512, &randomness, 0)",
        1,
    )

path.write_text(text, encoding="utf-8")
print(f"Updated {path}")
