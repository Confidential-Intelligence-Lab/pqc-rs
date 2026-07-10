#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/pqc-ml-kem/src/kpke_keygen.rs")
if not path.exists():
    raise SystemExit(f"{path} not found; run from the repository root")

text = path.read_text(encoding="utf-8")

old_function = """/// Expand 32-byte entropy into `rho` and `sigma`.
pub fn expand_keygen_seed(seed: &[u8; 32]) -> KpkeSeedMaterial {
    let expanded = symmetric::g(seed);
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];

    rho.copy_from_slice(&expanded[..32]);
    sigma.copy_from_slice(&expanded[32..]);

    KpkeSeedMaterial { rho, sigma }
}
"""

new_function = """/// Expand 32-byte entropy into `rho` and `sigma`.
///
/// This helper preserves the original structural behavior for internal fixtures.
/// FIPS 203 key generation must use [`expand_keygen_seed_for_parameter_set`].
pub fn expand_keygen_seed(seed: &[u8; 32]) -> KpkeSeedMaterial {
    let expanded = symmetric::g(seed);
    split_keygen_seed_material(&expanded)
}

/// Expand FIPS 203 K-PKE key-generation input into `rho` and `sigma`.
///
/// FIPS 203 derives the two 32-byte seeds as `G(d || k)`, where `k` is the
/// one-byte module rank for the selected parameter set.
pub fn expand_keygen_seed_for_parameter_set(
    parameter_set: MlKemParameterSet,
    d: &[u8; 32],
) -> KpkeSeedMaterial {
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(d);
    input[32] = parameter_set.k() as u8;

    let expanded = symmetric::g(&input);
    split_keygen_seed_material(&expanded)
}

fn split_keygen_seed_material(expanded: &[u8; 64]) -> KpkeSeedMaterial {
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];

    rho.copy_from_slice(&expanded[..32]);
    sigma.copy_from_slice(&expanded[32..]);

    KpkeSeedMaterial { rho, sigma }
}
"""

if new_function not in text:
    if old_function not in text:
        raise SystemExit("Could not locate expand_keygen_seed implementation")
    text = text.replace(old_function, new_function, 1)

old_call = "    let seed_material = expand_keygen_seed(seed);\n"
new_call = (
    "    let seed_material =\n"
    "        expand_keygen_seed_for_parameter_set(parameter_set, seed);\n"
)

if new_call not in text:
    if old_call not in text:
        raise SystemExit("Could not locate keygen seed-expansion call")
    text = text.replace(old_call, new_call, 1)

test_marker = """    #[test]
    fn noise_vector_has_expected_rank() {
"""
test_code = """    #[test]
    fn fips_seed_expansion_includes_parameter_set_rank() {
        let d = [0x47u8; 32];

        let k512 =
            expand_keygen_seed_for_parameter_set(MlKemParameterSet::MlKem512, &d);
        let k768 =
            expand_keygen_seed_for_parameter_set(MlKemParameterSet::MlKem768, &d);
        let k1024 =
            expand_keygen_seed_for_parameter_set(MlKemParameterSet::MlKem1024, &d);

        assert_ne!(k512, k768);
        assert_ne!(k768, k1024);
        assert_ne!(k512, k1024);
    }

"""

if "fips_seed_expansion_includes_parameter_set_rank" not in text:
    if test_marker not in text:
        raise SystemExit("Could not locate test insertion point")
    text = text.replace(test_marker, test_code + test_marker, 1)

path.write_text(text, encoding="utf-8")
print(f"Patched {path}")
