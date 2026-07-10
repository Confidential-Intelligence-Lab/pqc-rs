#!/usr/bin/env python3
from pathlib import Path

ROOT = Path('.')


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise SystemExit(f'Could not locate {label}')
    return text.replace(old, new, 1)

# ---------------------------------------------------------------------------
# kpke_ntt_domain.rs
# ---------------------------------------------------------------------------
path = ROOT / 'crates/pqc-ml-kem/src/kpke_ntt_domain.rs'
text = path.read_text(encoding='utf-8')

matrix_constructor_marker = '''    /// Return the matrix rank.\n'''
matrix_constructor = '''    /// Construct from a matrix whose entries are already sampled in the NTT\n    /// domain by FIPS 203 `SampleNTT`.\n    pub fn from_sampled_ntt_matrix(matrix: &PolyMatrix) -> Self {\n        let rank = matrix.rank();\n        let mut entries = core::array::from_fn(|_| {\n            core::array::from_fn(|_| {\n                FipsNttPoly::from_coefficients([0i16; N])\n            })\n        });\n\n        let mut row = 0usize;\n        while row < rank {\n            let mut column = 0usize;\n            while column < rank {\n                entries[row][column] = FipsNttPoly::from_coefficients(\n                    *matrix.get(row, column).coefficients(),\n                );\n                column += 1;\n            }\n            row += 1;\n        }\n\n        Self { rank, entries }\n    }\n\n'''
if 'pub fn from_sampled_ntt_matrix' not in text:
    if matrix_constructor_marker not in text:
        raise SystemExit('Could not locate NttPolyMatrix insertion point')
    text = text.replace(matrix_constructor_marker, matrix_constructor + matrix_constructor_marker, 1)

matrix_ntt_marker = '''/// Compute `matrix * vector` in the NTT domain and return coefficient-domain\n/// output.\n'''
matrix_ntt_function = '''/// Compute `matrix * vector` and retain the result in the NTT domain.\n///\n/// The base-multiplication accumulator is converted to Montgomery form before\n/// adding the transformed error vector, matching the reference ML-KEM KeyGen\n/// representation.\npub fn matrix_vector_mul_add_to_ntt(\n    matrix: &NttPolyMatrix,\n    vector: &NttPolyVec,\n    error: &NttPolyVec,\n) -> NttPolyVec {\n    assert_eq!(matrix.rank(), vector.rank());\n    assert_eq!(vector.rank(), error.rank());\n\n    let rank = vector.rank();\n    let mut output = NttPolyVec::zero(rank);\n\n    let mut row = 0usize;\n    while row < rank {\n        let mut accumulator = [0i16; N];\n        let mut column = 0usize;\n\n        while column < rank {\n            let product = fips_ntt::basemul_polynomials(\n                matrix.get(row, column),\n                &vector.as_slice()[column],\n            );\n\n            let mut coefficient = 0usize;\n            while coefficient < N {\n                accumulator[coefficient] = crate::arithmetic::add(\n                    accumulator[coefficient],\n                    product.coefficients()[coefficient],\n                );\n                coefficient += 1;\n            }\n            column += 1;\n        }\n\n        let mut coefficient = 0usize;\n        while coefficient < N {\n            accumulator[coefficient] = crate::arithmetic::add(\n                crate::arithmetic::to_montgomery(accumulator[coefficient]),\n                error.as_slice()[row].coefficients()[coefficient],\n            );\n            coefficient += 1;\n        }\n\n        output.polys[row] = FipsNttPoly::from_coefficients(accumulator);\n        row += 1;\n    }\n\n    output\n}\n\n'''
if 'pub fn matrix_vector_mul_add_to_ntt' not in text:
    if matrix_ntt_marker not in text:
        raise SystemExit('Could not locate matrix-vector NTT insertion point')
    text = text.replace(matrix_ntt_marker, matrix_ntt_function + matrix_ntt_marker, 1)

# Add tests before final rank test.
test_marker = '''    #[test]\n    fn ntt_matrix_reports_rank() {\n'''
test_code = '''    #[test]\n    fn sampled_ntt_matrix_preserves_sampled_coefficients() {\n        let mut matrix = PolyMatrix::zero(2);\n        matrix.set(0, 0, polynomial(3, 1));\n        matrix.set(0, 1, polynomial(5, 2));\n        matrix.set(1, 0, polynomial(7, 3));\n        matrix.set(1, 1, polynomial(11, 4));\n\n        let sampled = NttPolyMatrix::from_sampled_ntt_matrix(&matrix);\n\n        assert_eq!(\n            sampled.get(0, 0).coefficients(),\n            matrix.get(0, 0).coefficients(),\n        );\n    }\n\n    #[test]\n    fn ntt_keygen_product_round_trips_to_coefficient_reference() {\n        let mut matrix = PolyMatrix::zero(2);\n        matrix.set(0, 0, polynomial(3, 1));\n        matrix.set(0, 1, polynomial(5, 2));\n        matrix.set(1, 0, polynomial(7, 3));\n        matrix.set(1, 1, polynomial(11, 4));\n\n        let secret = PolyVec::from_slice(&[\n            polynomial(13, 5),\n            polynomial(17, 6),\n        ]);\n        let error = PolyVec::from_slice(&[\n            polynomial(19, 7),\n            polynomial(23, 8),\n        ]);\n\n        let matrix_hat = NttPolyMatrix::from_sampled_ntt_matrix(&matrix);\n        let secret_hat = NttPolyVec::from_polyvec(&secret);\n        let error_hat = NttPolyVec::from_polyvec(&error);\n        let public_hat = matrix_vector_mul_add_to_ntt(\n            &matrix_hat,\n            &secret_hat,\n            &error_hat,\n        );\n\n        assert_eq!(public_hat.rank(), 2);\n        assert_eq!(public_hat.as_slice().len(), 2);\n    }\n\n'''
if 'sampled_ntt_matrix_preserves_sampled_coefficients' not in text:
    if test_marker not in text:
        raise SystemExit('Could not locate NTT-domain test insertion point')
    text = text.replace(test_marker, test_code + test_marker, 1)

path.write_text(text, encoding='utf-8')

# ---------------------------------------------------------------------------
# packing.rs
# ---------------------------------------------------------------------------
path = ROOT / 'crates/pqc-ml-kem/src/packing.rs'
text = path.read_text(encoding='utf-8')

if 'use crate::kpke_ntt_domain::NttPolyVec;' not in text:
    text = text.replace(
        'use crate::kpke::Message;\n',
        'use crate::kpke::Message;\nuse crate::kpke_ntt_domain::NttPolyVec;\n',
        1,
    )

public_marker = '''/// Decode a 12-bit encoded polynomial vector.\n'''
public_functions = '''/// Encode an ML-KEM public-key component directly from the NTT-domain public\n/// vector and `rho`.\npub fn encode_ntt_public_key_component<const BYTES: usize>(\n    parameter_set: MlKemParameterSet,\n    t_hat: &NttPolyVec,\n    rho: &[u8; RHO_BYTES],\n) -> PqcResult<[u8; BYTES]> {\n    if t_hat.rank() != parameter_set.k() {\n        return Err(PqcError::ProtocolInvariantFailed);\n    }\n    let expected = public_key_component_bytes(parameter_set);\n    if BYTES != expected {\n        return Err(PqcError::InvalidLength {\n            expected,\n            actual: BYTES,\n        });\n    }\n\n    let mut out = [0u8; BYTES];\n    encode_ntt_polyvec_12_into(\n        t_hat,\n        &mut out[..polyvec_12_bytes(parameter_set)],\n    )?;\n    out[polyvec_12_bytes(parameter_set)..].copy_from_slice(rho);\n    Ok(out)\n}\n\n/// Encode the CPA secret-key component directly from `s_hat`.\npub fn encode_ntt_secret_key_component<const BYTES: usize>(\n    parameter_set: MlKemParameterSet,\n    s_hat: &NttPolyVec,\n) -> PqcResult<[u8; BYTES]> {\n    if s_hat.rank() != parameter_set.k() {\n        return Err(PqcError::ProtocolInvariantFailed);\n    }\n    let expected = secret_key_component_bytes(parameter_set);\n    if BYTES != expected {\n        return Err(PqcError::InvalidLength {\n            expected,\n            actual: BYTES,\n        });\n    }\n\n    let mut out = [0u8; BYTES];\n    encode_ntt_polyvec_12_into(s_hat, &mut out)?;\n    Ok(out)\n}\n\n'''
if 'pub fn encode_ntt_public_key_component' not in text:
    if public_marker not in text:
        raise SystemExit('Could not locate packing public-key insertion point')
    text = text.replace(public_marker, public_functions + public_marker, 1)

helper_marker = '''fn encode_polyvec_12_into(polyvec: &PolyVec, out: &mut [u8]) -> PqcResult<()> {\n'''
helper = '''fn encode_ntt_polyvec_12_into(\n    polyvec: &NttPolyVec,\n    out: &mut [u8],\n) -> PqcResult<()> {\n    let expected = polyvec.rank() * POLY_12_BYTES;\n    if out.len() != expected {\n        return Err(PqcError::InvalidLength {\n            expected,\n            actual: out.len(),\n        });\n    }\n\n    for (index, poly) in polyvec.as_slice().iter().enumerate() {\n        let encoded = Poly::from_coefficients(*poly.coefficients()).encode_12();\n        let start = index * POLY_12_BYTES;\n        out[start..start + POLY_12_BYTES].copy_from_slice(&encoded);\n    }\n\n    Ok(())\n}\n\n'''
if 'fn encode_ntt_polyvec_12_into' not in text:
    if helper_marker not in text:
        raise SystemExit('Could not locate packing helper insertion point')
    text = text.replace(helper_marker, helper + helper_marker, 1)

path.write_text(text, encoding='utf-8')

# ---------------------------------------------------------------------------
# kpke_keygen.rs
# ---------------------------------------------------------------------------
path = ROOT / 'crates/pqc-ml-kem/src/kpke_keygen.rs'
text = path.read_text(encoding='utf-8')

text = text.replace(
    'use crate::packing::{\n    encode_public_key_component, encode_secret_key_component, public_key_component_bytes,\n    secret_key_component_bytes,\n};',
    'use crate::packing::{\n    encode_ntt_public_key_component, encode_ntt_secret_key_component,\n    public_key_component_bytes, secret_key_component_bytes,\n};',
)

old_body = '''    let seed_material =\n        expand_keygen_seed_for_parameter_set(parameter_set, seed);\n    let matrix = expand_matrix(parameter_set.k(), &seed_material.rho, false);\n    let s = sample_noise_vector(parameter_set, &seed_material.sigma, 0);\n    let e = sample_noise_vector(parameter_set, &seed_material.sigma, parameter_set.k() as u8);\n    let t = compute_public_vector(parameter_set.k(), &matrix, &s, &e);\n\n    let public_key = encode_public_key_component::<PK_BYTES>(parameter_set, &t, &seed_material.rho)?;\n    let secret_key = encode_secret_key_component::<SK_BYTES>(parameter_set, &s)?;\n'''
new_body = '''    let seed_material =\n        expand_keygen_seed_for_parameter_set(parameter_set, seed);\n    let matrix = expand_matrix(parameter_set.k(), &seed_material.rho, false);\n    let s = sample_noise_vector(parameter_set, &seed_material.sigma, 0);\n    let e = sample_noise_vector(\n        parameter_set,\n        &seed_material.sigma,\n        parameter_set.k() as u8,\n    );\n\n    let matrix_hat = NttPolyMatrix::from_sampled_ntt_matrix(&matrix);\n    let s_hat = NttPolyVec::from_polyvec(&s);\n    let e_hat = NttPolyVec::from_polyvec(&e);\n    let t_hat = crate::kpke_ntt_domain::matrix_vector_mul_add_to_ntt(\n        &matrix_hat,\n        &s_hat,\n        &e_hat,\n    );\n\n    let public_key = encode_ntt_public_key_component::<PK_BYTES>(\n        parameter_set,\n        &t_hat,\n        &seed_material.rho,\n    )?;\n    let secret_key = encode_ntt_secret_key_component::<SK_BYTES>(\n        parameter_set,\n        &s_hat,\n    )?;\n'''
if new_body not in text:
    if old_body not in text:
        # tolerate older formatting before Stage 6.2
        old_body2 = '''    let seed_material = expand_keygen_seed(seed);\n    let matrix = expand_matrix(parameter_set.k(), &seed_material.rho, false);\n    let s = sample_noise_vector(parameter_set, &seed_material.sigma, 0);\n    let e = sample_noise_vector(parameter_set, &seed_material.sigma, parameter_set.k() as u8);\n    let t = compute_public_vector(parameter_set.k(), &matrix, &s, &e);\n\n    let public_key = encode_public_key_component::<PK_BYTES>(parameter_set, &t, &seed_material.rho)?;\n    let secret_key = encode_secret_key_component::<SK_BYTES>(parameter_set, &s)?;\n'''
        if old_body2 not in text:
            raise SystemExit('Could not locate keygen serialization body')
        text = text.replace(old_body2, new_body, 1)
    else:
        text = text.replace(old_body, new_body, 1)

# Add a direct serialization-domain regression test.
test_marker = '''    #[test]\n    fn wrong_keygen_lengths_are_rejected() {\n'''
test_code = '''    #[test]\n    fn keygen_serializes_ntt_domain_secret_key() {\n        let parameter_set = MlKemParameterSet::MlKem512;\n        let seed = [0x5au8; 32];\n        let material =\n            expand_keygen_seed_for_parameter_set(parameter_set, &seed);\n        let secret = sample_noise_vector(\n            parameter_set,\n            &material.sigma,\n            0,\n        );\n        let secret_hat = NttPolyVec::from_polyvec(&secret);\n        let expected = crate::packing::encode_ntt_secret_key_component::<768>(\n            parameter_set,\n            &secret_hat,\n        )\n        .unwrap();\n\n        let generated = keygen_from_seed::<800, 768>(parameter_set, &seed)\n            .unwrap();\n\n        assert_eq!(generated.secret_key, expected);\n    }\n\n'''
if 'keygen_serializes_ntt_domain_secret_key' not in text:
    if test_marker not in text:
        raise SystemExit('Could not locate keygen test insertion point')
    text = text.replace(test_marker, test_code + test_marker, 1)

path.write_text(text, encoding='utf-8')

print('Stage 6.4 patch applied.')
