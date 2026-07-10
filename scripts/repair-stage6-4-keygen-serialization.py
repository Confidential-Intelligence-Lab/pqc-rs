\
#!/usr/bin/env python3
from pathlib import Path
import re

path = Path("crates/pqc-ml-kem/src/kpke_keygen.rs")
if not path.exists():
    raise SystemExit(f"{path} not found; run this script from the repository root")

text = path.read_text(encoding="utf-8")

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

packing_pattern = re.compile(
    r"use crate::packing::\{\n(?P<body>.*?)\n\};",
    re.DOTALL,
)

match = packing_pattern.search(text)
if not match:
    raise SystemExit("Could not locate crate::packing import block")

packing_import = """use crate::packing::{
    encode_ntt_public_key_component, encode_ntt_secret_key_component,
    public_key_component_bytes, secret_key_component_bytes,
};"""

text = text[:match.start()] + packing_import + text[match.end():]

ntt_import = "use crate::kpke_ntt_domain::{NttPolyMatrix, NttPolyVec};\n"
if ntt_import not in text:
    insertion = "use crate::matrix::expand_matrix;\n"
    if insertion not in text:
        raise SystemExit("Could not locate matrix import insertion point")
    text = text.replace(insertion, ntt_import + insertion, 1)

# ---------------------------------------------------------------------------
# Locate keygen_from_seed by brace matching.
# ---------------------------------------------------------------------------

signature = "pub fn keygen_from_seed<const PK_BYTES: usize, const SK_BYTES: usize>("
function_start = text.find(signature)
if function_start < 0:
    raise SystemExit("Could not locate keygen_from_seed")

open_brace = text.find("{", function_start)
if open_brace < 0:
    raise SystemExit("Could not locate keygen_from_seed opening brace")

depth = 0
function_end = None
for index in range(open_brace, len(text)):
    char = text[index]
    if char == "{":
        depth += 1
    elif char == "}":
        depth -= 1
        if depth == 0:
            function_end = index + 1
            break

if function_end is None:
    raise SystemExit("Could not locate keygen_from_seed closing brace")

function = text[function_start:function_end]

# Preserve the validation prefix and output suffix, replace only the algorithm body.
algorithm_start = function.find("    let seed_material")
output_start = function.find("    Ok(KpkeKeygenOutput")

if algorithm_start < 0:
    raise SystemExit("Could not locate seed-material statement in keygen_from_seed")
if output_start < 0:
    raise SystemExit("Could not locate KpkeKeygenOutput construction")
if output_start <= algorithm_start:
    raise SystemExit("Unexpected keygen_from_seed layout")

replacement = """    let seed_material =
        expand_keygen_seed_for_parameter_set(parameter_set, seed);
    let matrix = expand_matrix(parameter_set.k(), &seed_material.rho, false);
    let secret = sample_noise_vector(parameter_set, &seed_material.sigma, 0);
    let error = sample_noise_vector(
        parameter_set,
        &seed_material.sigma,
        parameter_set.k() as u8,
    );

    // FIPS 203 ExpandA/SampleNTT already returns matrix entries in the NTT
    // representation. Do not apply another forward transform to the matrix.
    let matrix_hat = NttPolyMatrix::from_sampled_ntt_matrix(&matrix);
    let secret_hat = NttPolyVec::from_polyvec(&secret);
    let error_hat = NttPolyVec::from_polyvec(&error);
    let public_hat = crate::kpke_ntt_domain::matrix_vector_mul_add_to_ntt(
        &matrix_hat,
        &secret_hat,
        &error_hat,
    );

    // FIPS 203 serializes the NTT-domain vectors directly:
    // ekPKE = ByteEncode12(t_hat) || rho
    // dkPKE = ByteEncode12(s_hat)
    let public_key = encode_ntt_public_key_component::<PK_BYTES>(
        parameter_set,
        &public_hat,
        &seed_material.rho,
    )?;
    let secret_key = encode_ntt_secret_key_component::<SK_BYTES>(
        parameter_set,
        &secret_hat,
    )?;

"""

new_function = (
    function[:algorithm_start]
    + replacement
    + function[output_start:]
)

text = text[:function_start] + new_function + text[function_end:]

# ---------------------------------------------------------------------------
# Add a regression test if absent.
# ---------------------------------------------------------------------------

test_name = "keygen_serializes_ntt_domain_secret_key"
if test_name not in text:
    marker = """    #[test]
    fn wrong_keygen_lengths_are_rejected() {
"""
    test = """    #[test]
    fn keygen_serializes_ntt_domain_secret_key() {
        let parameter_set = MlKemParameterSet::MlKem512;
        let seed = [0x5au8; 32];
        let material =
            expand_keygen_seed_for_parameter_set(parameter_set, &seed);
        let secret = sample_noise_vector(
            parameter_set,
            &material.sigma,
            0,
        );
        let secret_hat = NttPolyVec::from_polyvec(&secret);
        let expected =
            crate::packing::encode_ntt_secret_key_component::<768>(
                parameter_set,
                &secret_hat,
            )
            .unwrap();

        let generated =
            keygen_from_seed::<800, 768>(parameter_set, &seed).unwrap();

        assert_eq!(generated.secret_key, expected);
    }

"""
    if marker not in text:
        raise SystemExit("Could not locate keygen test insertion point")
    text = text.replace(marker, test + marker, 1)

path.write_text(text, encoding="utf-8")
print(f"Repaired {path}")
