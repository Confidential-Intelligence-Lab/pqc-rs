#!/usr/bin/env python3
from pathlib import Path

encrypt_path = Path("crates/pqc-ml-kem/src/kpke_encrypt.rs")
runner_path = Path(
    "crates/pqc-test-harness/src/bin/ml-kem-acvp-encapsulation.rs"
)

if not encrypt_path.exists():
    raise SystemExit(f"{encrypt_path} not found; run from repository root")
if not runner_path.exists():
    raise SystemExit(f"{runner_path} not found; run from repository root")

text = encrypt_path.read_text(encoding="utf-8")

text = text.replace(
    "use crate::sampling::{sample_eta2_poly, sample_eta2_vector};",
    "use crate::sampling::{sample_eta1_vector, sample_eta2_poly, sample_eta2_vector};",
)

if "sample_eta1_vector" not in text and "sample_eta2_vector" in text:
    text = text.replace(
        "sample_eta2_vector,",
        "sample_eta1_vector, sample_eta2_vector,",
        1,
    )

for old, new in [
    (
        "let r = sample_eta2_vector(parameter_set, randomness.as_bytes(), 0);",
        "let r = sample_eta1_vector(parameter_set, randomness.as_bytes(), 0);",
    ),
    (
        "let r = sample_eta2_vector(parameter_set, randomness, 0);",
        "let r = sample_eta1_vector(parameter_set, randomness, 0);",
    ),
]:
    if old in text:
        text = text.replace(old, new, 1)
        break

text = text.replace(
    "let public_ntt = NttPolyVec::from_polyvec(t_hat);",
    "let public_ntt = NttPolyVec::from_sampled_ntt_polyvec(t_hat);",
)

text = text.replace(
    "let matrix_ntt = NttPolyMatrix::from_matrix(&transposed_matrix);",
    "let matrix_ntt = NttPolyMatrix::from_sampled_ntt_matrix(&transposed_matrix);",
)

test_marker = "    #[test]\n    fn encrypt_512_is_deterministic_and_has_correct_shape() {\n"
test_code = '''    #[test]
    fn ml_kem_512_ephemeral_secret_uses_eta1() {
        let randomness = EncryptionRandomness::new([0x33u8; 32]);
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

        assert_ne!(eta1, eta2);
    }

'''

if "ml_kem_512_ephemeral_secret_uses_eta1" not in text:
    if test_marker not in text:
        raise SystemExit("Could not locate encryption test insertion point")
    text = text.replace(test_marker, test_code + test_marker, 1)

encrypt_path.write_text(text, encoding="utf-8")
print(f"Updated {encrypt_path}")

text = runner_path.read_text(encoding="utf-8")

old_execute = '''    if actual.ciphertext != expected_ciphertext {
        return Err(mismatch_report(
            case,
            "ciphertext",
            &actual.ciphertext,
            expected_ciphertext,
        ));
    }

    if actual.shared_secret.as_bytes() != expected_shared_secret {
        return Err(mismatch_report(
            case,
            "shared secret",
            actual.shared_secret.as_bytes(),
            expected_shared_secret,
        ));
    }

    Ok(())
'''

new_execute = '''    let ciphertext_matches = actual.ciphertext == expected_ciphertext;
    let shared_secret_matches =
        actual.shared_secret.as_bytes() == expected_shared_secret;

    if ciphertext_matches && shared_secret_matches {
        return Ok(());
    }

    let mut details = Vec::new();

    if !ciphertext_matches {
        details.push(mismatch_report(
            case,
            "ciphertext",
            &actual.ciphertext,
            expected_ciphertext,
        ));
    } else {
        details.push(format!(
            "parameterSet={}, tgId={}, tcId={}\\n  ciphertext: match",
            case.parameter_set, case.tg_id, case.tc_id
        ));
    }

    if !shared_secret_matches {
        details.push(mismatch_report(
            case,
            "shared secret",
            actual.shared_secret.as_bytes(),
            expected_shared_secret,
        ));
    } else {
        details.push(format!(
            "parameterSet={}, tgId={}, tcId={}\\n  shared secret: match",
            case.parameter_set, case.tg_id, case.tc_id
        ));
    }

    Err(details.join("\\n"))
'''

if new_execute not in text:
    if old_execute not in text:
        raise SystemExit("Could not locate ACVP comparison block")
    text = text.replace(old_execute, new_execute, 1)

runner_path.write_text(text, encoding="utf-8")
print(f"Updated {runner_path}")
