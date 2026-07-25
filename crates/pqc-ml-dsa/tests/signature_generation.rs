#![cfg(feature = "internal-api")]

use pqc_ml_dsa::keygen::keygen_internal;
use pqc_ml_dsa::params::MlDsaParameterSet;
use pqc_ml_dsa::poly::Poly;
use pqc_ml_dsa::signature::{encode_hint_vector, sign_internal, SignatureError};

#[test]
fn deterministic_signing_produces_standardized_lengths() {
    for parameter_set in [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ] {
        let key_pair = keygen_internal(parameter_set, &[0x11; 32]).unwrap();
        let signature = sign_internal(
            parameter_set,
            key_pair.private_key(),
            b"message",
            b"context",
            &[0_u8; 32],
        )
        .unwrap();

        assert_eq!(signature.len(), parameter_set.parameters().signature_bytes);
    }
}

#[test]
fn deterministic_signing_is_reproducible() {
    let parameter_set = MlDsaParameterSet::MlDsa44;
    let key_pair = keygen_internal(parameter_set, &[0x22; 32]).unwrap();

    let first = sign_internal(
        parameter_set,
        key_pair.private_key(),
        b"message",
        b"",
        &[0_u8; 32],
    )
    .unwrap();
    let second = sign_internal(
        parameter_set,
        key_pair.private_key(),
        b"message",
        b"",
        &[0_u8; 32],
    )
    .unwrap();

    assert_eq!(first, second);
}

#[test]
fn hedged_randomness_changes_signature() {
    let parameter_set = MlDsaParameterSet::MlDsa44;
    let key_pair = keygen_internal(parameter_set, &[0x33; 32]).unwrap();

    let first = sign_internal(
        parameter_set,
        key_pair.private_key(),
        b"message",
        b"",
        &[0_u8; 32],
    )
    .unwrap();
    let second = sign_internal(
        parameter_set,
        key_pair.private_key(),
        b"message",
        b"",
        &[1_u8; 32],
    )
    .unwrap();

    assert_ne!(first, second);
}

#[test]
fn hint_encoding_is_canonical() {
    let mut first = [0_i32; 256];
    first[1] = 1;
    first[9] = 1;

    let mut second = [0_i32; 256];
    second[7] = 1;

    let encoded =
        encode_hint_vector(&[Poly::from_coeffs(first), Poly::from_coeffs(second)], 5).unwrap();

    assert_eq!(&encoded[..3], &[1, 9, 7]);
    assert_eq!(encoded[5], 2);
    assert_eq!(encoded[6], 3);
}

#[test]
fn hint_encoding_rejects_non_binary_coefficients() {
    let mut coefficients = [0_i32; 256];
    coefficients[0] = 2;

    assert!(matches!(
        encode_hint_vector(&[Poly::from_coeffs(coefficients)], 1),
        Err(SignatureError::Encoding)
    ));
}
