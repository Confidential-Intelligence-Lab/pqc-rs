#![cfg(feature = "internal-api")]

use pqc_ml_dsa::keygen::keygen_internal;
use pqc_ml_dsa::params::MlDsaParameterSet;
use pqc_ml_dsa::signature::sign_internal;
use pqc_ml_dsa::verification::{
    decode_hint_vector, decode_public_key, decode_signature, verify_internal, VerificationError,
};

#[test]
fn generated_signatures_verify_for_all_parameter_sets() {
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

        assert!(verify_internal(
            parameter_set,
            key_pair.public_key(),
            b"message",
            b"context",
            &signature,
        )
        .unwrap());
    }
}

#[test]
fn modified_message_context_and_signature_are_rejected() {
    let parameter_set = MlDsaParameterSet::MlDsa44;
    let key_pair = keygen_internal(parameter_set, &[0x22; 32]).unwrap();
    let signature = sign_internal(
        parameter_set,
        key_pair.private_key(),
        b"message",
        b"context",
        &[0_u8; 32],
    )
    .unwrap();

    assert!(!verify_internal(
        parameter_set,
        key_pair.public_key(),
        b"message!",
        b"context",
        &signature,
    )
    .unwrap());

    assert!(!verify_internal(
        parameter_set,
        key_pair.public_key(),
        b"message",
        b"context!",
        &signature,
    )
    .unwrap());

    let mut modified = signature;
    modified[0] ^= 1;

    assert!(!verify_internal(
        parameter_set,
        key_pair.public_key(),
        b"message",
        b"context",
        &modified,
    )
    .unwrap());
}

#[test]
fn mismatched_public_key_is_rejected() {
    let parameter_set = MlDsaParameterSet::MlDsa65;
    let signer = keygen_internal(parameter_set, &[0x33; 32]).unwrap();
    let other = keygen_internal(parameter_set, &[0x34; 32]).unwrap();
    let signature = sign_internal(
        parameter_set,
        signer.private_key(),
        b"message",
        b"",
        &[0_u8; 32],
    )
    .unwrap();

    assert!(!verify_internal(
        parameter_set,
        other.public_key(),
        b"message",
        b"",
        &signature,
    )
    .unwrap());
}

#[test]
fn generated_objects_strictly_decode() {
    for parameter_set in [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ] {
        let key_pair = keygen_internal(parameter_set, &[0x44; 32]).unwrap();
        let signature = sign_internal(
            parameter_set,
            key_pair.private_key(),
            b"message",
            b"",
            &[1_u8; 32],
        )
        .unwrap();

        let public_key = decode_public_key(parameter_set, key_pair.public_key()).unwrap();
        let decoded_signature = decode_signature(parameter_set, &signature).unwrap();

        assert_eq!(public_key.t1().len(), parameter_set.parameters().k);
        assert_eq!(decoded_signature.z().len(), parameter_set.parameters().l);
        assert_eq!(
            decoded_signature.hints().len(),
            parameter_set.parameters().k
        );
    }
}

#[test]
fn malformed_lengths_are_rejected() {
    assert!(matches!(
        decode_public_key(MlDsaParameterSet::MlDsa44, &[0_u8; 10]),
        Err(VerificationError::InvalidPublicKeyLength)
    ));

    assert!(matches!(
        decode_signature(MlDsaParameterSet::MlDsa44, &[0_u8; 10]),
        Err(VerificationError::InvalidSignatureLength)
    ));
}

#[test]
fn hint_decoder_rejects_non_monotonic_indices() {
    let mut encoded = vec![0_u8; 82];
    encoded[0] = 9;
    encoded[1] = 7;
    encoded[80] = 2;
    encoded[81] = 2;

    assert!(matches!(
        decode_hint_vector(&encoded, 2, 80),
        Err(VerificationError::InvalidSignatureEncoding)
    ));
}

#[test]
fn hint_decoder_rejects_nonzero_padding() {
    let mut encoded = vec![0_u8; 82];
    encoded[0] = 7;
    encoded[80] = 1;
    encoded[81] = 1;
    encoded[5] = 3;

    assert!(matches!(
        decode_hint_vector(&encoded, 2, 80),
        Err(VerificationError::InvalidSignatureEncoding)
    ));
}
