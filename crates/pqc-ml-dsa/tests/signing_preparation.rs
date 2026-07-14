use pqc_ml_dsa::keygen::keygen_internal;
use pqc_ml_dsa::params::MlDsaParameterSet;
use pqc_ml_dsa::signing::{
    compute_message_representative, decode_private_key, prepare_signing, sample_mask_vector,
    SigningError,
};

#[test]
fn generated_private_keys_decode_for_all_parameter_sets() {
    for parameter_set in [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ] {
        let key_pair = keygen_internal(parameter_set, &[0x11; 32]).unwrap();
        let decoded = decode_private_key(parameter_set, key_pair.private_key()).unwrap();
        let parameters = parameter_set.parameters();

        assert_eq!(decoded.s1().len(), parameters.l);
        assert_eq!(decoded.s2().len(), parameters.k);
        assert_eq!(decoded.t0().len(), parameters.k);
    }
}

#[test]
fn signing_preparation_is_deterministic() {
    let set = MlDsaParameterSet::MlDsa65;
    let key_pair = keygen_internal(set, &[0x22; 32]).unwrap();
    let randomness = [0x33; 32];

    let first = prepare_signing(
        set,
        key_pair.private_key(),
        b"message",
        b"context",
        &randomness,
    )
    .unwrap();
    let second = prepare_signing(
        set,
        key_pair.private_key(),
        b"message",
        b"context",
        &randomness,
    )
    .unwrap();

    assert_eq!(first.mu(), second.mu());
    assert_eq!(first.rho_double_prime(), second.rho_double_prime());
}

#[test]
fn transcript_separates_message_context_and_randomness() {
    let set = MlDsaParameterSet::MlDsa44;
    let key_pair = keygen_internal(set, &[0x44; 32]).unwrap();

    let base = prepare_signing(
        set,
        key_pair.private_key(),
        b"message",
        b"context",
        &[0_u8; 32],
    )
    .unwrap();
    let changed_message = prepare_signing(
        set,
        key_pair.private_key(),
        b"message!",
        b"context",
        &[0_u8; 32],
    )
    .unwrap();
    let changed_context = prepare_signing(
        set,
        key_pair.private_key(),
        b"message",
        b"context!",
        &[0_u8; 32],
    )
    .unwrap();
    let changed_randomness = prepare_signing(
        set,
        key_pair.private_key(),
        b"message",
        b"context",
        &[1_u8; 32],
    )
    .unwrap();

    assert_ne!(base.mu(), changed_message.mu());
    assert_ne!(base.mu(), changed_context.mu());
    assert_eq!(base.mu(), changed_randomness.mu());
    assert_ne!(
        base.rho_double_prime(),
        changed_randomness.rho_double_prime()
    );
}

#[test]
fn context_limit_is_enforced() {
    let error = compute_message_representative(&[0_u8; 64], &[0_u8; 256], b"message");
    assert!(matches!(error, Err(SigningError::ContextTooLong)));
}

#[test]
fn mask_vectors_have_parameter_dimensions_and_bounds() {
    for set in [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ] {
        let parameters = set.parameters();
        let vector = sample_mask_vector(&[0x55; 64], 7, parameters.l, parameters.gamma1).unwrap();

        assert_eq!(vector.len(), parameters.l);
        for polynomial in vector {
            assert!(polynomial.coeffs().iter().all(|coefficient| {
                (-parameters.gamma1 + 1..=parameters.gamma1).contains(coefficient)
            }));
        }
    }
}

#[test]
fn private_key_length_is_strict() {
    assert!(matches!(
        decode_private_key(MlDsaParameterSet::MlDsa44, &[0_u8; 31]),
        Err(SigningError::InvalidPrivateKeyLength)
    ));
}
