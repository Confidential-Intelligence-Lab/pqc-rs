use pqc_ml_dsa::{
    MlDsa, MlDsaError, MlDsaKeyGenSeed, MlDsaParameterSet, MlDsaPrivateKey, MlDsaPublicKey,
    MlDsaSignature, PreHashAlgorithm, ML_DSA_KEYGEN_SEED_BYTES,
};
use rand_core::OsRng;

const PARAMETER_SETS: [MlDsaParameterSet; 3] = [
    MlDsaParameterSet::MlDsa44,
    MlDsaParameterSet::MlDsa65,
    MlDsaParameterSet::MlDsa87,
];

fn deterministic_seed(parameter_set: MlDsaParameterSet, byte: u8) -> MlDsaKeyGenSeed {
    MlDsaKeyGenSeed::from_bytes(parameter_set, [byte; ML_DSA_KEYGEN_SEED_BYTES])
}

#[test]
fn deterministic_public_api_round_trips_all_parameter_sets() {
    for parameter_set in PARAMETER_SETS {
        let implementation = MlDsa::new(parameter_set);
        let seed = deterministic_seed(parameter_set, 0x42);
        let key_pair = implementation.keygen_from_seed(&seed).unwrap();
        let signature = implementation
            .sign_deterministic(key_pair.private_key(), b"message", b"context")
            .unwrap();

        assert_eq!(key_pair.public_key().parameter_set(), parameter_set);
        assert_eq!(key_pair.private_key().parameter_set(), parameter_set);
        assert_eq!(signature.parameter_set(), parameter_set);
        assert!(implementation
            .verify(key_pair.public_key(), b"message", b"context", &signature,)
            .unwrap());
    }
}

#[test]
fn deterministic_and_hedged_signing_are_explicit() {
    let implementation = MlDsa::new(MlDsaParameterSet::MlDsa44);
    let seed = deterministic_seed(MlDsaParameterSet::MlDsa44, 0x11);
    let key_pair = seed.expand().unwrap();

    let first = implementation
        .sign_deterministic(key_pair.private_key(), b"message", b"")
        .unwrap();
    let second = implementation
        .sign_deterministic(key_pair.private_key(), b"message", b"")
        .unwrap();
    let hedged = implementation
        .sign_hedged(key_pair.private_key(), b"message", b"", &mut OsRng)
        .unwrap();

    assert_eq!(first, second);
    assert_ne!(first, hedged);
    assert!(implementation
        .verify(key_pair.public_key(), b"message", b"", &hedged)
        .unwrap());
}

#[test]
fn randomized_key_generation_produces_a_usable_key_pair() {
    let implementation = MlDsa::new(MlDsaParameterSet::MlDsa44);
    let key_pair = implementation.keygen(&mut OsRng).unwrap();
    let signature = implementation
        .sign_deterministic(key_pair.private_key(), b"message", b"")
        .unwrap();

    assert!(implementation
        .verify(key_pair.public_key(), b"message", b"", &signature)
        .unwrap());
}

#[test]
fn keygen_seed_is_parameter_bound_and_reproducibly_expandable() {
    let parameter_set = MlDsaParameterSet::MlDsa44;
    let seed = deterministic_seed(parameter_set, 0x5a);

    assert_eq!(seed.parameter_set(), parameter_set);
    assert_eq!(seed.as_bytes(), &[0x5a; ML_DSA_KEYGEN_SEED_BYTES]);
    assert!(core::mem::needs_drop::<MlDsaKeyGenSeed>());

    let first = seed.expand().unwrap();
    let second = seed.expand().unwrap();

    assert_eq!(first.public_key(), second.public_key());
    assert_eq!(
        first.private_key().as_bytes(),
        second.private_key().as_bytes()
    );

    let mismatched = MlDsa::new(MlDsaParameterSet::MlDsa65);
    assert_eq!(
        mismatched.keygen_from_seed(&seed).err().unwrap(),
        MlDsaError::ParameterSetMismatch
    );
}

#[test]
fn randomized_keygen_seed_expands_to_a_usable_key_pair() {
    let parameter_set = MlDsaParameterSet::MlDsa44;
    let implementation = MlDsa::new(parameter_set);
    let seed = implementation.generate_keygen_seed(&mut OsRng).unwrap();
    let key_pair = seed.expand().unwrap();
    let signature = implementation
        .sign_deterministic(key_pair.private_key(), b"message", b"")
        .unwrap();

    assert_eq!(seed.parameter_set(), parameter_set);
    assert!(implementation
        .verify(key_pair.public_key(), b"message", b"", &signature)
        .unwrap());
}

#[test]
fn hash_ml_dsa_round_trip_is_exposed() {
    let implementation = MlDsa::new(MlDsaParameterSet::MlDsa44);
    let seed = deterministic_seed(MlDsaParameterSet::MlDsa44, 0x22);
    let key_pair = seed.expand().unwrap();
    let signature = implementation
        .hash_sign_deterministic(
            key_pair.private_key(),
            b"message",
            b"context",
            PreHashAlgorithm::Sha2_256,
        )
        .unwrap();

    assert!(implementation
        .hash_verify(
            key_pair.public_key(),
            b"message",
            b"context",
            PreHashAlgorithm::Sha2_256,
            &signature,
        )
        .unwrap());
    assert!(!implementation
        .hash_verify(
            key_pair.public_key(),
            b"changed",
            b"context",
            PreHashAlgorithm::Sha2_256,
            &signature,
        )
        .unwrap());
}

#[test]
fn typed_decoding_rejects_malformed_encodings() {
    let parameter_set = MlDsaParameterSet::MlDsa44;

    assert_eq!(
        MlDsaPublicKey::from_bytes(parameter_set, &[0_u8; 31]).unwrap_err(),
        MlDsaError::InvalidPublicKey
    );
    assert_eq!(
        MlDsaPrivateKey::from_bytes(parameter_set, &[0_u8; 31])
            .err()
            .unwrap(),
        MlDsaError::InvalidPrivateKey
    );
    assert_eq!(
        MlDsaSignature::from_bytes(parameter_set, &[0_u8; 31]).unwrap_err(),
        MlDsaError::InvalidSignature
    );
}

#[test]
fn verification_rejects_modified_input_and_context() {
    let parameter_set = MlDsaParameterSet::MlDsa44;
    let implementation = MlDsa::new(parameter_set);
    let seed = deterministic_seed(parameter_set, 0x33);
    let key_pair = seed.expand().unwrap();
    let signature = implementation
        .sign_deterministic(key_pair.private_key(), b"message", b"context")
        .unwrap();

    assert!(!implementation
        .verify(key_pair.public_key(), b"changed", b"context", &signature,)
        .unwrap());
    assert!(!implementation
        .verify(key_pair.public_key(), b"message", b"changed", &signature,)
        .unwrap());

    let mut modified = signature.as_bytes().to_vec();
    modified[0] ^= 1;
    let modified = MlDsaSignature::from_bytes(parameter_set, &modified).unwrap();
    assert!(!implementation
        .verify(key_pair.public_key(), b"message", b"context", &modified,)
        .unwrap());
}

#[test]
fn parameter_mismatch_and_oversized_context_are_reported() {
    let implementation_44 = MlDsa::new(MlDsaParameterSet::MlDsa44);
    let implementation_65 = MlDsa::new(MlDsaParameterSet::MlDsa65);
    let seed_44 = deterministic_seed(MlDsaParameterSet::MlDsa44, 0x44);
    let seed_65 = deterministic_seed(MlDsaParameterSet::MlDsa65, 0x45);
    let key_pair_44 = implementation_44.keygen_from_seed(&seed_44).unwrap();
    let key_pair_65 = implementation_65.keygen_from_seed(&seed_65).unwrap();
    let signature_44 = implementation_44
        .sign_deterministic(key_pair_44.private_key(), b"message", b"")
        .unwrap();
    let signature_65 = implementation_65
        .sign_deterministic(key_pair_65.private_key(), b"message", b"")
        .unwrap();

    assert_eq!(
        implementation_44
            .sign_deterministic(key_pair_65.private_key(), b"message", b"")
            .unwrap_err(),
        MlDsaError::ParameterSetMismatch
    );
    assert_eq!(
        implementation_44
            .verify(key_pair_44.public_key(), b"message", b"", &signature_65,)
            .unwrap_err(),
        MlDsaError::ParameterSetMismatch
    );

    let oversized_context = [0_u8; 256];
    assert_eq!(
        implementation_44
            .sign_deterministic(key_pair_44.private_key(), b"message", &oversized_context,)
            .unwrap_err(),
        MlDsaError::ContextTooLong
    );

    assert!(implementation_44
        .verify(key_pair_44.public_key(), b"message", b"", &signature_44,)
        .unwrap());
}
